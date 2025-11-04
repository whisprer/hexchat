use anyhow::{Result, Context};
use bytes::BytesMut;
use proto::{Message, parse_line};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{ClientConfig, ServerName};
use tokio_rustls::TlsConnector;
use sha2::{Sha256, Digest};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;
use tracing::warn;

pub struct Connection {
    cb_tls_server_end_point: Option<Vec<u8>>,
    stream: Box<dyn Io + Send + Sync>,
    buf: BytesMut,
}

#[async_trait::async_trait]
pub trait Io {
    async fn read(&mut self, dst: &mut [u8]) -> Result<usize>;
    async fn write_all(&mut self, src: &[u8]) -> Result<()>;
}

#[async_trait::async_trait]
impl Io for TcpStream {
    async fn read(&mut self, dst: &mut [u8]) -> Result<usize> { Ok(AsyncReadExt::read(self, dst).await?) }
    async fn write_all(&mut self, src: &[u8]) -> Result<()> { Ok(AsyncWriteExt::write_all(self, src).await?) }
}

struct TlsIo(tokio_rustls::client::TlsStream<TcpStream>);

#[async_trait::async_trait]
impl Io for TlsIo {
    async fn read(&mut self, dst: &mut [u8]) -> Result<usize> { Ok(AsyncReadExt::read(&mut self.0, dst).await?) }
    async fn write_all(&mut self, src: &[u8]) -> Result<()> { Ok(AsyncWriteExt::write_all(&mut self.0, src).await?) }
}


pub enum TlsConfig {
    Off,
    Rustls { client_auth: Option<ClientAuth> },
}

pub struct ClientAuth {
    pub cert_path: String,
    pub key_path: String,
}
impl Connection {
    pub fn tls_server_end_point(&self) -> Option<&[u8]> { self.cb_tls_server_end_point.as_deref() }
    pub async fn connect(host: &str, port: u16, tls: TlsConfig) -> Result<Self> {
        let addr = format!("{host}:{port}");
        let mut tcp = timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;
        tcp.set_nodelay(true)?;
        if !matches!(tls, TlsConfig::Off) {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta|{
                tokio_rustls::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject, ta.spki, ta.name_constraints)
            }));
            let cfg = ClientConfig::builder().with_safe_default_cipher_suites().with_safe_default_kx_groups()
                .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13, &tokio_rustls::rustls::version::TLS12]).unwrap()
                .with_root_certificates(roots).with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(cfg));
            let server_name = ServerName::try_from(host).context("invalid DNSname")?;
            let mut tls_stream = connector.connect(server_name, tcp).await?;
            let mut cb_tlsep: Option<Vec<u8>> = None;
            if let Some((conn, _io)) = tls_stream.get_ref() {
                if let Some(certs) = conn.peer_certificates() {
                    if let Some(leaf) = certs.first() {
                        let mut hasher = Sha256::new();
                        hasher.update(&leaf.0);
                        let digest = hasher.finalize().to_vec();
                        cb_tlsep = Some(digest);
                    }
                }
            }
            Ok(Self{ stream: Box::new(TlsIo(tls_stream)), buf: BytesMut::with_capacity(4096), cb_tls_server_end_point: cb_tlsep })
        } else {
            Ok(Self{ stream: Box::new(tcp), buf: BytesMut::with_capacity(4096), cb_tls_server_end_point: None })
        }
    }

    pub async fn send_msg(&mut self, m: &Message) -> Result<()> {
        let line = m.to_line();
        self.stream.write_all(line.as_bytes()).await?;
        Ok(())
    }

    pub async fn send_raw(&mut self, raw: &str) -> Result<()> {
        let mut s = raw.to_string();
        if !s.ends_with("\r\n") { s.push_str("\r\n"); }
        self.stream.write_all(s.as_bytes()).await?;
        Ok(())
    }

    pub async fn next_message(&mut self) -> Result<Message> {
        let mut tmp = [0u8; 1024];
        loop {
            if let Some(idx) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line = self.buf.split_to(idx + 2);
                let s = String::from_utf8_lossy(&line).to_string();
                match parse_line(&s) {
                    Ok(m) => return Ok(m),
                    Err(e) => warn!("parse error: {e}; line={s:?}"),
                }
            }
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 { anyhow::bail!("connection closed"); }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}





pub mod cap_sasl {
    use anyhow::{Result, Context, bail};
    use base64::{engine::general_purpose, Engine as _};
    use std::collections::HashSet;
    use super::Connection;
    use proto::Message;

    use hmac::{Hmac, Mac};
    use pbkdf2::pbkdf2_hmac;
    use sha2::{Sha256, Sha512, Digest};
    use rand::{RngCore, rngs::OsRng};
    use subtle::ConstantTimeEq;
    use tracing::{debug, error};

    #[derive(Debug, Clone, Default)]
    pub struct CapRequest {
        pub want: Vec<&'static str>, // e.g., ["server-time","message-tags","sasl"]
    }
    impl CapRequest {
        pub fn defaults(include_sasl: bool) -> Self {
            let mut v = vec!["server-time", "message-tags"];
            if include_sasl { v.push("sasl"); }
            Self{ want: v }
        }
    }

    #[derive(Debug, Clone)]
    pub enum SaslMech {
        Plain { authzid: Option<String>, username: String, password: String },
        ScramSha256 { authzid: Option<String>, username: String, password: String },
        ScramSha512 { authzid: Option<String>, username: String, password: String },
        External { authzid: Option<String> },
    }

    struct ScramState {
        algo: &'static str,           // "SHA-256" | "SHA-512"
        auth_message: String,         // client-first-bare + "," + server-first + "," + client-final-without-proof
        expected_server_sig: Vec<u8>, // HMAC(ServerKey, auth_message)
    }

    fn b64(s: &str) -> String { general_purpose::STANDARD.encode(s.as_bytes()) }
    fn b64_bytes(bytes: &[u8]) -> String { general_purpose::STANDARD.encode(bytes) }
    fn saslname(s: &str) -> String { s.replace('=', "=3D").replace(',', "=2C") }
    fn gen_nonce() -> String { let mut n = [0u8; 18]; OsRng.fill_bytes(&mut n); b64_bytes(&n) }

    struct ScramParsed { salt: Vec<u8>, iter: u32, nonce: String }
    fn parse_scram_challenge(ch: &str) -> Result<ScramParsed> {
        let mut salt_b64=None; let mut iter=None; let mut nonce=None;
        for kv in ch.split(',') {
            if let Some((k,v)) = kv.split_once('=') {
                match k { "r"=>nonce=Some(v.to_string()), "s"=>salt_b64=Some(v.to_string()), "i"=>iter=Some(v.parse::<u32>()?), _=>{} }
            }
        }
        let salt = general_purpose::STANDARD.decode(salt_b64.context("missing salt")?)?;
        Ok(ScramParsed{ salt, iter: iter.context("missing iterations")?, nonce: nonce.context("missing nonce")? })
    }
    fn xor_in_place(dst: &mut [u8], src: &[u8]) { for (d,s) in dst.iter_mut().zip(src.iter()) { *d ^= *s; } }

    pub async fn negotiate(
        conn: &mut Connection,
        nick: &str,
        user: &str,
        realname: &str,
        caps: CapRequest,
        sasl: Option<SaslMech>,
    ) -> Result<()> {
        conn.send_raw(&format!("NICK {}", nick)).await?;
        conn.send_raw(&format!("USER {} 0 * :{}", user, realname)).await?;
        conn.send_raw("CAP LS 302").await?;

        let mut cap_in_progress = true;
        let mut ls_partial: HashSet<String> = HashSet::new();
        let want: HashSet<String> = caps.want.iter().map(|s| s.to_string()).collect();
        let mut req_sent = false;

        // SCRAM state
        let mut scram_client_nonce: Option<String> = None;
        let mut scram_cfb: Option<String> = None;
        let mut scram_state: Option<ScramState> = None;

        loop {
            let msg = conn.next_message().await?;
            let cmd = msg.command.as_str();

            if cmd == "CAP" {
                let sub = msg.params.get(1).map(String::as_str).unwrap_or("");
                match sub {
                    "LS" => {
                        if let Some(caps_str) = msg.params.last() {
                            for c in caps_str.split_whitespace() { ls_partial.insert(c.to_string()); }
                        }
                        let is_cont = msg.params.iter().any(|p| p == "*");
                        if !is_cont && !req_sent {
                            let to_req: Vec<String> = want.intersection(&ls_partial).cloned().collect();
                            if !to_req.is_empty() {
                                conn.send_raw(&format!("CAP REQ :{}", to_req.join(" "))).await?;
                                req_sent = true;
                            } else {
                                conn.send_raw("CAP END").await?;
                                cap_in_progress = false;
                            }
                        }
                    }
                    "ACK" => {
                        let ackd = msg.params.last().cloned().unwrap_or_default();
                        if ackd.split_whitespace().any(|c| c == "sasl") && sasl.is_some() {
                            match &sasl {
                                Some(SaslMech::Plain{..}) => { conn.send_raw("AUTHENTICATE PLAIN").await?; }
                                Some(SaslMech::ScramSha256{ username, .. }) => {
                                    let cnonce = gen_nonce();
                                    let cfb = format!("n={},r={}", saslname(username), cnonce);
                                    scram_client_nonce = Some(cnonce.clone());
                                    scram_cfb = Some(cfb.clone());
                                    conn.send_raw("AUTHENTICATE SCRAM-SHA-256").await?;
                                }
                                Some(SaslMech::ScramSha512{ username, .. }) => {
                                    let cnonce = gen_nonce();
                                    let cfb = format!("n={},r={}", saslname(username), cnonce);
                                    scram_client_nonce = Some(cnonce.clone());
                                    scram_cfb = Some(cfb.clone());
                                    conn.send_raw("AUTHENTICATE SCRAM-SHA-512")..await?;
                                }
                                Some(SaslMech::External{..}) => { conn.send_raw("AUTHENTICATE EXTERNAL").await?; }
                                None => {}
                            }
                        }
                    }
                    "NAK" => {
                        if cap_in_progress { conn.send_raw("CAP END").await?; cap_in_progress = false; }
                    }
                    _ => {}
                }
                continue;
            }

            if cmd == "AUTHENTICATE" {
                if msg.params.get(0).map(String::as_str) == Some("+") {
                    match &sasl {
                        Some(SaslMech::Plain{ authzid, username, password }) => {
                            let authz = authzid.as_deref().unwrap_or("");
                            let payload = format!("{}\x00{}\x00{}", authz, username, password);
                            conn.send_raw(&format!("AUTHENTICATE {}", b64(&payload))).await?;
                        }
                        Some(SaslMech::ScramSha256{ username, password, .. }) |
                        Some(SaslMech::ScramSha512{ username, password, .. }) => {
                            // GS2: p=tls-server-end-point,, if TLS is present; else n,,
                            let gs2 = if conn.tls_server_end_point().is_some() { "p=tls-server-end-point,," } else { "n,," };
                            let cfb = scram_cfb.clone().context("scram: no client-first-bare")?;
                            let first = format!("{}{}", gs2, cfb);
                            conn.send_raw(&format!("AUTHENTICATE {}", b64(&first))).await?;
                        }
                        Some(SaslMech::External{ authzid }) => {
                            if let Some(a) = authzid { conn.send_raw(&format!("AUTHENTICATE {}", b64(a))).await?; }
                            else { conn.send_raw("AUTHENTICATE +").await?; }
                        }
                        None => {}
                    }
                } else {
                    // Challenge or final
                    let data_b64 = msg.params.get(0).cloned().unwrap_or_default();
                    let challenge_bytes = base64::engine::general_purpose::STANDARD.decode(&data_b64).unwrap_or_default();
                    let challenge = String::from_utf8_lossy(&challenge_bytes).to_string();

                    match &sasl {
                        Some(SaslMech::ScramSha256{ username, password, .. }) => {
                            // server-first: r=...,s=...,i=...
                            let parsed = parse_scram_challenge(&challenge)?;
                            let cnonce = scram_client_nonce.clone().context("scram: missing client nonce")?;
                            if !parsed.nonce.starts_with(&cnonce) { bail!("scram: bad nonce"); }

                            // saltedPassword = PBKDF2-HMAC(SHA-256)
                            let mut salted = [0u8; 32];
                            pbkdf2_hmac::<Sha256>(password.as_bytes(), &parsed.salt, parsed.iter as usize, &mut salted);

                            // Channel binding c=
                            let cval = if let Some(tlsep) = conn.tls_server_end_point() {
                                let mut pre = b"p=tls-server-end-point,,".to_vec();
                                let mut v = pre.clone(); v.extend_from_slice(tlsep);
                                b64_bytes(&v)
                            } else { b64("n,,") };
                            let cbind = format!("c={}", cval);
                            let cn = format!("r={}", parsed.nonce);
                            let cfb = scram_cfb.clone().unwrap();
                            let cf_without_proof = format!("{},{}", cbind, cn);
                            let auth_message = format!("{},{},{}", cfb, challenge, cf_without_proof);

                            // ClientKey, StoredKey
                            let mut ck = Hmac::<Sha256>::new_from_slice(&salted).unwrap();
                            ck.update(b"Client Key");
                            let client_key = ck.finalize().into_bytes();
                            let mut hasher = Sha256::new(); hasher.update(&client_key);
                            let stored_key = hasher.finalize();

                            // ClientSignature
                            let mut sigmac = Hmac::<Sha256>::new_from_slice(&stored_key).unwrap();
                            sigmac.update(auth_message.as_bytes());
                            let client_signature = sigmac.finalize().into_bytes();

                            // ClientProof
                            let mut proof = client_key.to_vec(); for (d,s) in proof.iter_mut().zip(client_signature.iter()) { *d ^= *s; }
                            let final_msg = format!("{},p={}", cf_without_proof, b64_bytes(&proof));
                            conn.send_raw(&format!("AUTHENTICATE {}", b64(&final_msg))).await?;

                            // expected ServerSignature = HMAC(ServerKey, auth_message)
                            let mut skh = Hmac::<Sha256>::new_from_slice(&salted).unwrap();
                            skh.update(b"Server Key");
                            let server_key = skh.finalize().into_bytes();
                            let mut ssmac = Hmac::<Sha256>::new_from_slice(&server_key).unwrap();
                            ssmac.update(auth_message.as_bytes());
                            let expected_server_sig = ssmac.finalize().into_bytes().to_vec();
                            scram_state = Some(ScramState{ algo: "SHA-256", auth_message, expected_server_sig });
                        }
                        Some(SaslMech::ScramSha512{ username, password, .. }) => {
                            let parsed = parse_scram_challenge(&challenge)?;
                            let cnonce = scram_client_nonce.clone().context("scram: missing client nonce")?;
                            if !parsed.nonce.starts_with(&cnonce) { bail!("scram: bad nonce"); }

                            let mut salted = [0u8; 64];
                            pbkdf2_hmac::<Sha512>(password.as_bytes(), &parsed.salt, parsed.iter as usize, &mut salted);

                            let cval = if let Some(tlsep) = conn.tls_server_end_point() {
                                let mut pre = b"p=tls-server-end-point,,".to_vec();
                                let mut v = pre.clone(); v.extend_from_slice(tlsep);
                                b64_bytes(&v)
                            } else { b64("n,,") };
                            let cbind = format!("c={}", cval);
                            let cn = format!("r={}", parsed.nonce);
                            let cfb = scram_cfb.clone().unwrap();
                            let cf_without_proof = format!("{},{}", cbind, cn);
                            let auth_message = format!("{},{},{}", cfb, challenge, cf_without_proof);

                            let mut ck = Hmac::<Sha512>::new_from_slice(&salted).unwrap();
                            ck.update(b"Client Key");
                            let client_key = ck.finalize().into_bytes();
                            let mut hasher = Sha512::new(); hasher.update(&client_key);
                            let stored_key = hasher.finalize();

                            let mut sigmac = Hmac::<Sha512>::new_from_slice(&stored_key).unwrap();
                            sigmac.update(auth_message.as_bytes());
                            let client_signature = sigmac.finalize().into_bytes();

                            let mut proof = client_key.to_vec(); for (d,s) in proof.iter_mut().zip(client_signature.iter()) { *d ^= *s; }
                            let final_msg = format!("{},p={}", cf_without_proof, b64_bytes(&proof));
                            conn.send_raw(&format!("AUTHENTICATE {}", b64(&final_msg))).await?;

                            let mut skh = Hmac::<Sha512>::new_from_slice(&salted).unwrap();
                            skh.update(b"Server Key");
                            let server_key = skh.finalize().into_bytes();
                            let mut ssmac = Hmac::<Sha512>::new_from_slice(&server_key).unwrap();
                            ssmac.update(auth_message.as_bytes());
                            let expected_server_sig = ssmac.finalize().into_bytes().to_vec();
                            scram_state = Some(ScramState{ algo: "SHA-512", auth_message, expected_server_sig });
                        }
                        _ => {}
                    }

                    // If server-final contains v=, verify
                    if let Some(pos) = challenge.find("v=") {
                        if let Some(state) = &scram_state {
                            let vs = &challenge[pos+2..];
                            let vs_b64 = vs.split(',').next().unwrap_or("");
                            if let Ok(server_sig) = base64::engine::general_purpose::STANDARD.decode(vs_b64) {
                                if server_sig.ct_eq(&state.expected_server_sig).unwrap_u8() == 1 {
                                    debug!("SCRAM server signature verified OK ({})", state.algo);
                                } else {
                                    error!("SCRAM server signature mismatch — aborting");
                                    if cap_in_progress { let _ = conn.send_raw("CAP END").await; }
                                    bail!("SCRAM: server signature mismatch");
                                }
                            } else {
                                error!("SCRAM server signature (v=) not valid base64");
                                if cap_in_progress { let _ = conn.send_raw("CAP END").await; }
                                bail!("SCRAM: invalid server v= value");
                            }
                        }
                    }
                }
                continue;
            }

            if cmd == "900" || cmd == "903" {
                if cap_in_progress { conn.send_raw("CAP END").await?; cap_in_progress = false; }
                continue;
            }
            if cmd == "904" || cmd == "905" || cmd == "906" || cmd == "907" {
                if cap_in_progress { conn.send_raw("CAP END").await?; cap_in_progress = false; }
                continue;
            }

            if cmd == "001" { break; }
        }

        Ok(())
    }
}



