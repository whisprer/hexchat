// Backend for tokio-rustls 0.25 (rustls 0.22), rustls-pemfile 1.x
// Features:
// - TCP/TLS connect with system roots (webpki-roots)
// - Extract tls-server-end-point (SHA-256 of leaf cert) for channel binding
// - CAP negotiation (selective CAP REQ from CAP LS 302, multiline-aware)
// - SASL: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, EXTERNAL
// - Strict SCRAM server-signature verification (abort on mismatch)
#![allow(clippy::needless_lifetimes)]

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, BytesMut};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// IMPORTANT: use the rustls types re-exported by tokio-rustls to satisfy TlsConnector::from(Arc<ClientConfig>)
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore, OwnedTrustAnchor, Certificate, ClientConnection,
    version, 
};
use tokio_rustls::rustls::pki_types::{ServerName};
use tokio_rustls::{TlsConnector, client::TlsStream};

use tracing::{debug, error};

pub enum TlsConfig {
    Off,
    Rustls { client_auth: Option<ClientAuth> },
}

pub struct ClientAuth {
    pub cert_path: String,
    pub key_path: String,
}

enum Io {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

pub struct Connection {
    stream: Io,
    buf: BytesMut,
    cb_tls_server_end_point: Option<Vec<u8>>,
}

impl Connection {
    pub async fn connect(host: &str, port: u16, tls: TlsConfig) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect(&addr).await.with_context(|| format!("connecting to {}", addr))?;

        match tls {
            TlsConfig::Off => Ok(Self {
                stream: Io::Tcp(tcp),
                buf: BytesMut::with_capacity(4096),
                cb_tls_server_end_point: None,
            }),
            TlsConfig::Rustls { client_auth } => {
                let mut roots = RootCertStore::empty();
                // rustls 0.22 RootCertStore::add_trust_anchors uses OwnedTrustAnchor
                roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
                }));

                // Builder with defaults
                let cfg_builder = ClientConfig::builder()
                    .with_safe_default_cipher_suites()
                    .with_safe_default_kx_groups()
                    .with_protocol_versions(&[&version::TLS13, &version::TLS12])
                    .map_err(|_| anyhow!("unable to set TLS versions"))?;

                // optional client certs
                let cfg = if let Some(ca) = client_auth {
                    let mut cert_reader = BufReader::new(File::open(&ca.cert_path)
                        .with_context(|| format!("open cert {}", ca.cert_path))?);
                    // rustls-pemfile 1.x yields Vec<Vec<u8>>
                    let certs_raw = rustls_pemfile::certs(&mut cert_reader)
                        .with_context(|| "parse certs")?;
                    let certs: Vec<Certificate> = certs_raw.into_iter().map(Certificate).collect();

                    // keys: try pkcs8 first, then rsa
                    let key_der = {
                        let mut key_reader = BufReader::new(File::open(&ca.key_path)
                            .with_context(|| format!("open key {}", ca.key_path))?);
                        let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;
                        if let Some(k) = pkcs8.first() {
                            tokio_rustls::rustls::PrivateKey(k.clone())
                        } else {
                            // try RSA
                            let mut key_reader = BufReader::new(File::open(&ca.key_path)?);
                            let rsa = rustls_pemfile::rsa_private_keys(&mut key_reader)?;
                            let k = rsa.first().ok_or_else(|| anyhow!("no private keys in {}", ca.key_path))?;
                            tokio_rustls::rustls::PrivateKey(k.clone())
                        }
                    };

                    cfg_builder.with_root_certificates(roots)
                        .with_single_cert(certs, key_der)
                        .context("attach client auth")?
                } else {
                    cfg_builder.with_root_certificates(roots).with_no_client_auth()
                };

                let server_name = ServerName::try_from(host).map_err(|_| anyhow!("invalid DNS name for TLS: {}", host))?;
                let connector = TlsConnector::from(Arc::new(cfg));
                let mut tls_stream = connector.connect(server_name, tcp).await?;

                // Compute tls-server-end-point = SHA-256(peer cert DER)
                let mut cb_tlsep: Option<Vec<u8>> = None;
                let (_tcp, conn): (&TcpStream, &ClientConnection) = tls_stream.get_ref();
                if let Some(certs) = conn.peer_certificates() {
                    if let Some(leaf) = certs.first() {
                        use sha2::{Sha256, Digest};
                        let mut h = Sha256::new();
                        h.update(leaf.0.as_slice());
                        cb_tlsep = Some(h.finalize().to_vec());
                    }
                }

                Ok(Self {
                    stream: Io::Tls(tls_stream),
                    buf: BytesMut::with_capacity(4096),
                    cb_tls_server_end_point: cb_tlsep,
                })
            }
        }
    }

    pub fn tls_server_end_point(&self) -> Option<&[u8]> {
        self.cb_tls_server_end_point.as_deref()
    }

    pub async fn send_raw(&mut self, line: &str) -> Result<()> {
        let mut data = line.as_bytes().to_vec();
        data.extend_from_slice(b"\r\n");
        match &mut self.stream {
            Io::Tcp(s) => s.write_all(&data).await?,
            Io::Tls(s) => s.write_all(&data).await?,
        }
        Ok(())
    }

    pub async fn next_message(&mut self) -> Result<proto::Message> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line = self.buf.split_to(pos + 1).to_vec();
                if let Some(b'\n') = line.last() { line.pop(); }
                if let Some(b'\r') = line.last() { line.pop(); }
                let s = String::from_utf8(line).unwrap_or_default();
                return proto::Message::parse(&s).context("parse IRC line failed");
            }
            let mut tmp = [0u8; 2048];
            let n = match &mut self.stream {
                Io::Tcp(s) => s.read(&mut tmp).await?,
                Io::Tls(s) => s.read(&mut tmp).await?,
            };
            if n == 0 { bail!("eof"); }
            self.buf.put_slice(&tmp[..n]);
        }
    }
}

// real proto lives in crates/proto; this import assumes you add that crate as a dependency
use proto;

pub mod cap_sasl {
    use super::Connection;
    use anyhow::{Result, Context, bail};
    use base64::{engine::general_purpose, Engine as _};
    use hmac::{Hmac, Mac};
    use pbkdf2::pbkdf2_hmac;
    use rand::{RngCore, rngs::OsRng};
    use sha2::{Sha256, Sha512, Digest};
    use subtle::ConstantTimeEq;
    use std::collections::HashSet;
    use tracing::{debug, error};
    use proto::Message;

    #[derive(Debug, Clone, Default)]
    pub struct CapRequest { pub want: Vec<&'static str> }
    impl CapRequest {
        pub fn defaults(include_sasl: bool) -> Self {
            let mut v = vec!["server-time", "message-tags"];
            if include_sasl { v.push("sasl"); }
            Self { want: v }
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
        algo: &'static str,
        auth_message: String,
        expected_server_sig: Vec<u8>,
    }

    fn b64(s: &str) -> String { general_purpose::STANDARD.encode(s.as_bytes()) }
    fn b64_bytes(b: &[u8]) -> String { general_purpose::STANDARD.encode(b) }
    fn saslname(s: &str) -> String { s.replace('=', "=3D").replace(',', "=2C") }
    fn gen_nonce() -> String { let mut n = [0u8; 18]; OsRng.fill_bytes(&mut n); b64_bytes(&n) }

    struct ScramParsed { salt: Vec<u8>, iter: u32, nonce: String }
    fn parse_scram_challenge(ch: &str) -> Result<ScramParsed> {
        let mut salt_b64=None; let mut iter=None; let mut nonce=None;
        for kv in ch.split(',') {
            if let Some((k,v)) = kv.split_once('=') {
                match k {
                    "r" => nonce = Some(v.to_string()),
                    "s" => salt_b64 = Some(v.to_string()),
                    "i" => iter = Some(v.parse::<u32>()?),
                    _ => {}
                }
            }
        }
        let salt = general_purpose::STANDARD.decode(salt_b64.context("missing salt")?)?;
        Ok(ScramParsed{ salt, iter: iter.context("missing iterations")?, nonce: nonce.context("missing nonce")? })
    }

    pub async fn negotiate(conn: &mut Connection, nick: &str, user: &str, realname: &str, caps: CapRequest, sasl: Option<SaslMech>) -> Result<()> {
        conn.send_raw(&format!("NICK {}", nick)).await?;
        conn.send_raw(&format!("USER {} 0 * :{}", user, realname)).await?;
        conn.send_raw("CAP LS 302").await?;

        let mut cap_in_progress = true;
        let mut ls_partial: HashSet<String> = HashSet::new();
        let want: HashSet<String> = caps.want.iter().map(|s| s.to_string()).collect();
        let mut req_sent = false;

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
                            if !to_req.is_empty() { conn.send_raw(&format!("CAP REQ :{}", to_req.join(" "))).await?; req_sent = True; }
                            else { conn.send_raw("CAP END").await?; cap_in_progress = false; }
                        }
                    }
                    "ACK" => {
                        let ackd = msg.params.last().cloned().unwrap_or_default();
                        if ackd.split_whitespace().any(|c| c == "sasl") && sasl.is_some() {
                            match &sasl {
                                Some(SaslMech::Plain{..}) => conn.send_raw("AUTHENTICATE PLAIN").await?,
                                Some(SaslMech::ScramSha256{ username, .. }) => {
                                    let cnonce = gen_nonce(); let cfb = format!("n={},r={}", saslname(username), cnonce);
                                    scram_client_nonce = Some(cnonce.clone()); scram_cfb = Some(cfb.clone());
                                    conn.send_raw("AUTHENTICATE SCRAM-SHA-256").await?;
                                }
                                Some(SaslMech::ScramSha512{ username, .. }) => {
                                    let cnonce = gen_nonce(); let cfb = format!("n={},r={}", saslname(username), cnonce);
                                    scram_client_nonce = Some(cnonce.clone()); scram_cfb = Some(cfb.clone());
                                    conn.send_raw("AUTHENTICATE SCRAM-SHA-512").await?;
                                }
                                Some(SaslMech::External{..}) => conn.send_raw("AUTHENTICATE EXTERNAL").await?,
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
                        Some(SaslMech::ScramSha256{ .. }) | Some(SaslMech::ScramSha512{ .. }) => {
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
                    let data_b64 = msg.params.get(0).cloned().unwrap_or_default();
                    let challenge_bytes = base64::engine::general_purpose::STANDARD.decode(&data_b64).unwrap_or_default();
                    let challenge = String::from_utf8_lossy(&challenge_bytes).to_string();

                    match &sasl {
                        Some(SaslMech::ScramSha256{ username: _, password, .. }) => {
                            let parsed = parse_scram_challenge(&challenge)?;
                            let cnonce = scram_client_nonce.clone().context("scram: missing client nonce")?;
                            if !parsed.nonce.starts_with(&cnonce) { bail!("scram: bad nonce"); }

                            let mut salted = [0u8; 32];
                            pbkdf2_hmac::<Sha256>(password.as_bytes(), &parsed.salt, parsed.iter, &mut salted);

                            let cval = if let Some(tlsep) = conn.tls_server_end_point() {
                                let mut v = b"p=tls-server-end-point,,".to_vec(); v.extend_from_slice(tlsep); b64_bytes(&v)
                            } else { b64("n,,") };
                            let cbind = format!("c={}", cval);
                            let cn = format!("r={}", parsed.nonce);
                            let cfb = scram_cfb.clone().unwrap();
                            let cf_without_proof = format!("{},{}", cbind, cn);
                            let auth_message = format!("{},{},{}", cfb, challenge, cf_without_proof);

                            let mut ck = Hmac::<Sha256>::new_from_slice(&salted).unwrap();
                            ck.update(b"Client Key");
                            let client_key = ck.finalize().into_bytes();
                            let mut hasher = Sha256::new(); hasher.update(&client_key);
                            let stored_key = hasher.finalize();

                            let mut sigmac = Hmac::<Sha256>::new_from_slice(&stored_key).unwrap();
                            sigmac.update(auth_message.as_bytes());
                            let client_signature = sigmac.finalize().into_bytes();

                            let mut proof = client_key.to_vec();
                            for (a,b) in proof.iter_mut().zip(&client_signature){ *a ^= *b; }
                            let final_msg = format!("{},p={}", cf_without_proof, b64_bytes(&proof));
                            conn.send_raw(&format!("AUTHENTICATE {}", b64(&final_msg))).await?;

                            let mut skh = Hmac::<Sha256>::new_from_slice(&salted).unwrap();
                            skh.update(b"Server Key");
                            let server_key = skh.finalize().into_bytes();
                            let mut ssmac = Hmac::<Sha256>::new_from_slice(&server_key).unwrap();
                            ssmac.update(auth_message.as_bytes());
                            let expected_server_sig = ssmac.finalize().into_bytes().to_vec();
                            scram_state = Some(ScramState{ algo: "SHA-256", auth_message, expected_server_sig });
                        }
                        Some(SaslMech::ScramSha512{ username: _, password, .. }) => {
                            let parsed = parse_scram_challenge(&challenge)?;
                            let cnonce = scram_client_nonce.clone().context("scram: missing client nonce")?;
                            if !parsed.nonce.starts_with(&cnonce) { bail!("scram: bad nonce"); }

                            let mut salted = [0u8; 64];
                            pbkdf2_hmac::<Sha512>(password.as_bytes(), &parsed.salt, parsed.iter, &mut salted);

                            let cval = if let Some(tlsep) = conn.tls_server_end_point() {
                                let mut v = b"p=tls-server-end-point,,".to_vec(); v.extend_from_slice(tlsep); b64_bytes(&v)
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

                            let mut proof = client_key.to_vec();
                            for (a,b) in proof.iter_mut().zip(&client_signature){ *a ^= *b; }
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

                    // server-final verification (v=...)
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

            // success/failure numerics
            if cmd == "900" || cmd == "903" {
                if cap_in_progress { conn.send_raw("CAP END").await?; cap_in_progress = false; }
                continue;
            }
            if cmd == "904" || cmd == "905" || cmd == "906" || cmd == "907" {
                if cap_in_progress { conn.send_raw("CAP END").await?; cap_in_progress = false; }
                bail!("SASL failed with {}", cmd);
            }
            if cmd == "001" { break; }
        }
        Ok(())
    }
}
