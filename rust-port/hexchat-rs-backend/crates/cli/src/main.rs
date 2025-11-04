
use anyhow::Result;
use tracing::info;
use std::env;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let mut args = env::args().skip(1);
    let mut server = "irc.libera.chat".to_string();
    let mut port: u16 = 6697;
    let mut tls = true;
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut nick = "HexRs".to_string();
    let mut user = "hexrs".to_string();
    let mut realname = "HexChat RS".to_string();
    let mut join: Option<String> = None;
    let mut sasl_plain: Option<(String, String)> = None; // (user, pass)
    let mut sasl_scram256: Option<(String, String)> = None;
    let mut sasl_scram512: Option<(String, String)> = None;
    let mut sasl_external: bool = false;
    let mut sasl_authzid: Option<String> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--server" => server = args.next().unwrap_or(server),
            "--port" => port = args.next().and_then(|s| s.parse().ok()).unwrap_or(port),
            "--tls" => tls = true,
            "--notls" => tls = false,
            "--nick" => nick = args.next().unwrap_or(nick),
            "--user" => user = args.next().unwrap_or(user),
            "--realname" => realname = args.next().unwrap_or(realname),
            "--cert" => cert = args.next(),
            "--key" => key = args.next(),
            "--join" => join = args.next(),
            "--sasl-plain" => {
                if let Some(creds) = args.next() {
                    if let Some((u,p)) = creds.split_once(':') {
                        sasl_plain = Some((u.to_string(), p.to_string()));
                    }
            "--sasl-external" => { sasl_external = true; }
                }
            }
            "--sasl-authzid" => { sasl_authzid = args.next(); }
            "--sasl-scram256" => {
                if let Some(creds) = args.next() { if let Some((u,p)) = creds.split_once(':') { sasl_scram256 = Some((u.to_string(), p.to_string())); } }
            }
            "--sasl-scram512" => {
                if let Some(creds) = args.next() { if let Some((u,p)) = creds.split_once(':') { sasl_scram512 = Some((u.to_string(), p.to_string())); } }
            }
            _ => {}
        }
    }

    info!("connecting to {}:{} (tls={}) as {}", server, port, tls, nick);

    
let tls_cfg = if tls {
    if let (Some(c), Some(k)) = (cert.clone(), key.clone()) {
        net::TlsConfig::Rustls { client_auth: Some(net::ClientAuth{ cert_path: c, key_path: k }) }
    } else {
        net::TlsConfig::Rustls { client_auth: None }
    }
} else { net::TlsConfig::Off };
let mut conn = net::Connection::connect(&server, port, tls_cfg).await?;


    // CAP/SASL negotiation
    
let include_sasl = sasl_plain.is_some() || sasl_scram256.is_some() || sasl_scram512.is_some() || sasl_external;
let mut caps = net::cap_sasl::CapRequest::defaults(include_sasl);

    let sasl = if sasl_external {
        Some(net::cap_sasl::SaslMech::External { authzid: sasl_authzid.clone() })
    } else if let Some((u,p)) = sasl_scram512.clone() {
        Some(net::cap_sasl::SaslMech::ScramSha512 { authzid: sasl_authzid.clone(), username: u, password: p })
    } else if let Some((u,p)) = sasl_scram256.clone() {
        Some(net::cap_sasl::SaslMech::ScramSha256 { authzid: sasl_authzid.clone(), username: u, password: p })
    } else if let Some((u,p)) = sasl_plain.clone() {
        Some(net::cap_sasl::SaslMech::Plain {
        authzid: sasl_authzid.clone(),
        username: u,
        password: p,
    })
    ;
    net::cap_sasl::negotiate(&mut conn, &nick, &user, &realname, caps, sasl).await?;

    // If requested, join a channel now that we're welcomed
    if let Some(ch) = &join {
        conn.send_raw(&format!("JOIN {}", ch)).await?;
    }

    let engine = core::Engine::new(&server, &nick);

    loop {
        let msg = match conn.next_message().await {
            Ok(m) => m,
            Err(e) => { eprintln!("recv error: {e}"); break; }
        };
        let ev = engine.on_message(msg.clone());
        match &ev {
            core::Event::PrivMsg{ from, target, text } => {
                info!("{} -> {}: {}", from, target, text);
            }
            core::Event::Join{ nick, channel } => {
                info!("{} joined {}", nick, channel);
            }
            _ => {}
        }
    }

    Ok(())
}
