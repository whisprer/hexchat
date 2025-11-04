use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DccKind { Chat, Send }

#[derive(Debug, Clone)]
pub struct DccOffer {
    pub kind: DccKind,
    pub filename: Option<String>,
    pub ip: u32,
    pub port: u16,
    pub size: Option<u64>,
}

pub fn parse_dcc(ctcp_inner: &str) -> Result<DccOffer> {
    let mut it = ctcp_inner.split_whitespace();
    let cmd = it.next().ok_or_else(|| anyhow::anyhow!("empty"))?;
    if cmd != "DCC" { bail!("not DCC"); }
    let kind = match it.next().ok_or_else(|| anyhow::anyhow!("missing kind"))? {
        "SEND" => DccKind::Send,
        "CHAT" => DccKind::Chat,
        other => bail!("unknown kind {other}"),
    };
    let mut filename: Option<String> = None;
    if let DccKind::Send = kind {
        filename = Some(it.next().ok_or_else(|| anyhow::anyhow!("missing filename"))?.to_string());
    }
    let ip: u32 = it.next().ok_or_else(|| anyhow::anyhow!("missing ip"))?.parse()?;
    let port: u16 = it.next().ok_or_else(|| anyhow::anyhow!("missing port"))?.parse()?;
    let size: Option<u64> = it.next().and_then(|s| s.parse().ok());
    Ok(DccOffer{ kind, filename, ip, port, size })
}
