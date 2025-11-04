use anyhow::Result;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub server: String,
    pub port: u16,
    pub use_tls: bool,
    pub nick: String,
    pub user: String,
    pub realname: String,
    pub autojoin: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: "irc.libera.chat".into(),
            port: 6697,
            use_tls: true,
            nick: "HexRs".into(),
            user: "hexrs".into(),
            realname: "HexChat RS".into(),
            autojoin: vec!["#rust".into()],
        }
    }
}

impl Settings {
    pub fn load(path: &Utf8PathBuf) -> Result<Self> {
        if path.exists() {
            let s = fs::read_to_string(path)?;
            Ok(toml::from_str(&s)?)
        } else {
            Ok(Self::default())
        }
    }
    pub fn save(&self, path: &Utf8PathBuf) -> Result<()> {
        let s = toml::to_string_pretty(self)?;
        fs::write(path, s)?;
        Ok(())
    }
}
