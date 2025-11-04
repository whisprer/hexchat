use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use proto::Message;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChannelId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub name: String,
    pub users: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerState {
    pub network: String,
    pub nick: String,
    pub channels: HashMap<ChannelId, Channel>,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<RwLock<ServerState>>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Welcome(String),
    Join { nick: String, channel: String },
    Part { nick: String, channel: String },
    PrivMsg { from: String, target: String, text: String },
    Notice { from: String, target: String, text: String },
    Topic { channel: String, text: String },
    Unknown(Message),
}

impl Engine {
    pub fn new(network: impl Into<String>, nick: impl Into<String>) -> Self {
        let state = ServerState {
            network: network.into(),
            nick: nick.into(),
            channels: HashMap::new(),
        };
        Self { inner: Arc::new(RwLock::new(state)) }
    }

    pub fn state(&self) -> ServerState { self.inner.read().clone() }

    pub fn on_message(&self, msg: Message) -> Event {
        let mut st = self.inner.write();
        match msg.command.as_str() {
            "001" => Event::Welcome(msg.params.get(1).cloned().unwrap_or_default()),
            "JOIN" => {
                let who = msg.prefix.as_ref().map(|p| p.raw.split('!').next().unwrap_or(&p.raw).to_string()).unwrap_or_default();
                let chan = msg.params.last().cloned().unwrap_or_default();
                let id = ChannelId(chan.clone());
                st.channels.entry(id.clone()).or_insert(Channel{
                    name: chan.clone(),
                    users: HashSet::new(),
                }).users.insert(who.clone());
                Event::Join{ nick: who, channel: chan }
            }
            "PART" => {
                let who = msg.prefix.as_ref().map(|p| p.raw.split('!').next().unwrap_or(&p.raw).to_string()).unwrap_or_default();
                let chan = msg.params.first().cloned().unwrap_or_default();
                let id = ChannelId(chan.clone());
                if let Some(c) = st.channels.get_mut(&id) { c.users.remove(&who); }
                Event::Part{ nick: who, channel: chan }
            }
            "PRIVMSG" => {
                let who = msg.prefix.as_ref().map(|p| p.raw.split('!').next().unwrap_or(&p.raw).to_string()).unwrap_or_default();
                let target = msg.params.get(0).cloned().unwrap_or_default();
                let text = msg.params.get(1).cloned().unwrap_or_default();
                Event::PrivMsg{ from: who, target, text }
            }
            "NOTICE" => {
                let who = msg.prefix.as_ref().map(|p| p.raw.split('!').next().unwrap_or(&p.raw).to_string()).unwrap_or_default();
                let target = msg.params.get(0).cloned().unwrap_or_default();
                let text = msg.params.get(1).cloned().unwrap_or_default();
                Event::Notice{ from: who, target, text }
            }
            "332" => {
                let chan = msg.params.get(1).cloned().unwrap_or_default();
                let text = msg.params.get(2).cloned().unwrap_or_default();
                Event::Topic{ channel: chan, text }
            }
            _ => Event::Unknown(msg),
        }
    }
}
