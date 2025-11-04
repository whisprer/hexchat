use anyhow::Result;
use proto::Message;
use core::Event;

pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn on_event(&self, _ev: &Event) -> Result<()> { Ok(()) }
    fn on_outgoing(&self, _msg: &Message) -> Result<()> { Ok(()) }
}

pub struct PluginHost {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginHost {
    pub fn new() -> Self { Self{ plugins: Vec::new() } }
    pub fn register(&mut self, p: Box<dyn Plugin>) { self.plugins.push(p); }
    pub fn dispatch_event(&self, ev: &Event) {
        for p in &self.plugins { let _ = p.on_event(ev); }
    }
    pub fn dispatch_outgoing(&self, m: &Message) {
        for p in &self.plugins { let _ = p.on_outgoing(m); }
    }
}
