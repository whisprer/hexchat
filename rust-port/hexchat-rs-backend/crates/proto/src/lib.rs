use anyhow::{Result, bail};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tags(pub Vec<(String, Option<String>)>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub tags: Option<Tags>,
    pub prefix: Option<Prefix>,
    pub command: String,
    pub params: Vec<String>,
}

impl Message {
    pub fn to_line(&self) -> String {
        let mut out = String::new();
        if let Some(tags) = &self.tags {
            out.push('@');
            for (i,(k,v)) in tags.0.iter().enumerate() {
                if i>0 { out.push(';'); }
                out.push_str(k);
                if let Some(val) = v {
                    out.push('=');
                    out.push_str(val);
                }
            }
            out.push(' ');
        }
        if let Some(prefix) = &self.prefix {
            out.push(':');
            out.push_str(&prefix.raw);
            out.push(' ');
        }
        out.push_str(&self.command);
        for (i, p) in self.params.iter().enumerate() {
            out.push(' ');
            if i == self.params.len()-1 && (p.contains(' ') || p.is_empty()) {
                out.push(':');
                out.push_str(p);
            } else {
                out.push_str(p);
            }
        }
        out.push('\r');
        out.push('\n');
        out
    }
}

fn take_until<'a>(s: &'a str, ch: char) -> (&'a str, &'a str) {
    if let Some(idx) = s.find(ch) {
        (&s[..idx], &s[idx+1..])
    } else {
        (s, "")
    }
}

pub fn parse_line(mut s: &str) -> Result<Message> {
    let mut tags: Option<Tags> = None;
    let mut prefix: Option<Prefix> = None;
    s = s.trim_end_matches(|c| c == '\r' || c == '\n');

    if s.starts_with('@') {
        let (tag_blob, rest) = take_until(&s[1..], ' ');
        let mut kvs = Vec::new();
        for part in tag_blob.split(';') {
            if let Some(eq) = part.find('=') {
                kvs.push((part[..eq].to_string(), Some(part[eq+1..].to_string())));
            } else {
                kvs.push((part.to_string(), None));
            }
        }
        tags = Some(Tags(kvs));
        s = rest;
    }

    if s.starts_with(':') {
        let (pfx, rest) = take_until(&s[1..], ' ');
        prefix = Some(Prefix{ raw: pfx.to_string() });
        s = rest;
    }

    let (cmd, rest) = take_until(s, ' ');
    if cmd.is_empty() { bail!("missing command"); }
    let mut params = Vec::new();
    let mut r = rest;
    while !r.is_empty() {
        if r.starts_with(':') {
            params.push(r[1..].to_string());
            r = "";
            break;
        }
        let (p, rest2) = take_until(r, ' ');
        if !p.is_empty() {
            params.push(p.to_string());
        }
        r = rest2;
    }

    Ok(Message{ tags, prefix, command: cmd.to_string(), params })
}
