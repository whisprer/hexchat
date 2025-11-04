use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Prefix {
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub prefix: Option<Prefix>,
    pub command: String,
    pub params: Vec<String>,
}

impl Message {
    pub fn parse(line: &str) -> Result<Self> {
        let mut s = line.trim().to_string();
        let prefix = if s.starts_with(':') {
            if let Some(space) = s.find(' ') {
                let p = Prefix { raw: s[1..space].to_string() };
                s = s[space + 1..].to_string();
                Some(p)
            } else { None }
        } else { None };

        let mut parts = s.split_whitespace();
        let command = parts.next().unwrap_or("").to_string();
        let mut params: Vec<String> = Vec::new();
        let mut trailing = false;
        for tok in parts {
            if trailing {
                if let Some(last) = params.last_mut() {
                    last.push(' ');
                    last.push_str(tok);
                }
            } else if tok.starts_with(':') {
                params.push(tok[1..].to_string());
                trailing = true;
            } else {
                params.push(tok.to_string());
            }
        }
        Ok(Message { prefix, command, params })
    }

    pub fn to_string(&self) -> String {
        let mut out = String::new();
        if let Some(p) = &self.prefix {
            out.push(':');
            out.push_str(&p.raw);
            out.push(' ');
        }
        out.push_str(&self.command);
        if !self.params.is_empty() {
            for (i, p) in self.params.iter().enumerate() {
                out.push(' ');
                if i == self.params.len() - 1 && (p.contains(' ') || p.starts_with(':')) {
                    out.push(':');
                }
                out.push_str(p);
            }
        }
        out
    }
}
