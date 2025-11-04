pub fn strip_colors(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let b = s.as_bytes()[i];
        match b {
            0x02 | 0x0F | 0x16 | 0x1D | 0x1F => { i += 1; }
            0x03 => {
                i += 1;
                let mut n = 0;
                while i < s.len() && s.as_bytes()[i].is_ascii_digit() && n < 2 { i+=1; n+=1; }
                if i < s.len() && s.as_bytes()[i] == b',' {
                    i += 1;
                    let mut m = 0;
                    while i < s.len() && s.as_bytes()[i].is_ascii_digit() && m < 2 { i+=1; m+=1; }
                }
            }
            _ => { out.push(s.as_bytes()[i] as char); i += 1; }
        }
    }
    out
}
