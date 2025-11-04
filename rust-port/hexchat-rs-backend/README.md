# HexChat-RS Backend (Engine)

A clean-room Rust backend inspired by HexChat's `src/common` engine. It provides:
- IRC protocol parsing & formatting
- Connection management (TCP + TLS with rustls)
- Core state (servers, channels, users)
- Minimal DCC structures
- Config load/save (TOML)
- Text formatting helpers (colors, attrs)
- Simple plugin trait surface

GPL-2.0-or-later to remain compatible with HexChat licensing.

## Quick Start

```bash
# Build
cargo build

# Run a simple CLI session
RUST_LOG=info cargo run -p cli --   --server irc.libera.chat --port 6697 --tls   --nick WoflFrenTest --user wofl --realname "Wofl Fren"   --join "#hexchat"
```
