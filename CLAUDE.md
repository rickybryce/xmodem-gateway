# CLAUDE.md

## Project Overview

XMODEM Gateway -- a standalone telnet-based XMODEM file transfer server, SSH
gateway, and AI chat client written in Rust. Author: Ricky Bryce.

This project was modeled after the bryceview project at `/home/ricky/bryceview/`,
adapted as a dedicated gateway with file transfer, SSH proxy, and AI features.

## Build & Test

```sh
cargo build           # debug build
cargo build --release # release build
cargo test            # run all unit tests
cargo clippy          # lint check (should produce zero warnings)
```

## Architecture

| File | Responsibility |
|------|----------------|
| `src/main.rs` | Entry point, tokio runtime, POSIX signal handling (SIGINT/SIGTERM/SIGHUP) |
| `src/config.rs` | `xmodem.conf` key=value parser, auto-creation with defaults, global singleton |
| `src/telnet.rs` | Telnet server, session management, terminal detection, auth, menus, file transfer UI, SSH gateway, AI chat UI |
| `src/xmodem.rs` | XMODEM protocol (CRC-16 + checksum), send/receive, telnet IAC-aware raw I/O |
| `src/aichat.rs` | Groq API client (llama-3.3-70b-versatile), word-wrap for terminal display |
| `src/ssh.rs` | SSH server interface (russh server, Ed25519 host key, duplex bridge to TelnetSession) |
| `src/gui.rs` | eframe/egui configuration editor, live console output, serial port detection, shutdown coordination |

## Key Design Decisions

- **Telnet + SSH** -- telnet for retro hardware (Commodore 64, CP/M, AltairDuino),
  SSH for encrypted modern access. Telnet defaults to port 2323, SSH to 2222.
- **Config file** (`xmodem.conf`) is auto-created in the binary's working
  directory if missing. Key=value format, comments with `#`.
- **Security is optional** -- disabled by default. When enabled, uses
  username/password from config with per-IP lockout (3 failures = 5 min ban).
- **Three terminal types**: PETSCII (Commodore 64), ANSI, ASCII. Detected via
  backspace byte (0x14=PETSCII, 0x08/0x7F=ANSI, other=ASCII). Color is offered
  as Y/N after detection (defaults to N for ANSI/ASCII, Y for PETSCII).
- **XMODEM protocol**: 128-byte blocks, CRC-16 with checksum fallback, 8 MB max
  file size, 90s negotiation timeout, IAC escaping toggle (off by default).
- **SSH Server**: Optional encrypted interface on port 2222 (default disabled).
  Ed25519 host key auto-generated and persisted to `xmodem_ssh_host_key`.
  Own credentials independent of telnet. Bridges to TelnetSession via duplex.
- **SSH Gateway**: Proxies telnet sessions to remote SSH servers via russh. ANSI
  sequences are stripped for PETSCII/ASCII terminals.
- **AI Chat**: Groq API with paginated response display. Requires API key in config.
- **Verbose logging**: XMODEM protocol diagnostics gated behind `verbose = true`
  in config. Off by default for clean production output.
- **Signal handling** uses `signal-hook` crate with an AtomicBool flag and a
  watcher thread that fires a tokio Notify.

## Conventions

- All telnet output uses `send()` / `send_line()` which handle PETSCII
  case-swapping automatically.
- Color output uses the `green()`, `red()`, `cyan()`, `yellow()`, `amber()`,
  `dim()`, `white()` helper methods which return terminal-appropriate strings.
- File transfer paths are always relative to the configured `transfer_dir`.
  Filenames are validated to prevent path traversal. Directory changes are
  canonicalized to prevent symlink escape.
- The `is_esc_key()` function is shared between telnet.rs and xmodem.rs (pub
  crate) -- 0x1B for ANSI, additionally 0x5F for PETSCII.
- Screen layout: max 22 rows, 40 columns for PETSCII, 80 for ANSI/ASCII.
  Enforced by unit tests.

## Testing

401 tests covering: CRC-16 computation, XMODEM round-trip transfers (small,
exact block, multi-block, all byte values, protocol bytes in data, empty,
oversized), telnet IAC subnegotiation parsing, PETSCII encoding, filename
validation, auth lockout logic, constant-time credential comparison, config
file parsing/roundtrip, signal handler registration, screen layout constraints
(row counts, column widths, message lengths), pagination math, gateway output
filtering, gateway input normalization, AI chat word wrapping, color helper
dispatch (ANSI/PETSCII/ASCII), link marker colorization, serial modem AT
command parsing (all commands, edge cases, quiet/verbose/numeric modes,
dial target parsing, buffer overflow protection, S-register query/set/defaults),
+++ escape detection (configurable via S2/S12),
SSH host key generation/roundtrip, shutdown broadcast message format,
menu item/help consistency, config sanitization, GUI numeric field sync
(valid/invalid/boundary/overflow), App initialization, console log buffer cap,
local IP detection, serial port enumeration, color palette consistency.
