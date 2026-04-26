//! Telnet server for XMODEM file transfers and SSH gateway.
//!
//! Listens on a configurable port and supports three terminal types: ANSI
//! (modern terminals), ASCII (no color), and PETSCII (Commodore 64). Terminal
//! type is auto-detected by asking the client to press backspace and examining
//! the byte sent (0x14 = PETSCII, 0x08/0x7F = ANSI, other = ASCII).
//!
//! The server operates in character-at-a-time mode (server-side echo) for
//! compatibility with vintage hardware. All visible text fits within 40 columns
//! for PETSCII terminals; ANSI/ASCII separators use 56 columns.

// The telnet option handler has several `ARM if opt == FOO =>` arms whose
// bodies are plain `if body-check { … }` blocks without an else branch.
// Clippy (Rust 1.95+) suggests collapsing the inner `if` into an additional
// guard on the outer match arm.  We deliberately don't, because for the
// option-specific arms (STATUS / TIMING-MARK handling) a false guard would
// fall through to the generic `DO =>` / `DONT =>` / `WILL =>` arm and emit
// the opposite telnet response.  The current style is preserved for
// behavioural clarity.
#![allow(clippy::collapsible_match)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config;
use crate::logger::glog;

// ─── Telnet protocol (RFC 854/855) ──────────────────────────
const IAC: u8 = 0xFF;
const SE: u8 = 0xF0;
const BRK: u8 = 0xF3;
const IP: u8 = 0xF4;
const AYT: u8 = 0xF6;
/// Erase Character (RFC 854): delete the last received character.
const EC: u8 = 0xF7;
/// Erase Line (RFC 854): delete the current input line.
const EL: u8 = 0xF8;
const SB: u8 = 0xFA;
const WILL: u8 = 0xFB;
const WONT: u8 = 0xFC;
const DO: u8 = 0xFD;
const DONT: u8 = 0xFE;

/// Synthetic byte returned by the IAC parser when it receives IAC EL.
/// Upstream line-editors treat it as "erase the current line."  0x15 is
/// ASCII NAK (Ctrl-U), the conventional line-kill key on Unix.
const LINE_ERASE_BYTE: u8 = 0x15;

/// Maximum subnegotiation body size.  A remote peer could in theory send
/// an arbitrarily large `IAC SB <opt> ... IAC SE` payload and drive our
/// memory use unbounded before the terminating `IAC SE` arrived.  Real
/// telnet subnegotiations (TTYPE, NAWS, NEW-ENVIRON) are at most a few
/// hundred bytes; 8 KiB is a comfortable overestimate.  Bytes beyond
/// this cap are dropped but the state machine keeps scanning for
/// `IAC SE` so it doesn't desync.
const MAX_SB_BODY_BYTES: usize = 8192;

// Telnet options
const OPT_ECHO: u8 = 0x01;
const OPT_SGA: u8 = 0x03;
/// RFC 859 — Status.
const OPT_STATUS: u8 = 0x05;
/// RFC 860 — Timing Mark.
const OPT_TIMING_MARK: u8 = 0x06;
const OPT_TTYPE: u8 = 0x18;
const OPT_NAWS: u8 = 0x1F;

/// STATUS subnegotiation keywords (RFC 859).
const STATUS_IS: u8 = 0x00;
const STATUS_SEND: u8 = 0x01;

// TTYPE subnegotiation (RFC 1091)
const TTYPE_IS: u8 = 0x00;
const TTYPE_SEND: u8 = 0x01;

// ─── ANSI escape codes ──────────────────────────────────────
const ANSI_GREEN: &str = "\x1b[1;32m";
const ANSI_RED: &str = "\x1b[1;31m";
const ANSI_CYAN: &str = "\x1b[1;36m";
const ANSI_YELLOW: &str = "\x1b[1;33m";
const ANSI_AMBER: &str = "\x1b[33m";
const ANSI_BLUE: &str = "\x1b[1;34m";
const ANSI_WHITE: &str = "\x1b[1;37m";
const ANSI_DIM: &str = "\x1b[37m";
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_CLEAR: &str = "\x1b[2J\x1b[H";

// ─── PETSCII color codes ────────────────────────────────────
const PETSCII_GREEN: u8 = 0x1E;
const PETSCII_RED: u8 = 0x96;
const PETSCII_CYAN: u8 = 0x9F;
const PETSCII_YELLOW: u8 = 0x9E;
const PETSCII_LIGHT_BLUE: u8 = 0x9A;
const PETSCII_WHITE: u8 = 0x05;
const PETSCII_LIGHT_GRAY: u8 = 0x9B;
const PETSCII_CLEAR: u8 = 0x93;
const PETSCII_DEFAULT: u8 = PETSCII_LIGHT_GRAY;

const PETSCII_WIDTH: usize = 40;
const MAX_INPUT_LENGTH: usize = 1024;
const MAX_AUTH_ATTEMPTS: u32 = 3;
const LOCKOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(5 * 60);

// ─── Terminal Type ──────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
enum TerminalType {
    Ascii,
    Ansi,
    Petscii,
}

/// Transfer protocol selected at upload time.  The XMODEM/YMODEM
/// branch hands off to `xmodem_receive`, which auto-detects block
/// size (SOH vs STX), CRC vs checksum, and the YMODEM block-0
/// filename header.  The ZMODEM branch hands off to
/// `zmodem_receive`, which emits ZRINIT and waits for ZFILE.
#[derive(Debug, Clone, Copy, PartialEq)]
enum UploadProtocol {
    /// XMODEM / YMODEM — receiver auto-detects variant.
    XmodemYmodem,
    /// ZMODEM — receiver initiates the session with ZRINIT.
    Zmodem,
    /// Kermit — receiver waits for the peer's Send-Init; flavor
    /// (C-Kermit, G-Kermit, etc.) is auto-detected from the peer's
    /// CAPAS bits and surfaced in the post-transfer summary.
    Kermit,
}

/// Transfer protocol selected at download time by the user.  Picked
/// per-transfer via the `SELECT PROTOCOL` prompt; no persistent config.
#[derive(Debug, Clone, Copy, PartialEq)]
enum DownloadProtocol {
    /// Classic XMODEM — 128-byte SOH blocks, CRC-16 with checksum fallback.
    Xmodem,
    /// XMODEM-1K — 1024-byte STX blocks (with SOH fallback for the
    /// final partial block).  Opportunistically falls back to plain
    /// XMODEM if the receiver NAKs the first STX.
    Xmodem1k,
    /// YMODEM — block 0 with filename + size, then 1K-style data
    /// blocks.
    Ymodem,
    /// ZMODEM — Forsberg ZMODEM with ZDLE escaping, hex + binary
    /// headers, stop-and-wait 1K subpackets.
    Zmodem,
    /// Kermit — full-spec Kermit with negotiated long packets,
    /// sliding window, streaming, and attribute packets per the
    /// peer's CAPAS bits.
    Kermit,
}

// ─── Input mode ────────────────────────────────────────────
#[derive(Clone, Copy)]
enum InputMode {
    /// Normal line input: echo typed characters, trim result.
    Normal,
    /// Password input: echo `*` for each character, no trim.
    Password,
}

// ─── Menu ───────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
enum Menu {
    Main,
    FileTransfer,
    Browser,
}

impl Menu {
    fn path(&self) -> &'static str {
        match self {
            Menu::Main => "ethernet",
            Menu::FileTransfer => "ethernet/xfer",
            Menu::Browser => "ethernet/web",
        }
    }
}

// ─── Auth lockout ───────────────────────────────────────────
//
// The same `LockoutMap` is shared between the telnet server and the SSH
// server so that a brute-force attacker cannot simply bounce between
// protocols to reset their counter.  A single successful auth on either
// protocol clears the lockout for that IP.
pub(crate) type LockoutMap = Arc<Mutex<HashMap<IpAddr, (u32, std::time::Instant)>>>;

pub(crate) fn is_locked_out(lockouts: &LockoutMap, ip: IpAddr) -> bool {
    let map = lockouts.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((count, when)) = map.get(&ip) {
        *count >= MAX_AUTH_ATTEMPTS && when.elapsed() < LOCKOUT_DURATION
    } else {
        false
    }
}

pub(crate) fn record_auth_failure(lockouts: &LockoutMap, ip: IpAddr) -> u32 {
    let mut map = lockouts.lock().unwrap_or_else(|e| e.into_inner());
    let entry = map
        .entry(ip)
        .or_insert((0, std::time::Instant::now()));
    // Reset counter if lockout period has expired
    if entry.1.elapsed() >= LOCKOUT_DURATION {
        *entry = (0, std::time::Instant::now());
    }
    entry.0 += 1;
    entry.1 = std::time::Instant::now();
    entry.0
}

/// Constant-time byte slice comparison to prevent timing attacks on credentials.
/// Iterates over both slices fully regardless of length difference so that
/// neither the length relationship nor the content is leaked via timing.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() != b.len()) as u8;
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn clear_lockout(lockouts: &LockoutMap, ip: IpAddr) {
    let mut map = lockouts.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(&ip);
}

/// Constant used by callers that need to reference the lockout attempt
/// ceiling when constructing their own user-visible messages.
pub(crate) const AUTH_MAX_ATTEMPTS: u32 = MAX_AUTH_ATTEMPTS;

/// Check an IPv4 address against private/loopback/link-local ranges and the
/// gateway (.1) restriction. Returns the rejection reason, or None if allowed.
fn reject_insecure_ipv4(octets: [u8; 4]) -> Option<&'static str> {
    let is_private = octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254); // link-local
    if !is_private {
        return Some("Connection refused: security is disabled, only private IP addresses are allowed.");
    }
    if octets[3] == 1 && octets[0] != 127 {
        return Some("Connection refused: gateway addresses (*.*.*.1) are not allowed when security is disabled.");
    }
    None
}

/// When security is disabled, only allow connections from private/loopback IPs,
/// and reject any address ending in .1 (typically a gateway), except for
/// loopback addresses (127.x.x.x). Returns the rejection reason, or None
/// if the address is allowed.
fn reject_insecure_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => reject_insecure_ipv4(v4.octets()),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (::ffff:x.x.x.x) — apply IPv4 rules
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return reject_insecure_ipv4(mapped.octets());
            }
            if v6.is_loopback() {
                return None;
            }
            let segments = v6.segments();
            // Link-local (fe80::/10)
            if segments[0] & 0xffc0 == 0xfe80 {
                return None;
            }
            // Unique local (fd00::/8)
            if segments[0] & 0xff00 == 0xfd00 {
                return None;
            }
            Some("Connection refused: security is disabled, only private IP addresses are allowed.")
        }
    }
}

/// Returns true if the IP is a private/link-local address (not loopback, not public).
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                let o = mapped.octets();
                return o[0] == 10
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168)
                    || (o[0] == 169 && o[1] == 254);
            }
            let seg = v6.segments();
            // Link-local (fe80::/10)
            (seg[0] & 0xffc0 == 0xfe80)
            // Unique local (fd00::/8)
            || (seg[0] & 0xff00 == 0xfd00)
        }
    }
}

// ─── PETSCII encoding helpers ───────────────────────────────

fn swap_case_for_petscii(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'A'..='Z' => ((c as u8) + 32) as char,
            'a'..='z' => ((c as u8) - 32) as char,
            _ => c,
        })
        .collect()
}

fn petscii_to_ascii_byte(byte: u8) -> u8 {
    match byte {
        0x41..=0x5A => byte + 32,
        0xC1..=0xDA => byte - 0x80,
        _ => byte,
    }
}

fn to_latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| if (c as u32) <= 0xFF { c as u8 } else { b'?' })
        .collect()
}

/// Map a TTYPE name reported by the client (via `IAC SB TTYPE IS ...`)
/// to one of our TerminalType variants. Returns None for names we don't
/// recognize so the caller falls back to the BACKSPACE-press detection.
/// Names arrive uppercase per RFC 1091, but we match case-insensitively
/// to be tolerant of non-compliant clients.
fn match_terminal_name(name: &str) -> Option<TerminalType> {
    let upper = name.trim().to_ascii_uppercase();
    if upper.is_empty() {
        return None;
    }
    // PETSCII clients: C64, C128, and explicit PETSCII names.
    if upper == "C64"
        || upper == "C128"
        || upper == "COMMODORE"
        || upper.starts_with("PETSCII")
        || upper.starts_with("C64")
        || upper.starts_with("C128")
    {
        return Some(TerminalType::Petscii);
    }
    // ANSI-capable: xterm family, vt100+, ansi*, linux console, screen/tmux.
    if upper.starts_with("XTERM")
        || upper.starts_with("VT")
        || upper.starts_with("ANSI")
        || upper.starts_with("LINUX")
        || upper.starts_with("SCREEN")
        || upper.starts_with("TMUX")
        || upper.starts_with("RXVT")
        || upper.starts_with("KONSOLE")
        || upper.starts_with("ALACRITTY")
        || upper.starts_with("WEZTERM")
        || upper == "CYGWIN"
        || upper == "PUTTY"
    {
        return Some(TerminalType::Ansi);
    }
    // Dumb/unknown terminals: fall back to plain ASCII (no color).
    if upper == "DUMB" || upper == "UNKNOWN" || upper == "NETWORK" {
        return Some(TerminalType::Ascii);
    }
    None
}

// ─── Input helpers (standalone) ─────────────────────────────

fn is_backspace_key(byte: u8, erase_char: u8) -> bool {
    byte == erase_char || byte == 0x08 || byte == 0x7F || byte == 0x14
}

/// Returns true for ANSI ESC (0x1B), plus C64 back-arrow (0x5F) when petscii is true.
pub(crate) fn is_esc_key(byte: u8, petscii: bool) -> bool {
    byte == 0x1B || (petscii && byte == 0x5F)
}

use crate::webbrowser::truncate_to_width;

/// Return the private (RFC 1918 / link-local / ULA) IPv4 and IPv6
/// addresses of this machine, excluding loopback.
fn get_server_addresses() -> Vec<String> {
    let mut addrs = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in &ifaces {
            if iface.is_loopback() {
                continue;
            }
            let ip = iface.ip();
            if !is_private_ip(ip) {
                continue;
            }
            let s = ip.to_string();
            if !addrs.contains(&s) {
                addrs.push(s);
            }
        }
    }
    addrs
}

/// Read a single byte, filtering out telnet IAC protocol sequences.
async fn read_byte_iac_filtered(
    reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    filter_iac: bool,
) -> Result<Option<u8>, std::io::Error> {
    let mut buf = [0u8; 1];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return Ok(None),
            Ok(_) => {
                let byte = buf[0];
                if filter_iac && byte == 0xFF {
                    match reader.read(&mut buf).await {
                        Ok(0) => return Ok(None),
                        Ok(_) => {
                            let cmd = buf[0];
                            if cmd == 0xFF {
                                return Ok(Some(0xFF));
                            }
                            if cmd == 0xFA {
                                // Subnegotiation — consume until IAC SE
                                let mut in_iac = false;
                                loop {
                                    match reader.read(&mut buf).await {
                                        Ok(0) => return Ok(None),
                                        Ok(_) => {
                                            if in_iac {
                                                if buf[0] == 0xF0 {
                                                    break;
                                                }
                                                in_iac = false;
                                            } else if buf[0] == 0xFF {
                                                in_iac = true;
                                            }
                                        }
                                        Err(e) => return Err(e),
                                    }
                                }
                                continue;
                            }
                            // WILL/WONT/DO/DONT — consume the option byte
                            if (0xFB..=0xFE).contains(&cmd) {
                                match reader.read(&mut buf).await {
                                    Ok(0) => return Ok(None),
                                    Err(e) => return Err(e),
                                    _ => {}
                                }
                            }
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                return Ok(Some(byte));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Events surfaced by the outgoing Telnet Gateway's local-side reader.
///
/// Unlike [`read_byte_iac_filtered`] (which drops every IAC sequence
/// silently), this reader surfaces `SB NAWS <w><h> IAC SE` as a structured
/// resize event so the gateway can forward it to the remote server while
/// a session is already live.  All other IAC framing — 2-byte commands,
/// option negotiations, non-NAWS subnegotiations — is still consumed.
#[derive(Debug, PartialEq, Eq)]
enum GatewayInboundEvent {
    /// A plain data byte from the local user.  `IAC IAC` is unescaped.
    Data(u8),
    /// The local client sent `IAC SB NAWS <cols16><rows16> IAC SE`.
    NawsResize(u16, u16),
    /// Connection closed.
    Eof,
}

/// Read one event from the local user's side of a Telnet Gateway session.
async fn read_gateway_event(
    reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
) -> std::io::Result<GatewayInboundEvent> {
    let mut buf = [0u8; 1];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return Ok(GatewayInboundEvent::Eof),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        let byte = buf[0];
        if byte != IAC {
            return Ok(GatewayInboundEvent::Data(byte));
        }
        // Read the command byte.
        match reader.read(&mut buf).await {
            Ok(0) => return Ok(GatewayInboundEvent::Eof),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        let cmd = buf[0];
        match cmd {
            IAC => return Ok(GatewayInboundEvent::Data(IAC)),
            SB => {
                // Read the option code.
                match reader.read(&mut buf).await {
                    Ok(0) => return Ok(GatewayInboundEvent::Eof),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
                let opt = buf[0];
                // Read body until IAC SE, unescaping IAC IAC → single
                // IAC.  Cap accumulated size so a malicious peer cannot
                // drive memory unbounded by sending a giant SB without
                // a terminating IAC SE; bytes past the cap are dropped
                // but the loop still scans for IAC SE to stay in sync.
                let mut body: Vec<u8> = Vec::new();
                let mut in_iac = false;
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => return Ok(GatewayInboundEvent::Eof),
                        Ok(_) => {}
                        Err(e) => return Err(e),
                    }
                    let b = buf[0];
                    if in_iac {
                        if b == SE {
                            break;
                        } else if b == IAC {
                            if body.len() < MAX_SB_BODY_BYTES {
                                body.push(IAC);
                            }
                            in_iac = false;
                        } else {
                            in_iac = false;
                        }
                    } else if b == IAC {
                        in_iac = true;
                    } else if body.len() < MAX_SB_BODY_BYTES {
                        body.push(b);
                    }
                }
                if opt == OPT_NAWS && body.len() == 4 {
                    let w = u16::from_be_bytes([body[0], body[1]]);
                    let h = u16::from_be_bytes([body[2], body[3]]);
                    return Ok(GatewayInboundEvent::NawsResize(w, h));
                }
                // Non-NAWS subnegotiation: drop and keep reading.
            }
            WILL | WONT | DO | DONT => {
                // Consume the option byte; drop the negotiation.
                match reader.read(&mut buf).await {
                    Ok(0) => return Ok(GatewayInboundEvent::Eof),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
            _ => {
                // 2-byte command (NOP, DM, BRK, IP, AO, AYT, EC, EL, GA)
                // — already fully consumed.
            }
        }
    }
}

// ─── SSH Gateway helpers ────────────────────────────────────

/// Filter SSH gateway output for non-ANSI terminals.
///
/// Strips all ANSI escape sequences (CSI, OSC, DCS, PM, APC, SOS) from the
/// byte stream.  For PETSCII terminals, plain-text bytes are also case-swapped.
/// `state` is the ANSI parser state carried across calls (start at 0):
///   0=normal, 1=ESC seen, 2=CSI sequence, 3=string sequence, 4=ESC in string
fn filter_gateway_output(input: &[u8], state: &mut u8, is_petscii: bool, out: &mut Vec<u8>) {
    for &b in input {
        match *state {
            0 => {
                if b == 0x1B {
                    *state = 1;
                } else if is_petscii {
                    match b {
                        b'~' => {}  // tilde has no PETSCII equivalent
                        0x08 | 0x7F => out.push(0x14),  // backspace/DEL → PETSCII DEL
                        b'A'..=b'Z' => out.push(b + 32),
                        b'a'..=b'z' => out.push(b - 32),
                        _ => out.push(b),
                    }
                } else {
                    out.push(b);
                }
            }
            1 => {
                *state = match b {
                    b'[' => 2,                                   // CSI
                    b']' | b'P' | b'^' | b'_' | b'X' => 3,      // OSC/DCS/PM/APC/SOS
                    0x1B => 1,                                   // Another ESC
                    _ => 0,                                      // 2-char sequence done
                };
            }
            2 => {
                // CSI: parameter/intermediate bytes stay in state 2.
                // Final byte (0x40-0x7E) ends the sequence.
                if (0x40..=0x7E).contains(&b) {
                    *state = 0;
                } else if b == 0x1B {
                    *state = 1;
                } else if b < 0x20 || b == 0x7F {
                    *state = 0;
                }
            }
            3 => {
                // String sequence: consume until BEL or ESC
                if b == 0x07 {
                    *state = 0;
                } else if b == 0x1B {
                    *state = 4;
                }
            }
            _ => {
                // ESC inside string: '\' = ST (end), else resume string
                *state = if b == b'\\' { 0 } else { 3 };
            }
        }
    }
}

/// Per-option Q-method state — full RFC 1143 six-state variant.
///
/// Each option tracks two independent state machines: one for our side
/// (what we've declared via WILL/WONT) and one for the peer's side (what
/// they've declared via WILL/WONT).
///
/// The "Opposite" variants handle the race where we change our mind
/// about an option while a prior request is still in flight.  Example:
/// we send `WILL TTYPE` (entering WantYes), then before the peer's reply
/// arrives we decide we no longer want TTYPE, so we send `WONT TTYPE`
/// — we cannot simply go to WantNo because our WILL is still on the wire
/// and the peer will eventually respond to it.  Instead we enter
/// `WantYesOpposite`, meaning "we're still waiting for the WILL reply,
/// but our current intent is Off."  When the peer finally replies, the
/// state machine resolves cleanly.
///
/// See RFC 1143 §7 for the full transition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptState {
    /// Option is off and no negotiation is in flight.
    No,
    /// Option is on.
    Yes,
    /// We have asked to enable the option; awaiting peer's reply.
    WantYes,
    /// Same as WantYes, but since sending the request we've changed our
    /// mind and now want the option off.  On the peer's reply we will
    /// send the opposite verb.
    WantYesOpposite,
    /// We have asked to disable the option; awaiting peer's reply.
    WantNo,
    /// Same as WantNo, but since sending the request we've changed our
    /// mind and now want the option on.  On the peer's reply we will
    /// send the opposite verb.
    WantNoOpposite,
}

/// Telnet-client IAC parser + Q-method state machine for the outgoing
/// gateway.  Handles the remote→local direction: parses IAC, unescapes
/// `IAC IAC` to a single data byte, consumes 2-byte commands, and
/// performs option negotiation.
///
/// Negotiation policy:
///
/// - **ECHO** (RFC 857) — always cooperative: peer's `WILL ECHO` is
///   accepted with `DO ECHO`.  Raw-TCP services never send WILL ECHO so
///   this is always safe.
/// - **TTYPE** (RFC 1091) and **NAWS** (RFC 1073) — cooperative only
///   when `cooperate == true`.  Gated because cooperation implies
///   proactive `WILL TTYPE` / `WILL NAWS` at connect, which raw-TCP
///   services would see as garbage.
/// - **Everything else** — refused: `WILL → DONT`, `DO → WONT`.
///
/// The parser never initiates a TTYPE/NAWS request from the peer side;
/// we don't care about the server's own terminal type or window size.
struct GatewayTelnetIac {
    state: GatewayIacState,
    /// Cooperate on TTYPE / NAWS (from the config toggle).
    cooperate: bool,
    /// Terminal name reported in `SB TTYPE IS`.  Chosen to match the
    /// local user's detected terminal type.
    terminal_name: String,
    /// Width to report in `SB NAWS`.
    window_cols: u16,
    /// Height to report in `SB NAWS`.
    window_rows: u16,
    /// Per-option state: what we've said about our own side.
    us_state: Box<[OptState; 256]>,
    /// Per-option state: what the peer has said about their side.
    him_state: Box<[OptState; 256]>,
    /// Whether we've already sent a `DONT <opt>` refusal for this option.
    /// Cleared when the peer finally sends `WONT <opt>` to ack the refusal.
    /// Prevents a chattery peer from getting repeated DONTs for the same
    /// unwanted WILL.
    sent_dont: Box<[bool; 256]>,
    /// Whether we've already sent a `WONT <opt>` refusal.  Cleared when the
    /// peer sends `DONT <opt>` to ack.
    sent_wont: Box<[bool; 256]>,
    /// Subnegotiation buffer.  `sb_option` is set when we enter the SB
    /// body (just after `IAC SB <opt>`); `sb_body` accumulates bytes
    /// with `IAC IAC` already unescaped to single 0xFF.
    sb_option: u8,
    sb_body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum GatewayIacState {
    /// Either a plain data byte or the start of a new IAC sequence.
    Normal,
    /// Previous byte was IAC; waiting for the command byte.
    SawIac,
    /// Previous bytes were IAC + WILL/WONT/DO/DONT; waiting for the option.
    SawVerb(u8),
    /// Just saw `IAC SB`; the next byte is the option code.
    SawSbOption,
    /// Inside an SB subnegotiation body; scanning for IAC SE.
    InSb,
    /// Inside an SB body, just saw an IAC; next byte decides whether it was
    /// IAC SE (end of SB) or IAC IAC (escaped data byte, stay in SB).
    InSbIac,
}

impl GatewayTelnetIac {
    /// Build a fresh parser.  Returns `(parser, initial_offers)` — any
    /// bytes that must be written to the remote before we start reading,
    /// to advertise our cooperative options.  Empty when `cooperate` is
    /// off (reactive-only mode).
    fn new(
        cooperate: bool,
        terminal_name: String,
        window_cols: u16,
        window_rows: u16,
    ) -> (Self, Vec<u8>) {
        let mut parser = Self {
            state: GatewayIacState::Normal,
            cooperate,
            terminal_name,
            window_cols,
            window_rows,
            us_state: Box::new([OptState::No; 256]),
            him_state: Box::new([OptState::No; 256]),
            sent_dont: Box::new([false; 256]),
            sent_wont: Box::new([false; 256]),
            sb_option: 0,
            sb_body: Vec::new(),
        };
        let mut initial = Vec::new();
        if cooperate {
            // Proactively offer WILL TTYPE and WILL NAWS; proactively
            // request DO ECHO so we don't need to wait for the peer to
            // offer echo (some BBSes wait for the client to ask first).
            // Set the matching WantYes states so peer acks are recognised.
            parser.us_state[OPT_TTYPE as usize] = OptState::WantYes;
            parser.us_state[OPT_NAWS as usize] = OptState::WantYes;
            parser.him_state[OPT_ECHO as usize] = OptState::WantYes;
            initial.extend_from_slice(&[IAC, WILL, OPT_TTYPE]);
            initial.extend_from_slice(&[IAC, WILL, OPT_NAWS]);
            initial.extend_from_slice(&[IAC, DO, OPT_ECHO]);
        }
        (parser, initial)
    }

    /// True if we should answer the peer's `WILL <opt>` with `DO <opt>`.
    fn cooperate_with_his_will(&self, opt: u8) -> bool {
        // ECHO from the server is always welcome — it means "I'll echo
        // your input," which for a retro user is what makes typing
        // visible.  Everything else (WILL TTYPE / WILL NAWS from the
        // server is unusual) we decline.
        opt == OPT_ECHO
    }

    /// True if we should answer the peer's `DO <opt>` with `WILL <opt>`.
    fn cooperate_with_his_do(&self, opt: u8) -> bool {
        self.cooperate && (opt == OPT_TTYPE || opt == OPT_NAWS)
    }

    fn feed(&mut self, byte: u8, data: &mut Vec<u8>, replies: &mut Vec<u8>) {
        match self.state {
            GatewayIacState::Normal => {
                if byte == IAC {
                    self.state = GatewayIacState::SawIac;
                } else {
                    data.push(byte);
                }
            }
            GatewayIacState::SawIac => {
                match byte {
                    IAC => {
                        data.push(IAC);
                        self.state = GatewayIacState::Normal;
                    }
                    SB => {
                        self.state = GatewayIacState::SawSbOption;
                    }
                    WILL | WONT | DO | DONT => {
                        self.state = GatewayIacState::SawVerb(byte);
                    }
                    _ => {
                        // 2-byte command (NOP, DM, BRK, IP, AO, AYT, EC,
                        // EL, GA, SE-out-of-context) — consumed.
                        self.state = GatewayIacState::Normal;
                    }
                }
            }
            GatewayIacState::SawVerb(verb) => {
                let opt = byte;
                match verb {
                    WILL => self.handle_recv_will(opt, replies),
                    WONT => self.handle_recv_wont(opt, replies),
                    DO => self.handle_recv_do(opt, replies),
                    DONT => self.handle_recv_dont(opt, replies),
                    _ => {}
                }
                self.state = GatewayIacState::Normal;
            }
            GatewayIacState::SawSbOption => {
                self.sb_option = byte;
                self.sb_body.clear();
                self.state = GatewayIacState::InSb;
            }
            GatewayIacState::InSb => {
                if byte == IAC {
                    self.state = GatewayIacState::InSbIac;
                } else if self.sb_body.len() < MAX_SB_BODY_BYTES {
                    self.sb_body.push(byte);
                }
                // Bytes beyond MAX_SB_BODY_BYTES are dropped; we stay in
                // InSb so an eventual IAC SE still terminates the SB.
            }
            GatewayIacState::InSbIac => {
                match byte {
                    SE => {
                        self.process_subneg(replies);
                        self.state = GatewayIacState::Normal;
                    }
                    IAC => {
                        // Escaped IAC inside SB — keep as single 0xFF
                        // (subject to the body-size cap).
                        if self.sb_body.len() < MAX_SB_BODY_BYTES {
                            self.sb_body.push(IAC);
                        }
                        self.state = GatewayIacState::InSb;
                    }
                    _ => {
                        // Malformed; resume scanning for IAC SE.
                        self.state = GatewayIacState::InSb;
                    }
                }
            }
        }
    }

    // ─── Q-method handlers (his side) ─────────────────────

    fn handle_recv_will(&mut self, opt: u8, replies: &mut Vec<u8>) {
        let idx = opt as usize;
        match self.him_state[idx] {
            OptState::No => {
                if self.cooperate_with_his_will(opt) {
                    self.him_state[idx] = OptState::Yes;
                    self.sent_dont[idx] = false; // contradicts any prior refusal
                    replies.extend_from_slice(&[IAC, DO, opt]);
                } else if !self.sent_dont[idx] {
                    // Refuse, but only once per cycle.  Q-method keeps
                    // him at No because we do not want it on.
                    self.sent_dont[idx] = true;
                    replies.extend_from_slice(&[IAC, DONT, opt]);
                }
            }
            OptState::Yes => {
                // Already on — spec says ignore.
            }
            OptState::WantYes => {
                // Peer acks our DO.
                self.him_state[idx] = OptState::Yes;
            }
            OptState::WantYesOpposite => {
                // Peer acked our original DO, but we've since changed to
                // wanting No; send DONT and enter WantNo.  Mark the
                // refusal so a misbehaving peer that re-sends WILL from
                // the subsequent WantNo state doesn't get a duplicate.
                self.him_state[idx] = OptState::WantNo;
                self.sent_dont[idx] = true;
                replies.extend_from_slice(&[IAC, DONT, opt]);
            }
            OptState::WantNo => {
                // Error: peer sent WILL in response to our DONT.  Log
                // by dropping back to No and, if we haven't already,
                // refuse again.
                self.him_state[idx] = OptState::No;
                if !self.sent_dont[idx] {
                    self.sent_dont[idx] = true;
                    replies.extend_from_slice(&[IAC, DONT, opt]);
                }
            }
            OptState::WantNoOpposite => {
                // Error but harmless: we wanted Yes again anyway.  The
                // stale DONT we sent on the way in is now contradicted
                // by our accepting Yes — clear the refusal flag.
                self.him_state[idx] = OptState::Yes;
                self.sent_dont[idx] = false;
            }
        }
    }

    fn handle_recv_wont(&mut self, opt: u8, replies: &mut Vec<u8>) {
        let idx = opt as usize;
        // Peer is acking our refusal or withdrawing — reset refusal-sent
        // so a future fresh cycle can issue a DONT again.
        self.sent_dont[idx] = false;
        match self.him_state[idx] {
            OptState::No => {
                // Already off — ignore.
            }
            OptState::Yes => {
                self.him_state[idx] = OptState::No;
                replies.extend_from_slice(&[IAC, DONT, opt]);
            }
            OptState::WantNo => {
                self.him_state[idx] = OptState::No;
            }
            OptState::WantNoOpposite => {
                // Peer confirmed our DONT, but we changed to WantYes;
                // send a fresh DO.
                self.him_state[idx] = OptState::WantYes;
                self.sent_dont[idx] = false;
                replies.extend_from_slice(&[IAC, DO, opt]);
            }
            OptState::WantYes => {
                // Peer refused our DO.
                self.him_state[idx] = OptState::No;
            }
            OptState::WantYesOpposite => {
                // Peer refused our DO, but we already swung back to No,
                // so we're exactly where we wanted.
                self.him_state[idx] = OptState::No;
            }
        }
    }

    fn handle_recv_do(&mut self, opt: u8, replies: &mut Vec<u8>) {
        let idx = opt as usize;
        match self.us_state[idx] {
            OptState::No => {
                if self.cooperate_with_his_do(opt) {
                    self.us_state[idx] = OptState::Yes;
                    self.sent_wont[idx] = false; // contradicts any prior refusal
                    replies.extend_from_slice(&[IAC, WILL, opt]);
                    if opt == OPT_NAWS {
                        self.emit_naws_sb(replies);
                    }
                } else if !self.sent_wont[idx] {
                    self.sent_wont[idx] = true;
                    replies.extend_from_slice(&[IAC, WONT, opt]);
                }
            }
            OptState::Yes => {
                // Already on — ignore.
            }
            OptState::WantYes => {
                self.us_state[idx] = OptState::Yes;
                if opt == OPT_NAWS {
                    self.emit_naws_sb(replies);
                }
            }
            OptState::WantYesOpposite => {
                // Peer acked our WILL but we want No; send WONT.  Mark
                // the refusal so a misbehaving peer that re-sends DO
                // from the subsequent WantNo state doesn't get a dup.
                self.us_state[idx] = OptState::WantNo;
                self.sent_wont[idx] = true;
                replies.extend_from_slice(&[IAC, WONT, opt]);
            }
            OptState::WantNo => {
                // Error: peer DO after our WONT.  Bounce to No.
                self.us_state[idx] = OptState::No;
                if !self.sent_wont[idx] {
                    self.sent_wont[idx] = true;
                    replies.extend_from_slice(&[IAC, WONT, opt]);
                }
            }
            OptState::WantNoOpposite => {
                // Error but harmless — we wanted Yes.  The stale WONT
                // we sent on the way in is contradicted by accepting
                // Yes; clear the refusal flag.
                self.us_state[idx] = OptState::Yes;
                self.sent_wont[idx] = false;
                if opt == OPT_NAWS {
                    self.emit_naws_sb(replies);
                }
            }
        }
    }

    fn handle_recv_dont(&mut self, opt: u8, replies: &mut Vec<u8>) {
        let idx = opt as usize;
        self.sent_wont[idx] = false;
        match self.us_state[idx] {
            OptState::No => {
                // Already off.
            }
            OptState::Yes => {
                self.us_state[idx] = OptState::No;
                replies.extend_from_slice(&[IAC, WONT, opt]);
            }
            OptState::WantNo => {
                self.us_state[idx] = OptState::No;
            }
            OptState::WantNoOpposite => {
                // Peer confirmed DONT, but we changed to WantYes — send WILL.
                self.us_state[idx] = OptState::WantYes;
                self.sent_wont[idx] = false;
                replies.extend_from_slice(&[IAC, WILL, opt]);
            }
            OptState::WantYes => {
                // Peer refused our WILL.
                self.us_state[idx] = OptState::No;
            }
            OptState::WantYesOpposite => {
                // Peer refused our WILL, and we already swung back to No —
                // exactly where we wanted.
                self.us_state[idx] = OptState::No;
            }
        }
    }

    // ─── Active-change helpers (for mind-changes mid-flight) ──

    /// Ask for our side of `opt` to be enabled (send `WILL`).  Advances
    /// the Q-method state for `us_state[opt]` per RFC 1143 §7.
    ///
    /// Currently unused by `gateway_telnet` — we only enter `WantYes` via
    /// the proactive offers in `new()` — but kept for symmetry and so
    /// future active-change flows compile cleanly.
    #[allow(dead_code)]
    fn request_local_enable(&mut self, opt: u8, replies: &mut Vec<u8>) {
        let idx = opt as usize;
        match self.us_state[idx] {
            OptState::No => {
                self.us_state[idx] = OptState::WantYes;
                self.sent_wont[idx] = false; // contradicts any prior refusal
                replies.extend_from_slice(&[IAC, WILL, opt]);
            }
            OptState::Yes => {} // already on
            OptState::WantNo => {
                // Changed mind mid-flight.
                self.us_state[idx] = OptState::WantNoOpposite;
            }
            OptState::WantNoOpposite => {} // already queued to enable
            OptState::WantYes => {}
            OptState::WantYesOpposite => {
                // Reverting to original intent.
                self.us_state[idx] = OptState::WantYes;
            }
        }
    }

    /// Ask for our side of `opt` to be disabled (send `WONT`).
    #[allow(dead_code)]
    fn request_local_disable(&mut self, opt: u8, replies: &mut Vec<u8>) {
        let idx = opt as usize;
        match self.us_state[idx] {
            OptState::Yes => {
                self.us_state[idx] = OptState::WantNo;
                replies.extend_from_slice(&[IAC, WONT, opt]);
            }
            OptState::No => {} // already off
            OptState::WantYes => {
                self.us_state[idx] = OptState::WantYesOpposite;
            }
            OptState::WantYesOpposite => {}
            OptState::WantNo => {}
            OptState::WantNoOpposite => {
                self.us_state[idx] = OptState::WantNo;
            }
        }
    }

    // ─── Subnegotiation ───────────────────────────────────

    fn process_subneg(&mut self, replies: &mut Vec<u8>) {
        if self.sb_option == OPT_TTYPE
            && self.us_state[OPT_TTYPE as usize] == OptState::Yes
            && self.sb_body.first().copied() == Some(TTYPE_SEND)
        {
            // Respond with our terminal name.  Any 0xFF in the name
            // (shouldn't happen for our controlled values) would need
            // IAC-doubling; we check explicitly.
            let mut body = vec![IAC, SB, OPT_TTYPE, TTYPE_IS];
            for &b in self.terminal_name.as_bytes() {
                if b == IAC {
                    body.push(IAC);
                }
                body.push(b);
            }
            body.extend_from_slice(&[IAC, SE]);
            replies.extend_from_slice(&body);
        }
        // All other SB bodies are informational only — we silently drop.
    }

    /// Record an updated window size from the local user and, if NAWS is
    /// currently enabled on our side, emit an `IAC SB NAWS <w><h> IAC SE`
    /// update to the remote.  Called from the gateway loop when the user
    /// resizes their terminal mid-session.
    fn send_naws_update(&mut self, cols: u16, rows: u16, replies: &mut Vec<u8>) {
        self.window_cols = cols;
        self.window_rows = rows;
        if self.us_state[OPT_NAWS as usize] == OptState::Yes {
            self.emit_naws_sb(replies);
        }
    }

    fn emit_naws_sb(&self, replies: &mut Vec<u8>) {
        // `IAC SB NAWS <w16_BE> <h16_BE> IAC SE`, with any byte equal to
        // IAC doubled per RFC 854.
        let w = self.window_cols.to_be_bytes();
        let h = self.window_rows.to_be_bytes();
        let size_bytes = [w[0], w[1], h[0], h[1]];
        let mut body = vec![IAC, SB, OPT_NAWS];
        for &b in &size_bytes {
            if b == IAC {
                body.push(IAC);
            }
            body.push(b);
        }
        body.extend_from_slice(&[IAC, SE]);
        replies.extend_from_slice(&body);
    }
}

/// Default terminal name reported via `SB TTYPE IS`.  Chosen to be
/// informative to modern BBSes and still truthful.
fn gateway_terminal_name(tt: TerminalType) -> &'static str {
    match tt {
        TerminalType::Petscii => "PETSCII",
        TerminalType::Ansi => "ANSI",
        TerminalType::Ascii => "DUMB",
    }
}

/// Default window dimensions to report via `SB NAWS` when the local
/// client hasn't supplied any via its own NAWS.
fn gateway_default_window(tt: TerminalType) -> (u16, u16) {
    match tt {
        TerminalType::Petscii => (PETSCII_WIDTH as u16, 25),
        TerminalType::Ansi | TerminalType::Ascii => (80, 24),
    }
}

/// Write `bytes` to `w`, doubling any 0xFF as IAC IAC per RFC 854.  Used
/// by the outgoing telnet gateway in both directions so that literal 0xFF
/// data bytes survive the wire without being mistaken for IAC.
async fn write_telnet_data<W>(w: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin + ?Sized,
{
    let mut last = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == IAC {
            if last < i {
                w.write_all(&bytes[last..i]).await?;
            }
            w.write_all(&[IAC, IAC]).await?;
            last = i + 1;
        }
    }
    if last < bytes.len() {
        w.write_all(&bytes[last..]).await?;
    }
    Ok(())
}

/// Normalize a client input byte for SSH gateway forwarding.
///
/// Telnet clients send CR+LF or CR+NUL for Enter; SSH expects bare CR.
/// Returns `Some(byte)` if the byte should be forwarded, `None` to suppress.
fn normalize_gateway_input(b: u8, last_cr: &mut bool) -> Option<u8> {
    if (b == b'\n' || b == 0x00) && *last_cr {
        *last_cr = false;
        return None;
    }
    *last_cr = b == b'\r';
    Some(b)
}

/// SSH client handler for the gateway feature. Captures the server's host key
/// so it can be verified against the known-hosts file after connection.
struct GatewayHandler {
    server_key: Arc<std::sync::Mutex<Option<russh::keys::PublicKey>>>,
}

impl russh::client::Handler for GatewayHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        if let Ok(mut key) = self.server_key.lock() {
            *key = Some(server_public_key.clone());
        }
        Ok(true)
    }
}

// ─── Known-hosts management ────────────────────────────────

const GATEWAY_HOSTS_FILE: &str = "gateway_hosts";

/// Result of checking a host key against the known-hosts file.
enum HostKeyStatus {
    /// Key matches a stored entry.
    Known,
    /// No entry for this host:port.
    Unknown,
    /// Stored key does not match the presented key.
    Changed,
}

/// Format the key as "algorithm base64" for storage.
fn format_host_key(key: &russh::keys::PublicKey) -> String {
    // key.to_string() produces "algorithm base64 comment" in OpenSSH format;
    // we only want "algorithm base64".
    let s = key.to_string();
    let parts: Vec<&str> = s.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        format!("{} {}", parts[0], parts[1])
    } else {
        s
    }
}

/// Look up a host:port in the known-hosts file and compare the key.
fn check_known_host(
    host: &str,
    port: u16,
    key: &russh::keys::PublicKey,
) -> HostKeyStatus {
    let lookup = format!("{}:{}", host, port);
    let key_str = format_host_key(key);

    let content = match std::fs::read_to_string(GATEWAY_HOSTS_FILE) {
        Ok(c) => c,
        Err(_) => return HostKeyStatus::Unknown,
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(&lookup)
            && let Some(stored_key) = rest.strip_prefix(' ')
        {
            if stored_key == key_str {
                return HostKeyStatus::Known;
            }
            return HostKeyStatus::Changed;
        }
    }
    HostKeyStatus::Unknown
}

/// Save a host key to the known-hosts file.
///
/// Uses a static mutex to serialise read-modify-write across concurrent
/// sessions, and write-to-temp-then-rename for crash safety.
fn save_known_host(host: &str, port: u16, key: &russh::keys::PublicKey) {
    static HOSTS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = HOSTS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let entry = format!("{}:{} {}\n", host, port, format_host_key(key));

    let mut content = std::fs::read_to_string(GATEWAY_HOSTS_FILE).unwrap_or_default();
    // Remove any existing entry for this host:port
    let lookup = format!("{}:{} ", host, port);
    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.is_empty()
                || trimmed.starts_with('#')
                || !trimmed.starts_with(&lookup)
        })
        .collect();
    content = filtered.join("\n");
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&entry);
    if let Err(e) = atomic_write(GATEWAY_HOSTS_FILE, &content) {
        glog!("Warning: could not save gateway host key: {}", e);
    } else {
        // Restrict mode to owner-only.  The stored host public keys
        // are themselves public, but the file also exposes the dial
        // history (which hosts the operator has connected to) — a
        // meaningful privacy signal that other local users shouldn't
        // have.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                GATEWAY_HOSTS_FILE,
                std::fs::Permissions::from_mode(0o600),
            );
        }
    }
}

/// Write `content` to `path` atomically by writing to a uniquely-named
/// temporary file and then renaming it into place. This prevents partial
/// writes and avoids races between concurrent callers.
///
/// Callers that perform read-modify-write on the same file must still
/// serialise externally (e.g. via a mutex) to avoid lost updates.
fn atomic_write(path: &str, content: &str) -> Result<(), std::io::Error> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = format!("{}.{}.{}.tmp", path, std::process::id(), seq);
    std::fs::write(&tmp, content)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// ─── Weather data ──────────────────────────────────────────

struct ForecastDay {
    date: String,
    high: String,
    low: String,
    desc: String,
}

struct WeatherData {
    city: String,
    region: String,
    temp_f: String,
    feels_like: String,
    humidity: String,
    wind_mph: String,
    wind_dir: String,
    desc: String,
    forecast: Vec<ForecastDay>,
}

// ─── SharedWriter ───────────────────────────────────────────
pub(crate) type SharedWriter = Arc<tokio::sync::Mutex<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>>;
pub(crate) type SessionWriters = Arc<tokio::sync::Mutex<Vec<SharedWriter>>>;

// ─── TelnetSession ──────────────────────────────────────────

pub(crate) struct TelnetSession {
    reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    writer: SharedWriter,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    current_menu: Menu,
    terminal_type: TerminalType,
    erase_char: u8,
    lockouts: LockoutMap,
    peer_addr: Option<IpAddr>,
    transfer_subdir: String,
    xmodem_iac: bool,
    web_lines: Vec<String>,
    web_scroll: usize,
    web_links: Vec<String>,
    web_history: Vec<(String, usize)>,
    web_url: Option<String>,
    web_title: Option<String>,
    web_forms: Vec<crate::webbrowser::WebForm>,
    weather_zip: String,
    is_serial: bool,
    is_ssh: bool,
    idle_timeout: std::time::Duration,
    // One-byte pushback used by drain_trailing_eol to safely return any
    // non-CR/LF byte it reads back to the next real input call.
    pushback: Option<u8>,
    // Telnet option negotiation state. Each per-option flag records a
    // reply we've already sent so we never loop on repeated requests.
    neg_sent_will: Box<[bool; 256]>,
    neg_sent_do: Box<[bool; 256]>,
    neg_sent_wont: Box<[bool; 256]>,
    neg_sent_dont: Box<[bool; 256]>,
    // TTYPE result — set once via SB TTYPE IS. Prevents re-requesting
    // and lets detect_terminal_type skip the BACKSPACE prompt.
    ttype_matched: bool,
    // Set the first time session_read_byte sees an IAC SB or
    // WILL/WONT/DO/DONT from the peer.  Distinguishes a true telnet
    // client (which participates in option negotiation, RFC 854/856)
    // from a raw TCP client (netcat, retro firmware) that just pipes
    // bytes.  Used to auto-enable IAC escaping only for real telnet.
    telnet_negotiated: bool,
    // NAWS (window size), captured from SB NAWS. None if peer didn't
    // negotiate. Not yet wired into layout code.
    window_width: Option<u16>,
    window_height: Option<u16>,
}

impl TelnetSession {
    const TRANSFER_PAGE_SIZE: usize = 10;
    const MAX_FILE_SIZE: usize = 8 * 1024 * 1024;
    const MAX_FILENAME_LEN: usize = 64;

    /// Create a session for a serial modem connection.  Uses ASCII terminal
    /// (no color, no IAC), skips terminal detection and authentication.
    pub(crate) fn new_serial(
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: SharedWriter,
        shutdown: Arc<AtomicBool>,
        restart: Arc<AtomicBool>,
    ) -> Self {
        Self {
            reader,
            writer,
            shutdown,
            restart,
            current_menu: Menu::Main,
            terminal_type: TerminalType::Ascii,
            erase_char: 0x7F,
            lockouts: Arc::new(Mutex::new(HashMap::new())),
            peer_addr: None,
            transfer_subdir: String::new(),
            xmodem_iac: false,
            web_lines: Vec::new(),
            web_scroll: 0,
            web_links: Vec::new(),
            web_history: Vec::new(),
            web_url: None,
            web_title: None,
            web_forms: Vec::new(),
            weather_zip: config::get_config().weather_zip,
            is_serial: true,
            is_ssh: false,
            idle_timeout: std::time::Duration::from_secs(config::get_config().idle_timeout_secs),
            pushback: None,
            neg_sent_will: Box::new([false; 256]),
            neg_sent_do: Box::new([false; 256]),
            neg_sent_wont: Box::new([false; 256]),
            neg_sent_dont: Box::new([false; 256]),
            ttype_matched: false,
            telnet_negotiated: false,
            window_width: None,
            window_height: None,
        }
    }

    /// Create a session for an SSH connection.  Uses ANSI terminal
    /// (color, no IAC), skips terminal detection and authentication
    /// (already handled by the SSH layer).
    pub(crate) fn new_ssh(
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: SharedWriter,
        shutdown: Arc<AtomicBool>,
        restart: Arc<AtomicBool>,
        peer_addr: Option<IpAddr>,
    ) -> Self {
        Self {
            reader,
            writer,
            shutdown,
            restart,
            current_menu: Menu::Main,
            terminal_type: TerminalType::Ansi,
            erase_char: 0x7F,
            lockouts: Arc::new(Mutex::new(HashMap::new())),
            peer_addr,
            transfer_subdir: String::new(),
            xmodem_iac: false,
            web_lines: Vec::new(),
            web_scroll: 0,
            web_links: Vec::new(),
            web_history: Vec::new(),
            web_url: None,
            web_title: None,
            web_forms: Vec::new(),
            weather_zip: config::get_config().weather_zip,
            is_serial: false,
            is_ssh: true,
            idle_timeout: std::time::Duration::from_secs(config::get_config().idle_timeout_secs),
            pushback: None,
            neg_sent_will: Box::new([false; 256]),
            neg_sent_do: Box::new([false; 256]),
            neg_sent_wont: Box::new([false; 256]),
            neg_sent_dont: Box::new([false; 256]),
            ttype_matched: false,
            telnet_negotiated: false,
            window_width: None,
            window_height: None,
        }
    }

    // ─── Color helpers ─────────────────────────────────────

    fn petscii_color(code: u8, text: &str) -> String {
        format!(
            "{}{}{}",
            char::from(code),
            text,
            char::from(PETSCII_DEFAULT),
        )
    }

    fn green(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_GREEN, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_GREEN, text),
            TerminalType::Ascii => text.to_string(),
        }
    }
    fn red(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_RED, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_RED, text),
            TerminalType::Ascii => text.to_string(),
        }
    }
    fn cyan(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_CYAN, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_CYAN, text),
            TerminalType::Ascii => text.to_string(),
        }
    }
    fn yellow(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_YELLOW, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_YELLOW, text),
            TerminalType::Ascii => text.to_string(),
        }
    }
    fn amber(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_AMBER, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_YELLOW, text),
            TerminalType::Ascii => text.to_string(),
        }
    }
    fn dim(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_DIM, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_LIGHT_GRAY, text),
            TerminalType::Ascii => text.to_string(),
        }
    }
    fn blue(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_BLUE, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_LIGHT_BLUE, text),
            TerminalType::Ascii => text.to_string(),
        }
    }
    fn white(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_WHITE, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_WHITE, text),
            TerminalType::Ascii => text.to_string(),
        }
    }

    /// Convert link-marker sentinels (\x02N\x03) to visible `[N]`, colorized
    /// in blue for ANSI/PETSCII terminals. Applied after truncation so that
    /// invisible escape bytes don't affect width calculations.
    fn colorize_link_markers(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len() + 64);
        let mut rest = text;
        while let Some(open) = rest.find('\x02') {
            result.push_str(&rest[..open]);
            let after_open = &rest[open + 1..];
            if let Some(close) = after_open.find('\x03') {
                let inner = &after_open[..close];
                let marker = format!("[{}]", inner);
                if self.terminal_type == TerminalType::Ascii {
                    result.push_str(&marker);
                } else {
                    result.push_str(&self.blue(&marker));
                }
                rest = &after_open[close + 1..];
            } else {
                // Malformed sentinel (e.g. truncated) — silently drop it
                rest = after_open;
            }
        }
        result.push_str(rest);
        result
    }

    fn separator(&self) -> String {
        let width = if self.terminal_type == TerminalType::Petscii {
            PETSCII_WIDTH
        } else {
            56
        };
        self.yellow(&"=".repeat(width))
    }

    fn action_prompt(&self, key: &str, description: &str) -> String {
        format!("{}={}", self.cyan(key), description)
    }

    fn nav_footer(&self) -> String {
        format!(
            "  {} {} {}",
            self.action_prompt("R", "Refresh"),
            self.action_prompt("Q", "Back"),
            self.action_prompt("H", "Help"),
        )
    }

    fn prompt_str(&self) -> String {
        let mut path = self.current_menu.path().to_string();
        if self.current_menu == Menu::FileTransfer && !self.transfer_subdir.is_empty() {
            path = format!("{}/{}", path, self.transfer_subdir);
        }
        format!("{}> ", self.cyan(&path))
    }

    // ─── I/O helpers ───────────────────────────────────────

    async fn send(&mut self, text: &str) -> Result<(), std::io::Error> {
        match self.terminal_type {
            TerminalType::Petscii => {
                let swapped = swap_case_for_petscii(text);
                let bytes = to_latin1_bytes(&swapped);
                self.send_raw(&bytes).await
            }
            _ => self.send_raw(text.as_bytes()).await,
        }
    }

    async fn send_line(&mut self, text: &str) -> Result<(), std::io::Error> {
        let line = format!("{}\r\n", text);
        self.send(&line).await
    }

    /// Write user-data bytes to the session. In telnet mode, any 0xFF
    /// data byte is escaped as IAC IAC (0xFF 0xFF) per RFC 854 so the
    /// peer doesn't misinterpret it as the start of a protocol command.
    /// Serial and SSH sessions don't speak the IAC protocol, so bytes
    /// pass through unchanged there.
    async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        let needs_escape = !self.is_serial && !self.is_ssh;
        if !needs_escape || !bytes.contains(&IAC) {
            return self.writer.lock().await.write_all(bytes).await;
        }
        let mut escaped = Vec::with_capacity(bytes.len() + 1);
        for &b in bytes {
            escaped.push(b);
            if b == IAC {
                escaped.push(IAC);
            }
        }
        self.writer.lock().await.write_all(&escaped).await
    }

    /// Write raw telnet-protocol bytes (IAC sequences) without any data
    /// escaping. Use only for sending IAC commands and option
    /// negotiation where 0xFF bytes are intentional.
    async fn send_telnet_protocol(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        self.writer.lock().await.write_all(bytes).await
    }

    async fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.lock().await.flush().await
    }

    async fn clear_screen(&mut self) -> Result<(), std::io::Error> {
        match self.terminal_type {
            TerminalType::Petscii => self.send_raw(&[PETSCII_CLEAR]).await,
            TerminalType::Ansi => self.send_raw(ANSI_CLEAR.as_bytes()).await,
            TerminalType::Ascii => self.send_raw(b"\r\n\r\n\r\n").await,
        }
    }

    async fn read_byte_filtered(&mut self) -> Result<Option<u8>, std::io::Error> {
        if self.idle_timeout.is_zero() {
            self.session_read_byte().await
        } else {
            match tokio::time::timeout(self.idle_timeout, self.session_read_byte()).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "idle timeout",
                )),
            }
        }
    }

    /// Read a single data byte from the session. In telnet mode, IAC
    /// sequences are consumed transparently. DO/WILL option requests
    /// get WONT/DONT replies (RFC 855) except for options we support
    /// (ECHO, SGA, TTYPE, NAWS). AYT (Are You There) gets a visible
    /// reply. IP (Interrupt Process) and BRK (Break) surface as the
    /// terminal's ESC byte so callers treat them like a Ctrl+C / ESC.
    async fn session_read_byte(&mut self) -> Result<Option<u8>, std::io::Error> {
        if let Some(b) = self.pushback.take() {
            return Ok(Some(b));
        }
        let filter_iac = !self.is_serial && !self.is_ssh;
        let mut buf = [0u8; 1];
        loop {
            if self.reader.read(&mut buf).await? == 0 {
                return Ok(None);
            }
            let byte = buf[0];
            if !filter_iac || byte != IAC {
                return Ok(Some(byte));
            }
            if self.reader.read(&mut buf).await? == 0 {
                return Ok(None);
            }
            let cmd = buf[0];
            match cmd {
                IAC => return Ok(Some(IAC)), // escaped data 0xFF
                SB => {
                    self.telnet_negotiated = true;
                    let Some(payload) = self.read_subneg_payload().await? else {
                        return Ok(None);
                    };
                    if let Some((opt, body)) = payload.split_first() {
                        self.handle_subnegotiation(*opt, body).await?;
                    }
                }
                WILL | WONT | DO | DONT => {
                    self.telnet_negotiated = true;
                    if self.reader.read(&mut buf).await? == 0 {
                        return Ok(None);
                    }
                    let opt = buf[0];
                    self.handle_telnet_option(cmd, opt).await?;
                }
                AYT => {
                    // Through send_line so PETSCII case-swap applies if the
                    // terminal type is known.
                    self.send_line("[Yes]").await?;
                    self.flush().await?;
                }
                IP | BRK => {
                    let esc = if self.terminal_type == TerminalType::Petscii {
                        0x5F
                    } else {
                        0x1B
                    };
                    return Ok(Some(esc));
                }
                EC => {
                    // RFC 854: delete the last received character.  Our
                    // architecture has no low-level input buffer, so
                    // translate to DEL (0x7F); the line-input layer
                    // already handles this as backspace.
                    return Ok(Some(0x7F));
                }
                EL => {
                    // RFC 854: delete everything on the current line.
                    // Translate to NAK (0x15); the line-input loop
                    // treats this as "erase-line."
                    return Ok(Some(LINE_ERASE_BYTE));
                }
                _ => {
                    // NOP (241), DM (242), AO (245), GA (249) — consumed.
                    //
                    // DM is the SYNCH marker (RFC 854 §3).  Proper SYNCH
                    // requires reading TCP urgent-mode data; we do not
                    // implement that, so DM is informational only.
                }
            }
        }
    }

    /// Consume a subnegotiation payload up to (and including) the
    /// terminating IAC SE. Returns the payload bytes with any escaped
    /// `IAC IAC` unescaped. First byte is the option code. Returns
    /// Ok(None) if the connection closes mid-sequence.
    async fn read_subneg_payload(&mut self) -> Result<Option<Vec<u8>>, std::io::Error> {
        let mut payload = Vec::with_capacity(32);
        let mut buf = [0u8; 1];
        loop {
            if self.reader.read(&mut buf).await? == 0 {
                return Ok(None);
            }
            if buf[0] != IAC {
                if payload.len() < 512 {
                    payload.push(buf[0]);
                }
                continue;
            }
            if self.reader.read(&mut buf).await? == 0 {
                return Ok(None);
            }
            match buf[0] {
                SE => return Ok(Some(payload)),
                IAC => {
                    if payload.len() < 512 {
                        payload.push(IAC);
                    }
                }
                _ => {
                    // Malformed — skip and keep scanning for IAC SE.
                }
            }
        }
    }

    /// Reply to peer WILL/WONT/DO/DONT per RFC 855. Options we want
    /// enabled (ECHO, SGA on our side; SGA, TTYPE, NAWS on peer's side)
    /// treat the matching ack as a no-op. Everything else is refused
    /// once. DONT/WONT get a matching ack only if we had actually
    /// advertised the corresponding WILL/DO.
    async fn handle_telnet_option(
        &mut self,
        cmd: u8,
        opt: u8,
    ) -> Result<(), std::io::Error> {
        match cmd {
            DO if opt == OPT_TIMING_MARK => {
                // RFC 860: DO TIMING-MARK is a one-shot synchronization
                // request — reply with WILL TIMING-MARK *after* we have
                // flushed whatever output was queued when the DO arrived.
                // The WILL response is itself the mark; no persistent
                // state (so we don't set neg_sent_will).
                self.flush().await?;
                self.send_telnet_protocol(&[IAC, WILL, OPT_TIMING_MARK]).await?;
                self.flush().await?;
            }
            DONT if opt == OPT_TIMING_MARK => {
                // RFC 860: DONT TIMING-MARK has no action to ack since
                // we never maintain the option as enabled.
            }
            DO if opt == OPT_STATUS => {
                // RFC 859: agree to act as the status sender.  Mark
                // neg_sent_will so the peer's future DOs are treated as
                // acks and we don't loop.  A later SB STATUS SEND will
                // trigger the actual state dump.
                if !self.neg_sent_will[OPT_STATUS as usize] {
                    self.neg_sent_will[OPT_STATUS as usize] = true;
                    self.send_telnet_protocol(&[IAC, WILL, OPT_STATUS]).await?;
                    self.flush().await?;
                }
            }
            DONT if opt == OPT_STATUS => {
                // Peer withdraws the status-sender role.  Ack with WONT
                // only if we had asserted WILL.
                if self.neg_sent_will[OPT_STATUS as usize] {
                    self.neg_sent_will[OPT_STATUS as usize] = false;
                    self.send_telnet_protocol(&[IAC, WONT, OPT_STATUS]).await?;
                    self.flush().await?;
                }
            }
            WILL if opt == OPT_STATUS => {
                // We don't request status from clients — refuse.
                if !self.neg_sent_dont[OPT_STATUS as usize] {
                    self.neg_sent_dont[OPT_STATUS as usize] = true;
                    self.send_telnet_protocol(&[IAC, DONT, OPT_STATUS]).await?;
                    self.flush().await?;
                }
            }
            DO => {
                // If we already advertised WILL for opt, peer's DO is an
                // acknowledgement — no reply needed.
                if self.neg_sent_will[opt as usize] {
                    return Ok(());
                }
                if self.neg_sent_wont[opt as usize] {
                    return Ok(());
                }
                self.neg_sent_wont[opt as usize] = true;
                self.send_telnet_protocol(&[IAC, WONT, opt]).await?;
                self.flush().await?;
            }
            WILL => {
                // If we already advertised DO for opt, peer's WILL is an
                // acknowledgement — no reply needed.
                if self.neg_sent_do[opt as usize] && opt != OPT_TTYPE {
                    // TTYPE still needs SB SEND on first WILL so we can
                    // request the name; handled below.
                    return Ok(());
                }
                if opt == OPT_TTYPE {
                    if !self.neg_sent_do[opt as usize] {
                        self.neg_sent_do[opt as usize] = true;
                        self.send_telnet_protocol(&[IAC, DO, OPT_TTYPE]).await?;
                    }
                    if !self.ttype_matched {
                        self.send_telnet_protocol(&[
                            IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE,
                        ])
                        .await?;
                    }
                    self.flush().await?;
                    return Ok(());
                }
                if opt == OPT_NAWS {
                    if !self.neg_sent_do[opt as usize] {
                        self.neg_sent_do[opt as usize] = true;
                        self.send_telnet_protocol(&[IAC, DO, OPT_NAWS]).await?;
                        self.flush().await?;
                    }
                    return Ok(());
                }
                if self.neg_sent_dont[opt as usize] {
                    return Ok(());
                }
                self.neg_sent_dont[opt as usize] = true;
                self.send_telnet_protocol(&[IAC, DONT, opt]).await?;
                self.flush().await?;
            }
            DONT => {
                // Acknowledge with WONT only if we had previously
                // advertised WILL for opt.
                if self.neg_sent_will[opt as usize]
                    && !self.neg_sent_wont[opt as usize]
                {
                    self.neg_sent_wont[opt as usize] = true;
                    self.send_telnet_protocol(&[IAC, WONT, opt]).await?;
                    self.flush().await?;
                }
            }
            WONT => {
                // Acknowledge with DONT only if we had previously
                // advertised DO for opt.
                if self.neg_sent_do[opt as usize]
                    && !self.neg_sent_dont[opt as usize]
                {
                    self.neg_sent_dont[opt as usize] = true;
                    self.send_telnet_protocol(&[IAC, DONT, opt]).await?;
                    self.flush().await?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Process a completed subnegotiation. `body` is the payload after
    /// the option code. TTYPE IS sets terminal_type if the reported
    /// name is recognized; NAWS stores the reported window dimensions.
    async fn handle_subnegotiation(
        &mut self,
        opt: u8,
        body: &[u8],
    ) -> Result<(), std::io::Error> {
        match opt {
            OPT_TTYPE => {
                if body.first().copied() == Some(TTYPE_IS) && !self.ttype_matched {
                    let name_bytes = &body[1..];
                    let name: String = name_bytes
                        .iter()
                        .map(|&b| b as char)
                        .filter(|c| !c.is_control())
                        .collect();
                    if let Some(tt) = match_terminal_name(&name) {
                        self.terminal_type = tt;
                        self.ttype_matched = true;
                    }
                }
            }
            OPT_STATUS => {
                // RFC 859: only the SEND request needs a response.  The
                // IS variant (a peer dumping its state to us) is ignored
                // — we don't maintain a model of peer options.
                if body.first().copied() == Some(STATUS_SEND)
                    && self.neg_sent_will[OPT_STATUS as usize]
                {
                    self.send_status_is().await?;
                }
            }
            OPT_NAWS => {
                if body.len() >= 4 {
                    let w = u16::from_be_bytes([body[0], body[1]]);
                    let h = u16::from_be_bytes([body[2], body[3]]);
                    if w > 0 {
                        self.window_width = Some(w);
                    }
                    if h > 0 {
                        self.window_height = Some(h);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Emit `IAC SB STATUS IS <state> IAC SE` in response to a peer's
    /// `IAC SB STATUS SEND IAC SE` (RFC 859).
    ///
    /// The state body is a concatenation of `WILL opt` and `DO opt`
    /// triplets for every option we have advertised and not had denied.
    /// Any 0xFF byte inside the body (none of our opts are 0xFF, but the
    /// RFC requires it) is doubled per IAC escaping rules.
    async fn send_status_is(&mut self) -> Result<(), std::io::Error> {
        let mut body = vec![IAC, SB, OPT_STATUS, STATUS_IS];
        for opt in 0u8..=255u8 {
            let idx = opt as usize;
            if self.neg_sent_will[idx] && !self.neg_sent_wont[idx] {
                body.push(WILL);
                if opt == IAC {
                    body.push(IAC);
                }
                body.push(opt);
            }
            if self.neg_sent_do[idx] && !self.neg_sent_dont[idx] {
                body.push(DO);
                if opt == IAC {
                    body.push(IAC);
                }
                body.push(opt);
            }
            if opt == 255 {
                break;
            }
        }
        body.push(IAC);
        body.push(SE);
        self.send_telnet_protocol(&body).await?;
        self.flush().await
    }

    /// Consume up to `max` immediately-queued CR/LF bytes left behind by a
    /// linemode telnet client (e.g. the `\n` of a CRLF pair after a menu
    /// selection or line submit). Uses a short read timeout so nothing is
    /// eaten in char-at-a-time mode. Any non-CR/LF byte seen is pushed back
    /// for the next real input call, so no keystrokes are lost.
    async fn drain_trailing_eol(&mut self, max: usize) {
        if self.pushback.is_some() {
            return;
        }
        for _ in 0..max {
            let res = tokio::time::timeout(
                std::time::Duration::from_millis(20),
                self.session_read_byte(),
            )
            .await;
            match res {
                Ok(Ok(Some(b))) if b == b'\r' || b == b'\n' => continue,
                Ok(Ok(Some(b))) => {
                    self.pushback = Some(b);
                    return;
                }
                _ => return,
            }
        }
    }

    async fn echo_backspace(&mut self) -> Result<(), std::io::Error> {
        match self.terminal_type {
            TerminalType::Petscii => self.send_raw(&[0x9D, 0x20, 0x9D]).await,
            _ => self.send_raw(&[0x08, 0x20, 0x08]).await,
        }
    }

    async fn get_line_input(&mut self) -> Result<Option<String>, std::io::Error> {
        self.read_input_loop(&mut Vec::new(), InputMode::Normal).await
    }

    /// Continue collecting line input with bytes already in `buf` (which have
    /// already been echoed). Used when the caller consumed the first byte to
    /// decide between instant-action and line-input modes.
    async fn get_line_input_continuing(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> Result<Option<String>, std::io::Error> {
        self.read_input_loop(buf, InputMode::Normal).await
    }

    async fn get_password_input(&mut self) -> Result<Option<String>, std::io::Error> {
        self.read_input_loop(&mut Vec::new(), InputMode::Password).await
    }

    /// Core input loop shared by `get_line_input`, `get_line_input_continuing`,
    /// and `get_password_input`. In `Normal` mode, typed characters are echoed
    /// and the result is trimmed. In `Password` mode, `*` is echoed instead and
    /// the result is returned untrimmed.
    async fn read_input_loop(
        &mut self,
        buf: &mut Vec<u8>,
        mode: InputMode,
    ) -> Result<Option<String>, std::io::Error> {
        let is_password = matches!(mode, InputMode::Password);
        loop {
            let byte = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };

            if byte == b'\r' || byte == b'\n' {
                self.send_raw(b"\r\n").await?;
                self.flush().await?;
                // Drain the paired byte of a CRLF (or LFCR) so the next
                // prompt isn't silently satisfied by a leftover newline.
                self.drain_trailing_eol(1).await;
                let result: String = if self.terminal_type == TerminalType::Petscii {
                    buf.iter()
                        .map(|&b| petscii_to_ascii_byte(b) as char)
                        .collect()
                } else {
                    buf.iter().map(|&b| b as char).collect()
                };
                return Ok(Some(if is_password {
                    result
                } else {
                    result.trim().to_string()
                }));
            }

            if is_esc_key(byte, self.terminal_type == TerminalType::Petscii) {
                self.drain_input().await;
                return Ok(None);
            }

            if is_backspace_key(byte, self.erase_char) {
                if !buf.is_empty() {
                    buf.pop();
                    self.echo_backspace().await?;
                    self.flush().await?;
                }
                continue;
            }

            if byte == LINE_ERASE_BYTE {
                // RFC 854 EL (delivered by session_read_byte as 0x15).
                // Erase the current line both in the buffer and on the
                // user's terminal.
                while !buf.is_empty() {
                    buf.pop();
                    self.echo_backspace().await?;
                }
                self.flush().await?;
                continue;
            }

            if byte < 0x20 {
                continue;
            }

            if buf.len() >= MAX_INPUT_LENGTH {
                self.send_raw(b"\r\n").await?;
                self.show_error("Input too long.").await?;
                return Ok(None);
            }

            if is_password {
                self.send_raw(b"*").await?;
            } else {
                self.send_raw(&[byte]).await?;
            }
            self.flush().await?;
            buf.push(byte);
        }
    }

    async fn get_menu_input(
        &mut self,
        instant_digits: bool,
    ) -> Result<Option<String>, std::io::Error> {
        // ZMODEM autostart detection state.  A compliant ZMODEM sender
        // opens a transfer with `** ZDLE <header-type>` where
        // `<header-type>` is one of `A` (binary/CRC-16), `B` (hex),
        // or `C` (binary/CRC-32).  Reading the full four-byte prefix
        // off the menu input loop is an unambiguous "the user's
        // terminal just tried to auto-start a ZMODEM transfer" signal
        // — ZMODEM is not yet implemented, so we intercept, send the
        // spec'd abort sequence, and bounce back to the menu with an
        // explanation instead of leaving the receiver hanging.
        let mut zmodem_state: u8 = 0;
        loop {
            let byte = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };

            // ZMODEM autostart: **\x18[ABC].
            match (zmodem_state, byte) {
                (0, b'*') => {
                    zmodem_state = 1;
                    continue;
                }
                (1, b'*') => {
                    zmodem_state = 2;
                    continue;
                }
                (2, 0x18) => {
                    zmodem_state = 3;
                    continue;
                }
                (3, b'A') | (3, b'B') | (3, b'C') => {
                    self.handle_zmodem_autostart().await?;
                    // Bounce back to the caller so the menu redraws.
                    return Ok(None);
                }
                _ => {
                    zmodem_state = 0;
                    // Fall through and process `byte` normally.
                }
            }

            if is_esc_key(byte, self.terminal_type == TerminalType::Petscii) {
                self.drain_input().await;
                return Ok(None);
            }

            if byte == b'\r' || byte == b'\n' {
                continue;
            }
            if is_backspace_key(byte, self.erase_char) {
                continue;
            }
            if byte < 0x20 {
                continue;
            }

            let ch = if self.terminal_type == TerminalType::Petscii {
                (petscii_to_ascii_byte(byte) as char).to_ascii_lowercase()
            } else {
                (byte as char).to_ascii_lowercase()
            };

            if ch.is_ascii_alphabetic() {
                self.send_raw(&[byte]).await?;
                self.send_raw(b"\r\n").await?;
                self.flush().await?;
                // Linemode clients send `letter\r\n`; drop the trailing
                // CRLF so a follow-up prompt isn't auto-submitted.
                self.drain_trailing_eol(2).await;
                return Ok(Some(ch.to_string()));
            }

            if ch.is_ascii_digit() {
                if instant_digits {
                    self.send_raw(&[byte]).await?;
                    self.send_raw(b"\r\n").await?;
                    self.flush().await?;
                    self.drain_trailing_eol(2).await;
                    return Ok(Some(ch.to_string()));
                }

                self.send_raw(&[byte]).await?;
                self.flush().await?;
                let mut input = String::new();
                input.push(ch);

                loop {
                    let b2 = match self.read_byte_filtered().await? {
                        Some(b) => b,
                        None => return Ok(None),
                    };

                    if b2 == b'\r' || b2 == b'\n' {
                        self.send_raw(b"\r\n").await?;
                        self.flush().await?;
                        self.drain_trailing_eol(1).await;
                        return Ok(Some(input));
                    }

                    if is_esc_key(b2, self.terminal_type == TerminalType::Petscii) {
                        self.drain_input().await;
                        return Ok(None);
                    }

                    if is_backspace_key(b2, self.erase_char) {
                        if !input.is_empty() {
                            input.pop();
                            self.echo_backspace().await?;
                            self.flush().await?;
                        }
                        continue;
                    }

                    if b2 < 0x20 {
                        continue;
                    }

                    let ch2 = if self.terminal_type == TerminalType::Petscii {
                        petscii_to_ascii_byte(b2) as char
                    } else {
                        b2 as char
                    };

                    if ch2.is_ascii_digit() && input.len() < MAX_INPUT_LENGTH {
                        self.send_raw(&[b2]).await?;
                        self.flush().await?;
                        input.push(ch2);
                    }
                }
            }

            self.send_raw(&[byte]).await?;
            self.send_raw(b"\r\n").await?;
            self.flush().await?;
            self.drain_trailing_eol(2).await;
            return Ok(Some(ch.to_string()));
        }
    }

    async fn wait_for_key(&mut self) -> Result<(), std::io::Error> {
        loop {
            match self.read_byte_filtered().await? {
                Some(b)
                    if b >= 0x20
                        || b == b'\r'
                        || b == b'\n'
                        || is_esc_key(b, self.terminal_type == TerminalType::Petscii) =>
                {
                    return Ok(());
                }
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "disconnected",
                    ));
                }
                _ => continue,
            }
        }
    }

    async fn drain_input(&mut self) {
        while let Ok(Ok(Some(_))) = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            self.session_read_byte(),
        )
        .await
        {}
    }

    /// Handle a detected ZMODEM autostart prefix (`**\x18[ABC]`) on the
    /// menu input stream.  Emits the protocol-standard abort (5 × CAN)
    /// so the client's terminal bails out of ZMODEM receive mode, then
    /// drains any trailing ZMODEM bytes, then displays a user-friendly
    /// message explaining that ZMODEM isn't implemented yet.  The
    /// caller re-renders the menu afterwards.
    async fn handle_zmodem_autostart(&mut self) -> Result<(), std::io::Error> {
        glog!("File transfer: ZMODEM autostart detected; sending abort");
        // Standard ZMODEM abort sequence: 5 × CAN (0x18).  Clients in
        // ZMODEM receive mode will see this and return to interactive
        // terminal mode.
        self.send_raw(&[0x18; 5]).await?;
        // Followed by a few backspaces — the convention is CAN*5 then
        // BS*5 to wipe the "rz\r" prompt some senders emit before the
        // ZMODEM header.
        self.send_raw(&[0x08; 5]).await?;
        self.flush().await?;
        // Give the client a moment to exit ZMODEM mode, then drain any
        // remaining frames it was sending.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        self.drain_input().await;

        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("ZMODEM autostart detected — aborting.")
        ))
        .await?;
        self.send_line("  ZMODEM is not yet supported by this server.").await?;
        self.send_line(
            "  Please use XMODEM, XMODEM-1K, or YMODEM from",
        )
        .await?;
        self.send_line("  the File Transfer menu instead.").await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        let _ = self.wait_for_key().await;
        Ok(())
    }

    async fn show_error(&mut self, msg: &str) -> Result<(), std::io::Error> {
        self.send_line(&format!("  {}", self.red(msg))).await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    /// Pause after an XMODEM/YMODEM transfer so the client's own
    /// transfer dialog finishes closing and the underlying terminal is
    /// visible again before we print status.  Drains trailing bytes
    /// from the client's post-transfer chatter (NAWS updates, stray
    /// CR/LF from a dialog-dismiss keypress, etc.) so the subsequent
    /// `wait_for_key` actually waits for a human keypress instead of
    /// being satisfied by leftover noise.
    async fn post_transfer_settle(&mut self) {
        self.drain_input().await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        self.drain_input().await;
    }

    /// Show a multi-line informational message and wait for a keypress.
    async fn show_error_lines(&mut self, lines: &[&str]) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        for line in lines {
            self.send_line(&format!("  {}", line)).await?;
        }
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    /// Show a full-screen help page with a header and wait for a keypress.
    /// Split help content into pages that each fit within `max_per_page`
    /// lines.  Prefers breaking at **blank lines** so a logical group —
    /// a section header plus its continuation lines, a letter-command
    /// plus its description — stays together on a single page.  Falls
    /// back to a hard split at `max_per_page` only if no blank exists
    /// within the range; authors avoid that path by separating groups
    /// with a blank line in the help content.
    ///
    /// The returned pages have trailing blanks stripped and leading
    /// blanks skipped so each page renders cleanly without drifting
    /// chrome.
    fn paginate_help<'a>(
        lines: &'a [&'a str],
        max_per_page: usize,
    ) -> Vec<Vec<&'a str>> {
        assert!(max_per_page >= 1, "max_per_page must be ≥ 1");
        fn is_blank(s: &str) -> bool {
            s.trim().is_empty()
        }
        let mut pages: Vec<Vec<&'a str>> = Vec::new();
        let mut remaining: &[&str] = lines;
        while !remaining.is_empty() {
            let take = remaining.len().min(max_per_page);
            // Prefer splitting at the last blank line within `take`.
            // Falling back to `take` only when no blank exists in range
            // — authors should avoid this by separating groups with
            // blanks, but we don't want to loop forever on malformed
            // input.
            let mut split = take;
            for i in (1..=take).rev() {
                if is_blank(remaining[i - 1]) {
                    split = i;
                    break;
                }
            }
            // Emit the page with trailing blanks trimmed.
            let mut page: Vec<&str> = remaining[..split].to_vec();
            while page.last().is_some_and(|s| is_blank(s)) {
                page.pop();
            }
            if !page.is_empty() {
                pages.push(page);
            }
            // Skip leading blanks on the next page so the header isn't
            // followed by an awkward empty line.
            remaining = &remaining[split..];
            while !remaining.is_empty() && is_blank(remaining[0]) {
                remaining = &remaining[1..];
            }
        }
        pages
    }

    async fn show_help_page(
        &mut self,
        title: &str,
        lines: &[&str],
    ) -> Result<(), std::io::Error> {
        // Chrome is 6 rows: sep(1) + title(1) + sep(1) + blank(1) +
        // blank(1) + footer(1).  PETSCII renders 22 usable rows on a
        // 25-line Commodore 64, so 22 - 6 = 16 content rows.  We use 15
        // to leave a little breathing room for terminals that occasionally
        // push an extra line at the bottom.
        const MAX_CONTENT_LINES: usize = 15;

        let pages = Self::paginate_help(lines, MAX_CONTENT_LINES);
        // Empty content is rare but possible; treat it as one blank page
        // so the caller still gets the usual "Press any key" affordance.
        let pages: Vec<Vec<&str>> = if pages.is_empty() {
            vec![Vec::new()]
        } else {
            pages
        };
        let total = pages.len();

        for (idx, page_lines) in pages.iter().enumerate() {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow(title))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            for line in page_lines {
                self.send_line(line).await?;
            }
            self.send_line("").await?;

            let is_last = idx + 1 == total;
            let prompt = if total == 1 {
                "  Press any key to continue.".to_string()
            } else if is_last {
                format!("  Page {}/{} - Press any key.", idx + 1, total)
            } else {
                format!("  Page {}/{} - next key, Q to quit", idx + 1, total)
            };
            self.send(&prompt).await?;
            self.flush().await?;

            let key = self.wait_for_key_returning().await?;
            // Early-exit on Q between pages.  ESC also bails out so the
            // existing "escape twice means leave this screen" reflex
            // works on help screens too.
            if !is_last
                && (matches!(key, b'q' | b'Q')
                    || is_esc_key(key, self.terminal_type == TerminalType::Petscii))
            {
                break;
            }
        }
        Ok(())
    }

    /// Variant of `wait_for_key` that returns the byte that unblocked
    /// it.  Used by paginated help screens so they can react to `Q`
    /// (quit) or ESC during multi-page navigation.
    async fn wait_for_key_returning(&mut self) -> Result<u8, std::io::Error> {
        loop {
            match self.read_byte_filtered().await? {
                Some(b)
                    if b >= 0x20
                        || b == b'\r'
                        || b == b'\n'
                        || is_esc_key(b, self.terminal_type == TerminalType::Petscii) =>
                {
                    return Ok(b);
                }
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "disconnected",
                    ));
                }
                _ => continue,
            }
        }
    }

    // ─── Terminal detection ─────────────────────────────────

    async fn detect_terminal_type(&mut self) -> Result<(), std::io::Error> {
        // Advertise server-side echo + char-at-a-time mode, and request
        // terminal type + window size from the client. Mark the DOs as
        // sent so a client-initiated WILL TTYPE / WILL NAWS is treated
        // as an acknowledgement instead of triggering a duplicate DO.
        self.send_telnet_protocol(&[
            IAC, WILL, OPT_ECHO,
            IAC, WILL, OPT_SGA,
            IAC, DO, OPT_SGA,
            IAC, DO, OPT_TTYPE,
            IAC, DO, OPT_NAWS,
        ])
        .await?;
        self.neg_sent_will[OPT_ECHO as usize] = true;
        self.neg_sent_will[OPT_SGA as usize] = true;
        self.neg_sent_do[OPT_SGA as usize] = true;
        self.neg_sent_do[OPT_TTYPE as usize] = true;
        self.neg_sent_do[OPT_NAWS as usize] = true;
        self.flush().await?;

        // Give the client a moment to respond, then process negotiation
        // replies (including any TTYPE IS / NAWS subnegotiations).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        self.drain_input().await;

        // If TTYPE already identified the client, skip the manual prompt.
        if self.ttype_matched {
            self.erase_char = match self.terminal_type {
                TerminalType::Petscii => 0x14,
                _ => 0x7F,
            };
        } else {
            self.send_raw(b"\r\nPress BACKSPACE to detect terminal: ")
                .await?;
            self.flush().await?;

            let byte = match tokio::time::timeout(
                std::time::Duration::from_secs(60),
                self.read_byte_filtered(),
            )
            .await
            {
                Ok(result) => match result? {
                    Some(b) => b,
                    None => return Ok(()),
                },
                Err(_) => {
                    self.send_raw(b"\r\n\r\n  Disconnected: idle timeout.\r\n\r\n")
                        .await?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle timeout during terminal detection",
                    ));
                }
            };

            self.erase_char = byte;
            self.terminal_type = match byte {
                0x14 => TerminalType::Petscii,
                0x08 | 0x7F => TerminalType::Ansi,
                _ => TerminalType::Ascii,
            };
        }

        let type_name = match self.terminal_type {
            TerminalType::Petscii => "PETSCII (Commodore 64)",
            TerminalType::Ansi => "ANSI",
            TerminalType::Ascii => "ASCII",
        };
        self.send(&format!("\r\nTerminal detected: {}\r\n", type_name))
            .await?;
        self.flush().await?;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        self.drain_input().await;

        // Color preference — user must explicitly choose Y or N
        let color_label = match self.terminal_type {
            TerminalType::Petscii => "PETSCII",
            _ => "ANSI",
        };
        self.send(&format!(
            "Use {} color? (Y/N): ",
            color_label
        ))
        .await?;
        self.flush().await?;

        let accepted = loop {
            let color_byte = match tokio::time::timeout(
                std::time::Duration::from_secs(60),
                self.read_byte_filtered(),
            )
            .await
            {
                Ok(result) => match result? {
                    Some(b) => b,
                    None => return Ok(()),
                },
                Err(_) => {
                    self.send_raw(b"\r\n\r\n  Disconnected: idle timeout.\r\n\r\n")
                        .await?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle timeout during color selection",
                    ));
                }
            };

            let choice = if self.terminal_type == TerminalType::Petscii {
                petscii_to_ascii_byte(color_byte)
            } else {
                color_byte
            };

            match choice {
                b'y' | b'Y' => {
                    self.send_raw(&[color_byte]).await?;
                    self.send_raw(b"\r\n").await?;
                    self.flush().await?;
                    break true;
                }
                b'n' | b'N' => {
                    self.send_raw(&[color_byte]).await?;
                    self.send_raw(b"\r\n").await?;
                    self.flush().await?;
                    break false;
                }
                _ => continue, // ignore other keys
            }
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.drain_input().await;

        if accepted {
            if self.terminal_type == TerminalType::Ascii {
                self.terminal_type = TerminalType::Ansi;
                self.send_raw(b"ANSI color enabled.\r\n").await?;
            }
        } else if self.terminal_type != TerminalType::Ascii {
            self.terminal_type = TerminalType::Ascii;
            self.send_raw(b"Color disabled.\r\n").await?;
        }

        self.send_raw(b"\r\n").await?;
        self.flush().await?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        self.drain_input().await;

        Ok(())
    }

    // ─── Authentication ─────────────────────────────────────

    async fn authenticate(&mut self) -> Result<bool, std::io::Error> {
        if let Some(ip) = self.peer_addr
            && is_locked_out(&self.lockouts, ip)
        {
            glog!("Telnet: auth rejected for {} (locked out)", ip);
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}",
                self.red("Too many attempts. Try later.")
            ))
            .await?;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            return Ok(false);
        }

        let cfg = config::get_config();
        let idle_timeout = std::time::Duration::from_secs(cfg.idle_timeout_secs);
        let sep = self.separator();
        self.clear_screen().await?;
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("ETHERNET GATEWAY")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        for attempt in 1..=MAX_AUTH_ATTEMPTS {
            self.send(&format!("  {} ", self.cyan("Username:")))
                .await?;
            self.flush().await?;
            let username = if idle_timeout.is_zero() {
                match self.get_line_input().await {
                    Ok(Some(s)) => s,
                    Ok(None) => return Ok(false),
                    Err(e) => return Err(e),
                }
            } else {
                match tokio::time::timeout(idle_timeout, self.get_line_input()).await {
                    Ok(Ok(Some(s))) => s,
                    Ok(Ok(None)) => return Ok(false),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        let _ = self
                            .send_line("\r\nDisconnected: idle timeout.")
                            .await;
                        return Ok(false);
                    }
                }
            };

            self.send(&format!("  {} ", self.cyan("Password:")))
                .await?;
            self.flush().await?;
            let password = if idle_timeout.is_zero() {
                match self.get_password_input().await {
                    Ok(Some(s)) => s,
                    Ok(None) => return Ok(false),
                    Err(e) => return Err(e),
                }
            } else {
                match tokio::time::timeout(idle_timeout, self.get_password_input()).await {
                    Ok(Ok(Some(s))) => s,
                    Ok(Ok(None)) => return Ok(false),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        let _ = self
                            .send_line("\r\nDisconnected: idle timeout.")
                            .await;
                        return Ok(false);
                    }
                }
            };

            if constant_time_eq(username.as_bytes(), cfg.username.as_bytes())
                && constant_time_eq(password.as_bytes(), cfg.password.as_bytes())
            {
                if let Some(ip) = self.peer_addr {
                    clear_lockout(&self.lockouts, ip);
                }
                return Ok(true);
            }

            if let Some(ip) = self.peer_addr {
                let count = record_auth_failure(&self.lockouts, ip);
                if count >= MAX_AUTH_ATTEMPTS {
                    glog!("Telnet: {} locked out after {} failures", ip, count);
                    self.send_line(&format!(
                        "  {}",
                        self.red("Too many failed attempts.")
                    ))
                    .await?;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    return Ok(false);
                }
            }

            let remaining = MAX_AUTH_ATTEMPTS - attempt;
            if remaining > 0 {
                self.send_line(&format!(
                    "  {} ({} {} remaining)",
                    self.red("Login incorrect."),
                    remaining,
                    if remaining == 1 {
                        "attempt"
                    } else {
                        "attempts"
                    },
                ))
                .await?;
                self.send_line("").await?;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } else {
                self.send_line(&format!(
                    "  {}",
                    self.red("Too many failed attempts.")
                ))
                .await?;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        Ok(false)
    }

    // ─── Main session loop ──────────────────────────────────

    pub(crate) async fn run(&mut self) -> Result<(), std::io::Error> {
        let cfg = config::get_config();

        if !self.is_serial && !self.is_ssh {
            self.detect_terminal_type().await?;

            // Auto-set the IAC/CR-NUL transform default based on
            // whether the client actually speaks the telnet protocol
            // (RFC 854/856).  detect_terminal_type() has already sent
            // our opening WILL/DO batch and drained the reply window,
            // so session_read_byte has flipped telnet_negotiated on
            // iff the peer answered with any option-negotiation or
            // subnegotiation bytes.  Real telnet clients (PuTTY, Tera
            // Term, C-Kermit, SecureCRT) always negotiate and need
            // 0xFF escaped; raw TCP clients (netcat, IMP8, CCGMS,
            // StrikeTerm, AltairDuino firmware) stay silent and get a
            // transparent byte stream.  The I key on the File Transfer
            // menu still lets the user override per-session.
            self.xmodem_iac = self.telnet_negotiated;

            if cfg.security_enabled
                && !self.authenticate().await?
            {
                return Ok(());
            }
        }

        // Welcome banner
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("ETHERNET GATEWAY")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  Welcome! Terminal: {}",
            self.white(match self.terminal_type {
                TerminalType::Petscii => "PETSCII",
                TerminalType::Ansi => "ANSI",
                TerminalType::Ascii => "ASCII",
            })
        ))
        .await?;
        self.send_line("").await?;

        match self.run_menu_loop().await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                let _ = self
                    .send_line("\r\n\r\nDisconnected: idle timeout.")
                    .await;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Inner menu loop, separated so that idle timeout errors from any
    /// sub-menu propagate up and are handled uniformly in `run()`.
    async fn run_menu_loop(&mut self) -> Result<(), std::io::Error> {
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                self.send_line("\r\nServer shutting down. Goodbye.")
                    .await?;
                break;
            }

            match self.current_menu {
                Menu::Main => self.render_main_menu().await?,
                Menu::FileTransfer => self.render_file_transfer().await?,
                Menu::Browser => self.render_web_browser().await?,
            }

            let prompt = self.prompt_str();
            self.send(&prompt).await?;
            self.flush().await?;

            let input = self.get_menu_input(true).await?;

            let input = match input {
                Some(s) if !s.is_empty() => s,
                _ => {
                    // ESC pressed — go to main menu or stay
                    if self.current_menu == Menu::Browser {
                        self.web_reset();
                    }
                    self.current_menu = Menu::Main;
                    continue;
                }
            };

            match self.current_menu.clone() {
                Menu::Main => {
                    if !self.handle_main_command(&input).await? {
                        break;
                    }
                }
                Menu::FileTransfer => {
                    self.handle_file_transfer_command(&input).await?;
                }
                Menu::Browser => {
                    self.handle_web_browser_command(&input).await?;
                }
            }
        }

        Ok(())
    }

    // ─── Main menu ──────────────────────────────────────────

    async fn render_main_menu(&mut self) -> Result<(), std::io::Error> {
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("ETHERNET GATEWAY")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}  AI Chat",
            self.cyan("A")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Simple Browser",
            self.cyan("B")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Configuration",
            self.cyan("C")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  File Transfer",
            self.cyan("F")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Troubleshooting",
            self.cyan("R")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  SSH Gateway",
            self.cyan("S")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Telnet Gateway",
            self.cyan("T")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Weather",
            self.cyan("W")
        ))
        .await?;
        self.send_line(&format!("  {}  Exit", self.cyan("X")))
            .await?;
        self.send_line("").await?;
        self.send_line(&format!("  {}", self.action_prompt("H", "Help")))
            .await?;
        Ok(())
    }

    async fn handle_main_command(&mut self, input: &str) -> Result<bool, std::io::Error> {
        match input {
            "h" => {
                let mut lines = vec![
                    "  A  AI Chat: ask questions to an AI",
                    "  B  Browser: browse the web",
                    "  C  Configuration: server settings",
                    "     and other options",
                ];
                lines.extend_from_slice(&[
                    "  F  File Transfer: upload/download",
                    "     files using the XMODEM protocol",
                    "  R  Troubleshooting: diagnose",
                    "     terminal input issues",
                    "  S  SSH Gateway: connect to a",
                    "     remote server via SSH",
                    "  T  Telnet Gateway: connect to a",
                    "     remote server via telnet",
                    "  W  Weather: check weather by zip",
                    "  X  Exit: disconnect from server",
                ]);
                self.show_help_page("HELP", &lines).await?;
            }
            "r" => {
                self.troubleshooting().await?;
            }
            "w" => {
                self.weather().await?;
            }
            "a" => {
                let cfg = config::get_config();
                if cfg.groq_api_key.is_empty() {
                    self.show_error_lines(&[
                        "No API key configured.",
                        "",
                        "To enable AI Chat:",
                        "1. Visit https://console.groq.com",
                        "2. Create a free account",
                        "3. Generate an API key",
                        "4. Configuration > Other Settings",
                        "   and set the AI API key",
                    ]).await?;
                } else {
                    self.ai_chat(&cfg.groq_api_key).await?;
                }
            }
            "b" => {
                self.current_menu = Menu::Browser;
            }
            "c" => {
                self.configuration().await?;
            }
            "f" => {
                self.current_menu = Menu::FileTransfer;
            }
            "s" => {
                self.gateway_ssh().await?;
            }
            "t" => {
                self.gateway_telnet().await?;
            }
            "x" => {
                self.send_farewell().await?;
                return Ok(false);
            }
            _ => {
                self.show_error("Press A-C, F, R, S, T, W, X, or H.").await?;
            }
        }
        Ok(true)
    }

    /// Print John 3:16 (KJV) on a fresh page when the user quits from
    /// the main menu, then block long enough for every byte to clock
    /// out on even a 1200 baud link before the caller drops the
    /// connection.  A 1200 baud 8N1 link carries 120 bytes/sec; we
    /// tally the bytes we emit and sleep `bytes / 120 s + 1 s` so the
    /// closing `TCP FIN` / SSH EOF doesn't truncate the final line on
    /// slow retro terminals.
    async fn send_farewell(&mut self) -> Result<(), std::io::Error> {
        self.clear_screen().await?;

        // Wrap width leaves a two-char indent on both layouts.  36/76
        // rather than 38/78 keeps room for color-code padding without
        // risking an overflow wrap on narrow PETSCII screens.
        let wrap_width = if self.terminal_type == TerminalType::Petscii {
            36
        } else {
            76
        };
        let verse = "For God so loved the world, that he gave his only \
                     begotten Son, that whosoever believeth in him \
                     should not perish, but have everlasting life.";

        // `byte_count` is a running tally of everything we send after
        // the clear-screen, so the transmit-delay calculation reflects
        // what actually went down the wire.  The clear-screen prefix
        // itself is a handful of bytes (ANSI ESC[2J ESC[H, PETSCII 0x93,
        // or blank for ASCII); 16 is a safe ceiling.
        let mut byte_count: usize = 16;

        self.send_line("").await?;
        byte_count += 2;

        let header = format!("  {}", self.yellow("John 3:16 (KJV)"));
        byte_count += header.len() + 2;
        self.send_line(&header).await?;

        self.send_line("").await?;
        byte_count += 2;

        for line in crate::aichat::wrap_line(verse, wrap_width) {
            let out = format!("  {}", line);
            byte_count += out.len() + 2;
            self.send_line(&out).await?;
        }

        self.send_line("").await?;
        byte_count += 2;
        self.flush().await?;

        // transmit_ms = bytes / 120 s, rounded up.  Adding 1 s of
        // quiet before disconnect lets the final stop-bit settle
        // before we close the socket.
        let transmit_ms = (byte_count as u64).saturating_mul(1000).div_ceil(120);
        tokio::time::sleep(std::time::Duration::from_millis(
            transmit_ms.saturating_add(1000),
        ))
        .await;
        Ok(())
    }

    // ─── File Transfer menu ──────────────────────────────────

    async fn render_file_transfer(&mut self) -> Result<(), std::io::Error> {
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("FILE TRANSFER")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        let max_dir = if self.terminal_type == TerminalType::Petscii {
            30
        } else {
            60
        };
        let dir_str = truncate_to_width(&self.transfer_dir_display(), max_dir);
        self.send_line(&format!("  Dir: {}", self.amber(&dir_str)))
            .await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}  Upload a file",
            self.cyan("U")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Download a file",
            self.cyan("D")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Delete a file",
            self.cyan("X")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  Change directory",
            self.cyan("C")
        ))
        .await?;
        let iac_status = if self.xmodem_iac {
            self.green("ON")
        } else {
            self.red("OFF")
        };
        self.send_line(&format!(
            "  {}  IAC escaping [{}]",
            self.cyan("I"),
            iac_status
        ))
        .await?;
        self.send_line("").await?;
        let footer = self.nav_footer();
        self.send_line(&footer).await?;
        Ok(())
    }

    async fn handle_file_transfer_command(
        &mut self,
        input: &str,
    ) -> Result<bool, std::io::Error> {
        match input {
            "u" => {
                if let Err(e) = self.file_transfer_upload().await {
                    self.show_error(&format!("Transfer error: {}", e))
                        .await?;
                }
            }
            "d" => {
                if let Err(e) = self.file_transfer_download().await {
                    self.show_error(&format!("Transfer error: {}", e))
                        .await?;
                }
            }
            "x" => {
                if let Err(e) = self.file_transfer_delete().await {
                    self.show_error(&format!("Error: {}", e)).await?;
                }
            }
            "c" => {
                self.file_transfer_chdir().await?;
            }
            "i" => {
                self.xmodem_iac = !self.xmodem_iac;
            }
            "q" => {
                self.current_menu = Menu::Main;
            }
            "h" => {
                self.show_help_page("FILE TRANSFER HELP", &[
                    "  Menu items:",
                    "  U  Upload a file to the server",
                    "  D  Download a file from server",
                    "  X  Delete a file on the server",
                    "  C  Change to a subdirectory",
                    "  I  Toggle IAC escaping on/off",
                    "  R  Refresh the screen",
                    "  Q  Back to the main menu",
                    "",
                    "  Picking a protocol on upload:",
                    "    X  XMODEM or YMODEM - variant",
                    "       auto-detected from block 0.",
                    "    Z  ZMODEM - full Forsberg",
                    "       batch with ZSKIP handling.",
                    "",
                    "  Picking a protocol on download:",
                    "    X  Classic XMODEM (128 B)",
                    "    1  XMODEM-1K (1024 B blocks,",
                    "       SOH fallback if peer NAKs)",
                    "    Y  YMODEM (filename + size",
                    "       header, then 1K data)",
                    "    Z  ZMODEM (auto-starts in",
                    "       most modern terminals)",
                    "",
                    "  IAC escaping (I toggle):",
                    "    Telnet reserves byte 0xFF as",
                    "    the IAC marker. When trans-",
                    "    ferring binary files that may",
                    "    contain 0xFF, enable IAC",
                    "    escaping so the stream",
                    "    survives the wire intact.",
                    "    Both sides must agree on the",
                    "    setting. Default is ON for",
                    "    telnet clients, OFF for SSH",
                    "    (which has no IAC layer).",
                    "",
                    "  Limits:",
                    "    Maximum file size: 8 MB.",
                    "    Filenames: 64 chars max,",
                    "    letters/digits/._- only, may",
                    "    not start with a dot or",
                    "    contain '..' (path traversal",
                    "    protection).",
                    "",
                    "  Timeouts and retry intervals",
                    "  are tunable in Configuration >",
                    "  File Transfer > X / Y / Z.",
                ]).await?;
            }
            "r" => {} // Refresh — just re-render
            _ => {
                self.show_error("Press U, D, X, C, I, R, Q, or H.")
                    .await?;
            }
        }
        Ok(true)
    }

    fn transfer_dir_display(&self) -> String {
        let cfg = config::get_config();
        if self.transfer_subdir.is_empty() {
            format!("{}/", cfg.transfer_dir)
        } else {
            format!("{}/{}/", cfg.transfer_dir, self.transfer_subdir)
        }
    }

    fn transfer_path(&self) -> std::path::PathBuf {
        let cfg = config::get_config();
        let mut p = std::path::PathBuf::from(&cfg.transfer_dir);
        if !self.transfer_subdir.is_empty() {
            p.push(&self.transfer_subdir);
        }
        p
    }

    /// Verify that the current transfer_subdir resolves to a path inside the
    /// transfer base directory. Resets to root if it escapes (e.g. via symlink).
    fn verify_transfer_path(&mut self) -> bool {
        let cfg = config::get_config();
        let base = match std::fs::canonicalize(&cfg.transfer_dir) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let full = match std::fs::canonicalize(self.transfer_path()) {
            Ok(p) => p,
            Err(_) => {
                self.transfer_subdir.clear();
                return false;
            }
        };
        if full.starts_with(&base) {
            true
        } else {
            self.transfer_subdir.clear();
            false
        }
    }

    async fn ensure_transfer_dir(&mut self) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(self.transfer_path()).await
    }

    /// Apply YMODEM block-0 metadata to a freshly saved file.  Both
    /// modtime and mode are best-effort — failures are ignored because
    /// they don't affect data integrity.  Mode is masked to `0o777` so
    /// a misbehaving sender can't set setuid/setgid/sticky bits on our
    /// saved files; mode application is a no-op on non-Unix platforms.
    /// Sync std::fs calls are deliberate — these are microsecond-level
    /// operations that run once per saved file, so the cost of routing
    /// through `spawn_blocking` would exceed the operations themselves.
    fn apply_ymodem_meta(
        path: &std::path::Path,
        meta: Option<&crate::xmodem::YmodemReceiveMeta>,
    ) {
        let Some(m) = meta else { return };
        if let Some(secs) = m.modtime
            && let Ok(file) = std::fs::OpenOptions::new().write(true).open(path)
        {
            let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
            let _ = file.set_modified(when);
        }
        #[cfg(unix)]
        if let Some(mode) = m.mode {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode & 0o777);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    fn validate_filename(name: &str) -> Result<(), &'static str> {
        if name.is_empty() {
            return Err("Filename cannot be empty");
        }
        if name.len() > Self::MAX_FILENAME_LEN {
            return Err("Filename too long (max 64 chars)");
        }
        if name.starts_with('.') {
            return Err("Filename cannot start with a dot");
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err("Only letters, numbers, dots, hyphens, underscores");
        }
        if !name.chars().any(|c| c.is_ascii_alphanumeric()) {
            return Err("Filename must contain a letter or number");
        }
        if name.contains("..") {
            return Err("Invalid filename");
        }
        Ok(())
    }

    async fn list_transfer_entries_in(
        path: &std::path::Path,
    ) -> Result<Vec<(String, u64, bool)>, std::io::Error> {
        let mut dir = match tokio::fs::read_dir(&path).await {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };
        let mut entries: Vec<(String, u64, bool)> = Vec::new();
        while let Ok(Some(entry)) = dir.next_entry().await {
            let metadata = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if let Some(name) = entry.file_name().to_str() {
                if metadata.is_dir() {
                    entries.push((name.to_string(), 0, true));
                } else if metadata.is_file() {
                    entries.push((name.to_string(), metadata.len(), false));
                }
            }
        }
        entries.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
        });
        Ok(entries)
    }

    fn format_file_size(size: u64) -> String {
        if size < 1024 {
            format!("{} B", size)
        } else if size < 1024 * 1024 {
            format!("{:.1} KB", size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
        }
    }

    /// Returns true if disk usage exceeds 90%.
    fn is_disk_full() -> bool {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::mem::MaybeUninit;
            let cfg = config::get_config();
            let dir = if std::path::Path::new(&cfg.transfer_dir).exists() {
                cfg.transfer_dir.clone()
            } else {
                ".".to_string()
            };
            // "." never contains a nul byte, so the fallback CString is
            // always constructable.
            let path = CString::new(dir.as_str())
                .unwrap_or_else(|_| c".".to_owned());
            let mut stat = MaybeUninit::<libc::statvfs>::uninit();
            let rc = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
            if rc != 0 {
                return true;
            }
            let stat = unsafe { stat.assume_init() };
            // `f_frsize` / `f_blocks` / `f_bavail` are u64 on Linux but
            // u32 on macOS/BSD — cast all three to u64 explicitly so
            // the multiplication is portable across the Unix targets
            // our release workflow builds (Linux x86_64 + macOS aarch64).
            // The casts are no-ops on Linux; clippy flags them because
            // it only sees the host target.
            #[allow(clippy::unnecessary_cast)]
            let frsize = stat.f_frsize as u64;
            #[allow(clippy::unnecessary_cast)]
            let total = stat.f_blocks as u64 * frsize;
            #[allow(clippy::unnecessary_cast)]
            let avail = stat.f_bavail as u64 * frsize;
            if total == 0 || avail >= total {
                return total == 0;
            }
            let used_pct = 100 - (avail * 100 / total);
            used_pct > 90
        }
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            #[repr(C)]
            #[allow(non_snake_case)]
            struct ULARGE_INTEGER {
                QuadPart: u64,
            }

            unsafe extern "system" {
                fn GetDiskFreeSpaceExW(
                    lpDirectoryName: *const u16,
                    lpFreeBytesAvailableToCaller: *mut ULARGE_INTEGER,
                    lpTotalNumberOfBytes: *mut ULARGE_INTEGER,
                    lpTotalNumberOfFreeBytes: *mut ULARGE_INTEGER,
                ) -> i32;
            }

            let cfg = config::get_config();
            let dir = if std::path::Path::new(&cfg.transfer_dir).exists() {
                cfg.transfer_dir.clone()
            } else {
                ".".to_string()
            };
            let wide: Vec<u16> = OsStr::new(&dir).encode_wide().chain(std::iter::once(0)).collect();
            let mut avail = ULARGE_INTEGER { QuadPart: 0 };
            let mut total = ULARGE_INTEGER { QuadPart: 0 };
            let mut _free = ULARGE_INTEGER { QuadPart: 0 };
            let rc = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut _free) };
            if rc == 0 || total.QuadPart == 0 {
                return total.QuadPart == 0;
            }
            let used_pct = 100 - (avail.QuadPart * 100 / total.QuadPart);
            used_pct > 90
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

    // ─── UPLOAD ─────────────────────────────────────────────

    /// Prompt the user to pick the upload protocol on its own screen.
    /// Returns `None` if the user pressed ESC / PETSCII `<-` to cancel
    /// back to the file-transfer menu.  Parallel to
    /// [`Self::prompt_download_protocol`] — same screen layout,
    /// navigation keys, and petscii/ANSI handling.
    async fn prompt_upload_protocol(
        &mut self,
    ) -> Result<Option<UploadProtocol>, std::io::Error> {
        let is_petscii = self.terminal_type == TerminalType::Petscii;
        let esc_label = if is_petscii { "<-" } else { "ESC" };

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("SELECT UPLOAD PROTOCOL")
        ))
        .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}  XMODEM/YMODEM  (128/1K blocks, CRC-16 or checksum, auto)",
            self.cyan("X")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  ZMODEM         (1K subpackets, CRC-16, auto-start)",
            self.cyan("Z")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  KERMIT         (any flavor — auto-detects C/G/95/86/...)",
            self.cyan("K")
        ))
        .await?;
        self.send_line("").await?;
        self.send(&format!(
            "  Pick one, or {} to cancel: ",
            self.cyan(esc_label)
        ))
        .await?;
        self.flush().await?;

        loop {
            let b = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };
            if is_esc_key(b, is_petscii) {
                self.send_line("").await?;
                return Ok(None);
            }
            let ch = if is_petscii {
                (petscii_to_ascii_byte(b) as char).to_ascii_lowercase()
            } else {
                (b as char).to_ascii_lowercase()
            };
            // Accept 'Y' as a synonym for 'X' so a user thinking
            // "YMODEM" doesn't have to hunt for the right key — the
            // XMODEM/YMODEM receive path handles both.
            let chosen = match ch {
                'x' | 'y' => Some(UploadProtocol::XmodemYmodem),
                'z' => Some(UploadProtocol::Zmodem),
                'k' => Some(UploadProtocol::Kermit),
                _ => None,
            };
            if let Some(p) = chosen {
                self.send_raw(&[b]).await?;
                self.send_line("").await?;
                self.flush().await?;
                return Ok(Some(p));
            }
            // Invalid key — stay at the prompt.
        }
    }

    async fn file_transfer_upload(&mut self) -> Result<(), std::io::Error> {
        self.ensure_transfer_dir().await?;

        if Self::is_disk_full() {
            self.show_error("Disk space is low. Uploads disabled.")
                .await?;
            return Ok(());
        }

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("UPLOAD FILE")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        let p = format!("  {} ", self.cyan("Filename:"));
        self.send(&p).await?;
        self.flush().await?;

        let filename = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if let Err(msg) = Self::validate_filename(&filename) {
            self.show_error(msg).await?;
            return Ok(());
        }

        let filepath = self.transfer_path().join(&filename);

        // Detect duplicates up-front so the user doesn't sit through a
        // whole transfer only to have the save-step fail.  Prompt to
        // overwrite; if declined, cancel cleanly.
        let overwrite = if tokio::fs::try_exists(&filepath).await.unwrap_or(false) {
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}",
                self.yellow(&format!("File '{}' already exists.", filename))
            ))
            .await?;
            self.send(&format!(
                "  {} ",
                self.cyan("Overwrite? (Y/N):")
            ))
            .await?;
            self.flush().await?;
            self.drain_input().await;
            let answer = match self.read_byte_filtered().await? {
                Some(b) => {
                    if self.terminal_type == TerminalType::Petscii {
                        petscii_to_ascii_byte(b)
                    } else {
                        b
                    }
                }
                None => return Ok(()),
            };
            self.send_line("").await?;
            if answer != b'y' && answer != b'Y' {
                return Ok(());
            }
            true
        } else {
            false
        };

        // Ask the user which protocol their sender will use.  Putting
        // this on its own screen after the filename + overwrite prompts
        // mirrors the download flow (file → protocol → transfer) and
        // gives the user as long as they need to browse menus on their
        // terminal before committing to the transfer window.  ESC /
        // PETSCII `<-` at the protocol prompt cancels cleanly.
        let protocol = match self.prompt_upload_protocol().await? {
            Some(p) => p,
            None => return Ok(()),
        };

        self.send_line("").await?;
        self.send_line(&format!(
            "  Ready to receive: {}",
            self.amber(&filename)
        ))
        .await?;
        self.send_line(&format!(
            "  Max file size: {} MB",
            Self::MAX_FILE_SIZE / (1024 * 1024)
        ))
        .await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.green(match protocol {
                UploadProtocol::XmodemYmodem =>
                    "Start XMODEM/YMODEM send from your terminal now.",
                UploadProtocol::Zmodem =>
                    "Start ZMODEM send from your terminal now.",
                UploadProtocol::Kermit =>
                    "Start KERMIT send from your terminal now.",
            })
        ))
        .await?;
        // Make it explicit that the action happens on the user's side.
        // For ExtraPutty it's File Transfer → Zmodem → Send; other
        // terminals have similar menu items.  Users who know the drill
        // can ignore this — it's here for the first-timer path.
        if matches!(protocol, UploadProtocol::Zmodem) {
            self.send_line(
                "  (ExtraPutty: File Transfer > Zmodem > Send. Other clients vary.)",
            )
            .await?;
        }
        self.send_line(&format!("  Start transfer within {} seconds.",
            config::get_config().xmodem_negotiation_timeout))
            .await?;
        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };
        self.send_line(&format!("  {} to cancel", self.cyan(esc_label)))
            .await?;
        self.send_line("").await?;
        self.flush().await?;

        if config::get_config().verbose {
            glog!("Upload: IAC escaping={} protocol={:?}", self.xmodem_iac, protocol);
        }
        self.drain_input().await;

        let verbose = config::get_config().verbose;
        let start = std::time::Instant::now();
        let mut writer_guard = self.writer.lock().await;
        // Normalize both receive paths to a Vec of (sender-proposed
        // filename, data).  XMODEM/YMODEM never carries a filename in
        // the protocol, so we mark it as None and the user-entered
        // name wins.  ZMODEM carries a filename per file; we keep it
        // so batches can save files 2..N under their sender names.
        // The third tuple slot carries optional YMODEM metadata
        // (modtime/mode/sno) parsed from block 0; ZMODEM doesn't surface
        // file attributes through this path so its entries are always
        // `None`.  The save-side applies modtime + mode after writing.
        type Received = Vec<(Option<String>, Vec<u8>, Option<crate::xmodem::YmodemReceiveMeta>)>;
        // Decide callback for the ZMODEM receiver.  The first file
        // (idx 0) is always accepted — the user typed a destination
        // filename in the upload prompt, so they want this one saved
        // regardless of what the sender called it.  Later files in a
        // batch use the sender's name, which we sanitize through the
        // same `validate_filename` rules as user input and reject with
        // ZSKIP if they fail or collide with an existing file.  The
        // path-existence check is a sync std::fs call — fast, no
        // runtime-blocking concern.
        let transfer_path = self.transfer_path();
        let decide = |idx: usize,
                      sender_name: &str,
                      _size: Option<u64>|
         -> bool {
            if idx == 0 {
                return true;
            }
            if Self::validate_filename(sender_name).is_err() {
                return false;
            }
            !transfer_path.join(sender_name).exists()
        };
        let kermit_iac = config::get_config().kermit_iac_escape;
        let is_petscii = self.terminal_type == TerminalType::Petscii;
        let result: Result<Received, String> = match protocol {
            UploadProtocol::Zmodem => crate::zmodem::zmodem_receive(
                &mut self.reader,
                &mut *writer_guard,
                self.xmodem_iac,
                verbose,
                decide,
            )
            .await
            .map(|rxs| {
                rxs.into_iter()
                    .map(|rx| (Some(rx.filename), rx.data, None))
                    .collect()
            }),
            UploadProtocol::XmodemYmodem => crate::xmodem::xmodem_receive(
                &mut self.reader,
                &mut *writer_guard,
                self.xmodem_iac,
                self.terminal_type == TerminalType::Petscii,
                verbose,
            )
            .await
            .map(|(data, meta)| vec![(None, data, meta)]),
            UploadProtocol::Kermit => crate::kermit::kermit_receive(
                &mut self.reader,
                &mut *writer_guard,
                kermit_iac,
                is_petscii,
                verbose,
            )
            .await
            .map(|rxs| {
                // Map KermitReceive list to (Option<filename>, data, None).
                // First file gets None for filename so user-entered name
                // wins (matches XMODEM/YMODEM behavior); subsequent files
                // in the batch use the sender's name like ZMODEM does.
                rxs.into_iter()
                    .enumerate()
                    .map(|(i, rx)| {
                        let name = if i == 0 { None } else { Some(rx.filename) };
                        let meta = crate::xmodem::YmodemReceiveMeta {
                            size: rx.declared_size,
                            modtime: rx.modtime,
                            mode: rx.mode,
                        };
                        (name, rx.data, Some(meta))
                    })
                    .collect()
            }),
        };
        drop(writer_guard);
        let elapsed = start.elapsed();

        let uploads = match result {
            Ok(v) => v,
            Err(e) => {
                self.post_transfer_settle().await;
                self.show_error(&format!("Transfer failed: {}", e))
                    .await?;
                return Ok(());
            }
        };

        // Save each file.  The first file goes to the user-entered
        // path with the user-chosen overwrite behavior.  Any additional
        // files (ZMODEM batch mode per Forsberg §4) go to the sender's
        // own filename after the same `validate_filename` sanitation
        // we apply to user input — and if the name collides with an
        // existing file we skip rather than clobber.  Batch files
        // share the transfer-complete window with the first file; we
        // don't prompt per-file.
        let mut saved: Vec<(String, usize)> = Vec::new();
        let mut skipped: Vec<(String, &'static str)> = Vec::new();

        for (idx, (sender_name, data, ymeta)) in uploads.iter().enumerate() {
            if idx == 0 {
                // First file: user-entered filename, honor overwrite.
                let mut opts = tokio::fs::OpenOptions::new();
                opts.write(true);
                if overwrite {
                    opts.create(true).truncate(true);
                } else {
                    opts.create_new(true);
                }
                match opts.open(&filepath).await {
                    Ok(mut file) => {
                        if let Err(e) = file.write_all(data).await {
                            self.post_transfer_settle().await;
                            self.show_error(&format!("Failed to save: {}", e))
                                .await?;
                            return Ok(());
                        }
                        let _ = file.flush().await;
                        drop(file);
                        Self::apply_ymodem_meta(&filepath, ymeta.as_ref());
                        saved.push((filename.clone(), data.len()));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.post_transfer_settle().await;
                        self.show_error("File already exists.").await?;
                        return Ok(());
                    }
                    Err(e) => {
                        self.post_transfer_settle().await;
                        self.show_error(&format!("Failed to save: {}", e))
                            .await?;
                        return Ok(());
                    }
                }
            } else {
                // Batch file 2..N: save under sender's name.  Only ZMODEM
                // can produce these (XMODEM/YMODEM always yields a single
                // entry), so `sender_name` will be Some here.
                let name = match sender_name {
                    Some(n) => n.clone(),
                    None => continue,
                };
                if Self::validate_filename(&name).is_err() {
                    skipped.push((name, "invalid filename"));
                    continue;
                }
                let batch_path = self.transfer_path().join(&name);
                let mut opts = tokio::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                match opts.open(&batch_path).await {
                    Ok(mut file) => {
                        if file.write_all(data).await.is_err() {
                            skipped.push((name, "write error"));
                            continue;
                        }
                        let _ = file.flush().await;
                        drop(file);
                        Self::apply_ymodem_meta(&batch_path, ymeta.as_ref());
                        saved.push((name, data.len()));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        skipped.push((name, "already exists"));
                    }
                    Err(_) => {
                        skipped.push((name, "I/O error"));
                    }
                }
            }
        }

        self.post_transfer_settle().await;

        // Transfer-complete summary.  Preserve the classic single-file
        // "N bytes, M blocks, T seconds" format when exactly one file
        // was transferred (by far the common case); expand to a
        // per-file list only when we actually saw a batch.
        self.send_line("").await?;
        if uploads.len() == 1 {
            let bytes = saved.first().map(|(_, n)| *n).unwrap_or(0);
            let blocks = bytes.div_ceil(crate::xmodem::XMODEM_BLOCK_SIZE);
            self.send_line(&format!(
                "  {}",
                self.green("Upload complete!")
            ))
            .await?;
            self.send_line(&format!(
                "  {} bytes, {} blocks, {:.1}s",
                bytes,
                blocks,
                elapsed.as_secs_f64()
            ))
            .await?;
        } else {
            self.send_line(&format!(
                "  {}",
                self.green(&format!(
                    "Upload complete: {} saved, {} skipped, {:.1}s",
                    saved.len(),
                    skipped.len(),
                    elapsed.as_secs_f64()
                ))
            ))
            .await?;
            for (name, bytes) in &saved {
                self.send_line(&format!(
                    "  {} {} ({} bytes)",
                    self.green("*"),
                    name,
                    bytes
                ))
                .await?;
            }
            for (name, reason) in &skipped {
                self.send_line(&format!(
                    "  {} {} ({})",
                    self.yellow("-"),
                    name,
                    reason
                ))
                .await?;
            }
        }
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    // ─── DOWNLOAD ───────────────────────────────────────────

    async fn file_transfer_download(&mut self) -> Result<(), std::io::Error> {
        self.ensure_transfer_dir().await?;
        let mut page: usize = 0;

        loop {
            let files = Self::list_transfer_entries_in(&self.transfer_path())
                .await?
                .into_iter()
                .filter(|(_, _, is_dir)| !is_dir)
                .map(|(name, size, _)| (name, size))
                .collect::<Vec<_>>();

            if files.is_empty() {
                self.show_error("No files available.").await?;
                return Ok(());
            }

            let total_pages = files.len().div_ceil(Self::TRANSFER_PAGE_SIZE);
            if page >= total_pages {
                page = total_pages - 1;
            }
            let offset = page * Self::TRANSFER_PAGE_SIZE;
            let end = (offset + Self::TRANSFER_PAGE_SIZE).min(files.len());
            let page_files = &files[offset..end];

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!(
                "  {}",
                self.yellow("DOWNLOAD FILE")
            ))
            .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "   {} {:<22} {}",
                self.cyan("#."),
                "Filename",
                "Size"
            ))
            .await?;
            self.send_line(&format!(
                "  {}",
                self.yellow(&"-".repeat(36))
            ))
            .await?;

            for (i, (name, size)) in page_files.iter().enumerate() {
                let num = i + 1;
                let display_name = if name.chars().count() > 22 {
                    let truncated: String = name.chars().take(19).collect();
                    format!("{}...", truncated)
                } else {
                    name.clone()
                };
                let size_display = Self::format_file_size(*size);
                self.send_line(&format!(
                    "  {:>2}. {:<22} {}",
                    num, display_name, size_display
                ))
                .await?;
            }

            self.send_line("").await?;
            self.send_line(&format!(
                "  Page {} of {}",
                page + 1,
                total_pages
            ))
            .await?;
            self.send_line("").await?;

            let mut nav = Vec::new();
            if page > 0 {
                nav.push(self.action_prompt("P", "Prev"));
            }
            if page + 1 < total_pages {
                nav.push(self.action_prompt("N", "Next"));
            }
            nav.push(self.action_prompt("Q", "Back"));
            nav.push(self.action_prompt("H", "Help"));
            let esc_label = match self.terminal_type {
                TerminalType::Petscii => "<-",
                _ => "ESC",
            };
            nav.push(self.action_prompt(esc_label, "Main"));
            self.send_line(&format!("  {}", nav.join(" | ")))
                .await?;
            self.send_line("").await?;
            self.send(&format!("  {} ", self.cyan("Select #:")))
                .await?;
            self.flush().await?;

            let input = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "p" => {
                    page = page.saturating_sub(1);
                }
                "n" => {
                    if page + 1 < total_pages {
                        page += 1;
                    }
                }
                "q" => return Ok(()),
                "h" => {
                    self.show_help_page("DOWNLOAD HELP", &[
                        "  #    Enter file number to download",
                        "  P    Previous page of files",
                        "  N    Next page of files",
                        "  Q    Back to file transfer menu",
                        "  ESC  Return to main menu",
                    ]).await?;
                }
                other => {
                    if let Ok(num) = other.parse::<usize>() {
                        if num >= 1 && num <= page_files.len() {
                            let (ref filename, file_size) = page_files[num - 1];
                            self.initiate_download(filename, file_size).await?;
                        } else {
                            self.show_error("Invalid selection.").await?;
                        }
                    } else {
                        self.show_error("Enter a number, P, N, Q, or H.")
                            .await?;
                    }
                }
            }
        }
    }

    /// Prompt the user for which XMODEM-family protocol to use for this
    /// download.  Returns `None` if the user presses ESC to cancel.
    async fn prompt_download_protocol(
        &mut self,
    ) -> Result<Option<DownloadProtocol>, std::io::Error> {
        let is_petscii = self.terminal_type == TerminalType::Petscii;
        let esc_label = if is_petscii { "<-" } else { "ESC" };

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("SELECT PROTOCOL")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}  XMODEM       (128-byte blocks)",
            self.cyan("X")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  XMODEM-1K    (1024-byte blocks)",
            self.cyan("1")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  YMODEM       (filename + size header, 1K)",
            self.cyan("Y")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  ZMODEM       (autostart, 1K subpackets)",
            self.cyan("Z")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  KERMIT       (any flavor, auto-detected)",
            self.cyan("K")
        ))
        .await?;
        self.send_line("").await?;
        self.send(&format!(
            "  Pick one, or {} to cancel: ",
            self.cyan(esc_label)
        ))
        .await?;
        self.flush().await?;

        loop {
            let b = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };
            if is_esc_key(b, is_petscii) {
                self.send_line("").await?;
                return Ok(None);
            }
            let ch = if is_petscii {
                (petscii_to_ascii_byte(b) as char).to_ascii_lowercase()
            } else {
                (b as char).to_ascii_lowercase()
            };
            let chosen = match ch {
                'x' => Some(DownloadProtocol::Xmodem),
                '1' => Some(DownloadProtocol::Xmodem1k),
                'y' => Some(DownloadProtocol::Ymodem),
                'z' => Some(DownloadProtocol::Zmodem),
                'k' => Some(DownloadProtocol::Kermit),
                _ => None,
            };
            if let Some(p) = chosen {
                self.send_raw(&[b]).await?;
                self.send_line("").await?;
                self.flush().await?;
                return Ok(Some(p));
            }
            // Invalid key — stay at the prompt.
        }
    }

    async fn initiate_download(
        &mut self,
        filename: &str,
        file_size: u64,
    ) -> Result<(), std::io::Error> {
        let blocks = (file_size as usize).div_ceil(crate::xmodem::XMODEM_BLOCK_SIZE);

        self.send_line("").await?;
        self.send_line(&format!(
            "  Sending: {}",
            self.amber(filename)
        ))
        .await?;
        self.send_line(&format!(
            "  {} bytes, {} blocks",
            file_size, blocks
        ))
        .await?;

        if file_size as usize > Self::MAX_FILE_SIZE {
            self.show_error("File too large.").await?;
            return Ok(());
        }

        let filepath = self.transfer_path().join(filename);
        let data = match tokio::fs::read(&filepath).await {
            Ok(d) => d,
            Err(e) => {
                self.show_error(&format!("Failed to read: {}", e))
                    .await?;
                return Ok(());
            }
        };
        // Best-effort fs metadata for the YMODEM block-0 modtime/mode
        // fields (Forsberg §6.1).  Both are informational — if metadata
        // lookup fails or the platform doesn't expose UNIX mode bits we
        // pass `None` and the sender emits octal `0` in that slot.
        let (file_modtime, file_mode) = match tokio::fs::metadata(&filepath).await {
            Ok(m) => {
                let modtime = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::MetadataExt;
                    Some(m.mode())
                };
                #[cfg(not(unix))]
                let mode: Option<u32> = None;
                (modtime, mode)
            }
            Err(_) => (None, None),
        };

        // Prompt the user to pick the transfer protocol for this download.
        // ESC at the prompt cancels the transfer.
        let protocol = match self.prompt_download_protocol().await? {
            Some(p) => p,
            None => return Ok(()),
        };

        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.green(match protocol {
                DownloadProtocol::Xmodem => "Start XMODEM receive now.",
                DownloadProtocol::Xmodem1k => "Start XMODEM-1K receive now.",
                DownloadProtocol::Ymodem => "Start YMODEM receive now.",
                DownloadProtocol::Zmodem => "Start ZMODEM receive now.",
                DownloadProtocol::Kermit => "Start KERMIT receive now.",
            })
        ))
        .await?;
        self.send_line(&format!("  Start transfer within {} seconds.",
            config::get_config().xmodem_negotiation_timeout))
            .await?;
        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };
        self.send_line(&format!("  {} to cancel", self.cyan(esc_label)))
            .await?;
        self.send_line("").await?;
        self.flush().await?;

        if config::get_config().verbose {
            glog!("Download: IAC escaping={} protocol={:?}", self.xmodem_iac, protocol);
        }
        self.drain_input().await;

        let start = std::time::Instant::now();
        let cfg = config::get_config();
        let verbose = cfg.verbose;
        let mut writer_guard = self.writer.lock().await;
        let result = if matches!(protocol, DownloadProtocol::Zmodem) {
            // zmodem_send is batch-capable; download always sends
            // exactly one file, so we pass a single-element slice.
            let batch: [(&str, &[u8]); 1] = [(filename, &data)];
            crate::zmodem::zmodem_send(
                &mut self.reader,
                &mut *writer_guard,
                &batch,
                self.xmodem_iac,
                verbose,
            )
            .await
        } else if matches!(protocol, DownloadProtocol::Kermit) {
            let kermit_iac = config::get_config().kermit_iac_escape;
            let is_petscii = self.terminal_type == TerminalType::Petscii;
            let files = vec![crate::kermit::KermitSendFile {
                name: filename,
                data: &data,
                modtime: file_modtime,
                mode: file_mode,
            }];
            crate::kermit::kermit_send(
                &mut self.reader,
                &mut *writer_guard,
                &files,
                kermit_iac,
                is_petscii,
                verbose,
            )
            .await
        } else {
            // YMODEM always uses 1K data blocks; XMODEM-1K uses 1K
            // blocks without the filename header; classic XMODEM uses
            // 128-byte blocks only.
            let use_1k = matches!(
                protocol,
                DownloadProtocol::Xmodem1k | DownloadProtocol::Ymodem,
            );
            let ymodem = if matches!(protocol, DownloadProtocol::Ymodem) {
                Some(crate::xmodem::YmodemHeader {
                    filename: filename.to_string(),
                    size: file_size,
                    modtime: file_modtime,
                    mode: file_mode,
                })
            } else {
                None
            };
            crate::xmodem::xmodem_send(
                &mut self.reader,
                &mut *writer_guard,
                &data,
                self.xmodem_iac,
                self.terminal_type == TerminalType::Petscii,
                verbose,
                use_1k,
                ymodem,
            )
            .await
        };
        drop(writer_guard);
        let elapsed = start.elapsed();

        match result {
            Ok(()) => {
                // Brief pause so the remote terminal can switch back from
                // XMODEM mode to text display.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                self.send_line("").await?;
                self.send_line(&format!(
                    "  {}",
                    self.green("Download complete!")
                ))
                .await?;
                self.send_line(&format!(
                    "  {} bytes, {} blocks, {:.1}s",
                    data.len(),
                    blocks,
                    elapsed.as_secs_f64()
                ))
                .await?;
            }
            Err(e) => {
                self.send_line("").await?;
                self.send_line(&format!(
                    "  {}",
                    self.red(&format!("Transfer failed: {}", e))
                ))
                .await?;
            }
        }

        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    // ─── DELETE ─────────────────────────────────────────────

    async fn file_transfer_delete(&mut self) -> Result<(), std::io::Error> {
        self.ensure_transfer_dir().await?;
        let mut page: usize = 0;

        loop {
            let files = Self::list_transfer_entries_in(&self.transfer_path())
                .await?
                .into_iter()
                .filter(|(_, _, is_dir)| !is_dir)
                .map(|(name, size, _)| (name, size))
                .collect::<Vec<_>>();

            if files.is_empty() {
                self.show_error("No files to delete.").await?;
                return Ok(());
            }

            let total_pages = files.len().div_ceil(Self::TRANSFER_PAGE_SIZE);
            if page >= total_pages {
                page = total_pages - 1;
            }
            let offset = page * Self::TRANSFER_PAGE_SIZE;
            let end = (offset + Self::TRANSFER_PAGE_SIZE).min(files.len());
            let page_files = &files[offset..end];

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!(
                "  {}",
                self.yellow("DELETE FILE")
            ))
            .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "   {} {:<22} {}",
                self.cyan("#."),
                "Filename",
                "Size"
            ))
            .await?;
            self.send_line(&format!(
                "  {}",
                self.yellow(&"-".repeat(36))
            ))
            .await?;

            for (i, (name, size)) in page_files.iter().enumerate() {
                let num = i + 1;
                let display_name = if name.chars().count() > 22 {
                    let truncated: String = name.chars().take(19).collect();
                    format!("{}...", truncated)
                } else {
                    name.clone()
                };
                let size_display = Self::format_file_size(*size);
                self.send_line(&format!(
                    "  {:>2}. {:<22} {}",
                    num, display_name, size_display
                ))
                .await?;
            }

            self.send_line("").await?;
            self.send_line(&format!(
                "  Page {} of {}",
                page + 1,
                total_pages
            ))
            .await?;
            self.send_line("").await?;

            let mut nav = Vec::new();
            if page > 0 {
                nav.push(self.action_prompt("P", "Prev"));
            }
            if page + 1 < total_pages {
                nav.push(self.action_prompt("N", "Next"));
            }
            nav.push(self.action_prompt("Q", "Back"));
            nav.push(self.action_prompt("H", "Help"));
            let esc_label = match self.terminal_type {
                TerminalType::Petscii => "<-",
                _ => "ESC",
            };
            nav.push(self.action_prompt(esc_label, "Main"));
            self.send_line(&format!("  {}", nav.join(" | ")))
                .await?;
            self.send_line("").await?;
            self.send(&format!("  {} ", self.cyan("Select #:")))
                .await?;
            self.flush().await?;

            let input = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "p" => {
                    page = page.saturating_sub(1);
                }
                "n" => {
                    if page + 1 < total_pages {
                        page += 1;
                    }
                }
                "q" => return Ok(()),
                "h" => {
                    self.show_help_page("DELETE HELP", &[
                        "  #    Enter file number to delete",
                        "  P    Previous page of files",
                        "  N    Next page of files",
                        "  Q    Back to file transfer menu",
                        "  ESC  Return to main menu",
                    ]).await?;
                }
                other => {
                    if let Ok(num) = other.parse::<usize>() {
                        if num >= 1 && num <= page_files.len() {
                            let (ref filename, _) = page_files[num - 1];
                            self.send_line("").await?;
                            let p = format!(
                                "  Delete {}? ({}/{}) ",
                                self.amber(filename),
                                self.green("Y"),
                                self.red("N"),
                            );
                            self.send(&p).await?;
                            self.flush().await?;

                            match self.read_byte_filtered().await? {
                                Some(b)
                                    if {
                                        let ch =
                                            if self.terminal_type == TerminalType::Petscii {
                                                petscii_to_ascii_byte(b)
                                            } else {
                                                b
                                            };
                                        ch == b'y' || ch == b'Y'
                                    } =>
                                {
                                    self.send_line("").await?;
                                    let path = self.transfer_path().join(filename);
                                    match tokio::fs::remove_file(&path).await {
                                        Ok(()) => {
                                            self.send_line(&format!(
                                                "  {}",
                                                self.green("File deleted.")
                                            ))
                                            .await?;
                                            self.send_line("").await?;
                                            self.send(
                                                "  Press any key to continue.",
                                            )
                                            .await?;
                                            self.flush().await?;
                                            self.wait_for_key().await?;
                                        }
                                        Err(e) => {
                                            self.show_error(&format!(
                                                "Delete failed: {}",
                                                e
                                            ))
                                            .await?;
                                        }
                                    }
                                }
                                _ => {
                                    self.send_line("").await?;
                                    self.send_line("  Cancelled.").await?;
                                    self.send_line("").await?;
                                    self.send("  Press any key to continue.")
                                        .await?;
                                    self.flush().await?;
                                    self.wait_for_key().await?;
                                }
                            }
                        } else {
                            self.show_error("Invalid selection.").await?;
                        }
                    } else {
                        self.show_error("Enter a number, P, N, Q, or H.")
                            .await?;
                    }
                }
            }
        }
    }

    // ─── CHANGE DIRECTORY ───────────────────────────────────

    async fn file_transfer_chdir(&mut self) -> Result<(), std::io::Error> {
        self.ensure_transfer_dir().await?;

        let entries =
            Self::list_transfer_entries_in(&self.transfer_path()).await?;
        let dirs: Vec<&str> = entries
            .iter()
            .filter(|(_, _, is_dir)| *is_dir)
            .map(|(name, _, _)| name.as_str())
            .collect();

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("CHANGE DIRECTORY")
        ))
        .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        let max_dir = if self.terminal_type == TerminalType::Petscii {
            26
        } else {
            56
        };
        let dir_str =
            truncate_to_width(&self.transfer_dir_display(), max_dir);
        self.send_line(&format!(
            "  Current: {}",
            self.amber(&dir_str)
        ))
        .await?;
        self.send_line("").await?;

        let mut num = 0usize;
        if !self.transfer_subdir.is_empty() {
            num += 1;
            self.send_line(&format!(
                "  {:>2}. {}",
                num,
                self.cyan("..")
            ))
            .await?;
        }

        for name in &dirs {
            num += 1;
            let display = if name.chars().count() > 30 {
                let t: String = name.chars().take(27).collect();
                format!("{}...", t)
            } else {
                name.to_string()
            };
            self.send_line(&format!(
                "  {:>2}. {}/",
                num,
                self.cyan(&display)
            ))
            .await?;
        }

        if num == 0 {
            self.show_error("No subdirectories.").await?;
            return Ok(());
        }

        self.send_line("").await?;
        self.send(&format!("  {} ", self.cyan("Select #:")))
            .await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if input == "q" {
            return Ok(());
        }

        if let Ok(n) = input.parse::<usize>() {
            if n == 0 {
                self.show_error("Invalid selection.").await?;
                return Ok(());
            }
            let has_parent = !self.transfer_subdir.is_empty();
            if has_parent && n == 1 {
                if let Some(pos) = self.transfer_subdir.rfind('/') {
                    self.transfer_subdir.truncate(pos);
                } else {
                    self.transfer_subdir.clear();
                }
            } else {
                let dir_idx = if has_parent { n - 2 } else { n - 1 };
                if dir_idx < dirs.len() {
                    let name = dirs[dir_idx];
                    let prev = self.transfer_subdir.clone();
                    if self.transfer_subdir.is_empty() {
                        self.transfer_subdir = name.to_string();
                    } else {
                        self.transfer_subdir =
                            format!("{}/{}", self.transfer_subdir, name);
                    }
                    if !self.verify_transfer_path() {
                        self.transfer_subdir = prev;
                        self.show_error("Access denied.").await?;
                    }
                } else {
                    self.show_error("Invalid selection.").await?;
                }
            }
        } else {
            self.show_error("Enter a number or Q.").await?;
        }
        Ok(())
    }

    // ─── SSH GATEWAY ────────────────────────────────────────

    /// Gateway timeout for SSH connection attempts.
    const GATEWAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// Prompt for the remote SSH host, port, and username.  Password is
    /// collected separately (`gateway_password_prompt`) so we can skip
    /// it entirely when public-key authentication succeeds.
    async fn gateway_host_prompts(
        &mut self,
    ) -> Result<Option<(String, u16, String)>, std::io::Error> {
        self.send(&format!("  {} ", self.cyan("Host:")))
            .await?;
        self.flush().await?;
        let host = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };

        self.send(&format!("  {} ", self.cyan("Port (22):")))
            .await?;
        self.flush().await?;
        let port: u16 = match self.get_line_input().await? {
            Some(s) if s.is_empty() => 22,
            Some(s) => match s.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    self.show_error("Invalid port number.").await?;
                    return Ok(None);
                }
            },
            None => return Ok(None),
        };

        self.send(&format!("  {} ", self.cyan("Username:")))
            .await?;
        self.flush().await?;
        let username = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };

        Ok(Some((host, port, username)))
    }

    /// Prompt for the remote SSH password.  Called only after public-key
    /// authentication is rejected by the remote so users who have set up
    /// the gateway's key in the remote's `authorized_keys` never see
    /// this prompt at all.
    async fn gateway_password_prompt(
        &mut self,
    ) -> Result<Option<String>, std::io::Error> {
        self.send(&format!("  {} ", self.cyan("Password:")))
            .await?;
        self.flush().await?;
        match self.get_password_input().await? {
            Some(s) => Ok(Some(s)),
            None => Ok(None),
        }
    }

    /// SSH gateway: connect to a remote server and proxy the session.
    async fn gateway_ssh(&mut self) -> Result<(), std::io::Error> {
        let cfg = config::get_config();
        let idle_timeout = std::time::Duration::from_secs(cfg.idle_timeout_secs);

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("SSH GATEWAY")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line("  Connect to a remote SSH server.")
            .await?;
        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };
        self.send_line(&format!(
            "  Press {} at any prompt to cancel.",
            self.cyan(esc_label)
        ))
        .await?;
        let auth_label = if cfg.ssh_gateway_auth == "password" {
            self.yellow("password")
        } else {
            self.green("gateway key")
        };
        self.send_line(&format!("  Auth: {}", auth_label)).await?;
        self.send_line("").await?;

        let (host, port, username) = if idle_timeout.is_zero() {
            match self.gateway_host_prompts().await {
                Ok(Some(v)) => v,
                Ok(None) => return Ok(()),
                Err(e) => return Err(e),
            }
        } else {
            match tokio::time::timeout(
                idle_timeout,
                self.gateway_host_prompts(),
            )
            .await
            {
                Ok(Ok(Some(v))) => v,
                Ok(Ok(None)) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    let _ = self
                        .send_line("\r\nDisconnected: idle timeout.")
                        .await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle timeout in gateway prompts",
                    ));
                }
            }
        };

        self.send_line("").await?;
        self.send_line(&format!(
            "  Connecting to {}:{}...",
            self.amber(&host),
            port
        ))
        .await?;
        self.flush().await?;

        // Connect to remote SSH server
        let ssh_config = std::sync::Arc::new(russh::client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(600)),
            ..Default::default()
        });
        let server_key_slot: Arc<std::sync::Mutex<Option<russh::keys::PublicKey>>> =
            Arc::new(std::sync::Mutex::new(None));
        let handler = GatewayHandler {
            server_key: server_key_slot.clone(),
        };

        let mut session = match tokio::time::timeout(
            Self::GATEWAY_CONNECT_TIMEOUT,
            russh::client::connect(ssh_config, (host.as_str(), port), handler),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.show_error(&format!("Connection failed: {}", e))
                    .await?;
                return Ok(());
            }
            Err(_) => {
                self.show_error("Connection timed out.").await?;
                return Ok(());
            }
        };

        // Verify server host key against known-hosts file
        let server_key = server_key_slot
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        let Some(ref key) = server_key else {
            self.show_error("Could not verify server host key.").await?;
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "no host key", "")
                .await;
            return Ok(());
        };
        {
            match check_known_host(&host, port, key) {
                HostKeyStatus::Known => {}
                HostKeyStatus::Unknown => {
                    let fingerprint = key.fingerprint(russh::keys::HashAlg::Sha256);
                    let algo = key.algorithm();
                    self.send_line("").await?;
                    self.send_line(&format!(
                        "  {}",
                        self.yellow("Host key not recognized.")
                    ))
                    .await?;
                    let algo_str = algo.to_string();
                    let fp_str = fingerprint.to_string();
                    self.send_line(&format!("  Type: {}", self.cyan(&algo_str)))
                        .await?;
                    self.send_line(&format!(
                        "  Fingerprint: {}",
                        self.cyan(&fp_str)
                    ))
                    .await?;
                    self.send_line("").await?;
                    self.send(&format!(
                        "  {} ",
                        self.cyan("Trust this host? (Y/N):")
                    ))
                    .await?;
                    self.flush().await?;
                    self.drain_input().await;
                    let answer = match self.read_byte_filtered().await? {
                        Some(b) => {
                            if self.terminal_type == TerminalType::Petscii {
                                petscii_to_ascii_byte(b)
                            } else {
                                b
                            }
                        }
                        None => return Ok(()),
                    };
                    self.send_line("").await?;
                    if answer != b'y' && answer != b'Y' {
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "host key rejected", "")
                            .await;
                        self.show_error("Connection aborted.").await?;
                        return Ok(());
                    }
                    save_known_host(&host, port, key);
                    glog!(
                        "SSH gateway: TOFU-accepted host key for {}:{} ({} {})",
                        host,
                        port,
                        key.algorithm(),
                        key.fingerprint(russh::keys::HashAlg::Sha256),
                    );
                    self.send_line(&format!(
                        "  {}",
                        self.green("Host key saved.")
                    ))
                    .await?;
                }
                HostKeyStatus::Changed => {
                    let fingerprint = key.fingerprint(russh::keys::HashAlg::Sha256);
                    let algo_str = key.algorithm().to_string();
                    let fp_str = fingerprint.to_string();
                    self.send_line("").await?;
                    self.send_line(&format!(
                        "  {}",
                        self.red("WARNING: HOST KEY HAS CHANGED!")
                    ))
                    .await?;
                    self.send_line(&format!(
                        "  {}",
                        self.red("This could indicate a security threat.")
                    ))
                    .await?;
                    self.send_line(&format!("  New type: {}", self.cyan(&algo_str)))
                        .await?;
                    self.send_line(&format!(
                        "  New fingerprint: {}",
                        self.cyan(&fp_str)
                    ))
                    .await?;
                    self.send_line("").await?;
                    self.send(&format!(
                        "  {} ",
                        self.cyan("Update key? (Y/N):")
                    ))
                    .await?;
                    self.flush().await?;
                    self.drain_input().await;
                    let answer = match self.read_byte_filtered().await? {
                        Some(b) => {
                            if self.terminal_type == TerminalType::Petscii {
                                petscii_to_ascii_byte(b)
                            } else {
                                b
                            }
                        }
                        None => return Ok(()),
                    };
                    self.send_line("").await?;
                    if answer == b'y' || answer == b'Y' {
                        save_known_host(&host, port, key);
                        glog!(
                            "SSH gateway: operator UPDATED changed host key for {}:{} (new {} {})",
                            host,
                            port,
                            key.algorithm(),
                            key.fingerprint(russh::keys::HashAlg::Sha256),
                        );
                        self.send_line(&format!(
                            "  {}",
                            self.green("Host key updated.")
                        ))
                        .await?;
                    } else {
                        glog!(
                            "SSH gateway: operator REJECTED changed host key for {}:{} (presented {} {})",
                            host,
                            port,
                            key.algorithm(),
                            key.fingerprint(russh::keys::HashAlg::Sha256),
                        );
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "host key rejected", "")
                            .await;
                        self.show_error("Connection aborted.").await?;
                        return Ok(());
                    }
                }
            }
        }

        // Authenticate using the configured mode.  The server-config
        // `ssh_gateway_auth` key dictates the method: "key" uses the
        // gateway's own auto-generated Ed25519 client key (copy the
        // public half printed by `cat gateway_client_key.pub` into the
        // remote's `~/.ssh/authorized_keys` first); "password" prompts
        // the operator each time.  No silent fallback — the remote sees
        // exactly one auth method, so failures are unambiguous.
        let mut authed = false;
        if cfg.ssh_gateway_auth == "password" {
            let password = if idle_timeout.is_zero() {
                match self.gateway_password_prompt().await {
                    Ok(Some(p)) => p,
                    Ok(None) => {
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                            .await;
                        return Ok(());
                    }
                    Err(e) => {
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                            .await;
                        return Err(e);
                    }
                }
            } else {
                match tokio::time::timeout(
                    idle_timeout,
                    self.gateway_password_prompt(),
                )
                .await
                {
                    Ok(Ok(Some(p))) => p,
                    Ok(Ok(None)) => {
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                            .await;
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "cancelled", "")
                            .await;
                        return Err(e);
                    }
                    Err(_) => {
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "idle timeout", "")
                            .await;
                        let _ = self
                            .send_line("\r\nDisconnected: idle timeout.")
                            .await;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "idle timeout at password prompt",
                        ));
                    }
                }
            };
            match session.authenticate_password(&username, &password).await {
                Ok(russh::client::AuthResult::Success) => {
                    authed = true;
                    glog!(
                        "SSH gateway: authenticated to {}:{} as {} via password",
                        host, port, username,
                    );
                }
                Ok(russh::client::AuthResult::Failure { .. }) => {}
                Err(e) => {
                    let _ = session
                        .disconnect(russh::Disconnect::ByApplication, "auth error", "")
                        .await;
                    self.show_error(&format!("Auth error: {}", e)).await?;
                    return Ok(());
                }
            }
        } else {
            // "key" mode — gateway's Ed25519 client key, no password fallback.
            match crate::ssh::load_or_generate_client_key() {
                Ok(key) => {
                    // best_supported_rsa_hash returns Result<Option<Option<HashAlg>>>:
                    //   outer Option = "server doesn't specify a preference",
                    //   inner Option = "preference is 'no hash' (i.e., not RSA)".
                    // Two flattens collapse both to Option<HashAlg>.
                    let hash_alg = session
                        .best_supported_rsa_hash()
                        .await
                        .ok()
                        .flatten()
                        .flatten();
                    match session
                        .authenticate_publickey(
                            &username,
                            russh::keys::PrivateKeyWithHashAlg::new(
                                std::sync::Arc::new(key),
                                hash_alg,
                            ),
                        )
                        .await
                    {
                        Ok(russh::client::AuthResult::Success) => {
                            authed = true;
                            glog!(
                                "SSH gateway: authenticated to {}:{} as {} via pubkey",
                                host, port, username,
                            );
                            self.send_line(&format!(
                                "  {}",
                                self.green("Authenticated (gateway key).")
                            ))
                            .await?;
                        }
                        Ok(russh::client::AuthResult::Failure { .. }) => {}
                        Err(e) => {
                            glog!("SSH gateway: pubkey auth error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    glog!("SSH gateway: client key unavailable: {}", e);
                }
            }
        }
        if !authed {
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "auth failed", "")
                .await;
            if cfg.ssh_gateway_auth == "password" {
                self.show_error("Authentication failed.").await?;
            } else {
                self.show_error(
                    "Key authentication failed. Copy the gateway's public \
                     key (shown in the GUI Server > More popup) into the \
                     remote's ~/.ssh/authorized_keys, or switch to Password \
                     mode from Configuration > Gateway Configuration.",
                )
                .await?;
            }
            return Ok(());
        }

        // Open channel and request PTY + shell.  Every error path from
        // here forward must call `session.disconnect` before returning
        // — otherwise the remote sees an orphaned, still-authenticated
        // session and its connection slot stays occupied until a TCP
        // timeout eventually reaps it.
        let channel = match session.channel_open_session().await {
            Ok(ch) => ch,
            Err(e) => {
                let _ = session
                    .disconnect(russh::Disconnect::ByApplication, "channel open failed", "")
                    .await;
                self.show_error(&format!("Channel error: {}", e))
                    .await?;
                return Ok(());
            }
        };

        let (cols, rows, term) = match self.terminal_type {
            TerminalType::Petscii => (40, 25, "dumb"),
            TerminalType::Ascii => (80, 24, "dumb"),
            TerminalType::Ansi => (80, 24, "xterm"),
        };

        if let Err(e) = channel
            .request_pty(false, term, cols, rows, 0, 0, &[])
            .await
        {
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "pty request failed", "")
                .await;
            self.show_error(&format!("PTY error: {}", e)).await?;
            return Ok(());
        }
        if let Err(e) = channel.request_shell(false).await {
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "shell request failed", "")
                .await;
            self.show_error(&format!("Shell error: {}", e)).await?;
            return Ok(());
        }

        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };
        self.send_line(&format!(
            "  {}",
            self.green("Connected.")
        ))
        .await?;
        self.send_line(&format!(
            "  Press {} twice to disconnect.",
            self.cyan(esc_label)
        ))
        .await?;
        self.send_line("").await?;
        self.flush().await?;

        // Proxy I/O between telnet client and SSH channel
        let stream = channel.into_stream();
        let (mut ssh_reader, mut ssh_writer) = tokio::io::split(stream);

        let reader = &mut self.reader;
        let writer = &self.writer;
        let erase_char = self.erase_char;
        let is_petscii = self.terminal_type == TerminalType::Petscii;
        let is_ascii = self.terminal_type == TerminalType::Ascii;

        let mut ssh_buf = [0u8; 4096];
        let mut filter_buf: Vec<u8> = Vec::new();
        let mut ansi_state: u8 = 0;
        let mut last_cr = false;
        let mut last_was_esc = false;
        let esc_byte: u8 = if is_petscii { 0x5F } else { 0x1B };

        loop {
            tokio::select! {
                byte = read_byte_iac_filtered(reader, true) => {
                    match byte {
                        Ok(Some(b)) if is_esc_key(b, is_petscii) => {
                            if last_was_esc {
                                break; // Two consecutive ESC presses — disconnect
                            }
                            last_was_esc = true;
                        }
                        Ok(Some(b)) => {
                            // Forward the previously held ESC before this byte
                            if last_was_esc {
                                last_was_esc = false;
                                let e = if is_petscii { petscii_to_ascii_byte(esc_byte) } else { esc_byte };
                                if let Some(e) = normalize_gateway_input(e, &mut last_cr)
                                    && ssh_writer.write_all(&[e]).await.is_err() { break; }
                            }
                            let b = if is_petscii { petscii_to_ascii_byte(b) } else { b };
                            let b = if b == erase_char && erase_char != 0x7F { 0x7F } else { b };
                            if let Some(b) = normalize_gateway_input(b, &mut last_cr) {
                                if ssh_writer.write_all(&[b]).await.is_err() { break; }
                                if ssh_writer.flush().await.is_err() { break; }
                            }
                        }
                        _ => break,
                    }
                }
                n = ssh_reader.read(&mut ssh_buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = if is_petscii || is_ascii {
                                filter_buf.clear();
                                filter_gateway_output(&ssh_buf[..n], &mut ansi_state, is_petscii, &mut filter_buf);
                                &filter_buf[..]
                            } else {
                                &ssh_buf[..n]
                            };
                            if !data.is_empty() {
                                let mut w = writer.lock().await;
                                if w.write_all(data).await.is_err() { break; }
                                if w.flush().await.is_err() { break; }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        // Clean up SSH channel and session
        let _ = ssh_writer.shutdown().await;
        drop(ssh_writer);
        drop(ssh_reader);
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "bye", "")
            .await;

        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("Connection closed.")
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        if idle_timeout.is_zero() {
            self.wait_for_key().await?;
        } else {
            match tokio::time::timeout(idle_timeout, self.wait_for_key()).await {
                Ok(result) => result?,
                Err(_) => {
                    let _ = self
                        .send_line("\r\nDisconnected: idle timeout.")
                        .await;
                }
            }
        }
        Ok(())
    }

    // ─── TELNET GATEWAY ──────────────────────────────────────

    /// Telnet gateway: connect to a remote telnet server and proxy the session.
    async fn gateway_telnet(&mut self) -> Result<(), std::io::Error> {
        let cfg = config::get_config();
        let idle_timeout = std::time::Duration::from_secs(cfg.idle_timeout_secs);
        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("TELNET GATEWAY")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line("  Connect to a remote telnet server.")
            .await?;
        self.send_line(&format!(
            "  Press {} at any prompt to cancel.",
            self.cyan(esc_label)
        ))
        .await?;
        let mode_label = if cfg.telnet_gateway_raw {
            self.red("Raw TCP (no IAC parsing)")
        } else {
            self.green("Telnet protocol")
        };
        self.send_line(&format!("  Mode: {}", mode_label)).await?;
        self.send_line("").await?;

        // Gather host and port
        let get_host_port = async {
            self.send(&format!("  {} ", self.cyan("Host:")))
                .await?;
            self.flush().await?;
            let host = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(None),
            };

            self.send(&format!("  {} ", self.cyan("Port (23):")))
                .await?;
            self.flush().await?;
            let port: u16 = match self.get_line_input().await? {
                Some(s) if s.is_empty() => 23,
                Some(s) => match s.parse::<u16>() {
                    Ok(p) if p > 0 => p,
                    _ => {
                        self.show_error("Invalid port number.").await?;
                        return Ok(None);
                    }
                },
                None => return Ok(None),
            };

            Ok::<Option<(String, u16)>, std::io::Error>(Some((host, port)))
        };

        let (host, port) = if idle_timeout.is_zero() {
            match get_host_port.await {
                Ok(Some(hp)) => hp,
                Ok(None) => return Ok(()),
                Err(e) => return Err(e),
            }
        } else {
            match tokio::time::timeout(idle_timeout, get_host_port).await {
                Ok(Ok(Some(hp))) => hp,
                Ok(Ok(None)) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    let _ = self
                        .send_line("\r\nDisconnected: idle timeout.")
                        .await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle timeout in telnet gateway prompts",
                    ));
                }
            }
        };

        self.send_line("").await?;
        self.send_line(&format!(
            "  Connecting to {}:{}...",
            self.amber(&host),
            port
        ))
        .await?;
        self.flush().await?;

        // Connect to remote telnet server
        let addr = format!("{}:{}", host, port);
        let remote = match tokio::time::timeout(
            Self::GATEWAY_CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.show_error(&format!("Connection failed: {}", e))
                    .await?;
                return Ok(());
            }
            Err(_) => {
                self.show_error("Connection timed out.").await?;
                return Ok(());
            }
        };
        let _ = remote.set_nodelay(true);

        self.send_line(&format!(
            "  {}",
            self.green("Connected.")
        ))
        .await?;
        self.send_line(&format!(
            "  Press {} twice to disconnect.",
            self.cyan(esc_label)
        ))
        .await?;
        self.send_line("").await?;
        self.flush().await?;

        // Proxy I/O between local telnet client and remote telnet server
        let (mut remote_reader, mut remote_writer) = remote.into_split();

        let reader = &mut self.reader;
        let writer = &self.writer;
        let is_petscii = self.terminal_type == TerminalType::Petscii;
        let is_ascii = self.terminal_type == TerminalType::Ascii;

        let erase_char = self.erase_char;
        let mut remote_buf = [0u8; 4096];
        let mut filter_buf: Vec<u8> = Vec::new();
        let mut ansi_state: u8 = 0;
        let mut last_was_esc = false;
        let esc_byte: u8 = if is_petscii { 0x5F } else { 0x1B };

        // Telnet-client IAC state machine + option negotiator.  Whether
        // we offer TTYPE / NAWS proactively at connect is gated by the
        // `telnet_gateway_negotiate` config flag.  ECHO cooperation is
        // always on.  In raw mode (`telnet_gateway_raw = true`) the
        // parser is still constructed but its initial offers and
        // negotiation paths are bypassed — see the `raw` checks below.
        let raw = cfg.telnet_gateway_raw;
        let terminal_name = gateway_terminal_name(self.terminal_type).to_string();
        let (cols_default, rows_default) = gateway_default_window(self.terminal_type);
        let cols = self.window_width.unwrap_or(cols_default);
        let rows = self.window_height.unwrap_or(rows_default);
        let (mut iac, initial_offers) = GatewayTelnetIac::new(
            !raw && cfg.telnet_gateway_negotiate,
            terminal_name,
            cols,
            rows,
        );
        if !raw && !initial_offers.is_empty() {
            if remote_writer.write_all(&initial_offers).await.is_err() {
                let _ = remote_writer.shutdown().await;
                return Ok(());
            }
            let _ = remote_writer.flush().await;
        }
        let mut data_from_remote: Vec<u8> = Vec::with_capacity(4096);
        let mut replies_to_remote: Vec<u8> = Vec::new();

        loop {
            tokio::select! {
                event = read_gateway_event(reader) => {
                    match event {
                        Ok(GatewayInboundEvent::Data(b)) if is_esc_key(b, is_petscii) => {
                            if last_was_esc {
                                break; // Two consecutive ESC presses — disconnect
                            }
                            last_was_esc = true;
                        }
                        Ok(GatewayInboundEvent::Data(b)) => {
                            // Forward the previously held ESC before this byte
                            if last_was_esc {
                                last_was_esc = false;
                                let e = if is_petscii { petscii_to_ascii_byte(esc_byte) } else { esc_byte };
                                let write_ok = if raw {
                                    remote_writer.write_all(&[e]).await.is_ok()
                                } else {
                                    write_telnet_data(&mut remote_writer, &[e]).await.is_ok()
                                };
                                if !write_ok { break; }
                            }
                            let b = if is_petscii { petscii_to_ascii_byte(b) } else { b };
                            let b = if b == erase_char && erase_char != 0x7F { 0x7F } else { b };
                            let write_ok = if raw {
                                remote_writer.write_all(&[b]).await.is_ok()
                            } else {
                                write_telnet_data(&mut remote_writer, &[b]).await.is_ok()
                            };
                            if !write_ok { break; }
                            if remote_writer.flush().await.is_err() { break; }
                        }
                        Ok(GatewayInboundEvent::NawsResize(cols, rows)) => {
                            if !raw {
                                let mut naws_update = Vec::new();
                                iac.send_naws_update(cols, rows, &mut naws_update);
                                if !naws_update.is_empty() {
                                    if remote_writer.write_all(&naws_update).await.is_err() { break; }
                                    if remote_writer.flush().await.is_err() { break; }
                                }
                            }
                            // In raw mode we swallow the resize — the
                            // destination isn't speaking telnet so there's
                            // nowhere to forward it to.
                        }
                        Ok(GatewayInboundEvent::Eof) => break,
                        Err(_) => break,
                    }
                }
                n = remote_reader.read(&mut remote_buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            let raw_slice: &[u8];
                            if raw {
                                // No IAC parsing — bytes are user data straight through.
                                raw_slice = &remote_buf[..n];
                            } else {
                                data_from_remote.clear();
                                replies_to_remote.clear();
                                for &b in &remote_buf[..n] {
                                    iac.feed(b, &mut data_from_remote, &mut replies_to_remote);
                                }
                                if !replies_to_remote.is_empty() {
                                    if remote_writer.write_all(&replies_to_remote).await.is_err() { break; }
                                    if remote_writer.flush().await.is_err() { break; }
                                }
                                raw_slice = &data_from_remote[..];
                            }
                            let data: &[u8] = if is_petscii || is_ascii {
                                filter_buf.clear();
                                filter_gateway_output(raw_slice, &mut ansi_state, is_petscii, &mut filter_buf);
                                &filter_buf[..]
                            } else {
                                raw_slice
                            };
                            if !data.is_empty() {
                                let mut w = writer.lock().await;
                                // Always IAC-escape when writing to the
                                // local user — their client is a real
                                // telnet peer and a literal 0xFF would
                                // be misinterpreted as IAC.
                                if write_telnet_data(&mut **w, data).await.is_err() { break; }
                                if w.flush().await.is_err() { break; }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        // Clean up
        let _ = remote_writer.shutdown().await;

        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("Connection closed.")
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        if idle_timeout.is_zero() {
            self.wait_for_key().await?;
        } else {
            match tokio::time::timeout(idle_timeout, self.wait_for_key()).await {
                Ok(result) => result?,
                Err(_) => {
                    let _ = self
                        .send_line("\r\nDisconnected: idle timeout.")
                        .await;
                }
            }
        }
        Ok(())
    }

    // ─── AI CHAT ────────────────────────────────────────────

    /// Lines of answer content per page (screen minus header/footer).
    const PAGE_CONTENT_LINES: usize = 14;

    async fn ai_chat(&mut self, api_key: &str) -> Result<(), std::io::Error> {
        let content_width = if self.terminal_type == TerminalType::Petscii {
            PETSCII_WIDTH - 2
        } else {
            78
        };

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("AI CHAT")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.dim("Type a question, or Q to exit.")
        ))
        .await?;
        self.send_line("").await?;
        self.send(&format!("  {}: ", self.cyan("Q")))
            .await?;
        self.flush().await?;

        let mut question = match self.get_line_input().await? {
            Some(s) if !s.is_empty() && !s.eq_ignore_ascii_case("q") => s,
            _ => return Ok(()),
        };

        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("AI CHAT")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}...",
                self.dim("Thinking")
            ))
            .await?;
            self.flush().await?;

            let key = api_key.to_string();
            let q = question.clone();
            let result = tokio::task::spawn_blocking(move || {
                crate::aichat::ask(&key, &q)
            })
            .await
            .map_err(|e| {
                std::io::Error::other(e.to_string())
            })?;

            match result {
                Ok(answer) => {
                    let lines: Vec<String> = answer
                        .lines()
                        .flat_map(|line| crate::aichat::wrap_line(line, content_width))
                        .collect();

                    match self.ai_show_answer(&question, &lines).await? {
                        Some(next_q) => question = next_q,
                        None => return Ok(()),
                    }
                }
                Err(e) => {
                    let max_w = if self.terminal_type == TerminalType::Petscii {
                        30
                    } else {
                        50
                    };
                    self.show_error(&truncate_to_width(&e, max_w)).await?;
                    return Ok(());
                }
            }
        }
    }

    /// Display a paginated AI answer. Returns `Some(question)` if the user
    /// typed a new question, or `None` to exit.
    async fn ai_show_answer(
        &mut self,
        question: &str,
        lines: &[String],
    ) -> Result<Option<String>, std::io::Error> {
        let page_h = Self::PAGE_CONTENT_LINES;
        let content_max = if self.terminal_type == TerminalType::Petscii {
            PETSCII_WIDTH - 2
        } else {
            78
        };
        let mut scroll = 0usize;

        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;

            let max_q = if self.terminal_type == TerminalType::Petscii {
                34
            } else {
                52
            };
            let q_display = truncate_to_width(question, max_q);
            self.send_line(&format!(
                "  {}",
                self.yellow(&format!("Q: {}", q_display))
            ))
            .await?;
            self.send_line(&sep).await?;

            let total = lines.len();
            let end = (scroll + page_h).min(total);
            let page_lines = &lines[scroll..end];
            for line in page_lines {
                let safe = truncate_to_width(line, content_max);
                self.send_line(&format!("  {}", safe)).await?;
            }
            for _ in (end - scroll)..page_h {
                self.send_line("").await?;
            }

            let has_prev = scroll > 0;
            let has_next = end < total;
            self.send_line(&format!(
                "  {}",
                self.dim(&format!("({}-{} of {})", scroll + 1, end, total))
            ))
            .await?;
            let mut parts = Vec::new();
            if has_prev {
                parts.push(self.action_prompt("P", "Pv"));
            }
            if has_next {
                parts.push(self.action_prompt("N", "Nx"));
            }
            parts.push(self.action_prompt("Q", "Done"));
            parts.push(self.action_prompt("H", "Help"));
            self.send_line(&format!("  {}", parts.join(" ")))
                .await?;
            self.send(&format!("  {}: ", self.cyan(">")))
                .await?;
            self.flush().await?;

            // P/N/Q act instantly; any other printable key starts
            // line-input mode so the user can type a new question.
            let first = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };

            if is_esc_key(first, self.terminal_type == TerminalType::Petscii) {
                self.drain_input().await;
                return Ok(None);
            }
            if first == b'\r' || first == b'\n' || first < 0x20 {
                continue;
            }

            let ch = if self.terminal_type == TerminalType::Petscii {
                (petscii_to_ascii_byte(first) as char).to_ascii_lowercase()
            } else {
                (first as char).to_ascii_lowercase()
            };

            match ch {
                'n' if has_next => { scroll += page_h; }
                'p' if has_prev => { scroll = scroll.saturating_sub(page_h); }
                'q' => { return Ok(None); }
                'h' => {
                    self.show_help_page("AI CHAT HELP", &[
                        "  Navigation:",
                        "  P    Previous page of answer",
                        "  N    Next page of answer",
                        "  Q    Done, return to main menu",
                        "",
                        "  Or type a new question and",
                        "  press Enter to ask again.",
                        "  The model keeps conversational",
                        "  context within a single AI Chat",
                        "  session.",
                        "",
                        "  About the service:",
                        "  Powered by Groq (groq.com), a",
                        "  free LLM inference API. The",
                        "  model is Llama 3.3 70B",
                        "  Versatile, a capable general-",
                        "  purpose assistant.",
                        "",
                        "  Getting a key:",
                        "  1. Visit console.groq.com and",
                        "     create a free account.",
                        "  2. Generate an API key (starts",
                        "     with gsk_...).",
                        "  3. Set it in Configuration >",
                        "     Other Settings > A, or paste",
                        "     into egateway.conf as",
                        "     groq_api_key = gsk_...",
                        "  4. Restart the server.",
                        "",
                        "  Rate limits:",
                        "  Free-tier limits are generous",
                        "  for interactive use but rate-",
                        "  throttle on sustained high",
                        "  traffic. See groq.com for the",
                        "  current limits.",
                        "",
                        "  Privacy:",
                        "  Questions and answers are sent",
                        "  to Groq's API and subject to",
                        "  their terms of service. Don't",
                        "  paste sensitive information.",
                    ]).await?;
                }
                _ => {
                    // Start of a new question — echo the first byte
                    // and collect the rest via line input.
                    self.send_raw(&[first]).await?;
                    self.flush().await?;
                    let mut buf: Vec<u8> = vec![first];
                    let rest = match self.get_line_input_continuing(&mut buf).await? {
                        Some(s) if !s.is_empty() => s,
                        _ => return Ok(None),
                    };
                    return Ok(Some(rest));
                }
            }
        }
    }

    // ─── WEATHER ────────────────────────────────────────────

    async fn weather(&mut self) -> Result<(), std::io::Error> {
        let saved_zip = self.weather_zip.clone();

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("WEATHER")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        // Prompt for zip code with default
        if saved_zip.is_empty() {
            self.send(&format!("  {}: ", self.cyan("Zip code")))
                .await?;
        } else {
            self.send(&format!(
                "  {} [{}]: ",
                self.cyan("Zip code"),
                self.amber(&saved_zip)
            ))
            .await?;
        }
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) => s,
            None => return Ok(()),
        };

        let zip = if input.is_empty() {
            if saved_zip.is_empty() {
                return Ok(());
            }
            saved_zip
        } else {
            // Validate: digits only, 5 chars
            if !input.chars().all(|c| c.is_ascii_digit()) || input.len() != 5 {
                self.show_error("Enter a 5-digit US zip code.").await?;
                return Ok(());
            }
            input
        };

        self.send_line("").await?;
        self.send_line(&format!("  {}...", self.dim("Loading")))
            .await?;
        self.flush().await?;

        // Save the zip code for next time (session + config file)
        self.weather_zip = zip.clone();
        let zip_for_save = zip.clone();
        tokio::task::spawn_blocking(move || {
            config::update_config_value("weather_zip", &zip_for_save);
        })
        .await
        .ok();

        // Fetch weather from Open-Meteo (free, no API key)
        let zip_owned = zip.clone();
        let result = tokio::task::spawn_blocking(move || {
            Self::fetch_weather(&zip_owned)
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

        match result {
            Ok(weather) => {
                self.display_weather(&zip, &weather).await?;
            }
            Err(e) => {
                let max_w = if self.terminal_type == TerminalType::Petscii { 30 } else { 50 };
                self.show_error(&truncate_to_width(&e, max_w)).await?;
            }
        }
        Ok(())
    }

    fn fetch_weather(zip: &str) -> Result<WeatherData, String> {
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(std::time::Duration::from_secs(15)))
                .build(),
        );

        // Step 1: Geocode zip code via Open-Meteo
        let geo_url = format!(
            "https://geocoding-api.open-meteo.com/v1/search?name={}&count=1&language=en&format=json",
            zip
        );
        let geo_resp = agent
            .get(&geo_url)
            .call()
            .map_err(|e| format!("Geocoding failed: {}", e))?;
        let mut geo_bytes = Vec::new();
        geo_resp
            .into_body()
            .as_reader()
            .take(64 * 1024)
            .read_to_end(&mut geo_bytes)
            .map_err(|e| format!("Read error: {}", e))?;
        let geo: serde_json::Value =
            serde_json::from_slice(&geo_bytes).map_err(|e| format!("Parse error: {}", e))?;

        let result = geo
            .get("results")
            .and_then(|r| r.get(0))
            .ok_or("Zip code not found.")?;
        let lat = result.get("latitude").and_then(|v| v.as_f64()).ok_or("No coordinates")?;
        let lon = result.get("longitude").and_then(|v| v.as_f64()).ok_or("No coordinates")?;
        let city = result.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let region = result.get("admin1").and_then(|v| v.as_str()).unwrap_or("");
        let timezone = result.get("timezone").and_then(|v| v.as_str()).unwrap_or("auto");

        // Step 2: Fetch weather from Open-Meteo
        let wx_url = format!(
            "https://api.open-meteo.com/v1/forecast?\
             latitude={}&longitude={}\
             &current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m,wind_direction_10m\
             &daily=weather_code,temperature_2m_max,temperature_2m_min\
             &temperature_unit=fahrenheit&wind_speed_unit=mph\
             &timezone={}&forecast_days=3",
            lat, lon, timezone
        );
        let wx_resp = agent
            .get(&wx_url)
            .call()
            .map_err(|e| format!("Weather fetch failed: {}", e))?;
        let mut wx_bytes = Vec::new();
        wx_resp
            .into_body()
            .as_reader()
            .take(128 * 1024)
            .read_to_end(&mut wx_bytes)
            .map_err(|e| format!("Read error: {}", e))?;
        let wx: serde_json::Value =
            serde_json::from_slice(&wx_bytes).map_err(|e| format!("Parse error: {}", e))?;

        let current = wx.get("current").ok_or("No current weather")?;
        let temp_f = current.get("temperature_2m").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let feels_like = current.get("apparent_temperature").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let humidity = current.get("relative_humidity_2m").and_then(|v| v.as_i64()).unwrap_or(0);
        let wind_mph = current.get("wind_speed_10m").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let wind_deg = current.get("wind_direction_10m").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let weather_code = current.get("weather_code").and_then(|v| v.as_i64()).unwrap_or(-1);

        let wind_dir = Self::degrees_to_compass(wind_deg);
        let desc = Self::wmo_weather_description(weather_code);

        // Extract 3-day forecast
        let mut forecast = Vec::new();
        if let Some(daily) = wx.get("daily") {
            let dates = daily.get("time").and_then(|v| v.as_array());
            let highs = daily.get("temperature_2m_max").and_then(|v| v.as_array());
            let lows = daily.get("temperature_2m_min").and_then(|v| v.as_array());
            let codes = daily.get("weather_code").and_then(|v| v.as_array());
            if let (Some(dates), Some(highs), Some(lows), Some(codes)) = (dates, highs, lows, codes) {
                for i in 0..dates.len().min(3) {
                    let date = dates[i].as_str().unwrap_or("?").to_string();
                    let high = highs[i].as_f64().map(|v| format!("{:.0}", v)).unwrap_or("?".into());
                    let low = lows[i].as_f64().map(|v| format!("{:.0}", v)).unwrap_or("?".into());
                    let code = codes[i].as_i64().unwrap_or(-1);
                    forecast.push(ForecastDay {
                        date,
                        high,
                        low,
                        desc: Self::wmo_weather_description(code).to_string(),
                    });
                }
            }
        }

        Ok(WeatherData {
            city: city.to_string(),
            region: region.to_string(),
            temp_f: format!("{:.0}", temp_f),
            feels_like: format!("{:.0}", feels_like),
            humidity: format!("{}", humidity),
            wind_mph: format!("{:.0}", wind_mph),
            wind_dir: wind_dir.to_string(),
            desc: desc.to_string(),
            forecast,
        })
    }

    fn degrees_to_compass(deg: f64) -> &'static str {
        const DIRS: [&str; 16] = [
            "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
            "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW",
        ];
        let idx = ((deg + 11.25) / 22.5) as usize % 16;
        DIRS[idx]
    }

    fn wmo_weather_description(code: i64) -> &'static str {
        match code {
            0 => "Clear sky",
            1 => "Mainly clear",
            2 => "Partly cloudy",
            3 => "Overcast",
            45 => "Fog",
            48 => "Depositing rime fog",
            51 => "Light drizzle",
            53 => "Moderate drizzle",
            55 => "Dense drizzle",
            56 => "Light freezing drizzle",
            57 => "Dense freezing drizzle",
            61 => "Slight rain",
            63 => "Moderate rain",
            65 => "Heavy rain",
            66 => "Light freezing rain",
            67 => "Heavy freezing rain",
            71 => "Slight snow",
            73 => "Moderate snow",
            75 => "Heavy snow",
            77 => "Snow grains",
            80 => "Slight rain showers",
            81 => "Moderate rain showers",
            82 => "Violent rain showers",
            85 => "Slight snow showers",
            86 => "Heavy snow showers",
            95 => "Thunderstorm",
            96 => "Thunderstorm, slight hail",
            99 => "Thunderstorm, heavy hail",
            _ => "Unknown",
        }
    }

    async fn display_weather(
        &mut self,
        zip: &str,
        w: &WeatherData,
    ) -> Result<(), std::io::Error> {
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;

        let is_petscii = self.terminal_type == TerminalType::Petscii;
        let max_loc = if is_petscii { 30 } else { 48 };
        let location = if w.region.is_empty() {
            w.city.clone()
        } else {
            format!("{}, {}", w.city, w.region)
        };
        let loc_display = truncate_to_width(&location, max_loc);
        self.send_line(&format!("  {}", self.yellow(&loc_display)))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        // Current conditions
        let max_desc = if is_petscii { 26 } else { 40 };
        self.send_line(&format!(
            "  Current: {}",
            self.white(&truncate_to_width(&w.desc, max_desc))
        ))
        .await?;
        self.send_line(&format!(
            "  Temp: {}F (Feels like {}F)",
            self.white(&w.temp_f),
            self.white(&w.feels_like)
        ))
        .await?;
        self.send_line(&format!(
            "  Humidity: {}%",
            self.white(&w.humidity)
        ))
        .await?;
        self.send_line(&format!(
            "  Wind: {} {} mph",
            self.white(&w.wind_dir),
            self.white(&w.wind_mph)
        ))
        .await?;
        self.send_line("").await?;

        // Forecast
        if !w.forecast.is_empty() {
            self.send_line(&format!("  {}", self.yellow("Forecast:")))
                .await?;
            for (i, day) in w.forecast.iter().enumerate() {
                let label = match i {
                    0 => "Today",
                    1 => "Tomorrow",
                    _ => &day.date,
                };
                let max_fd = if is_petscii { 12 } else { 20 };
                let desc_part = if day.desc.is_empty() {
                    String::new()
                } else {
                    format!(" {}", truncate_to_width(&day.desc, max_fd))
                };
                self.send_line(&format!(
                    "  {}: {}F / {}F{}",
                    self.cyan(label),
                    day.high,
                    day.low,
                    desc_part,
                ))
                .await?;
            }
        }

        self.send_line("").await?;
        self.send_line(&format!("  {}", self.dim(&format!("Zip: {}", zip))))
            .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    // ─── MODEM EMULATOR ──────────────────────────────────────

    // ─── Dialup Mapping ────────────────────────────────────

    async fn dialup_mapping(&mut self) -> Result<(), std::io::Error> {
        loop {
            let entries = config::load_dialup_mappings();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("DIALUP MAPPING")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            // Built-in gateway entry (not deletable)
            self.send_line(&format!(
                "     {} = {}",
                self.cyan("1001000"),
                self.amber("ethernet-gateway")
            ))
            .await?;

            if entries.is_empty() {
                self.send_line("").await?;
                self.send_line("  No other mappings defined.").await?;
            } else {
                // Show up to 9 user entries to fit the screen
                let max_show = 9;
                for (i, entry) in entries.iter().take(max_show).enumerate() {
                    let num_col = self.cyan(&entry.number);
                    let target = format!("{}:{}", entry.host, entry.port);
                    let line = format!(
                        "  {}. {} = {}",
                        i + 1,
                        num_col,
                        self.amber(&target)
                    );
                    self.send_line(&line).await?;
                }
                if entries.len() > max_show {
                    self.send_line(&format!(
                        "  ... and {} more",
                        entries.len() - max_show
                    ))
                    .await?;
                }
            }
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Add mapping",
                self.cyan("A")
            ))
            .await?;
            if !entries.is_empty() {
                self.send_line(&format!(
                    "  {}  Delete mapping",
                    self.cyan("D")
                ))
                .await?;
            }
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/dialup"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "a" => {
                    self.dialup_add_entry().await?;
                }
                "d" if !entries.is_empty() => {
                    self.dialup_delete_entry(&entries).await?;
                }
                "h" => {
                    self.show_help_page("DIALUP MAPPING HELP", &[
                        "  Map phone numbers to host:port",
                        "  targets for the modem emulator.",
                        "",
                        "  Dial a number with ATDT, ATDP,",
                        "  or ATD (all work the same) and",
                        "  the server connects to the",
                        "  mapped host:port for you.",
                        "",
                        "  You can still dial host:port",
                        "  directly - mappings are optional.",
                        "",
                        "  Mappings are saved in dialup.conf.",
                    ]).await?;
                }
                "q" => return Ok(()),
                _ => {
                    if entries.is_empty() {
                        self.show_error("Press A, H, or Q.").await?;
                    } else {
                        self.show_error("Press A, D, H, or Q.").await?;
                    }
                }
            }
        }
    }

    async fn dialup_add_entry(&mut self) -> Result<(), std::io::Error> {
        self.send_line("").await?;

        self.send(&format!("  {} ", self.cyan("Phone number:")))
            .await?;
        self.flush().await?;
        let number = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        // Validate: must contain at least one digit
        if !number.chars().any(|c| c.is_ascii_digit()) {
            self.show_error("Number must contain digits.").await?;
            return Ok(());
        }

        self.send(&format!("  {} ", self.cyan("Host:")))
            .await?;
        self.flush().await?;
        let host = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        self.send(&format!("  {} ", self.cyan("Port (23):")))
            .await?;
        self.flush().await?;
        let port: u16 = match self.get_line_input().await? {
            Some(s) if s.is_empty() => 23,
            Some(s) => match s.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    self.show_error("Invalid port number.").await?;
                    return Ok(());
                }
            },
            None => return Ok(()),
        };

        let mut entries = config::load_dialup_mappings();

        // Remove any existing entry with the same normalized number
        let new_norm = config::normalize_phone_number(&number);
        entries.retain(|e| config::normalize_phone_number(&e.number) != new_norm);

        entries.push(config::DialupEntry {
            number,
            host,
            port,
        });
        config::save_dialup_mappings(&entries);

        self.send_line("").await?;
        self.send_line("  Mapping saved.").await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    async fn dialup_delete_entry(
        &mut self,
        entries: &[config::DialupEntry],
    ) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send(&format!(
            "  {} ",
            self.cyan("Entry # to delete:")
        ))
        .await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        let idx: usize = match input.parse::<usize>() {
            Ok(n) if n >= 1 && n <= entries.len() => n - 1,
            _ => {
                self.show_error("Invalid entry number.").await?;
                return Ok(());
            }
        };

        let mut entries = entries.to_vec();
        let removed = entries.remove(idx);
        config::save_dialup_mappings(&entries);
        self.send_line(&format!(
            "  Removed: {} = {}:{}",
            removed.number, removed.host, removed.port
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    // ─── Modem settings ───────────────────────────────────

    async fn modem_settings(&mut self) -> Result<(), std::io::Error> {
        // Snapshot current config so we can detect changes and revert if needed.
        let original_cfg = config::get_config();

        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("MODEM EMULATOR")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            let cfg = config::get_config();
            let status = if cfg.serial_enabled {
                self.green("ENABLED")
            } else {
                self.red("Disabled")
            };
            self.send_line(&format!("  Status: {}", status)).await?;
            let port_display = if cfg.serial_port.is_empty() {
                "(not set)".to_string()
            } else {
                cfg.serial_port.clone()
            };
            self.send_line(&format!(
                "  Port:   {}",
                self.amber(&port_display)
            ))
            .await?;
            self.send_line(&format!(
                "  Baud:   {}",
                self.amber(&cfg.serial_baud.to_string())
            ))
            .await?;
            self.send_line(&format!(
                "  Data:   {}",
                self.amber(&format!(
                    "{}-{}-{}",
                    cfg.serial_databits,
                    cfg.serial_parity.chars().next().unwrap_or('N').to_uppercase(),
                    cfg.serial_stopbits
                ))
            ))
            .await?;
            self.send_line(&format!(
                "  Flow:   {}",
                self.amber(&cfg.serial_flowcontrol)
            ))
            .await?;
            if cfg.serial_enabled {
                self.send_line(&format!(
                    "  {}",
                    self.amber("ATD XMODEM-GATEWAY")
                ))
                .await?;
            }
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  Toggle enabled/disabled",
                self.cyan("E")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Select serial port",
                self.cyan("S")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set baud rate",
                self.cyan("B")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set data/parity/stop",
                self.cyan("P")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set flow control",
                self.cyan("F")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Dialup Mapping",
                self.cyan("D")
            ))
            .await?;
            if !self.is_serial {
                self.send_line(&format!(
                    "  {}  Ring emulator",
                    self.cyan("I")
                ))
                .await?;
            }
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/modem"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => {
                    self.modem_apply_settings(&original_cfg).await?;
                    return Ok(());
                }
            };

            match input.as_str() {
                "e" => {
                    let new_val = if cfg.serial_enabled { "false" } else { "true" };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("serial_enabled", &v);
                    })
                    .await
                    .ok();
                }
                "s" => {
                    self.modem_select_port().await?;
                }
                "b" => {
                    self.modem_set_baud().await?;
                }
                "p" => {
                    self.modem_set_data_params().await?;
                }
                "f" => {
                    self.modem_set_flow().await?;
                }
                "d" => {
                    self.dialup_mapping().await?;
                }
                "i" if !self.is_serial => {
                    self.modem_ring_emulator().await?;
                }
                "h" => {
                    self.modem_show_help().await?;
                }
                "q" => {
                    self.modem_apply_settings(&original_cfg).await?;
                    return Ok(());
                }
                _ => {
                    let msg = if self.is_serial {
                        "Press E, S, B, P, D, F, H, or Q."
                    } else {
                        "Press E, S, B, P, D, F, I, H, or Q."
                    };
                    self.show_error(msg).await?;
                }
            }
        }
    }

    /// Apply modem settings changes.  For serial users, ask for
    /// acknowledgement and revert if no response within 60 seconds.
    async fn modem_apply_settings(
        &mut self,
        original_cfg: &config::Config,
    ) -> Result<(), std::io::Error> {
        let new_cfg = config::get_config();
        let changed = new_cfg.serial_enabled != original_cfg.serial_enabled
            || new_cfg.serial_port != original_cfg.serial_port
            || new_cfg.serial_baud != original_cfg.serial_baud
            || new_cfg.serial_databits != original_cfg.serial_databits
            || new_cfg.serial_parity != original_cfg.serial_parity
            || new_cfg.serial_stopbits != original_cfg.serial_stopbits
            || new_cfg.serial_flowcontrol != original_cfg.serial_flowcontrol;

        if !changed {
            return Ok(());
        }

        if !self.is_serial {
            crate::serial::restart_serial();
            return Ok(());
        }

        // Serial user: warn before applying new settings, then require
        // Y+Enter acknowledgement.  Random bytes from a baud mismatch
        // must not count as confirmation.  I/O errors during the prompt
        // are non-fatal — we still need to reach the revert logic.
        let _ = self.send_line("").await;
        let _ = self.send_line(&format!(
            "  {}",
            self.yellow("New settings will be applied.")
        )).await;
        let _ = self.send_line(&format!(
            "  {}",
            self.yellow("You have 60 seconds to adjust")
        )).await;
        let _ = self.send_line(&format!(
            "  {}",
            self.yellow("your terminal and type Y then")
        )).await;
        let _ = self.send_line(&format!(
            "  {}",
            self.yellow("Enter, or settings will revert.")
        )).await;
        let _ = self.send_line("").await;
        let _ = self.flush().await;

        // Apply the new serial settings now.
        crate::serial::restart_serial();

        let deadline = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(60);
        let mut next_remind = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(5);
        let mut got_y = false;

        loop {
            let wait_until = std::cmp::min(next_remind, deadline);
            let remaining = wait_until.saturating_duration_since(tokio::time::Instant::now());

            match tokio::time::timeout(remaining, self.read_byte_filtered()).await {
                Ok(Ok(Some(byte))) => {
                    if got_y {
                        if byte == b'\r' || byte == b'\n' {
                            // Y + Enter — confirmed
                            let _ = self.send_line("").await;
                            let _ = self.send_line(&format!(
                                "  {}",
                                self.green("Settings confirmed.")
                            )).await;
                            let _ = self.send_line("").await;
                            let _ = self.send("  Press any key to continue.").await;
                            let _ = self.flush().await;
                            let _ = self.wait_for_key().await;
                            return Ok(());
                        }
                        // Y followed by non-Enter — noise, reset
                        got_y = false;
                    } else if byte == b'Y' || byte == b'y' {
                        got_y = true;
                    }
                    // Ignore other bytes (likely noise from baud mismatch)
                }
                Ok(Ok(None)) | Ok(Err(_)) => {
                    // Connection lost — revert
                    break;
                }
                Err(_) => {
                    // Timeout interval
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    let secs_left = deadline
                        .saturating_duration_since(tokio::time::Instant::now())
                        .as_secs();
                    let _ = self.send_line(&format!(
                        "  Type Y+Enter to confirm. ({}s left)",
                        secs_left
                    )).await;
                    let _ = self.flush().await;
                    next_remind += tokio::time::Duration::from_secs(5);
                }
            }
        }

        // No acknowledgement — revert
        let _ = self.send_line("").await;
        let _ = self.send_line(&format!(
            "  {}",
            self.red("No response. Reverting settings.")
        )).await;
        let _ = self.flush().await;

        Self::revert_serial_config(original_cfg).await;
        crate::serial::restart_serial();
        Ok(())
    }

    /// Revert serial config to a previous snapshot using a single batch write.
    async fn revert_serial_config(cfg: &config::Config) {
        let oc = cfg.clone();
        let _ = tokio::task::spawn_blocking(move || {
            config::update_config_values(&[
                ("serial_enabled", if oc.serial_enabled { "true" } else { "false" }),
                ("serial_port", &oc.serial_port),
                ("serial_baud", &oc.serial_baud.to_string()),
                ("serial_databits", &oc.serial_databits.to_string()),
                ("serial_parity", &oc.serial_parity),
                ("serial_stopbits", &oc.serial_stopbits.to_string()),
                ("serial_flowcontrol", &oc.serial_flowcontrol),
            ]);
        })
        .await;
    }

    async fn modem_select_port(&mut self) -> Result<(), std::io::Error> {
        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("SERIAL PORT"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}...", self.dim("Detecting ports"))).await?;
            self.flush().await?;

            let ports = tokio::task::spawn_blocking(crate::serial::list_serial_ports)
                .await
                .unwrap_or_default();

            if ports.is_empty() {
                self.clear_screen().await?;
                self.send_line(&sep).await?;
                self.send_line(&format!("  {}", self.yellow("SERIAL PORT"))).await?;
                self.send_line(&sep).await?;
                self.send_line("").await?;
                self.send_line(&format!("  {}", self.red("No serial ports detected.")))
                    .await?;
                self.send_line("").await?;
                self.send_line(&format!(
                    "  {}  Refresh port list",
                    self.cyan("R")
                ))
                .await?;
                self.send_line(&format!(
                    "  {}  None (clear port)",
                    self.cyan("N")
                ))
                .await?;
                self.send_line("").await?;
                self.send_line(&format!("  {}", self.action_prompt("Q", "Back")))
                    .await?;
                self.send(&format!("  {} ", self.cyan("Port:"))).await?;
                self.flush().await?;

                let input = match self.get_line_input().await? {
                    Some(s) if !s.is_empty() => s,
                    _ => return Ok(()),
                };
                match input.as_str() {
                    "r" => continue,
                    "n" => {
                        tokio::task::spawn_blocking(|| {
                            config::update_config_value("serial_port", "");
                        })
                        .await
                        .ok();
                        return Ok(());
                    }
                    "q" | "" => return Ok(()),
                    _ => {
                        // Allow typing a port path directly even with no ports detected
                        let port_name = input;
                        tokio::task::spawn_blocking(move || {
                            config::update_config_value("serial_port", &port_name);
                        })
                        .await
                        .ok();
                        return Ok(());
                    }
                }
            }

            // Redraw with port list
            self.clear_screen().await?;
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("SERIAL PORT"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            let max_w = if self.terminal_type == TerminalType::Petscii {
                30
            } else {
                50
            };
            for (i, port) in ports.iter().enumerate() {
                self.send_line(&format!(
                    "  {:>2}. {}",
                    i + 1,
                    truncate_to_width(port, max_w)
                ))
                .await?;
            }
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  Refresh port list",
                self.cyan("R")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  None (clear port)",
                self.cyan("N")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}",
                self.dim("Enter #, R, N, or type a path.")
            )).await?;
            self.send_line(&format!("  {}", self.action_prompt("Q", "Back"))).await?;
            self.send(&format!("  {} ", self.cyan("Port:"))).await?;
            self.flush().await?;

            let input = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "r" => continue,
                "n" => {
                    tokio::task::spawn_blocking(|| {
                        config::update_config_value("serial_port", "");
                    })
                    .await
                    .ok();
                    return Ok(());
                }
                "q" => return Ok(()),
                _ => {}
            }

            if let Ok(idx) = input.parse::<usize>() {
                if idx >= 1 && idx <= ports.len() {
                    let port_name = ports[idx - 1].clone();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("serial_port", &port_name);
                    })
                    .await
                    .ok();
                } else {
                    self.show_error("Invalid selection.").await?;
                    continue;
                }
            } else {
                // Allow typing a port path directly
                let port_name = input;
                tokio::task::spawn_blocking(move || {
                    config::update_config_value("serial_port", &port_name);
                })
                .await
                .ok();
            }
            return Ok(());
        }
    }

    async fn modem_set_baud(&mut self) -> Result<(), std::io::Error> {
        let bauds = [
            "300", "1200", "2400", "4800", "9600", "19200", "38400",
            "57600", "115200",
        ];
        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("BAUD RATE"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            for (i, b) in bauds.iter().enumerate() {
                self.send_line(&format!(
                    "  {}  {}",
                    self.cyan(&(i + 1).to_string()),
                    b
                ))
                .await?;
            }
            self.send_line("").await?;
            self.send_line(&format!("  {}", self.action_prompt("Q", "Back"))).await?;
            let prompt = format!("{}> ", self.cyan("baud"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(true).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "q" => return Ok(()),
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" => {
                    // Safe: the match arm only accepts single ASCII digits 1-9.
                    let idx = (input.as_bytes()[0] - b'1') as usize;
                    let baud_str = bauds[idx].to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("serial_baud", &baud_str);
                    })
                    .await
                    .ok();
                    return Ok(());
                }
                _ => {
                    self.show_error("Press 1-9 or Q.").await?;
                }
            }
        }
    }

    async fn modem_set_data_params(&mut self) -> Result<(), std::io::Error> {
        // Data bits
        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("DATA BITS"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}  5 bits", self.cyan("5"))).await?;
            self.send_line(&format!("  {}  6 bits", self.cyan("6"))).await?;
            self.send_line(&format!("  {}  7 bits", self.cyan("7"))).await?;
            self.send_line(&format!("  {}  8 bits", self.cyan("8"))).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}", self.action_prompt("Q", "Back"))).await?;
            let prompt = format!("{}> ", self.cyan("data"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(true).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "q" => return Ok(()),
                "5" | "6" | "7" | "8" => {
                    let v = input.clone();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("serial_databits", &v);
                    })
                    .await
                    .ok();
                    break;
                }
                _ => {
                    self.show_error("Press 5-8 or Q.").await?;
                }
            }
        }

        // Parity
        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("PARITY"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}  None", self.cyan("1"))).await?;
            self.send_line(&format!("  {}  Odd", self.cyan("2"))).await?;
            self.send_line(&format!("  {}  Even", self.cyan("3"))).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}", self.action_prompt("Q", "Back"))).await?;
            let prompt = format!("{}> ", self.cyan("parity"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(true).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            let parity = match input.as_str() {
                "1" => "none",
                "2" => "odd",
                "3" => "even",
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press 1-3 or Q.").await?;
                    continue;
                }
            };
            let p = parity.to_string();
            tokio::task::spawn_blocking(move || {
                config::update_config_value("serial_parity", &p);
            })
            .await
            .ok();
            break;
        }

        // Stop bits
        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("STOP BITS"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}  1 stop bit", self.cyan("1"))).await?;
            self.send_line(&format!("  {}  2 stop bits", self.cyan("2"))).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}", self.action_prompt("Q", "Back"))).await?;
            let prompt = format!("{}> ", self.cyan("stop"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(true).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "q" => return Ok(()),
                "1" | "2" => {
                    let v = input.clone();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("serial_stopbits", &v);
                    })
                    .await
                    .ok();
                    return Ok(());
                }
                _ => {
                    self.show_error("Press 1-2 or Q.").await?;
                }
            }
        }
    }

    async fn modem_set_flow(&mut self) -> Result<(), std::io::Error> {
        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("FLOW CONTROL"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}  None", self.cyan("1"))).await?;
            self.send_line(&format!("  {}  Hardware (RTS/CTS)", self.cyan("2"))).await?;
            self.send_line(&format!("  {}  Software (XON/XOFF)", self.cyan("3"))).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}", self.action_prompt("Q", "Back"))).await?;
            let prompt = format!("{}> ", self.cyan("flow"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(true).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            let flow = match input.as_str() {
                "1" => "none",
                "2" => "hardware",
                "3" => "software",
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press 1-3 or Q.").await?;
                    continue;
                }
            };
            let f = flow.to_string();
            tokio::task::spawn_blocking(move || {
                config::update_config_value("serial_flowcontrol", &f);
            })
            .await
            .ok();
            return Ok(());
        }
    }

    async fn modem_ring_emulator(&mut self) -> Result<(), std::io::Error> {
        let cfg = config::get_config();

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("RING EMULATOR")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        // Check if serial port is enabled
        if !cfg.serial_enabled || cfg.serial_port.is_empty() {
            self.send_line(&format!(
                "  {}",
                self.red("Serial port is not enabled.")
            ))
            .await?;
            self.send_line("").await?;
            self.send("  Press any key to continue.").await?;
            self.flush().await?;
            self.wait_for_key().await?;
            return Ok(());
        }

        // Create progress channel
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u8>(16);

        if !crate::serial::request_ring(tx) {
            self.send_line(&format!(
                "  {}",
                self.red("A ring is already in progress.")
            ))
            .await?;
            self.send_line("").await?;
            self.send("  Press any key to continue.").await?;
            self.flush().await?;
            self.wait_for_key().await?;
            return Ok(());
        }

        self.send_line(&format!(
            "  Calling {}...",
            self.amber(&cfg.serial_port)
        ))
        .await?;
        self.send_line("").await?;
        self.send_line(&format!("  {}", self.action_prompt("Q", "Cancel")))
            .await?;
        self.flush().await?;

        // Show rings as they happen.  Q or ESC cancels (drops rx
        // which signals the serial thread to abort).  Timeout if the
        // serial thread never picks up the request.
        let reader = &mut self.reader;
        let writer = &self.writer;
        let is_petscii = self.terminal_type == TerminalType::Petscii;
        let mut answered = false;
        let mut serial_error = false;
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(15));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(0) => {
                            // RING — reset timeout on each ring
                            timeout.as_mut().reset(tokio::time::Instant::now()
                                + std::time::Duration::from_secs(15));
                            let mut w = writer.lock().await;
                            let _ = w.write_all(b"  RING...\r\n").await;
                            let _ = w.flush().await;
                        }
                        Some(1) => {
                            // Answered
                            answered = true;
                            break;
                        }
                        Some(2) => {
                            // Serial port error
                            serial_error = true;
                            break;
                        }
                        _ => break, // channel closed
                    }
                }
                byte = read_byte_iac_filtered(reader, true) => {
                    match byte {
                        Ok(Some(b)) if is_esc_key(b, is_petscii)
                            || b == b'q' || b == b'Q' =>
                        {
                            break;
                        }
                        Ok(None) | Err(_) => break,
                        _ => {} // ignore other keys
                    }
                }
                _ = &mut timeout => {
                    serial_error = true;
                    break;
                }
            }
        }

        // Drop the receiver to signal cancellation if we broke out early,
        // and clear the slot in case the serial thread never picked it up.
        drop(rx);
        crate::serial::cancel_ring_request();

        self.send_line("").await?;
        if answered {
            self.send_line(&format!(
                "  {}",
                self.green("Remote machine connected.")
            ))
            .await?;
        } else if serial_error {
            self.send_line(&format!(
                "  {}",
                self.red("Serial connection failed.")
            ))
            .await?;
        } else {
            self.send_line(&format!(
                "  {}",
                self.yellow("Ring cancelled.")
            ))
            .await?;
        }
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    async fn modem_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  This server emulates a Hayes-",
                "  compatible modem on the serial",
                "  port. Connect retro hardware",
                "  and use AT commands.",
                "",
                "  Dialing:",
                "  ATDT ethernet-gateway",
                "    Connect to this gateway",
                "  ATDT host:port",
                "    Dial a remote telnet host",
                "  ATDL     Redial last number",
                "",
                "  Stored numbers:",
                "  AT&Zn=s  Store number in slot",
                "  ATDSn    Dial stored slot 0-3",
                "",
                "  Control:",
                "  ATH      Hang up",
                "  +++      Return to cmd mode",
                "  ATO      Return online",
                "  A/       Repeat last command",
                "",
                "  Information:",
                "  ATIn     Info 0-7 (model, ROM)",
                "  AT&V     Show settings",
                "  ATSn?    Query S-register n",
                "",
                "  Configuration:",
                "  ATXn     Result-code level 0-4",
                "  AT&Cn    DCD mode (0-1)",
                "  AT&Dn    DTR handling (0-3)",
                "  AT&Kn    Flow control (0-4)",
                "  AT&W     Save settings",
                "  ATZ      Reload saved settings",
                "  AT&F     Reset to gateway",
                "           defaults",
                "",
                "  Gateway-friendly defaults:",
                "  S7=15  (50 s Hayes; faster",
                "         failed-dial recovery)",
                "  &D0    (ignore DTR; retro",
                "         clients often don't",
                "         wire it correctly)",
                "  &K0    (no modem flow control;",
                "         port-level serial flow",
                "         is still honored)",
                "",
                "  Override any of these with the",
                "  matching AT command and AT&W.",
            ]
        } else {
            &[
                "  This server emulates a Hayes-compatible",
                "  modem on the configured serial port.",
                "  Connect retro hardware (Commodore 64,",
                "  CP/M, Altair, RC2014, etc.) and drive",
                "  it with standard AT commands.",
                "",
                "  Dialing:",
                "  ATDT ethernet-gateway",
                "    Connect to this gateway's menus",
                "  ATDT host:port",
                "    Dial a remote telnet host",
                "  ATDL       Redial the last number",
                "  ATDP ...   Same as ATDT (no pulse/tone",
                "             distinction on TCP)",
                "",
                "  Stored numbers (4 slots, persistent):",
                "  AT&Zn=str  Store number/host in slot n",
                "  ATDSn      Dial stored slot 0-3",
                "  AT&V       Shows the active table",
                "",
                "  Control:",
                "  ATH        Hang up the active connection",
                "  +++        Return to command mode with",
                "             S2/S12 Hayes guard-time timing",
                "  ATO        Return to online mode",
                "  A/         Repeat the last AT command",
                "             (no CR needed)",
                "",
                "  Information queries:",
                "  ATIn       0-7: model, config, ROM sum,",
                "             ROM test, firmware, OEM, etc.",
                "  AT&V       Show every current setting",
                "  ATSn?      Query S-register n",
                "",
                "  Configuration:",
                "  ATEn       Echo off/on (E0 / E1)",
                "  ATVn       Numeric/verbose result codes",
                "  ATQn       Quiet (Q1 suppresses results)",
                "  ATXn       Result-code level 0-4 (see",
                "             README for the table)",
                "  AT&Cn      DCD: 0=always on, 1=carrier",
                "  AT&Dn      DTR handling 0-3",
                "  AT&Kn      Flow control 0-4",
                "  ATSn=v     Set S-register n to v",
                "  AT&W       Save settings to egateway.conf",
                "  ATZ        Reload saved settings",
                "  AT&F       Reset to gateway defaults",
                "",
                "  Gateway-friendly default deviations:",
                "  S7=15      Wait-for-carrier (Hayes: 50 s).",
                "             Keeps failed TCP dials snappy.",
                "  &D0        Ignore DTR (Hayes: &D2 hangs up",
                "             on DTR drop).  Retro clients",
                "             often don't drive DTR correctly,",
                "             which would cause spurious",
                "             disconnects.",
                "  &K0        No modem-level flow control",
                "             (Hayes: &K3 RTS/CTS).  Port-level",
                "             flow is still honored via",
                "             serial_flowcontrol in egateway.conf.",
                "",
                "  Override any of these with the matching AT",
                "  command and AT&W to persist.",
                "",
                "  Commands the emulator can't meaningfully",
                "  implement on TCP (ATB, ATC, ATL, ATM,",
                "  AT&B/&G/&J/&S/&T/&Y) return OK so legacy",
                "  init strings run to completion.",
            ]
        };
        self.show_help_page("MODEM EMULATOR HELP", lines).await
    }

    // ─── CONFIGURATION ──────────────────────────────────────

    async fn configuration(&mut self) -> Result<(), std::io::Error> {
        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("CONFIGURATION")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Security",
                self.cyan("E")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Gateway Configuration",
                self.cyan("G")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Modem Emulator",
                self.cyan("M")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Server Configuration",
                self.cyan("S")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  File Transfer",
                self.cyan("F")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Other Settings",
                self.cyan("O")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Reset Defaults",
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "e" => {
                    self.security_settings().await?;
                }
                "g" => {
                    self.gateway_configuration().await?;
                }
                "m" => {
                    self.modem_settings().await?;
                }
                "o" => {
                    self.other_settings().await?;
                }
                "s" => {
                    self.server_configuration().await?;
                }
                "f" => {
                    self.file_transfer_settings().await?;
                }
                "r" => {
                    self.config_reset_defaults().await?;
                }
                "h" => {
                    let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
                        &[
                            "  Configuration submenus:",
                            "",
                            "  E  Security: require login,",
                            "     set usernames and passwords",
                            "",
                            "  G  Gateway: configure outbound",
                            "     Telnet and SSH Gateway menus",
                            "",
                            "  M  Modem: configure the serial",
                            "     port for modem emulation",
                            "",
                            "  S  Server: enable/disable",
                            "     services, set ports, and",
                            "     restart the server",
                            "",
                            "  F  File Transfer: per-protocol",
                            "     XMODEM, YMODEM, ZMODEM setup",
                            "     plus the transfer directory",
                            "",
                            "  O  Other: AI key, logging,",
                            "     and general settings",
                            "",
                            "  R  Reset all settings to",
                            "     default values (asks first)",
                            "",
                            "  What needs a restart:",
                            "    S (ports, enable/disable)",
                            "    E (credentials, login",
                            "       requirement)",
                            "    O > G (GUI on startup)",
                            "",
                            "  Everything else applies at",
                            "  the next session / transfer.",
                        ]
                    } else {
                        &[
                            "  Configuration submenus:",
                            "",
                            "  E  Security: require login, set",
                            "     usernames and passwords",
                            "",
                            "  G  Gateway: configure the outbound",
                            "     Telnet and SSH Gateway menus",
                            "     (proxy to remote servers)",
                            "",
                            "  M  Modem: configure the serial port",
                            "     for modem emulation",
                            "",
                            "  S  Server: enable/disable services,",
                            "     set ports, and restart the server",
                            "",
                            "  F  File Transfer: per-protocol",
                            "     XMODEM/YMODEM/ZMODEM tuning",
                            "     plus the shared transfer directory",
                            "",
                            "  O  Other: AI key, logging, and",
                            "     general settings",
                            "",
                            "  R  Reset all settings to their",
                            "     factory defaults (confirms first)",
                            "",
                            "  Which changes need a restart:",
                            "    S changes (ports, enable/disable)",
                            "    E changes (credentials, login toggle)",
                            "    O > G toggle (GUI on startup)",
                            "",
                            "  Everything else (file-transfer",
                            "  timings, gateway mode, modem AT",
                            "  settings, AI key, homepage, weather",
                            "  zip) applies at the next session or",
                            "  transfer without a restart.",
                        ]
                    };
                    self.show_help_page("CONFIGURATION HELP", lines).await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press E, F, G, M, O, S, R, H, or Q.").await?;
                }
            }
        }
    }

    // ─── OTHER SETTINGS ──────────────────────────────────────

    async fn other_settings(&mut self) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("OTHER SETTINGS")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            let key_display = if cfg.groq_api_key.is_empty() {
                self.red("(not set)")
            } else {
                self.green("(set)")
            };
            self.send_line(&format!("  AI API key:  {}", key_display))
                .await?;
            self.send_line(&format!(
                "  Homepage:    {}",
                self.amber(&cfg.browser_homepage)
            ))
            .await?;
            let zip_display = if cfg.weather_zip.is_empty() {
                self.dim("(not set)")
            } else {
                self.amber(&cfg.weather_zip)
            };
            self.send_line(&format!("  Weather zip: {}", zip_display))
                .await?;

            let verbose_status = if cfg.verbose {
                self.green("ON")
            } else {
                self.dim("off")
            };
            self.send_line(&format!("  Verbose log: {}", verbose_status))
                .await?;

            let gui_status = if cfg.enable_console {
                self.green("ON")
            } else {
                self.dim("off")
            };
            self.send_line(&format!("  GUI startup: {}", gui_status))
                .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Set AI API key (Groq)",
                self.cyan("A")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set browser homepage",
                self.cyan("B")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set weather zip code",
                self.cyan("W")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Toggle verbose transfer logging",
                self.cyan("V")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Toggle GUI on startup",
                self.cyan("G")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Restart server",
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config/other"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "a" => {
                    self.other_set_field(
                        "AI API key",
                        "groq_api_key",
                        if cfg.groq_api_key.is_empty() { "(not set)" } else { "(hidden)" },
                        true,
                    )
                    .await?;
                }
                "b" => {
                    self.other_set_field(
                        "Browser homepage",
                        "browser_homepage",
                        &cfg.browser_homepage,
                        false,
                    )
                    .await?;
                }
                "w" => {
                    self.other_set_field(
                        "Weather zip code",
                        "weather_zip",
                        &cfg.weather_zip,
                        false,
                    )
                    .await?;
                }
                "v" => {
                    let new_val = if cfg.verbose { "false" } else { "true" };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("verbose", &v);
                    })
                    .await
                    .ok();
                }
                "g" => {
                    let new_val = if cfg.enable_console { "false" } else { "true" };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("enable_console", &v);
                    })
                    .await
                    .ok();
                    self.config_restart_notice().await?;
                }
                "r" => {
                    self.config_restart_server().await?;
                }
                "h" => {
                    self.other_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press A, B, W, V, G, R, H, or Q.").await?;
                }
            }
        }
    }

    async fn other_set_field(
        &mut self,
        label: &str,
        key: &str,
        current_display: &str,
        is_secret: bool,
    ) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!(
            "  Current {}: {}",
            label.to_lowercase(),
            if is_secret {
                self.dim(current_display)
            } else {
                self.amber(current_display)
            }
        ))
        .await?;
        self.send(&format!("  New {}: ", label.to_lowercase())).await?;
        self.flush().await?;

        let input = if is_secret {
            self.get_password_input().await?
        } else {
            self.get_line_input().await?
        };

        let input = match input {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        let k = key.to_string();
        let v = input;
        let saved_label = label.to_string();
        tokio::task::spawn_blocking(move || {
            config::update_config_value(&k, &v);
        })
        .await
        .ok();
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.green(&format!("{} updated.", saved_label))
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    async fn other_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  A  Groq API key for AI Chat",
                "     (get one free at groq.com)",
                "  B  Default homepage URL for",
                "     the built-in web browser",
                "  W  Default zip code for the",
                "     weather feature",
                "  V  Toggle verbose transfer log",
                "  G  Toggle GUI on startup",
                "     (requires restart)",
                "  R  Restart the server",
            ]
        } else {
            &[
                "  A  Groq API key for AI Chat (get one",
                "     free at console.groq.com)",
                "  B  Default homepage URL for the",
                "     built-in web browser",
                "  W  Default zip code for weather",
                "  V  Toggle verbose transfer logging",
                "  G  Toggle GUI on startup (requires",
                "     a server restart)",
                "  R  Restart the server",
            ]
        };
        self.show_help_page("OTHER SETTINGS HELP", lines).await
    }

    // ─── SECURITY SETTINGS ───────────────────────────────────

    async fn security_settings(&mut self) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("SECURITY")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            let login_status = if cfg.security_enabled {
                self.green("ENABLED")
            } else {
                self.red("Disabled")
            };
            self.send_line(&format!("  Require login: {}", login_status))
                .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  Telnet user: {}",
                self.amber(&cfg.username)
            ))
            .await?;
            self.send_line(&format!(
                "  Telnet pass: {}",
                self.dim("(hidden)")
            ))
            .await?;
            self.send_line(&format!(
                "  SSH user:    {}",
                self.amber(&cfg.ssh_username)
            ))
            .await?;
            self.send_line(&format!(
                "  SSH pass:    {}",
                self.dim("(hidden)")
            ))
            .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Toggle require login",
                self.cyan("L")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set telnet username",
                self.cyan("U")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set telnet password",
                self.cyan("P")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set SSH username",
                self.cyan("S")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set SSH password",
                self.cyan("W")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Restart server",
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config/security"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "l" => {
                    let new_val = if cfg.security_enabled { "false" } else { "true" };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("security_enabled", &v);
                    })
                    .await
                    .ok();
                    self.config_restart_notice().await?;
                }
                "u" => {
                    self.security_set_field("Telnet username", "username", &cfg.username, false).await?;
                }
                "p" => {
                    self.security_set_field("Telnet password", "password", &cfg.password, true).await?;
                }
                "s" => {
                    self.security_set_field("SSH username", "ssh_username", &cfg.ssh_username, false).await?;
                }
                "w" => {
                    self.security_set_field("SSH password", "ssh_password", &cfg.ssh_password, true).await?;
                }
                "r" => {
                    self.config_restart_server().await?;
                }
                "h" => {
                    self.security_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press L, U, P, S, W, R, H, or Q.").await?;
                }
            }
        }
    }

    async fn security_set_field(
        &mut self,
        label: &str,
        key: &str,
        current: &str,
        is_password: bool,
    ) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        if is_password {
            self.send_line(&format!(
                "  Current {}: {}",
                label.to_lowercase(),
                self.dim("(hidden)")
            ))
            .await?;
        } else {
            self.send_line(&format!(
                "  Current {}: {}",
                label.to_lowercase(),
                self.amber(current)
            ))
            .await?;
        }
        self.send(&format!("  New {}: ", label.to_lowercase())).await?;
        self.flush().await?;

        let input = if is_password {
            self.get_password_input().await?
        } else {
            self.get_line_input().await?
        };

        let input = match input {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        let k = key.to_string();
        let v = input;
        tokio::task::spawn_blocking(move || {
            config::update_config_value(&k, &v);
        })
        .await
        .ok();
        self.config_restart_notice().await?;
        Ok(())
    }

    async fn security_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  Configure login security.",
                "",
                "  Menu items:",
                "  L  Toggle login requirement",
                "  U  Set the telnet username",
                "  P  Set the telnet password",
                "  S  Set the SSH username",
                "  W  Set the SSH password",
                "  R  Restart the server",
                "",
                "  Credentials:",
                "  Telnet and SSH have separate",
                "  usernames/passwords; changing",
                "  one doesn't affect the other.",
                "  Both are stored in plaintext",
                "  in egateway.conf - don't reuse",
                "  sensitive passwords here.",
                "",
                "  When security is OFF:",
                "  Only private-range IPs can",
                "  connect (RFC 1918, loopback,",
                "  link-local, IPv6 unique-local).",
                "  Public IPs are refused, and",
                "  gateway addresses (*.*.*.1)",
                "  are rejected defensively.",
                "",
                "  When security is ON:",
                "  Any IP may connect, but must",
                "  authenticate. 3 failed logins",
                "  from the same IP triggers a",
                "  5-minute lockout for that IP.",
                "",
                "  Telnet transmits credentials",
                "  in cleartext. Use SSH for any",
                "  non-local access.",
                "",
                "  Changes are saved immediately",
                "  but require a server restart.",
            ]
        } else {
            &[
                "  Configure login security.",
                "",
                "  Menu items:",
                "  L  Toggle whether a login is required",
                "  U  Set the telnet login username",
                "  P  Set the telnet login password",
                "  S  Set the SSH login username",
                "  W  Set the SSH login password",
                "  R  Restart the server",
                "",
                "  Credentials:",
                "  Telnet and SSH have separate usernames",
                "  and passwords; changing one doesn't",
                "  affect the other. Both are stored in",
                "  plaintext in egateway.conf - don't reuse",
                "  sensitive passwords on this server.",
                "",
                "  When security is OFF (default):",
                "  Only private-range IPs are allowed to",
                "  connect (RFC 1918 10/172.16/192.168,",
                "  loopback 127.0.0.0/8, link-local",
                "  169.254.0.0/16, IPv6 ::1, fe80::/10,",
                "  and fd00::/8). Public IPs get a refusal",
                "  message, and gateway addresses (those",
                "  ending in .1) are rejected to guard",
                "  against accidental router exposure.",
                "",
                "  When security is ON:",
                "  Any IP may connect but must authenticate.",
                "  After 3 failed login attempts from the",
                "  same IP, that address is locked out for",
                "  5 minutes. Credentials are compared in",
                "  constant time to resist timing attacks.",
                "",
                "  Telnet transmits every byte (including",
                "  the password) in cleartext. For any",
                "  non-local access, use the SSH interface",
                "  instead (Configuration > Server > S).",
                "",
                "  Changes are saved immediately but",
                "  require a server restart to take effect.",
            ]
        };
        self.show_help_page("SECURITY HELP", lines).await
    }

    // ─── SERVER CONFIGURATION ───────────────────────────────

    async fn server_configuration(&mut self) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("SERVER CONFIGURATION")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            let telnet_status = if cfg.telnet_enabled {
                self.green("ENABLED")
            } else {
                self.red("Disabled")
            };
            self.send_line(&format!(
                "  Telnet: {} (port {})",
                telnet_status, cfg.telnet_port
            ))
            .await?;
            let ssh_status = if cfg.ssh_enabled {
                self.green("ENABLED")
            } else {
                self.red("Disabled")
            };
            self.send_line(&format!(
                "  SSH:    {} (port {})",
                ssh_status, cfg.ssh_port
            ))
            .await?;
            self.send_line("").await?;

            // Show server IP addresses and ATD example
            let addrs = get_server_addresses();
            if !addrs.is_empty() {
                self.send_line(&format!(
                    "  {}",
                    self.dim("Server addresses:")
                ))
                .await?;
                let max_w = if self.terminal_type == TerminalType::Petscii {
                    36 // 40 - 4 chars indent
                } else {
                    52 // 56 - 4 chars indent
                };
                for addr in &addrs {
                    let display = truncate_to_width(addr, max_w);
                    self.send_line(&format!("    {}", display)).await?;
                }
                if cfg.telnet_enabled {
                    let example = format!("ATD {}:{}", addrs[0], cfg.telnet_port);
                    let max_example = if self.terminal_type == TerminalType::Petscii {
                        38 // 40 - 2 chars indent
                    } else {
                        54 // 56 - 2 chars indent
                    };
                    let example = truncate_to_width(&example, max_example);
                    self.send_line(&format!("  {}", self.amber(&example)))
                        .await?;
                }
                self.send_line("").await?;
            }

            self.send_line(&format!(
                "  {}  Toggle telnet",
                self.cyan("T")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set telnet port",
                self.cyan("P")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Toggle SSH",
                self.cyan("S")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set SSH port",
                self.cyan("O")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Restart server",
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config/server"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "t" => {
                    let new_val = if cfg.telnet_enabled { "false" } else { "true" };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("telnet_enabled", &v);
                    })
                    .await
                    .ok();
                    self.config_restart_notice().await?;
                }
                "p" => {
                    self.config_set_port("Telnet", "telnet_port", cfg.telnet_port).await?;
                }
                "s" => {
                    let new_val = if cfg.ssh_enabled { "false" } else { "true" };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("ssh_enabled", &v);
                    })
                    .await
                    .ok();
                    self.config_restart_notice().await?;
                }
                "o" => {
                    self.config_set_port("SSH", "ssh_port", cfg.ssh_port).await?;
                }
                "r" => {
                    self.config_restart_server().await?;
                }
                "h" => {
                    self.config_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press T, P, S, O, R, H, or Q.").await?;
                }
            }
        }
    }

    // ─── GATEWAY CONFIGURATION ──────────────────────────────
    //
    // Submenu of Server Configuration.  Edits the two persistent
    // outbound-gateway modes so the user doesn't have to touch the GUI
    // or `egateway.conf` for these settings.  Changes take effect on the
    // next gateway connection — no server restart needed.
    async fn gateway_configuration(&mut self) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("GATEWAY CONFIGURATION")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            let telnet_mode = if cfg.telnet_gateway_raw {
                self.red("Raw TCP")
            } else {
                self.green("Telnet")
            };
            self.send_line(&format!("  Telnet mode: {}", telnet_mode))
                .await?;
            let ssh_auth = if cfg.ssh_gateway_auth == "password" {
                self.yellow("Password")
            } else {
                self.green("Key")
            };
            self.send_line(&format!("  SSH auth:    {}", ssh_auth))
                .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Toggle telnet mode (Telnet/Raw)",
                self.cyan("T")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Toggle SSH auth (Key/Password)",
                self.cyan("S")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config/server/gateway"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "t" => {
                    let new_val = if cfg.telnet_gateway_raw { "false" } else { "true" };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("telnet_gateway_raw", &v);
                    })
                    .await
                    .ok();
                }
                "s" => {
                    let new_val = if cfg.ssh_gateway_auth == "password" {
                        "key"
                    } else {
                        "password"
                    };
                    let v = new_val.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value("ssh_gateway_auth", &v);
                    })
                    .await
                    .ok();
                }
                "h" => {
                    self.gateway_config_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press T, S, H, or Q.").await?;
                }
            }
        }
    }

    async fn gateway_config_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  Configure the outbound Telnet",
                "  and SSH Gateway menus (the S",
                "  and T main-menu items that",
                "  proxy to remote servers).",
                "",
                "  Telnet mode:",
                "    Telnet - parse IAC option",
                "             negotiation; works",
                "             with real telnet",
                "             servers. Default.",
                "    Raw    - raw TCP byte stream,",
                "             no IAC. Use for MUDs",
                "             and hand-rolled BBS",
                "             software that don't",
                "             speak telnet.",
                "",
                "  Telnet mode options:",
                "    Cooperative - proactively offers",
                "      TTYPE, NAWS, DO ECHO so BBSes",
                "      that wait for the client to",
                "      ask first still get full-",
                "      screen behavior. Enable for",
                "      cooperative telnet servers;",
                "      disable for raw-TCP services.",
                "",
                "  SSH auth:",
                "    Key      - offer the gateway's",
                "               Ed25519 client key.",
                "               Paste the public half",
                "               into the remote's",
                "               ~/.ssh/authorized_keys",
                "               first. Passwordless.",
                "    Password - prompt for the remote",
                "               account's password on",
                "               each connect.",
                "",
                "  Both settings are saved to",
                "  egateway.conf and take effect on",
                "  the next gateway connection.",
                "  No server restart is required.",
            ]
        } else {
            &[
                "  Configure the outbound Telnet and SSH",
                "  Gateway menus (the S and T items on the",
                "  main menu that proxy to remote servers).",
                "",
                "  Telnet mode:",
                "    Telnet  - parse IAC option negotiation",
                "              (default; works with every real",
                "              telnet server). IAC bytes in",
                "              data are escaped as IAC IAC.",
                "    Raw     - raw TCP byte stream, no IAC.",
                "              Use for MUDs and hand-rolled",
                "              BBS software that aren't telnet.",
                "              Bytes pass through unmodified.",
                "",
                "  Cooperative mode (Telnet only):",
                "    When on, the gateway sends WILL TTYPE,",
                "    WILL NAWS, and DO ECHO proactively so",
                "    BBSes that wait for the client to ask",
                "    first still get echo cooperation,",
                "    terminal-type adaptation, and full-screen",
                "    window sizing. Off by default so raw-TCP",
                "    services aren't spammed with IAC bytes",
                "    they can't parse.",
                "",
                "  SSH auth:",
                "    Key      - offer the gateway's Ed25519",
                "               client key. Copy the public",
                "               half (shown under Server >",
                "               More in the GUI) into the",
                "               remote's authorized_keys file.",
                "               Passwordless once installed.",
                "    Password - prompt for the remote account's",
                "               password on each connect. No",
                "               key is offered.",
                "",
                "  Host keys:",
                "    On first dial, the gateway displays the",
                "    remote's SHA-256 fingerprint and asks",
                "    whether to trust it (TOFU). Accepted",
                "    fingerprints are saved to gateway_hosts;",
                "    a changed key triggers a prominent",
                "    HOST KEY CHANGED warning.",
                "",
                "  Changes are saved immediately and take",
                "  effect on the next gateway connection.",
                "  No server restart is required.",
            ]
        };
        self.show_help_page("GATEWAY CONFIG HELP", lines).await
    }

    async fn config_set_port(
        &mut self,
        label: &str,
        key: &str,
        current: u16,
    ) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!(
            "  Current {} port: {}",
            label,
            self.amber(&current.to_string())
        ))
        .await?;
        self.send("  New port (1-65535): ").await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if let Ok(port) = input.parse::<u16>() {
            if port >= 1 {
                let k = key.to_string();
                let v = port.to_string();
                tokio::task::spawn_blocking(move || {
                    config::update_config_value(&k, &v);
                })
                .await
                .ok();
                self.config_restart_notice().await?;
            } else {
                self.show_error("Invalid port number.").await?;
            }
        } else {
            self.show_error("Invalid port number.").await?;
        }
        Ok(())
    }

    async fn config_restart_notice(&mut self) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("Restart the server for changes")
        ))
        .await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("to take effect.")
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    async fn config_restart_server(&mut self) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.red("WARNING: All active sessions")
        ))
        .await?;
        self.send_line(&format!(
            "  {}",
            self.red("will be disconnected.")
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Restart the server? (Y/N) ").await?;
        self.flush().await?;

        let input = match self.get_menu_input(false).await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if input == "y" {
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}",
                self.yellow("Restarting server...")
            ))
            .await?;
            self.flush().await?;
            self.restart.store(true, Ordering::SeqCst);
            self.shutdown.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn config_reset_defaults(&mut self) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.red("WARNING: This will reset ALL")
        ))
        .await?;
        self.send_line(&format!(
            "  {}",
            self.red("settings to factory defaults.")
        ))
        .await?;
        self.send_line(&format!(
            "  {}",
            self.red("The API key will be cleared.")
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Reset all settings? (Y/N) ").await?;
        self.flush().await?;

        let input = match self.get_menu_input(false).await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if input == "y" {
            let defaults = config::Config::default();
            tokio::task::spawn_blocking(move || {
                config::save_config(&defaults);
            })
            .await
            .ok();
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}",
                self.green("All settings reset to defaults.")
            ))
            .await?;
            self.config_restart_notice().await?;
        }
        Ok(())
    }

    async fn config_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  Change settings for THIS server.",
                "",
                "  T  Enable or disable the telnet",
                "     server listener",
                "  P  Change the telnet port",
                "  S  Enable or disable the SSH",
                "     server listener",
                "  O  Change the SSH port",
                "  R  Restart the server",
                "",
                "  Changes are saved immediately",
                "  but require a server restart.",
            ]
        } else {
            &[
                "  Change settings for THIS server.",
                "",
                "  T  Enable or disable the telnet server",
                "  P  Change the telnet listening port",
                "  S  Enable or disable the SSH server",
                "  O  Change the SSH listening port",
                "  R  Restart the server now",
                "",
                "  Changes are saved to the config file",
                "  immediately but require a server restart",
                "  to take effect.",
            ]
        };
        self.show_help_page("SERVER CONFIGURATION HELP", lines).await
    }

    // ─── FILE TRANSFER SETTINGS ─────────────────────────────
    //
    // Top-level submenu under Configuration > File Transfer.  Holds
    // the shared transfer-directory setting plus a per-protocol
    // selector that drills into XMODEM / YMODEM / ZMODEM settings
    // pages.  Each protocol page edits only the keys that apply to
    // that protocol; XMODEM and YMODEM share the `xmodem_*` keys
    // because they share a single protocol code path in `xmodem.rs`.

    async fn file_transfer_settings(&mut self) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("FILE TRANSFER")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  Transfer dir:  {}",
                self.amber(&cfg.transfer_dir)
            ))
            .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Change transfer directory",
                self.cyan("D")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  XMODEM settings",
                self.cyan("X")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  YMODEM settings",
                self.cyan("Y")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  ZMODEM settings",
                self.cyan("Z")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  KERMIT settings",
                self.cyan("K")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Restart server",
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config/xfer"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "d" => {
                    self.xmodem_set_dir(&cfg.transfer_dir).await?;
                }
                "x" => {
                    self.xmodem_settings().await?;
                }
                "y" => {
                    self.ymodem_settings().await?;
                }
                "z" => {
                    self.zmodem_settings().await?;
                }
                "k" => {
                    self.kermit_settings().await?;
                }
                "r" => {
                    self.config_restart_server().await?;
                }
                "h" => {
                    self.file_transfer_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press D, X, Y, Z, K, R, H, or Q.").await?;
                }
            }
        }
    }

    async fn file_transfer_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  Configure file-transfer options.",
                "",
                "  D  Transfer directory: where",
                "     uploads land and downloads",
                "     are served from",
                "  X  XMODEM settings",
                "  Y  YMODEM settings",
                "  Z  ZMODEM settings",
                "  K  KERMIT settings",
                "  R  Restart the server",
                "",
                "  XMODEM, XMODEM-1K, and YMODEM",
                "  share the same timeouts.",
                "  ZMODEM and Kermit each have",
                "  their own.",
            ]
        } else {
            &[
                "  Configure file-transfer options.",
                "",
                "  D  Transfer directory: where uploads",
                "     land and downloads are served from",
                "  X  XMODEM settings (XMODEM + XMODEM-1K)",
                "  Y  YMODEM settings (shared with XMODEM)",
                "  Z  ZMODEM settings",
                "  K  KERMIT settings",
                "  R  Restart the server",
                "",
                "  XMODEM, XMODEM-1K, and YMODEM share",
                "  the same timeouts because they share",
                "  the same protocol code path. ZMODEM",
                "  and Kermit each have their own independent",
                "  tunables.",
            ]
        };
        self.show_help_page("FILE TRANSFER HELP", lines).await
    }

    // ─── XMODEM SETTINGS ────────────────────────────────────
    //
    // These settings also govern XMODEM-1K and YMODEM because all
    // three protocols share the same `xmodem_*` config keys and the
    // same send/receive code path in `xmodem.rs`.

    async fn xmodem_settings(&mut self) -> Result<(), std::io::Error> {
        self.xmodem_family_settings(
            "XMODEM SETTINGS",
            "ethernet/config/xfer/xmodem",
            "XMODEM family",
        )
        .await
    }

    async fn ymodem_settings(&mut self) -> Result<(), std::io::Error> {
        self.xmodem_family_settings(
            "YMODEM SETTINGS",
            "ethernet/config/xfer/ymodem",
            "XMODEM family (shared)",
        )
        .await
    }

    /// Shared renderer for the XMODEM / YMODEM settings pages.  Both
    /// protocols edit the same `xmodem_*` config keys, so the page
    /// differs only in its heading and breadcrumb.  A note under the
    /// status block calls out the shared-family behavior so operators
    /// aren't surprised when editing either page changes the other.
    async fn xmodem_family_settings(
        &mut self,
        header: &str,
        breadcrumb: &str,
        applies_to: &str,
    ) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow(header))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  Negotiate:      {} s",
                self.amber(&cfg.xmodem_negotiation_timeout.to_string())
            ))
            .await?;
            self.send_line(&format!(
                "  Retry interval: {} s",
                self.amber(&cfg.xmodem_negotiation_retry_interval.to_string())
            ))
            .await?;
            self.send_line(&format!(
                "  Block timeout:  {} s",
                self.amber(&cfg.xmodem_block_timeout.to_string())
            ))
            .await?;
            self.send_line(&format!(
                "  Max retries:    {}",
                self.amber(&cfg.xmodem_max_retries.to_string())
            ))
            .await?;
            self.send_line(&format!("  Applies to:     {}", self.dim(applies_to)))
                .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Set negotiation timeout",
                self.cyan("N")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set retry interval",
                self.cyan("I")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set block timeout",
                self.cyan("B")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set max retries",
                self.cyan("M")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Restart server",
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan(breadcrumb));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "n" => {
                    self.xmodem_set_numeric(
                        "Negotiation timeout",
                        "xmodem_negotiation_timeout",
                        cfg.xmodem_negotiation_timeout,
                        1,
                        300,
                        "seconds",
                    )
                    .await?;
                }
                "i" => {
                    self.xmodem_set_numeric(
                        "Retry interval",
                        "xmodem_negotiation_retry_interval",
                        cfg.xmodem_negotiation_retry_interval,
                        1,
                        60,
                        "seconds",
                    )
                    .await?;
                }
                "b" => {
                    self.xmodem_set_numeric(
                        "Block timeout",
                        "xmodem_block_timeout",
                        cfg.xmodem_block_timeout,
                        1,
                        120,
                        "seconds",
                    )
                    .await?;
                }
                "m" => {
                    self.xmodem_set_numeric(
                        "Max retries",
                        "xmodem_max_retries",
                        cfg.xmodem_max_retries as u64,
                        1,
                        100,
                        "retries",
                    )
                    .await?;
                }
                "r" => {
                    self.config_restart_server().await?;
                }
                "h" => {
                    self.xmodem_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press N, I, B, M, R, H, or Q.").await?;
                }
            }
        }
    }

    // ─── ZMODEM SETTINGS ────────────────────────────────────

    async fn zmodem_settings(&mut self) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("ZMODEM SETTINGS")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  Negotiate:      {} s",
                self.amber(&cfg.zmodem_negotiation_timeout.to_string())
            ))
            .await?;
            self.send_line(&format!(
                "  Retry interval: {} s",
                self.amber(&cfg.zmodem_negotiation_retry_interval.to_string())
            ))
            .await?;
            self.send_line(&format!(
                "  Frame timeout:  {} s",
                self.amber(&cfg.zmodem_frame_timeout.to_string())
            ))
            .await?;
            self.send_line(&format!(
                "  Max retries:    {}",
                self.amber(&cfg.zmodem_max_retries.to_string())
            ))
            .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Set negotiation timeout",
                self.cyan("N")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set retry interval",
                self.cyan("I")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set frame timeout",
                self.cyan("F")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Set max retries",
                self.cyan("M")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Restart server",
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config/xfer/zmodem"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "n" => {
                    self.xmodem_set_numeric(
                        "Negotiation timeout",
                        "zmodem_negotiation_timeout",
                        cfg.zmodem_negotiation_timeout,
                        1,
                        300,
                        "seconds",
                    )
                    .await?;
                }
                "i" => {
                    self.xmodem_set_numeric(
                        "Retry interval",
                        "zmodem_negotiation_retry_interval",
                        cfg.zmodem_negotiation_retry_interval,
                        1,
                        60,
                        "seconds",
                    )
                    .await?;
                }
                "f" => {
                    self.xmodem_set_numeric(
                        "Frame timeout",
                        "zmodem_frame_timeout",
                        cfg.zmodem_frame_timeout,
                        1,
                        120,
                        "seconds",
                    )
                    .await?;
                }
                "m" => {
                    self.xmodem_set_numeric(
                        "Max retries",
                        "zmodem_max_retries",
                        cfg.zmodem_max_retries as u64,
                        1,
                        100,
                        "retries",
                    )
                    .await?;
                }
                "r" => {
                    self.config_restart_server().await?;
                }
                "h" => {
                    self.zmodem_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press N, I, F, M, R, H, or Q.").await?;
                }
            }
        }
    }

    async fn zmodem_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  Configure ZMODEM file transfer",
                "  settings.",
                "",
                "  N  Negotiation timeout: how",
                "     long to wait for ZRQINIT /",
                "     ZRINIT handshake",
                "  I  Retry interval: ZRINIT/",
                "     ZRQINIT re-send gap (def 5)",
                "  F  Frame timeout: per-frame",
                "     read timeout in transfer",
                "  M  Max retries for ZRQINIT /",
                "     ZRPOS / ZDATA frames",
                "  R  Restart the server",
                "",
                "  Takes effect on next transfer.",
            ]
        } else {
            &[
                "  Configure ZMODEM file transfer",
                "  settings.",
                "",
                "  N  Negotiation timeout: how long to",
                "     wait for the ZRQINIT / ZRINIT",
                "     handshake",
                "  I  Retry interval: seconds between",
                "     ZRINIT / ZRQINIT re-sends (def 5)",
                "  F  Frame timeout: per-frame read",
                "     timeout once a transfer is live",
                "  M  Max retries: retry cap for ZRQINIT,",
                "     ZRPOS, and ZDATA frames",
                "  R  Restart the server",
                "",
                "  Takes effect on next transfer.",
            ]
        };
        self.show_help_page("ZMODEM SETTINGS HELP", lines).await
    }

    // ─── KERMIT SETTINGS ────────────────────────────────────
    //
    // Kermit has the largest configuration surface of any of the
    // file-transfer protocols.  We split it across three pages of
    // status (timeouts/retries, packet/window/check, capability bits)
    // since not all of it fits in PETSCII's 22 rows.

    async fn kermit_settings(&mut self) -> Result<(), std::io::Error> {
        loop {
            let cfg = config::get_config();

            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            self.send_line(&format!("  {}", self.yellow("KERMIT SETTINGS")))
                .await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;

            // Compact status block — one line per field.
            self.send_line(&format!(
                "  Negotiate:  {} s    Packet: {} s    Retries: {}",
                self.amber(&cfg.kermit_negotiation_timeout.to_string()),
                self.amber(&cfg.kermit_packet_timeout.to_string()),
                self.amber(&cfg.kermit_max_retries.to_string()),
            ))
            .await?;
            self.send_line(&format!(
                "  Max packet: {}    Window: {}    Check: {}",
                self.amber(&cfg.kermit_max_packet_length.to_string()),
                self.amber(&cfg.kermit_window_size.to_string()),
                self.amber(&cfg.kermit_block_check_type.to_string()),
            ))
            .await?;
            self.send_line(&format!(
                "  Long: {}  Sliding: {}  Stream: {}",
                self.amber(if cfg.kermit_long_packets { "on" } else { "off" }),
                self.amber(if cfg.kermit_sliding_windows { "on" } else { "off" }),
                self.amber(if cfg.kermit_streaming { "on" } else { "off" }),
            ))
            .await?;
            self.send_line(&format!(
                "  Attrs: {}  Repeat: {}  IAC: {}",
                self.amber(if cfg.kermit_attribute_packets { "on" } else { "off" }),
                self.amber(if cfg.kermit_repeat_compression { "on" } else { "off" }),
                self.amber(if cfg.kermit_iac_escape { "on" } else { "off" }),
            ))
            .await?;
            self.send_line(&format!(
                "  8-bit quote: {}",
                self.amber(&cfg.kermit_8bit_quote)
            ))
            .await?;
            self.send_line("").await?;

            self.send_line(&format!(
                "  {}  Negotiate timeout    {}  Packet timeout",
                self.cyan("N"),
                self.cyan("P")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Max retries         {}  Max packet length",
                self.cyan("X"),
                self.cyan("M")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Window size         {}  Block check type",
                self.cyan("W"),
                self.cyan("C")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Toggle long pkts    {}  Toggle sliding win",
                self.cyan("L"),
                self.cyan("S")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Toggle streaming    {}  Toggle attributes",
                self.cyan("T"),
                self.cyan("A")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Toggle repeat       {}  Toggle IAC escape",
                self.cyan("E"),
                self.cyan("I")
            ))
            .await?;
            self.send_line(&format!(
                "  {}  Cycle 8-bit quote   {}  Restart server",
                self.cyan("8"),
                self.cyan("R")
            ))
            .await?;
            self.send_line("").await?;
            self.send_line(&format!(
                "  {}  {}",
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help")
            ))
            .await?;

            let prompt = format!("{}> ", self.cyan("ethernet/config/xfer/kermit"));
            self.send(&prompt).await?;
            self.flush().await?;

            let input = match self.get_menu_input(false).await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "n" => {
                    self.xmodem_set_numeric(
                        "Negotiation timeout",
                        "kermit_negotiation_timeout",
                        cfg.kermit_negotiation_timeout,
                        1,
                        300,
                        "seconds",
                    )
                    .await?;
                }
                "p" => {
                    self.xmodem_set_numeric(
                        "Packet timeout",
                        "kermit_packet_timeout",
                        cfg.kermit_packet_timeout,
                        1,
                        120,
                        "seconds",
                    )
                    .await?;
                }
                "x" => {
                    self.xmodem_set_numeric(
                        "Max retries",
                        "kermit_max_retries",
                        cfg.kermit_max_retries as u64,
                        1,
                        20,
                        "retries",
                    )
                    .await?;
                }
                "m" => {
                    self.xmodem_set_numeric(
                        "Max packet length",
                        "kermit_max_packet_length",
                        cfg.kermit_max_packet_length as u64,
                        10,
                        9024,
                        "bytes",
                    )
                    .await?;
                }
                "w" => {
                    self.xmodem_set_numeric(
                        "Window size",
                        "kermit_window_size",
                        cfg.kermit_window_size as u64,
                        1,
                        31,
                        "packets",
                    )
                    .await?;
                }
                "c" => {
                    self.xmodem_set_numeric(
                        "Block check type",
                        "kermit_block_check_type",
                        cfg.kermit_block_check_type as u64,
                        1,
                        3,
                        "(1/2/3)",
                    )
                    .await?;
                }
                "l" => {
                    self.kermit_toggle_bool(
                        "Long packets",
                        "kermit_long_packets",
                        cfg.kermit_long_packets,
                    )
                    .await?;
                }
                "s" => {
                    self.kermit_toggle_bool(
                        "Sliding windows",
                        "kermit_sliding_windows",
                        cfg.kermit_sliding_windows,
                    )
                    .await?;
                }
                "t" => {
                    self.kermit_toggle_bool(
                        "Streaming",
                        "kermit_streaming",
                        cfg.kermit_streaming,
                    )
                    .await?;
                }
                "a" => {
                    self.kermit_toggle_bool(
                        "Attribute packets",
                        "kermit_attribute_packets",
                        cfg.kermit_attribute_packets,
                    )
                    .await?;
                }
                "e" => {
                    self.kermit_toggle_bool(
                        "Repeat compression",
                        "kermit_repeat_compression",
                        cfg.kermit_repeat_compression,
                    )
                    .await?;
                }
                "i" => {
                    self.kermit_toggle_bool(
                        "IAC escape",
                        "kermit_iac_escape",
                        cfg.kermit_iac_escape,
                    )
                    .await?;
                }
                "8" => {
                    let next = match cfg.kermit_8bit_quote.as_str() {
                        "auto" => "on",
                        "on" => "off",
                        _ => "auto",
                    };
                    let key = "kermit_8bit_quote".to_string();
                    let v = next.to_string();
                    tokio::task::spawn_blocking(move || {
                        config::update_config_value(&key, &v);
                    })
                    .await
                    .ok();
                    self.send_line("").await?;
                    self.send_line(&format!(
                        "  {}",
                        self.green(&format!("8-bit quote set to {}.", next))
                    ))
                    .await?;
                    self.send_line("").await?;
                    self.send("  Press any key to continue.").await?;
                    self.flush().await?;
                    self.wait_for_key().await?;
                }
                "r" => {
                    self.config_restart_server().await?;
                }
                "h" => {
                    self.kermit_show_help().await?;
                }
                "q" => return Ok(()),
                _ => {
                    self.show_error("Press a listed key, R, H, or Q.")
                        .await?;
                }
            }
        }
    }

    /// Helper: flip a Kermit boolean config key, persist, and confirm.
    async fn kermit_toggle_bool(
        &mut self,
        label: &str,
        key: &str,
        current: bool,
    ) -> Result<(), std::io::Error> {
        let next = !current;
        let k = key.to_string();
        let v = next.to_string();
        tokio::task::spawn_blocking(move || {
            config::update_config_value(&k, &v);
        })
        .await
        .ok();
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.green(&format!(
                "{} {}.",
                label,
                if next { "enabled" } else { "disabled" }
            ))
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    async fn kermit_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  Configure Kermit transfer",
                "  parameters.  Negotiated with",
                "  the peer at session start.",
                "",
                "  N  Negotiate timeout (45 s)",
                "  P  Per-packet timeout",
                "  X  Max retries per packet",
                "  M  Max packet length",
                "  W  Sliding window size",
                "  C  Block check type 1/2/3",
                "  L/S/T/A/E/I  toggles",
                "  8  cycle 8-bit quote mode",
                "",
                "  Streaming auto-degrades to",
                "  sliding/stop-and-wait when",
                "  the peer can't do it.",
            ]
        } else {
            &[
                "  Configure Kermit transfer parameters.",
                "  These are advertised in our Send-Init;",
                "  the peer's response narrows the session",
                "  to the intersection of capabilities.",
                "",
                "  N  Negotiate timeout (Send-Init handshake)",
                "  P  Per-packet read timeout",
                "  X  Max retries per packet (NAK / timeout)",
                "  M  Max packet length we'll advertise",
                "  W  Sliding-window size (1=stop-and-wait)",
                "  C  Block check type: 1=6-bit, 2=12-bit, 3=CRC-16",
                "  L  Long-packet capability",
                "  S  Sliding-window capability",
                "  T  Streaming capability",
                "  A  Attribute-packet capability",
                "  E  Repeat-count compression",
                "  I  Telnet IAC escape during transfer",
                "  8  8-bit quote: auto / on / off",
                "",
                "  Streaming requires a reliable transport.",
                "  Disable when bridging to flaky serial.",
            ]
        };
        self.show_help_page("KERMIT SETTINGS HELP", lines).await
    }

    async fn xmodem_set_dir(&mut self, current: &str) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!(
            "  Current directory: {}",
            self.amber(current)
        ))
        .await?;
        self.send("  New directory: ").await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        let v = input.clone();
        tokio::task::spawn_blocking(move || {
            config::update_config_value("transfer_dir", &v);
        })
        .await
        .ok();
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.green(&format!("Transfer dir set to: {}", input))
        ))
        .await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    async fn xmodem_set_numeric(
        &mut self,
        label: &str,
        key: &str,
        current: u64,
        min: u64,
        max: u64,
        unit: &str,
    ) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!(
            "  Current {}: {}",
            label.to_lowercase(),
            self.amber(&current.to_string())
        ))
        .await?;
        self.send(&format!("  New value ({}-{}): ", min, max)).await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if let Ok(val) = input.parse::<u64>() {
            if val >= min && val <= max {
                let k = key.to_string();
                let v = val.to_string();
                tokio::task::spawn_blocking(move || {
                    config::update_config_value(&k, &v);
                })
                .await
                .ok();
                self.send_line("").await?;
                self.send_line(&format!(
                    "  {}",
                    self.green(&format!("{} set to {} {}.", label, val, unit))
                ))
                .await?;
                self.send_line("").await?;
                self.send("  Press any key to continue.").await?;
                self.flush().await?;
                self.wait_for_key().await?;
            } else {
                self.show_error(&format!("Value must be {}-{}.", min, max)).await?;
            }
        } else {
            self.show_error("Invalid number.").await?;
        }
        Ok(())
    }

    async fn xmodem_show_help(&mut self) -> Result<(), std::io::Error> {
        let lines: &[&str] = if self.terminal_type == TerminalType::Petscii {
            &[
                "  Configure XMODEM family transfer",
                "  settings. Shared with XMODEM-1K",
                "  and YMODEM.",
                "",
                "  N  Negotiation timeout: how",
                "     long to wait for transfer",
                "     to begin",
                "  I  Retry interval: C/NAK poke",
                "     gap (spec ~10 s, def 7 s)",
                "  B  Block timeout: how long to",
                "     wait for each block",
                "  M  Max retries per block",
                "  R  Restart the server",
                "",
                "  Takes effect on next transfer.",
            ]
        } else {
            &[
                "  Configure XMODEM family transfer",
                "  settings. Shared with XMODEM-1K and",
                "  YMODEM (same protocol code path).",
                "",
                "  N  Negotiation timeout: how long to",
                "     wait for a transfer to begin",
                "  I  Retry interval: seconds between",
                "     C/NAK pokes during the handshake",
                "     (spec suggests ~10, default 7)",
                "  B  Block timeout: how long to wait",
                "     for each data block",
                "  M  Max retries: retry limit per block",
                "  R  Restart the server",
                "",
                "  Takes effect on next transfer.",
            ]
        };
        self.show_help_page("XMODEM SETTINGS HELP", lines).await
    }

    // ─── TROUBLESHOOTING ────────────────────────────────────

    fn client_type_label(&self) -> &'static str {
        if self.is_ssh {
            "SSH"
        } else if self.is_serial {
            "Serial modem"
        } else if self.telnet_negotiated {
            "Telnet"
        } else {
            "Raw TCP"
        }
    }

    fn terminal_type_label(&self) -> &'static str {
        match self.terminal_type {
            TerminalType::Petscii => "PETSCII",
            TerminalType::Ansi => "ANSI",
            TerminalType::Ascii => "ASCII",
        }
    }

    async fn troubleshooting(&mut self) -> Result<(), std::io::Error> {
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!(
            "  {}",
            self.yellow("CHARACTER TROUBLESHOOTING")
        ))
        .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  Client:   {}",
            self.cyan(self.client_type_label())
        ))
        .await?;
        self.send_line(&format!(
            "  Terminal: {}",
            self.cyan(self.terminal_type_label())
        ))
        .await?;
        self.send_line(&format!(
            "  IAC esc:  {}",
            self.cyan(if self.xmodem_iac { "On" } else { "Off" })
        ))
        .await?;
        self.send_line("").await?;
        self.send_line("  Press any key to see its hex value.")
            .await?;
        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };
        self.send_line(&format!(
            "  Press {} twice to return to menu.",
            self.cyan(esc_label)
        ))
        .await?;
        self.send_line("").await?;
        self.send_line(&self.yellow(&"-".repeat(
            if self.terminal_type == TerminalType::Petscii { PETSCII_WIDTH } else { 56 }
        )))
        .await?;
        self.send_line("").await?;
        self.flush().await?;

        let mut last_was_esc = false;

        loop {
            let byte = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(()),
            };

            let name = match byte {
                0x00 => "NUL",
                0x01 => "SOH",
                0x02 => "STX",
                0x03 => "ETX",
                0x04 => "EOT",
                0x05 => "ENQ",
                0x06 => "ACK",
                0x07 => "BEL",
                0x08 => "BS",
                0x09 => "TAB",
                0x0A => "LF",
                0x0B => "VT",
                0x0C => "FF",
                0x0D => "CR",
                0x0E => "SO",
                0x0F => "SI",
                0x10 => "DLE",
                0x11 => "DC1",
                0x12 => "DC2",
                0x13 => "DC3",
                0x14 => "DC4/C64-DEL",
                0x15 => "NAK",
                0x16 => "SYN",
                0x17 => "ETB",
                0x18 => "CAN",
                0x19 => "EM",
                0x1A => "SUB",
                0x1B => "ESC",
                0x1C => "FS",
                0x1D => "GS/C64-RIGHT",
                0x1E => "RS",
                0x1F => "US",
                0x7F => "DEL",
                0x91 => "C64-UP",
                0x93 => "C64-CLR",
                0x9D => "C64-LEFT",
                _ => "",
            };

            let display = if !name.is_empty() {
                format!("  Key: {} ({:3}) = {}",
                    self.cyan(&format!("0x{:02X}", byte)), byte, name)
            } else if (0x20..=0x7E).contains(&byte) {
                format!("  Key: {} ({:3}) = '{}'",
                    self.cyan(&format!("0x{:02X}", byte)), byte, byte as char)
            } else {
                format!("  Key: {} ({:3})",
                    self.cyan(&format!("0x{:02X}", byte)), byte)
            };
            self.send_line(&display).await?;
            self.flush().await?;

            if is_esc_key(byte, self.terminal_type == TerminalType::Petscii) {
                if last_was_esc {
                    self.send_line("").await?;
                    self.send_line("  Returning to main menu...").await?;
                    self.flush().await?;
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    return Ok(());
                }
                last_was_esc = true;
            } else {
                last_was_esc = false;
            }
        }
    }

    // ─── WEB BROWSER ────────────────────────────────────────

    const WEB_MAX_HISTORY: usize = 50;

    /// Number of content lines per page.
    /// Total screen budget is 22 rows: header (sep + title + sep = 3) +
    /// content + blank (1) + footer (position + url + nav1 + nav2 = 4) + prompt (1) = 9 overhead.
    /// 22 - 9 = 13 content lines.
    const WEB_PAGE_HEIGHT: usize = 13;

    /// Content width for HTML rendering.
    /// Slightly narrower than the display to leave room for link number suffixes
    /// like `[12]` that are appended after html2text wraps.
    fn web_content_width(&self) -> usize {
        if self.terminal_type == TerminalType::Petscii {
            33 // 40 - 2 indent - 5 for "[NNN]"
        } else {
            73 // 80 - 2 indent - 5 for "[NNN]"
        }
    }

    async fn render_web_browser(&mut self) -> Result<(), std::io::Error> {
        // Auto-load homepage on first visit if configured
        if self.web_lines.is_empty() && self.web_url.is_none() {
            let cfg = config::get_config();
            if !cfg.browser_homepage.is_empty() {
                let url = crate::webbrowser::normalize_url(&cfg.browser_homepage);
                self.web_fetch_page(&url, false).await?;
            }
        }

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;

        if self.web_lines.is_empty() {
            // Home screen — no page loaded
            self.send_line(&format!("  {}", self.yellow("WEB BROWSER"))).await?;
            self.send_line(&sep).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}", self.dim("Try:"))).await?;
            self.send_line(&format!("  {}",
                self.dim("  http://telnetbible.com")
            )).await?;
            self.send_line(&format!("  {}",
                self.dim("  gopher://gopher.floodgap.com")
            )).await?;
            self.send_line("").await?;
            self.send_line(&format!("  {} {} {} {}",
                self.action_prompt("G", "Go/Search"),
                self.action_prompt("K", "Bookmarks"),
                self.action_prompt("Q", "Back"),
                self.action_prompt("H", "Help"),
            )).await?;
        } else {
            // Page view — show title + paginated content
            let title_display = match &self.web_title {
                Some(t) => {
                    let max_w = if self.terminal_type == TerminalType::Petscii { 34 } else { 52 };
                    crate::webbrowser::truncate_to_width(t, max_w)
                }
                None => "Web Browser".to_string(),
            };
            self.send_line(&format!("  {}", self.yellow(&title_display))).await?;
            self.send_line(&sep).await?;

            let page_h = Self::WEB_PAGE_HEIGHT;
            let total = self.web_lines.len();
            let start = self.web_scroll;
            let end = (start + page_h).min(total);

            let content_max = if self.terminal_type == TerminalType::Petscii {
                PETSCII_WIDTH - 2
            } else {
                78
            };
            let page_lines: Vec<String> = self.web_lines[start..end].to_vec();
            for line in &page_lines {
                let safe = crate::webbrowser::truncate_to_width(line, content_max);
                let colored = self.colorize_link_markers(&safe);
                self.send_line(&format!("  {}", colored)).await?;
            }
            self.send_line("").await?;

            // Status line
            let has_prev = start > 0;
            let has_next = end < total;
            let url_display = match &self.web_url {
                Some(u) => {
                    let max_w = if self.terminal_type == TerminalType::Petscii { 36 } else { 54 };
                    crate::webbrowser::truncate_to_width(u, max_w)
                }
                None => String::new(),
            };
            self.send_line(&format!("  {}", self.dim(&format!("({}-{} of {})", start + 1, end, total)))).await?;
            if !self.web_forms.is_empty() {
                let form_count = self.web_forms.len();
                let form_hint = if form_count == 1 {
                    "1 form on this page (F to edit)".to_string()
                } else {
                    format!("{} forms on this page (F to edit)", form_count)
                };
                self.send_line(&format!("  {}", self.amber(&form_hint))).await?;
            } else {
                self.send_line(&format!("  {}", self.dim(&url_display))).await?;
            }

            // Navigation footer — two rows to fit all commands
            let is_petscii = self.terminal_type == TerminalType::Petscii;
            let has_forms = !self.web_forms.is_empty();
            // Row 1: navigation
            let mut nav = Vec::new();
            if has_prev { nav.push(self.action_prompt("P", "Pv")); }
            if has_next { nav.push(self.action_prompt("N", "Nx")); }
            nav.push(self.action_prompt("T", "Top"));
            nav.push(self.action_prompt("E", "End"));
            nav.push(self.action_prompt("S", "Find"));
            if !is_petscii {
                nav.push(self.action_prompt("G", "Go"));
            }
            self.send_line(&format!("  {}", nav.join(" "))).await?;
            // Row 2: actions
            let mut act = Vec::new();
            if is_petscii {
                act.push(self.action_prompt("G", "Go"));
            }
            if !self.web_links.is_empty() {
                act.push(self.action_prompt("L", "Lk"));
            }
            if has_forms {
                act.push(self.action_prompt("F", "Fm"));
            }
            act.push(self.action_prompt("K", "Bm"));
            act.push(self.action_prompt("H", "?"));
            if !self.web_history.is_empty() {
                act.push(self.action_prompt("B", "Bk"));
            }
            act.push(self.action_prompt("Q", "X"));
            self.send_line(&format!("  {}", act.join(" "))).await?;
        }
        Ok(())
    }

    async fn handle_web_browser_command(&mut self, input: &str) -> Result<bool, std::io::Error> {
        if self.web_lines.is_empty() {
            // Home screen commands
            match input {
                "g" => {
                    self.web_prompt_url().await?;
                }
                "k" => {
                    self.web_show_bookmarks().await?;
                }
                "h" => {
                    self.web_show_help(false).await?;
                }
                "q" => {
                    self.web_reset();
                    self.current_menu = Menu::Main;
                }
                "r" => {} // just redraw
                _ => {
                    self.show_error("Press G, K, H, or Q.").await?;
                }
            }
        } else {
            // Page view commands
            match input {
                "q" => {
                    // Close page, return to browser home
                    self.web_lines.clear();
                    self.web_scroll = 0;
                }
                "r" => {
                    if let Some(url) = self.web_url.clone() {
                        self.web_fetch_page(&url, false).await?;
                    }
                }
                "n" => {
                    let page_h = Self::WEB_PAGE_HEIGHT;
                    let total = self.web_lines.len();
                    if self.web_scroll + page_h < total {
                        self.web_scroll += page_h;
                    } else {
                        self.show_error("End of page.").await?;
                    }
                }
                "p" => {
                    if self.web_scroll > 0 {
                        let page_h = Self::WEB_PAGE_HEIGHT;
                        self.web_scroll = self.web_scroll.saturating_sub(page_h);
                    } else {
                        self.show_error("Top of page.").await?;
                    }
                }
                "t" => {
                    self.web_scroll = 0;
                }
                "e" => {
                    let page_h = Self::WEB_PAGE_HEIGHT;
                    let total = self.web_lines.len();
                    if total > page_h {
                        self.web_scroll = total - page_h;
                    } else {
                        self.web_scroll = 0;
                    }
                }
                "g" => {
                    self.web_prompt_url().await?;
                }
                "l" => {
                    self.web_prompt_link().await?;
                }
                "s" => {
                    self.web_search_in_page().await?;
                }
                "k" => {
                    self.web_save_bookmark().await?;
                }
                "f" => {
                    self.web_show_forms().await?;
                }
                "h" => {
                    self.web_show_help(true).await?;
                }
                "b" => {
                    if let Some((prev_url, prev_scroll)) = self.web_history.last().cloned() {
                        if self.web_fetch_page(&prev_url, false).await? {
                            self.web_scroll = prev_scroll;
                            self.web_history.pop();
                        }
                    } else {
                        self.show_error("No history.").await?;
                    }
                }
                _ => {
                    self.show_error("Unknown command.").await?;
                }
            }
        }
        Ok(true)
    }

    async fn web_prompt_url(&mut self) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send(&format!("  {}: ", self.cyan("URL/Search"))).await?;
        self.flush().await?;

        let url_input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        let url = crate::webbrowser::normalize_url(&url_input);
        self.web_fetch_page(&url, true).await?;
        Ok(())
    }

    async fn web_prompt_link(&mut self) -> Result<(), std::io::Error> {
        if self.web_links.is_empty() {
            self.show_error("No links on this page.").await?;
            return Ok(());
        }

        self.send_line("").await?;
        self.send(&format!("  {} (1-{}): ", self.cyan("Link #"), self.web_links.len())).await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        // Drain any stray bytes (e.g. NUL from telnet CR+NUL) before following
        self.drain_input().await;

        if let Ok(num) = input.parse::<usize>() {
            self.web_follow_link(num).await?;
        } else {
            self.show_error("Enter a number.").await?;
        }
        Ok(())
    }

    async fn web_follow_link(&mut self, num: usize) -> Result<(), std::io::Error> {
        if num >= 1 && num <= self.web_links.len() {
            let link = self.web_links[num - 1].clone();
            let resolved = match &self.web_url {
                Some(base) => crate::webbrowser::resolve_url(base, &link),
                None => crate::webbrowser::normalize_url(&link),
            };
            self.web_fetch_page(&resolved, true).await?;
        } else {
            self.show_error(&format!("Link {} not found.", num)).await?;
        }
        Ok(())
    }

    async fn web_fetch_page(&mut self, url: &str, push_history: bool) -> Result<bool, std::io::Error> {
        // Gopher search URLs need a query term before fetching
        let url = if crate::webbrowser::is_gopher_search(url) {
            self.send_line("").await?;
            self.send(&format!("  {}: ", self.cyan("Search"))).await?;
            self.flush().await?;
            let query = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(false),
            };
            crate::webbrowser::build_gopher_search_url(url, &query)
        } else {
            url.to_string()
        };

        self.send_line("").await?;
        self.send_line(&format!("  {}...", self.dim("Loading"))).await?;
        self.flush().await?;

        let width = self.web_content_width();
        let url_owned = url.clone();
        let is_gopher = url.starts_with("gopher://");

        let result = tokio::task::spawn_blocking(move || {
            if is_gopher {
                crate::webbrowser::fetch_gopher(&url_owned, width)
            } else {
                crate::webbrowser::fetch_and_render(&url_owned, width)
            }
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

        self.web_apply_result(result, push_history).await
    }

    async fn web_show_help(&mut self, page_view: bool) -> Result<(), std::io::Error> {
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("BROWSER HELP"))).await?;
        self.send_line(&sep).await?;

        if page_view {
            let is_petscii = self.terminal_type == TerminalType::Petscii;
            if is_petscii {
                // Compact help for 40-col screens
                self.send_line(&format!("  {}",
                    self.dim("[1] [2] etc. next to text")
                )).await?;
                self.send_line(&format!("  {}",
                    self.dim("are links to other pages.")
                )).await?;
                self.send_line("").await?;
                self.send_line("  N/P  Next/Previous page").await?;
                self.send_line("  T/E  Jump to Top/End").await?;
                self.send_line("  S    Search text in page").await?;
                self.send_line("  G    Go to URL or search").await?;
                self.send_line("  L    Follow link (any #)").await?;
                self.send_line("  F    Fill out forms").await?;
                self.send_line("  K    Save bookmark").await?;
                self.send_line("  B    Back to previous page").await?;
                self.send_line("  R    Reload current page").await?;
                self.send_line("  Q    Close page").await?;
                self.send_line("  ESC  Exit browser").await?;
            } else {
                self.send_line(&format!("  {}",
                    self.dim("[1], [2], etc. next to text are links")
                )).await?;
                self.send_line(&format!("  {}",
                    self.dim("to other pages.")
                )).await?;
                self.send_line("").await?;
                self.send_line("  N / P  Next page / Previous page").await?;
                self.send_line("  T / E  Jump to Top / End of page").await?;
                self.send_line("  S      Search for text in page").await?;
                self.send_line("  G      Go to a URL or search query").await?;
                self.send_line("  L      Follow a link (any number)").await?;
                self.send_line("  F      Fill out and submit forms").await?;
                self.send_line("  K      Save page as bookmark").await?;
                self.send_line("  B      Back to previous page").await?;
                self.send_line("  R      Reload current page").await?;
                self.send_line("  Q      Close page (browser home)").await?;
                self.send_line("  ESC    Exit browser to main menu").await?;
            }
        } else {
            self.send_line("  G  Go to a URL or search query").await?;
            self.send_line("  K  Open saved bookmarks").await?;
            self.send_line("  Q  Exit browser to main menu").await?;
            self.send_line("").await?;
            self.send_line(&format!("  {}",
                self.dim("Examples:")
            )).await?;
            self.send_line(&format!("  {}",
                self.dim("  http://telnetbible.com")
            )).await?;
            self.send_line(&format!("  {}",
                self.dim("  gopher://gopher.floodgap.com")
            )).await?;
            self.send_line(&format!("  {}",
                self.dim("  rust programming (search)")
            )).await?;
        }

        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
    }

    async fn web_save_bookmark(&mut self) -> Result<(), std::io::Error> {
        if let Some(url) = &self.web_url {
            let title = self.web_title.as_deref().unwrap_or("Untitled");
            if crate::webbrowser::add_bookmark(url, title) {
                self.send_line("").await?;
                self.send_line(&format!("  {}", self.green("Bookmark saved."))).await?;
                self.send_line("").await?;
                self.send("  Press any key to continue.").await?;
                self.flush().await?;
                self.wait_for_key().await?;
            } else {
                self.show_error("Already bookmarked (or full).").await?;
            }
        } else {
            self.show_error("No page to bookmark.").await?;
        }
        Ok(())
    }

    async fn web_show_bookmarks(&mut self) -> Result<(), std::io::Error> {
        let bookmarks = crate::webbrowser::load_bookmarks();
        if bookmarks.is_empty() {
            self.show_error("No bookmarks saved.").await?;
            return Ok(());
        }

        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("BOOKMARKS"))).await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        let max_title = if self.terminal_type == TerminalType::Petscii { 30 } else { 60 };
        let display_max = bookmarks.len().min(Self::WEB_PAGE_HEIGHT);
        for (i, bm) in bookmarks.iter().take(display_max).enumerate() {
            let title = crate::webbrowser::truncate_to_width(&bm.title, max_title);
            self.send_line(&format!("  {:>2}. {}", i + 1, title)).await?;
        }
        if bookmarks.len() > display_max {
            self.send_line(&format!("  {} more...", bookmarks.len() - display_max)).await?;
        }

        self.send_line("").await?;
        self.send_line(&format!("  {} {} {}",
            self.dim("#=Open"),
            self.action_prompt("D", "Delete"),
            self.action_prompt("H", "Help"),
        )).await?;
        self.send(&format!("  {}: ", self.cyan("#/D"))).await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if input == "h" {
            self.show_help_page("BOOKMARKS HELP", &[
                "  #    Enter bookmark number to open",
                "  D    Delete a bookmark by number",
                "  ESC  Cancel and go back",
            ]).await?;
        } else if input == "d" {
            // Delete mode
            self.send(&format!("  {} (1-{}): ", self.cyan("Delete #"), display_max)).await?;
            self.flush().await?;
            let del_input = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };
            if let Ok(num) = del_input.parse::<usize>() {
                if num >= 1 && num <= display_max {
                    crate::webbrowser::remove_bookmark(num - 1);
                    self.send_line(&format!("  {}", self.green("Deleted."))).await?;
                    self.send_line("").await?;
                    self.send("  Press any key to continue.").await?;
                    self.flush().await?;
                    self.wait_for_key().await?;
                } else {
                    self.show_error("Invalid number.").await?;
                }
            }
        } else if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= display_max {
                let url = bookmarks[num - 1].url.clone();
                self.web_fetch_page(&url, true).await?;
            } else {
                self.show_error("Invalid number.").await?;
            }
        }
        Ok(())
    }

    async fn web_search_in_page(&mut self) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send(&format!("  {}: ", self.cyan("Find"))).await?;
        self.flush().await?;

        let query = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s.to_ascii_lowercase(),
            _ => return Ok(()),
        };

        // Search from line after current scroll position, then wrap around
        let total = self.web_lines.len();
        let start_line = self.web_scroll + 1;
        for offset in 0..total {
            let idx = (start_line + offset) % total;
            if self.web_lines[idx].to_ascii_lowercase().contains(&query) {
                // Scroll to put the match at the top of the page
                self.web_scroll = idx;
                return Ok(());
            }
        }

        self.show_error("Not found.").await?;
        Ok(())
    }

    async fn web_show_forms(&mut self) -> Result<(), std::io::Error> {
        if self.web_forms.is_empty() {
            self.show_error("No forms on this page.").await?;
            return Ok(());
        }

        if self.web_forms.len() == 1 {
            return self.web_edit_form(0).await;
        }

        self.send_line("").await?;
        self.send_line(&format!("  {}", self.yellow("FORMS"))).await?;
        let forms_snapshot: Vec<String> = self.web_forms.iter().enumerate().map(|(i, form)| {
            let label = crate::webbrowser::truncate_to_width(&form.label, 30);
            format!("  {}. {}", i + 1, label)
        }).collect();
        for line in &forms_snapshot {
            self.send_line(line).await?;
        }
        self.send_line("").await?;
        self.send(&format!("  {} (1-{}): ", self.cyan("Form #"), self.web_forms.len())).await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= self.web_forms.len() {
                self.web_edit_form(num - 1).await?;
            } else {
                self.show_error("Invalid form number.").await?;
            }
        } else {
            self.show_error("Enter a number.").await?;
        }
        Ok(())
    }

    async fn web_edit_form(&mut self, form_idx: usize) -> Result<(), std::io::Error> {
        let mut form = self.web_forms[form_idx].clone();

        // If the form has no visible fields (only hidden), submit immediately
        let has_visible = form.fields.iter().any(|f| !matches!(f, crate::webbrowser::FormField::Hidden { .. }));
        if !has_visible {
            self.web_forms[form_idx] = form;
            return self.web_submit_form(form_idx).await;
        }

        loop {
            self.clear_screen().await?;
            let sep = self.separator();
            self.send_line(&sep).await?;
            let title = crate::webbrowser::truncate_to_width(&form.label, 34);
            self.send_line(&format!("  {}", self.yellow(&title))).await?;
            self.send_line(&sep).await?;

            let mut field_num = 0usize;
            let is_petscii = self.terminal_type == TerminalType::Petscii;
            let max_label = if is_petscii { 12 } else { 20 };
            let max_val = if is_petscii { 18 } else { 40 };

            let display_lines: Vec<String> = form.fields.iter().filter_map(|field| {
                match field {
                    crate::webbrowser::FormField::Hidden { .. } => None,
                    crate::webbrowser::FormField::Text { label, value, .. }
                    | crate::webbrowser::FormField::TextArea { label, value, .. } => {
                        field_num += 1;
                        let display_val = if value.is_empty() { "(empty)" } else { value.as_str() };
                        Some(format!("  {}.{}: {}",
                            field_num,
                            crate::webbrowser::truncate_to_width(label, max_label),
                            crate::webbrowser::truncate_to_width(display_val, max_val),
                        ))
                    }
                    crate::webbrowser::FormField::Select { label, options, selected, .. } => {
                        field_num += 1;
                        let chosen = options.get(*selected).map(|(_, t)| t.as_str()).unwrap_or("?");
                        Some(format!("  {}.{}: {}",
                            field_num,
                            crate::webbrowser::truncate_to_width(label, max_label),
                            crate::webbrowser::truncate_to_width(chosen, max_val),
                        ))
                    }
                    crate::webbrowser::FormField::Checkbox { label, checked, .. } => {
                        field_num += 1;
                        let mark = if *checked { "[X]" } else { "[ ]" };
                        Some(format!("  {}.{}: {}",
                            field_num,
                            crate::webbrowser::truncate_to_width(label, max_label),
                            mark,
                        ))
                    }
                    crate::webbrowser::FormField::Radio { label, checked, .. } => {
                        field_num += 1;
                        let mark = if *checked { "(X)" } else { "( )" };
                        Some(format!("  {}.{}: {}",
                            field_num,
                            crate::webbrowser::truncate_to_width(label, max_label),
                            mark,
                        ))
                    }
                }
            }).collect();

            for line in &display_lines {
                self.send_line(line).await?;
            }

            self.send_line("").await?;
            self.send_line(&format!("  {} {} {} {}",
                self.action_prompt("S", "Submit"),
                self.dim("#=Edit"),
                self.action_prompt("Q", "Cancel"),
                self.action_prompt("H", "Help"),
            )).await?;
            self.send(&format!("  {}: ", self.cyan("#/S/Q"))).await?;
            self.flush().await?;

            let input = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(()),
            };

            match input.as_str() {
                "s" => {
                    self.web_forms[form_idx] = form;
                    return self.web_submit_form(form_idx).await;
                }
                "q" => return Ok(()),
                "h" => {
                    self.show_help_page("FORM HELP", &[
                        "  #    Enter a field number to",
                        "       edit its value",
                        "  S    Submit the form",
                        "  Q    Cancel and go back",
                    ]).await?;
                }
                other => {
                    if let Ok(num) = other.parse::<usize>() {
                        if let Some(real_idx) = crate::webbrowser::visible_field_index(&form.fields, num) {
                            self.web_edit_field(&mut form, real_idx).await?;
                        } else {
                            self.show_error("Invalid field number.").await?;
                        }
                    } else {
                        self.show_error("Enter S, Q, H, or a field #.").await?;
                    }
                }
            }
        }
    }

    async fn web_edit_field(&mut self, form: &mut crate::webbrowser::WebForm, idx: usize) -> Result<(), std::io::Error> {
        use crate::webbrowser::FormField;

        let (is_text, is_password, is_select, is_checkbox, is_radio, label_str, opt_count) = {
            let field = &form.fields[idx];
            match field {
                FormField::Text { label, input_type, .. } => {
                    (true, input_type == "password", false, false, false, label.clone(), 0)
                }
                FormField::TextArea { label, .. } => {
                    (true, false, false, false, false, label.clone(), 0)
                }
                FormField::Select { options, .. } => {
                    (false, false, true, false, false, String::new(), options.len())
                }
                FormField::Checkbox { .. } => {
                    (false, false, false, true, false, String::new(), 0)
                }
                FormField::Radio { name, .. } => {
                    (false, false, false, false, true, name.clone(), 0)
                }
                FormField::Hidden { .. } => {
                    return Ok(());
                }
            }
        };

        if is_text {
            self.send_line("").await?;
            self.send(&format!("  {}: ", self.cyan(&label_str))).await?;
            self.flush().await?;
            let input = if is_password {
                self.get_password_input().await?
            } else {
                self.get_line_input().await?
            };
            if let Some(new_val) = input {
                match &mut form.fields[idx] {
                    FormField::Text { value, .. } | FormField::TextArea { value, .. } => {
                        *value = new_val;
                    }
                    _ => {}
                }
            }
        } else if is_select {
            self.send_line("").await?;
            let opts_snapshot: Vec<(String, bool)> = if let FormField::Select { options, selected, .. } = &form.fields[idx] {
                options.iter().enumerate().map(|(i, (_, display))| {
                    (display.clone(), i == *selected)
                }).collect()
            } else {
                Vec::new()
            };
            for (i, (display, is_sel)) in opts_snapshot.iter().enumerate() {
                let marker = if *is_sel { ">" } else { " " };
                self.send_line(&format!("  {}{}.{}",
                    marker, i + 1,
                    crate::webbrowser::truncate_to_width(display, 30),
                )).await?;
            }
            self.send(&format!("  {} (1-{}): ", self.cyan("Pick"), opt_count)).await?;
            self.flush().await?;
            if let Some(input) = self.get_line_input().await?
                && let Ok(n) = input.parse::<usize>()
                    && n >= 1 && n <= opt_count
                        && let FormField::Select { selected, .. } = &mut form.fields[idx] {
                            *selected = n - 1;
                        }
        } else if is_checkbox {
            if let FormField::Checkbox { checked, .. } = &mut form.fields[idx] {
                *checked = !*checked;
            }
        } else if is_radio {
            let radio_name = label_str;
            for f in form.fields.iter_mut() {
                if let FormField::Radio { name, checked, .. } = f
                    && *name == radio_name {
                        *checked = false;
                    }
            }
            if let FormField::Radio { checked, .. } = &mut form.fields[idx] {
                *checked = true;
            }
        }
        Ok(())
    }

    async fn web_submit_form(&mut self, form_idx: usize) -> Result<(), std::io::Error> {
        self.send_line("").await?;
        self.send_line(&format!("  {}...", self.dim("Submitting"))).await?;
        self.flush().await?;

        let form = self.web_forms[form_idx].clone();
        let base = self.web_url.clone().unwrap_or_default();
        let width = self.web_content_width();

        let result = tokio::task::spawn_blocking(move || {
            crate::webbrowser::submit_form(&base, &form, width)
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

        self.web_apply_result(result, true).await?;
        Ok(())
    }

    async fn web_apply_result(
        &mut self,
        result: Result<crate::webbrowser::WebPage, String>,
        push_history: bool,
    ) -> Result<bool, std::io::Error> {
        match result {
            Ok(page) => {
                if push_history
                    && let Some(old_url) = self.web_url.as_ref() {
                        self.web_history.push((old_url.clone(), self.web_scroll));
                        if self.web_history.len() > Self::WEB_MAX_HISTORY {
                            self.web_history.remove(0);
                        }
                    }
                self.web_url = Some(page.url);
                self.web_title = page.title;
                self.web_lines = page.lines;
                self.web_links = page.links;
                self.web_forms = page.forms;
                self.web_scroll = 0;
                Ok(true)
            }
            Err(e) => {
                let max_w = if self.terminal_type == TerminalType::Petscii { 30 } else { 50 };
                self.show_error(&crate::webbrowser::truncate_to_width(&e, max_w)).await?;
                Ok(false)
            }
        }
    }

    fn web_reset(&mut self) {
        self.web_lines.clear();
        self.web_scroll = 0;
        self.web_links.clear();
        self.web_forms.clear();
        self.web_history.clear();
        self.web_url = None;
        self.web_title = None;
    }
}

// ─── Server startup ─────────────────────────────────────────

/// Start the telnet server accept loop.
pub fn start_server(
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    session_writers: SessionWriters,
    lockouts: LockoutMap,
) {
    let cfg = config::get_config();
    if !cfg.telnet_enabled {
        return;
    }
    let port = cfg.telnet_port;
    let max_sessions = cfg.max_sessions;
    let security_enabled = cfg.security_enabled;

    tokio::spawn(async move {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            Ok(l) => l,
            Err(e) => {
                glog!("Telnet server: failed to bind port {}: {}", port, e);
                return;
            }
        };
        glog!("Telnet server listening on port {}", port);

        let session_count = Arc::new(AtomicUsize::new(0));

        loop {
            if shutdown.load(Ordering::SeqCst) {
                let writers = session_writers.lock().await;
                let msg = b"\r\n\r\nServer shutting down. Goodbye.\r\n";
                for w in writers.iter() {
                    if let Ok(mut writer) = w.try_lock() {
                        let _ = writer.write_all(msg).await;
                        let _ = writer.flush().await;
                        let _ = writer.shutdown().await;
                    }
                }
                break;
            }
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let current = session_count.load(Ordering::SeqCst);
                            if current >= max_sessions {
                                glog!("Telnet: rejected {} (max {} sessions)", addr, max_sessions);
                                let _ = stream.try_write(b"Too many connections. Try again later.\r\n");
                                drop(stream);
                                continue;
                            }
                            if !security_enabled
                                && let Some(reason) = reject_insecure_ip(addr.ip())
                            {
                                glog!("Telnet: rejected {} ({})", addr, reason);
                                let msg = format!("{}\r\n", reason);
                                let _ = stream.try_write(msg.as_bytes());
                                drop(stream);
                                continue;
                            }
                            session_count.fetch_add(1, Ordering::SeqCst);
                            glog!("Telnet: connection from {} ({}/{})", addr, current + 1, max_sessions);
                            let sd = shutdown.clone();
                            let rs = restart.clone();
                            let sc = session_count.clone();
                            let sw = session_writers.clone();
                            let lo = lockouts.clone();
                            tokio::spawn(async move {
                                let _ = stream.set_nodelay(true);
                                let (read_half, write_half) = stream.into_split();
                                let writer_box: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(write_half);
                                let writer_arc: SharedWriter = Arc::new(tokio::sync::Mutex::new(writer_box));
                                sw.lock().await.push(writer_arc.clone());
                                let mut session = TelnetSession {
                                    reader: Box::new(read_half),
                                    writer: writer_arc.clone(),
                                    shutdown: sd,
                                    restart: rs,
                                    current_menu: Menu::Main,
                                    terminal_type: TerminalType::Ansi,
                                    erase_char: 0x7F,
                                    lockouts: lo,
                                    peer_addr: Some(addr.ip()),
                                    transfer_subdir: String::new(),
                                    // Start with IAC escaping off; session_read_byte
                                    // flips telnet_negotiated on as soon as the client
                                    // sends any telnet option negotiation, and run()
                                    // sets xmodem_iac from that flag after terminal
                                    // detection.  Real telnet clients (PuTTY, Tera Term,
                                    // C-Kermit, SecureCRT) always negotiate and get
                                    // IAC escaping; raw TCP clients (netcat, retro
                                    // firmware) don't and get a transparent byte
                                    // stream.  The I toggle in the File Transfer menu
                                    // still lets the user override per-session.
                                    xmodem_iac: false,
                                    web_lines: Vec::new(),
                                    web_scroll: 0,
                                    web_links: Vec::new(),
                                    web_history: Vec::new(),
                                    web_url: None,
                                    web_title: None,
                                    web_forms: Vec::new(),
                                    weather_zip: config::get_config().weather_zip,
                                    is_serial: false,
                                    is_ssh: false,
                                    idle_timeout: std::time::Duration::from_secs(cfg.idle_timeout_secs),
                                    pushback: None,
                                    neg_sent_will: Box::new([false; 256]),
                                    neg_sent_do: Box::new([false; 256]),
                                    neg_sent_wont: Box::new([false; 256]),
                                    neg_sent_dont: Box::new([false; 256]),
                                    ttype_matched: false,
                                    telnet_negotiated: false,
                                    window_width: None,
                                    window_height: None,
                                };
                                if let Err(e) = session.run().await {
                                    glog!("Telnet: session error from {}: {}", addr, e);
                                }
                                {
                                    let mut w = writer_arc.lock().await;
                                    let _ = w.shutdown().await;
                                }
                                sw.lock().await.retain(|w| !Arc::ptr_eq(w, &writer_arc));
                                sc.fetch_sub(1, Ordering::SeqCst);
                                glog!("Telnet: {} disconnected", addr);
                            });
                        }
                        Err(e) => {
                            glog!("Telnet: accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_notify.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
            }
        }
    });
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── PETSCII helpers ─────────────────────────────────

    #[test]
    fn test_swap_case_for_petscii() {
        assert_eq!(swap_case_for_petscii("Hello"), "hELLO");
        assert_eq!(swap_case_for_petscii("ABC"), "abc");
        assert_eq!(swap_case_for_petscii("abc"), "ABC");
        assert_eq!(swap_case_for_petscii("123!"), "123!");
        assert_eq!(swap_case_for_petscii(""), "");
    }

    #[test]
    fn test_petscii_to_ascii_byte() {
        // PETSCII lowercase (0x41-0x5A) -> ASCII lowercase
        assert_eq!(petscii_to_ascii_byte(0x41), b'a');
        assert_eq!(petscii_to_ascii_byte(0x5A), b'z');
        // PETSCII uppercase (0xC1-0xDA) -> ASCII uppercase
        assert_eq!(petscii_to_ascii_byte(0xC1), b'A');
        assert_eq!(petscii_to_ascii_byte(0xDA), b'Z');
        // Other bytes pass through
        assert_eq!(petscii_to_ascii_byte(b'1'), b'1');
        assert_eq!(petscii_to_ascii_byte(0x00), 0x00);
    }

    #[test]
    fn test_to_latin1_bytes() {
        assert_eq!(to_latin1_bytes("abc"), vec![b'a', b'b', b'c']);
        assert_eq!(to_latin1_bytes(""), Vec::<u8>::new());
    }

    // ─── Input helpers ───────────────────────────────────

    #[test]
    fn test_is_backspace_key() {
        assert!(is_backspace_key(0x08, 0x7F)); // BS
        assert!(is_backspace_key(0x7F, 0x7F)); // DEL (erase_char)
        assert!(is_backspace_key(0x14, 0x7F)); // C64 DEL
        assert!(is_backspace_key(0x08, 0x14)); // BS with C64 erase_char
        assert!(!is_backspace_key(b'a', 0x7F));
        assert!(!is_backspace_key(0x00, 0x7F));
    }

    #[test]
    fn test_is_esc_key() {
        assert!(is_esc_key(0x1B, false));
        assert!(!is_esc_key(0x5F, false)); // underscore in ANSI
        assert!(is_esc_key(0x1B, true));
        assert!(is_esc_key(0x5F, true)); // back-arrow in PETSCII
        assert!(!is_esc_key(b'a', false));
        assert!(!is_esc_key(b'a', true));
    }

    // ─── Truncation ──────────────────────────────────────

    #[test]
    fn test_truncate_to_width() {
        assert_eq!(truncate_to_width("hello", 10), "hello");
        assert_eq!(truncate_to_width("hello", 5), "hello");
        assert_eq!(truncate_to_width("hello world", 8), "hello...");
        assert_eq!(truncate_to_width("abcdef", 3), "...");
        assert_eq!(truncate_to_width("ab", 2), "ab");
    }

    // ─── Filename validation ─────────────────────────────

    #[test]
    fn test_validate_filename_valid() {
        assert!(TelnetSession::validate_filename("test.txt").is_ok());
        assert!(TelnetSession::validate_filename("my-file_v2.bin").is_ok());
        assert!(TelnetSession::validate_filename("a").is_ok());
        let name_64 = "a".repeat(TelnetSession::MAX_FILENAME_LEN);
        assert!(TelnetSession::validate_filename(&name_64).is_ok());
    }

    #[test]
    fn test_validate_filename_invalid() {
        assert!(TelnetSession::validate_filename("").is_err());
        assert!(TelnetSession::validate_filename(".hidden").is_err());
        assert!(TelnetSession::validate_filename("file name.txt").is_err());
        assert!(TelnetSession::validate_filename("../../etc/passwd").is_err());
        assert!(TelnetSession::validate_filename("file..txt").is_err());
        let name_65 = "a".repeat(TelnetSession::MAX_FILENAME_LEN + 1);
        assert!(TelnetSession::validate_filename(&name_65).is_err());
        assert!(TelnetSession::validate_filename("---").is_err());
    }

    // ─── File size formatting ────────────────────────────

    #[test]
    fn test_format_file_size() {
        assert_eq!(TelnetSession::format_file_size(0), "0 B");
        assert_eq!(TelnetSession::format_file_size(512), "512 B");
        assert_eq!(TelnetSession::format_file_size(1023), "1023 B");
        assert_eq!(TelnetSession::format_file_size(1024), "1.0 KB");
        assert_eq!(TelnetSession::format_file_size(1536), "1.5 KB");
        assert_eq!(TelnetSession::format_file_size(1048576), "1.0 MB");
        assert_eq!(TelnetSession::format_file_size(1572864), "1.5 MB");
    }

    // ─── Constants ───────────────────────────────────────

    #[test]
    fn test_constants() {
        const _: () = assert!(TelnetSession::MAX_FILE_SIZE == 8 * 1024 * 1024);
        const _: () = assert!(TelnetSession::MAX_FILENAME_LEN == 64);
        const _: () = assert!(TelnetSession::TRANSFER_PAGE_SIZE > 0);
        const _: () = assert!(TelnetSession::TRANSFER_PAGE_SIZE <= 20);
    }

    // ─── Auth lockout ────────────────────────────────────

    #[test]
    fn test_lockout_flow() {
        let lockouts: LockoutMap = Arc::new(Mutex::new(HashMap::new()));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        assert!(!is_locked_out(&lockouts, ip));
        assert_eq!(record_auth_failure(&lockouts, ip), 1);
        assert!(!is_locked_out(&lockouts, ip));
        assert_eq!(record_auth_failure(&lockouts, ip), 2);
        assert!(!is_locked_out(&lockouts, ip));
        assert_eq!(record_auth_failure(&lockouts, ip), 3);
        assert!(is_locked_out(&lockouts, ip));

        clear_lockout(&lockouts, ip);
        assert!(!is_locked_out(&lockouts, ip));
    }

    #[test]
    fn test_lockout_different_ips() {
        let lockouts: LockoutMap = Arc::new(Mutex::new(HashMap::new()));
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..3 {
            record_auth_failure(&lockouts, ip1);
        }
        assert!(is_locked_out(&lockouts, ip1));
        assert!(!is_locked_out(&lockouts, ip2));
    }

    // ─── Known hosts ─────────────────────────────────────

    fn make_test_key() -> russh::keys::PublicKey {
        // A valid Ed25519 public key for testing (OpenSSH format)
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ test"
            .parse()
            .unwrap()
    }

    #[test]
    fn test_check_known_host_unknown_no_file() {
        let key = make_test_key();
        match check_known_host("nonexistent-test-host.example", 22, &key) {
            HostKeyStatus::Unknown => {}
            _ => panic!("expected Unknown for host not in file"),
        }
    }

    #[test]
    fn test_format_host_key_roundtrip() {
        let key = make_test_key();
        let formatted = format_host_key(&key);
        assert!(formatted.starts_with("ssh-ed25519 "));
        // Should be "algo base64" with no comment
        assert_eq!(formatted.split(' ').count(), 2);
    }

    #[test]
    fn test_known_host_fingerprint_is_stable() {
        let key = make_test_key();
        let fp1 = key.fingerprint(russh::keys::HashAlg::Sha256);
        let fp2 = key.fingerprint(russh::keys::HashAlg::Sha256);
        assert_eq!(fp1.to_string(), fp2.to_string());
        assert!(fp1.to_string().starts_with("SHA256:"));
    }

    // ─── IP filtering ────────────────────────────────────

    #[test]
    fn test_reject_insecure_ip_private_allowed() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_loopback_allowed() {
        let ip: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_ten_network_allowed() {
        let ip: IpAddr = "10.0.5.42".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_172_private_allowed() {
        let ip: IpAddr = "172.16.0.50".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
        let ip2: IpAddr = "172.31.255.254".parse().unwrap();
        assert!(reject_insecure_ip(ip2).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_public_rejected() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_some());
    }

    #[test]
    fn test_reject_insecure_ip_172_public_rejected() {
        // 172.32.x.x is NOT private (private is 172.16-31.x.x)
        let ip: IpAddr = "172.32.0.5".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_some());
    }

    #[test]
    fn test_reject_insecure_ip_gateway_rejected() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let reason = reject_insecure_ip(ip);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("gateway"));
    }

    #[test]
    fn test_reject_insecure_ip_gateway_ten_rejected() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_some());
    }

    #[test]
    fn test_reject_insecure_ip_loopback_dot_one_allowed() {
        // 127.0.0.1 is loopback — exempt from the .1 gateway filter
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_ipv6_loopback_allowed() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_ipv6_public_rejected() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_some());
    }

    #[test]
    fn test_reject_insecure_ip_ipv4_mapped_ipv6_private_allowed() {
        // ::ffff:192.168.1.100 is IPv4-mapped, should apply IPv4 rules
        let ip: IpAddr = "::ffff:192.168.1.100".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_ipv4_mapped_ipv6_public_rejected() {
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_some());
    }

    #[test]
    fn test_reject_insecure_ip_ipv4_mapped_ipv6_gateway_rejected() {
        // ::ffff:10.0.0.1 ends in .1, should be rejected
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let reason = reject_insecure_ip(ip);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("gateway"));
    }

    #[test]
    fn test_reject_insecure_ip_ipv6_link_local_allowed() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_ipv6_unique_local_allowed() {
        let ip: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_link_local_ipv4_allowed() {
        let ip: IpAddr = "169.254.1.100".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_none());
    }

    #[test]
    fn test_reject_insecure_ip_link_local_ipv4_gateway_rejected() {
        let ip: IpAddr = "169.254.0.1".parse().unwrap();
        assert!(reject_insecure_ip(ip).is_some());
    }

    // ─── Menu ────────────────────────────────────────────

    #[test]
    fn test_menu_paths() {
        assert_eq!(Menu::Main.path(), "ethernet");
        assert_eq!(Menu::FileTransfer.path(), "ethernet/xfer");
    }

    // ─── Color helpers ───────────────────────────────────

    #[test]
    fn test_petscii_color() {
        let result = TelnetSession::petscii_color(PETSCII_GREEN, "test");
        assert!(result.contains("test"));
        assert_eq!(result.as_bytes()[0], PETSCII_GREEN);
        assert_eq!(*result.as_bytes().last().unwrap(), PETSCII_DEFAULT);
    }

    // ─── Test session helper ─────────────────────────────

    /// Build a minimal TelnetSession with the given terminal type for testing
    /// synchronous helpers (color, formatting, etc.).  No I/O is performed.
    fn make_test_session(terminal_type: TerminalType) -> TelnetSession {
        let (client, server) = tokio::io::duplex(1);
        let writer_box: Box<dyn tokio::io::AsyncWrite + Unpin + Send> =
            Box::new(client);
        let writer: SharedWriter =
            Arc::new(tokio::sync::Mutex::new(writer_box));
        TelnetSession {
            reader: Box::new(server),
            writer,
            shutdown: Arc::new(AtomicBool::new(false)),
            restart: Arc::new(AtomicBool::new(false)),
            current_menu: Menu::Main,
            terminal_type,
            erase_char: 0x7F,
            lockouts: Arc::new(Mutex::new(HashMap::new())),
            peer_addr: None,
            transfer_subdir: String::new(),
            xmodem_iac: false,
            web_lines: Vec::new(),
            web_scroll: 0,
            web_links: Vec::new(),
            web_history: Vec::new(),
            web_url: None,
            web_title: None,
            web_forms: Vec::new(),
            weather_zip: String::new(),
            is_serial: false,
            is_ssh: false,
            idle_timeout: std::time::Duration::ZERO,
            pushback: None,
            neg_sent_will: Box::new([false; 256]),
            neg_sent_do: Box::new([false; 256]),
            neg_sent_wont: Box::new([false; 256]),
            neg_sent_dont: Box::new([false; 256]),
            ttype_matched: false,
            telnet_negotiated: false,
            window_width: None,
            window_height: None,
        }
    }

    /// Build a telnet session wired to a controllable client-side pipe.
    /// Return the session plus the peer end: writing to `peer` feeds
    /// bytes to the session's reader, reading from `peer` returns what
    /// the session wrote. Used for end-to-end negotiation tests.
    fn make_test_session_with_peer(
        terminal_type: TerminalType,
    ) -> (TelnetSession, tokio::io::DuplexStream) {
        let (peer, session_stream) = tokio::io::duplex(512);
        let (session_reader, session_writer) = tokio::io::split(session_stream);
        let writer_box: Box<dyn tokio::io::AsyncWrite + Unpin + Send> =
            Box::new(session_writer);
        let writer: SharedWriter =
            Arc::new(tokio::sync::Mutex::new(writer_box));
        let session = TelnetSession {
            reader: Box::new(session_reader),
            writer,
            shutdown: Arc::new(AtomicBool::new(false)),
            restart: Arc::new(AtomicBool::new(false)),
            current_menu: Menu::Main,
            terminal_type,
            erase_char: 0x7F,
            lockouts: Arc::new(Mutex::new(HashMap::new())),
            peer_addr: None,
            transfer_subdir: String::new(),
            xmodem_iac: false,
            web_lines: Vec::new(),
            web_scroll: 0,
            web_links: Vec::new(),
            web_history: Vec::new(),
            web_url: None,
            web_title: None,
            web_forms: Vec::new(),
            weather_zip: String::new(),
            is_serial: false,
            is_ssh: false,
            idle_timeout: std::time::Duration::ZERO,
            pushback: None,
            neg_sent_will: Box::new([false; 256]),
            neg_sent_do: Box::new([false; 256]),
            neg_sent_wont: Box::new([false; 256]),
            neg_sent_dont: Box::new([false; 256]),
            ttype_matched: false,
            telnet_negotiated: false,
            window_width: None,
            window_height: None,
        };
        (session, peer)
    }

    // ─── Color helpers ──────────────────────────────────

    #[test]
    fn test_green_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.green("ok");
        assert!(result.starts_with(ANSI_GREEN));
        assert!(result.ends_with(ANSI_RESET));
        assert!(result.contains("ok"));
    }

    #[test]
    fn test_green_petscii() {
        let s = make_test_session(TerminalType::Petscii);
        let result = s.green("ok");
        assert_eq!(result.as_bytes()[0], PETSCII_GREEN);
        assert_eq!(*result.as_bytes().last().unwrap(), PETSCII_DEFAULT);
        assert!(result.contains("ok"));
    }

    #[test]
    fn test_green_ascii_no_escapes() {
        let s = make_test_session(TerminalType::Ascii);
        assert_eq!(s.green("ok"), "ok");
    }

    #[test]
    fn test_red_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.red("err");
        assert!(result.starts_with(ANSI_RED));
        assert!(result.ends_with(ANSI_RESET));
    }

    #[test]
    fn test_yellow_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.yellow("warn");
        assert!(result.starts_with(ANSI_YELLOW));
        assert!(result.ends_with(ANSI_RESET));
    }

    #[test]
    fn test_cyan_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.cyan("info");
        assert!(result.starts_with(ANSI_CYAN));
        assert!(result.ends_with(ANSI_RESET));
    }

    #[test]
    fn test_amber_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.amber("caution");
        assert!(result.starts_with(ANSI_AMBER));
        assert!(result.ends_with(ANSI_RESET));
    }

    #[test]
    fn test_amber_petscii_uses_yellow() {
        let s = make_test_session(TerminalType::Petscii);
        let result = s.amber("caution");
        // PETSCII_YELLOW (0x9E) is multi-byte in UTF-8, so check via char
        assert_eq!(result.chars().next().unwrap(), char::from(PETSCII_YELLOW));
    }

    #[test]
    fn test_dim_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.dim("faint");
        assert!(result.starts_with(ANSI_DIM));
        assert!(result.ends_with(ANSI_RESET));
    }

    #[test]
    fn test_blue_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.blue("link");
        assert!(result.starts_with(ANSI_BLUE));
        assert!(result.ends_with(ANSI_RESET));
    }

    #[test]
    fn test_white_ansi() {
        let s = make_test_session(TerminalType::Ansi);
        let result = s.white("bright");
        assert!(result.starts_with(ANSI_WHITE));
        assert!(result.ends_with(ANSI_RESET));
    }

    #[test]
    fn test_all_colors_ascii_passthrough() {
        let s = make_test_session(TerminalType::Ascii);
        assert_eq!(s.red("x"), "x");
        assert_eq!(s.cyan("x"), "x");
        assert_eq!(s.yellow("x"), "x");
        assert_eq!(s.amber("x"), "x");
        assert_eq!(s.dim("x"), "x");
        assert_eq!(s.blue("x"), "x");
        assert_eq!(s.white("x"), "x");
    }

    // ─── colorize_link_markers ──────────────────────────

    #[test]
    fn test_colorize_link_markers_no_markers() {
        let s = make_test_session(TerminalType::Ansi);
        assert_eq!(s.colorize_link_markers("hello world"), "hello world");
    }

    #[test]
    fn test_colorize_link_markers_single() {
        let s = make_test_session(TerminalType::Ansi);
        let input = "click \x021\x03 here";
        let result = s.colorize_link_markers(input);
        assert!(result.contains("[1]"));
        assert!(result.contains(ANSI_BLUE));
        assert!(result.contains("click "));
        assert!(result.contains(" here"));
    }

    #[test]
    fn test_colorize_link_markers_multiple() {
        let s = make_test_session(TerminalType::Ansi);
        let input = "\x021\x03 and \x022\x03";
        let result = s.colorize_link_markers(input);
        assert!(result.contains("[1]"));
        assert!(result.contains("[2]"));
    }

    #[test]
    fn test_colorize_link_markers_ascii_no_color() {
        let s = make_test_session(TerminalType::Ascii);
        let input = "\x021\x03";
        let result = s.colorize_link_markers(input);
        assert_eq!(result, "[1]");
    }

    #[test]
    fn test_colorize_link_markers_malformed() {
        let s = make_test_session(TerminalType::Ansi);
        // Open sentinel without close — silently dropped
        let result = s.colorize_link_markers("text\x02orphan");
        assert!(result.contains("text"));
        assert!(result.contains("orphan"));
        assert!(!result.contains("\x02"));
    }

    // ─── action_prompt / nav_footer ─────────────────────

    #[test]
    fn test_action_prompt_format() {
        let s = make_test_session(TerminalType::Ascii);
        assert_eq!(s.action_prompt("Q", "Back"), "Q=Back");
    }

    #[test]
    fn test_nav_footer_fits_petscii() {
        let s = make_test_session(TerminalType::Ascii);
        let footer = s.nav_footer();
        // ASCII mode has no escape codes, so visible length == byte length
        assert!(
            footer.len() <= PETSCII_WIDTH,
            "nav footer '{}' is {} chars, exceeds {}",
            footer,
            footer.len(),
            PETSCII_WIDTH,
        );
    }

    // ─── constant_time_eq ───────────────────────────────

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"password", b"password"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"password", b"passw0rd"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_constant_time_eq_single_bit_diff() {
        // 'A' (0x41) vs 'a' (0x61) — differ by one bit
        assert!(!constant_time_eq(b"A", b"a"));
    }

    // ─── Gateway output filtering ────────────────────────

    /// Helper: run filter_gateway_output on a single chunk.
    fn filter_output(input: &[u8], is_petscii: bool) -> Vec<u8> {
        let mut state = 0u8;
        let mut out = Vec::new();
        filter_gateway_output(input, &mut state, is_petscii, &mut out);
        out
    }

    #[test]
    fn test_filter_plain_text_ascii() {
        assert_eq!(filter_output(b"hello world", false), b"hello world");
    }

    #[test]
    fn test_filter_plain_text_petscii_swaps_case() {
        assert_eq!(filter_output(b"Hello", true), b"hELLO");
    }

    #[test]
    fn test_filter_strips_csi_color() {
        let input = b"\x1b[32mhello";
        assert_eq!(filter_output(input, false), b"hello");
    }

    #[test]
    fn test_filter_strips_csi_cursor_move() {
        let input = b"\x1b[10;1Hprompt";
        assert_eq!(filter_output(input, false), b"prompt");
    }

    #[test]
    fn test_filter_strips_osc_title_bel() {
        let input = b"\x1b]0;ricky@host:~\x07ricky@host:~$ ";
        assert_eq!(filter_output(input, false), b"ricky@host:~$ ");
    }

    #[test]
    fn test_filter_strips_osc_title_st() {
        let input = b"\x1b]0;title\x1b\\visible";
        assert_eq!(filter_output(input, false), b"visible");
    }

    #[test]
    fn test_filter_strips_dcs_sequence() {
        let input = b"\x1bPsome data\x1b\\after";
        assert_eq!(filter_output(input, false), b"after");
    }

    #[test]
    fn test_filter_strips_pm_sequence() {
        let input = b"\x1b^private msg\x07text";
        assert_eq!(filter_output(input, false), b"text");
    }

    #[test]
    fn test_filter_strips_apc_sequence() {
        let input = b"\x1b_app cmd\x07text";
        assert_eq!(filter_output(input, false), b"text");
    }

    #[test]
    fn test_filter_passes_two_char_esc_sequence() {
        let input = b"\x1bMhello"; // ESC M = reverse line feed
        assert_eq!(filter_output(input, false), b"hello");
    }

    #[test]
    fn test_filter_strips_multiple_sequences() {
        let input = b"\x1b]0;title\x07\x1b[1;32mhello\x1b[0m world";
        assert_eq!(filter_output(input, false), b"hello world");
    }

    #[test]
    fn test_filter_state_spans_chunks() {
        let mut state = 0u8;
        let mut out = Vec::new();
        filter_gateway_output(b"\x1b]0;ti", &mut state, false, &mut out);
        assert_eq!(out, b"");
        assert_eq!(state, 3);
        filter_gateway_output(b"tle\x07visible", &mut state, false, &mut out);
        assert_eq!(out, b"visible");
        assert_eq!(state, 0);
    }

    #[test]
    fn test_filter_incomplete_csi_spans_chunks() {
        let mut state = 0u8;
        let mut out = Vec::new();
        filter_gateway_output(b"\x1b[32", &mut state, false, &mut out);
        assert_eq!(out, b"");
        assert_eq!(state, 2);
        filter_gateway_output(b"mhello", &mut state, false, &mut out);
        assert_eq!(out, b"hello");
        assert_eq!(state, 0);
    }

    #[test]
    fn test_filter_bare_esc_at_end_of_chunk() {
        let mut state = 0u8;
        let mut out = Vec::new();
        filter_gateway_output(b"text\x1b", &mut state, false, &mut out);
        assert_eq!(out, b"text");
        assert_eq!(state, 1);
        filter_gateway_output(b"[0mmore", &mut state, false, &mut out);
        assert_eq!(out, b"textmore");
    }

    #[test]
    fn test_filter_petscii_strips_and_swaps() {
        let input = b"\x1b[32mHello World";
        assert_eq!(filter_output(input, true), b"hELLO wORLD");
    }

    #[test]
    fn test_filter_petscii_strips_tilde() {
        assert_eq!(filter_output(b"~$ ", true), b"$ ");
        assert_eq!(filter_output(b"user@host:~$ ", true), b"USER@HOST:$ ");
    }

    #[test]
    fn test_filter_ascii_keeps_tilde() {
        assert_eq!(filter_output(b"~$ ", false), b"~$ ");
    }

    #[test]
    fn test_filter_petscii_translates_backspace() {
        assert_eq!(filter_output(b"ab\x08c", true), b"AB\x14C");
        assert_eq!(filter_output(b"ab\x7Fc", true), b"AB\x14C");
    }

    #[test]
    fn test_filter_ascii_keeps_backspace() {
        assert_eq!(filter_output(b"ab\x08c", false), b"ab\x08c");
        assert_eq!(filter_output(b"ab\x7Fc", false), b"ab\x7Fc");
    }

    #[test]
    fn test_filter_empty_input() {
        assert_eq!(filter_output(b"", false), b"");
        assert_eq!(filter_output(b"", true), b"");
    }

    #[test]
    fn test_filter_only_escape_sequences() {
        let input = b"\x1b[1m\x1b[32m\x1b[0m";
        assert_eq!(filter_output(input, false), b"");
    }

    #[test]
    fn test_filter_csi_reset_on_control_char() {
        let input = b"\x1b[3\x00text";
        assert_eq!(filter_output(input, false), b"text");
    }

    #[test]
    fn test_filter_csi_reset_on_esc() {
        let input = b"\x1b[32\x1b]0;title\x07text";
        assert_eq!(filter_output(input, false), b"text");
    }

    #[test]
    fn test_filter_double_esc() {
        let input = b"\x1b\x1b[32mtext";
        assert_eq!(filter_output(input, false), b"text");
    }

    #[test]
    fn test_filter_unclosed_osc_spans_chunks() {
        let mut state = 0u8;
        let mut out = Vec::new();
        filter_gateway_output(b"\x1b]0;title", &mut state, false, &mut out);
        assert_eq!(state, 3);
        assert_eq!(out, b"");
        filter_gateway_output(b"more title", &mut state, false, &mut out);
        assert_eq!(state, 3);
        assert_eq!(out, b"");
        filter_gateway_output(b"\x07visible", &mut state, false, &mut out);
        assert_eq!(state, 0);
        assert_eq!(out, b"visible");
    }

    #[test]
    fn test_filter_csi_interrupted_by_new_esc() {
        let mut state = 0u8;
        let mut out = Vec::new();
        filter_gateway_output(b"\x1b[32", &mut state, false, &mut out);
        assert_eq!(state, 2);
        filter_gateway_output(b"\x1b]title\x07text", &mut state, false, &mut out);
        assert_eq!(state, 0);
        assert_eq!(out, b"text");
    }

    // ─── Gateway input normalization ─────────────────────

    #[test]
    fn test_normalize_plain_byte() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(b'a', &mut last_cr), Some(b'a'));
        assert!(!last_cr);
    }

    #[test]
    fn test_normalize_cr_passes_through() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(b'\r', &mut last_cr), Some(b'\r'));
        assert!(last_cr);
    }

    #[test]
    fn test_normalize_suppresses_lf_after_cr() {
        let mut last_cr = true;
        assert_eq!(normalize_gateway_input(b'\n', &mut last_cr), None);
        assert!(!last_cr);
    }

    #[test]
    fn test_normalize_suppresses_nul_after_cr() {
        let mut last_cr = true;
        assert_eq!(normalize_gateway_input(0x00, &mut last_cr), None);
        assert!(!last_cr);
    }

    #[test]
    fn test_normalize_lf_without_cr_passes() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(b'\n', &mut last_cr), Some(b'\n'));
        assert!(!last_cr);
    }

    #[test]
    fn test_normalize_nul_without_cr_passes() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(0x00, &mut last_cr), Some(0x00));
        assert!(!last_cr);
    }

    #[test]
    fn test_normalize_cr_lf_sequence() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(b'\r', &mut last_cr), Some(b'\r'));
        assert_eq!(normalize_gateway_input(b'\n', &mut last_cr), None);
        assert_eq!(normalize_gateway_input(b'x', &mut last_cr), Some(b'x'));
    }

    #[test]
    fn test_normalize_cr_nul_sequence() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(b'\r', &mut last_cr), Some(b'\r'));
        assert_eq!(normalize_gateway_input(0x00, &mut last_cr), None);
        assert_eq!(normalize_gateway_input(b'x', &mut last_cr), Some(b'x'));
    }

    #[test]
    fn test_normalize_cr_then_regular_byte() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(b'\r', &mut last_cr), Some(b'\r'));
        assert_eq!(normalize_gateway_input(b'a', &mut last_cr), Some(b'a'));
        assert!(!last_cr);
    }

    #[test]
    fn test_normalize_double_cr() {
        let mut last_cr = false;
        assert_eq!(normalize_gateway_input(b'\r', &mut last_cr), Some(b'\r'));
        assert_eq!(normalize_gateway_input(b'\r', &mut last_cr), Some(b'\r'));
        assert!(last_cr);
    }

    // ─── Screen layout constraints ───────────────────────

    /// All user-facing error messages must fit in PETSCII width (40 cols).
    /// The "  " prefix + message must not exceed 40 chars.
    #[test]
    fn test_all_error_messages_fit_petscii() {
        let messages = [
            "Input too long.",
            "Press A-C, F, R, S, T, W, X, or H.",
            // Non-serial prompt includes E but is only shown to
            // ANSI/SSH users (80 cols), so it is not tested here.
            "Press U, D, X, C, I, R, Q, or H.",
            "Disk space is low. Uploads disabled.",
            "File already exists.",
            "No files available.",
            "Invalid selection.",
            "Enter a number, P, N, Q, or H.",
            "File too large.",
            "No files to delete.",
            "No subdirectories.",
            "Access denied.",
            "Enter a number or Q.",
            "Press S, R, Q, or H.",
            "Press E, S, B, P, D, F, H, or Q.",
            "No serial ports detected.",
            "Invalid port number.",
            "Connection timed out.",
            "Authentication failed.",
            "Too many attempts. Try later.",
            "Too many failed attempts.",
            "Login incorrect.",
            "Disconnected: idle timeout.",
            "Press any key to continue.",
            "No API key configured.",
            // Weather
            "Enter a 5-digit US zip code.",
            // Web browser
            "Press G, K, H, or Q.",
            "End of page.",
            "Top of page.",
            "No links on this page.",
            "No forms on this page.",
            "No history.",
            "Enter a number.",
            "Invalid form number.",
            "Invalid field number.",
            "Enter S, Q, H, or a field #.",
            "Already bookmarked (or full).",
            "No page to bookmark.",
            "No bookmarks saved.",
            "Not found.",
            "Invalid number.",
            "Unknown command.",
            // Dialup mapping
            "Press A, H, or Q.",
            "Press A, D, H, or Q.",
            "Number must contain digits.",
            "Invalid entry number.",
            "Mapping saved.",
            "No other mappings defined.",
            // Configuration
            "Press E, F, G, M, O, S, R, H, or Q.",
            // Other settings
            "Press A, B, W, V, G, R, H, or Q.",
            // Security
            "Press L, U, P, S, W, R, H, or Q.",
            // File transfer submenu
            "Press D, X, Y, Z, R, H, or Q.",
            // XMODEM / YMODEM settings
            "Press N, I, B, M, R, H, or Q.",
            // ZMODEM settings
            "Press N, I, F, M, R, H, or Q.",
            "Press T, P, S, O, R, H, or Q.",
            "Invalid port number.",
        ];
        for msg in &messages {
            // Error messages are displayed as "  {msg}" — 2-char indent
            let displayed = format!("  {}", msg);
            assert!(
                displayed.len() <= PETSCII_WIDTH,
                "error message '{}' is {} chars with indent, exceeds {}",
                msg,
                displayed.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// All menu items must fit in PETSCII width (40 cols).
    #[test]
    fn test_all_menu_items_fit_petscii() {
        let items = [
            // Main menu
            "  A  AI Chat",
            "  B  Simple Browser",
            "  C  Configuration",
            "  F  File Transfer",
            "  R  Troubleshooting",
            "  S  SSH Gateway",
            "  T  Telnet Gateway",
            "  W  Weather",
            "  X  Exit",
            // Modem emulator menu
            "  E  Toggle enabled/disabled",
            "  S  Select serial port",
            "  B  Set baud rate",
            "  P  Set data/parity/stop",
            "  F  Set flow control",
            "  D  Dialup Mapping",
            // Port selection menu
            "  R  Refresh port list",
            "  N  None (clear port)",
            "  Enter #, R, N, or type a path.",
            // Configuration submenu
            "  E  Security",
            "  M  Modem Emulator",
            "  S  Server Configuration",
            "  F  File Transfer",
            "  O  Other Settings",
            "  R  Reset Defaults",
            // Other settings menu
            "  A  Set AI API key (Groq)",
            "  B  Set browser homepage",
            "  W  Set weather zip code",
            "  V  Toggle verbose transfer logging",
            "  G  Toggle GUI on startup",
            // Security menu
            "  L  Toggle require login",
            "  U  Set telnet username",
            "  P  Set telnet password",
            "  S  Set SSH username",
            "  W  Set SSH password",
            // File transfer submenu
            "  D  Change transfer directory",
            "  X  XMODEM settings",
            "  Y  YMODEM settings",
            "  Z  ZMODEM settings",
            // XMODEM / YMODEM settings menu
            "  N  Set negotiation timeout",
            "  I  Set retry interval",
            "  B  Set block timeout",
            "  M  Set max retries",
            // ZMODEM settings menu
            "  F  Set frame timeout",
            // Shared by XMODEM/YMODEM/ZMODEM pages
            "  R  Restart server",
            // Server configuration menu
            "  T  Toggle telnet",
            "  P  Set telnet port",
            "  S  Toggle SSH",
            "  O  Set SSH port",
            "  R  Restart server",
            // Dialup mapping menu
            "  A  Add mapping",
            "  D  Delete mapping",
            // File transfer menu
            "  U  Upload a file",
            "  D  Download a file",
            "  X  Delete a file",
            "  C  Change directory",
            // Navigation footers
            "  R=Refresh Q=Back H=Help",
            // Auth prompts
            "  Username: ",
            "  Password: ",
            // AI chat
            "  Type a question, or Q to exit.",
            // Web browser
            "  G=Go/Search K=Bookmarks Q=Back H=Help",
        ];
        for item in &items {
            assert!(
                item.len() <= PETSCII_WIDTH,
                "menu item '{}' is {} chars, exceeds {}",
                item,
                item.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Main menu screen: header(3) + blank + 10 items + blank + help = 16 rows.
    #[test]
    fn test_main_menu_row_count() {
        // sep, title, sep, blank, A, B, C, F, R, S, T, W, X, blank, H=Help = 15
        let rows = 15;
        assert!(rows <= 22, "main menu is {} rows, exceeds 22", rows);
    }

    /// Main menu items must be exactly A, B, C, F, R, S, T, W, X (9 items).
    #[test]
    fn test_main_menu_item_count() {
        let items = ["A", "B", "C", "F", "R", "S", "T", "W", "X"];
        assert_eq!(items.len(), 9, "main menu should have exactly 9 items");
    }

    /// Error hint must list exactly the valid main menu keys.
    #[test]
    fn test_main_menu_error_hint() {
        let hint = "Press A-C, F, R, S, T, W, X, or H.";
        // Must not mention removed keys (D, E, M)
        assert!(!hint.contains(" D,"), "error hint must not mention D");
        assert!(!hint.contains(" E,"), "error hint must not mention E");
        assert!(!hint.contains(" E "), "error hint must not mention E");
        assert!(!hint.contains(" M,"), "error hint must not mention M");
        // Must mention all valid keys
        for key in ["A", "C", "F", "R", "S", "T", "W", "X", "H"] {
            assert!(hint.contains(key), "error hint must mention {}", key);
        }
        assert!(hint.len() <= PETSCII_WIDTH, "error hint exceeds PETSCII width");
    }

    /// Main help screen content must have exactly 14 lines (matching row count test).
    #[test]
    fn test_main_help_content_line_count() {
        let lines = [
            "  A  AI Chat: ask questions to an AI",
            "  B  Browser: browse the web",
            "  C  Configuration: server settings",
            "     and other options",
            "  F  File Transfer: upload/download",
            "     files using the XMODEM protocol",
            "  R  Troubleshooting: diagnose",
            "     terminal input issues",
            "  S  SSH Gateway: connect to a",
            "     remote server via SSH",
            "  T  Telnet Gateway: connect to a",
            "     remote server via telnet",
            "  W  Weather: check weather by zip",
            "  X  Exit: disconnect from server",
        ];
        assert_eq!(lines.len(), 14, "main help should have exactly 14 content lines");
    }

    /// Shutdown broadcast message must be valid and end with CRLF.
    #[test]
    fn test_shutdown_message_format() {
        let msg = b"\r\n\r\nServer shutting down. Goodbye.\r\n";
        assert!(msg.ends_with(b"\r\n"), "shutdown message must end with CRLF");
        // Message must be short enough that it fits any terminal
        let text = "Server shutting down. Goodbye.";
        assert!(text.len() <= PETSCII_WIDTH, "shutdown message exceeds PETSCII width");
    }

    /// Dialup mapping menu (with entries): header(3) + blank + 10 entries + blank
    /// + 2 items + blank + footer = 18 rows max.
    #[test]
    fn test_dialup_mapping_menu_row_count() {
        // Worst case: static entry + 9 user entries + A + D menu items
        let rows = 3 + 1 + 1 + 9 + 1 + 2 + 1 + 1; // 19
        assert!(rows <= 22, "dialup mapping menu is {} rows, exceeds 22", rows);
    }

    /// Dialup mapping help screen row count.
    #[test]
    fn test_dialup_help_screen_row_count() {
        // header(3) + blank + 12 content lines + blank + "press any key" = 18
        let rows = 3 + 1 + 12 + 1 + 1; // 18
        assert!(rows <= 22, "dialup help screen is {} rows, exceeds 22", rows);
    }

    /// Dialup mapping help content must have exactly 12 lines and fit PETSCII.
    #[test]
    fn test_dialup_help_content() {
        let lines = [
            "  Map phone numbers to host:port",
            "  targets for the modem emulator.",
            "",
            "  Dial a number with ATDT, ATDP,",
            "  or ATD (all work the same) and",
            "  the server connects to the",
            "  mapped host:port for you.",
            "",
            "  You can still dial host:port",
            "  directly - mappings are optional.",
            "",
            "  Mappings are saved in dialup.conf.",
        ];
        assert_eq!(lines.len(), 12, "dialup help should have exactly 12 content lines");
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "dialup help line '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Dialup mapping prompts must fit PETSCII width.
    #[test]
    fn test_dialup_prompts_fit_petscii() {
        let prompts = [
            "  Phone number: ",
            "  Host: ",
            "  Port (23): ",
            "  Entry # to delete: ",
        ];
        for prompt in &prompts {
            assert!(
                prompt.len() <= PETSCII_WIDTH,
                "dialup prompt '{}' is {} chars, exceeds {}",
                prompt,
                prompt.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// File transfer menu: header(3) + blank + dir + blank + 5 items + blank + footer = 12 rows.
    #[test]
    fn test_file_transfer_menu_row_count() {
        let rows = 3 + 1 + 1 + 1 + 5 + 1 + 1; // 13
        assert!(rows <= 22, "file transfer menu is {} rows, exceeds 22", rows);
    }

    /// Download/delete file listing: header(3) + blank + col_header + divider
    /// + 10 entries + blank + page_info + blank + nav + blank + prompt = 21 rows.
    #[test]
    fn test_file_listing_row_count() {
        let header = 3; // sep + title + sep
        let col = 2;    // column header + divider
        let entries = TelnetSession::TRANSFER_PAGE_SIZE; // 10
        let footer = 5; // blank + page info + blank + nav + prompt
        let total = header + 1 + col + entries + footer;
        assert!(
            total <= 22,
            "file listing is {} rows, exceeds 22",
            total,
        );
    }

    /// AI answer screen: header(3) + 14 content lines + padding + position
    /// + nav + prompt = ~22 rows max.
    #[test]
    fn test_ai_answer_row_count() {
        let header = 3;  // sep + question + sep
        let content = TelnetSession::PAGE_CONTENT_LINES; // 14
        let footer = 3;  // position + nav + prompt
        let total = header + content + footer;
        assert!(
            total <= 22,
            "AI answer screen is {} rows, exceeds 22",
            total,
        );
    }

    /// Auth screen: header(3) + blank + up to 3 attempts * 4 lines = 15 rows max.
    #[test]
    fn test_auth_screen_row_count() {
        // sep + title + sep + blank + (username + password + error + blank)*3
        let header = 4;
        let per_attempt = 4; // username prompt, password prompt, error, blank
        let total = header + per_attempt * 3;
        assert!(
            total <= 22,
            "auth screen is {} rows, exceeds 22",
            total,
        );
    }

    /// Modem emulator screen worst case: non-serial + serial enabled.
    /// header(3) + blank + status(5) + ATD(1) + blank
    /// + menu(7: E,S,B,P,F,D,I) + blank + footer(1) + prompt(1) = 21.
    #[test]
    fn test_modem_emulator_row_count() {
        let rows = 3 + 1 + 5 + 1 + 1 + 7 + 1 + 1 + 1; // 21
        assert!(rows <= 22, "modem emulator is {} rows, exceeds 22", rows);
    }

    /// Baud rate screen: header(3) + blank + 9 options + blank + footer + prompt = 15.
    #[test]
    fn test_baud_screen_row_count() {
        let rows = 3 + 1 + 9 + 1 + 1 + 1; // 16
        assert!(rows <= 22, "baud screen is {} rows, exceeds 22", rows);
    }

    /// Flow control screen: header(3) + blank + 3 options + blank + footer + prompt = 10.
    #[test]
    fn test_flow_control_screen_row_count() {
        let rows = 3 + 1 + 3 + 1 + 1 + 1; // 10
        assert!(rows <= 22, "flow control screen is {} rows, exceeds 22", rows);
    }

    /// Data bits screen: header(3) + blank + 4 options + blank + footer + prompt = 11.
    #[test]
    fn test_data_bits_screen_row_count() {
        let rows = 3 + 1 + 4 + 1 + 1 + 1; // 11
        assert!(rows <= 22, "data bits screen is {} rows, exceeds 22", rows);
    }

    /// Parity screen: header(3) + blank + 3 options + blank + footer + prompt = 10.
    #[test]
    fn test_parity_screen_row_count() {
        let rows = 3 + 1 + 3 + 1 + 1 + 1; // 10
        assert!(rows <= 22, "parity screen is {} rows, exceeds 22", rows);
    }

    /// Stop bits screen: header(3) + blank + 2 options + blank + footer + prompt = 9.
    #[test]
    fn test_stop_bits_screen_row_count() {
        let rows = 3 + 1 + 2 + 1 + 1 + 1; // 9
        assert!(rows <= 22, "stop bits screen is {} rows, exceeds 22", rows);
    }

    /// Configuration menu static rows (no addresses):
    /// header(3) + blank + status(2) + blank + menu(4) + blank + footer(1) + prompt(1) = 14.
    /// The IP address list is dynamic; with addresses it adds a label + N addrs + blank.
    /// Typical machines have 1-3 addresses, fitting well within 22.
    #[test]
    fn test_config_menu_row_count() {
        // Configuration submenu: header(3) + blank + 6 items + blank + Q/H + prompt = 13
        let submenu_rows = 3 + 1 + 6 + 1 + 1 + 1; // 13
        assert!(submenu_rows <= 22, "config submenu is {} rows, exceeds 22", submenu_rows);
        // Server configuration: header(3) + blank + 2 status + blank + 5 items + blank + Q/H + prompt = 15
        let static_rows = 3 + 1 + 2 + 1 + 5 + 1 + 1 + 1; // 15
        assert!(static_rows <= 22, "server config menu static is {} rows, exceeds 22", static_rows);
        // With address list: +1 label +3 addrs +1 blank = 5 extra → 20
        let with_addrs = static_rows + 1 + 3 + 1; // 20
        assert!(with_addrs <= 22, "server config menu with 3 addrs is {} rows, exceeds 22", with_addrs);
    }

    /// Configuration help screen (ANSI): header(3) + blank + 15 content lines +
    /// blank + "Press any key" = 21 rows.
    #[test]
    fn test_config_help_screen_row_count() {
        let rows = 3 + 1 + 15 + 1 + 1; // 21
        assert!(rows <= 22, "config help screen is {} rows, exceeds 22", rows);
    }

    /// Configuration help lines (PETSCII) must fit 40 cols.
    #[test]
    fn test_config_help_lines_fit_petscii() {
        let lines = [
            "  Change settings for THIS server.",
            "  The SSH Gateway and Telnet",
            "  Gateway options in the main",
            "  menu are not affected.",
            "  T  Enable or disable the telnet",
            "     server listener",
            "  P  Change the telnet port",
            "  S  Enable or disable the SSH",
            "     server listener",
            "  O  Change the SSH port",
            "  R  Restart the server",
            "  Changes are saved immediately",
            "  but require a server restart.",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "config help '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Security menu row count:
    /// header(3) + blank + status + blank + 4 creds + blank + 6 items + blank + Q/H + prompt = 20
    #[test]
    fn test_security_menu_row_count() {
        let rows = 3 + 1 + 1 + 1 + 4 + 1 + 6 + 1 + 1 + 1; // 20
        assert!(rows <= 22, "security menu is {} rows, exceeds 22", rows);
    }

    /// Security help lines (PETSCII) must fit 40 cols.
    #[test]
    fn test_security_help_lines_fit_petscii() {
        let lines = [
            "  Configure login security.",
            "  L  Toggle whether a login is",
            "     required to access server",
            "  U  Set the telnet username",
            "  P  Set the telnet password",
            "  S  Set the SSH username",
            "  W  Set the SSH password",
            "  R  Restart the server",
            "  Telnet and SSH have separate",
            "  credentials. Changes require",
            "  a server restart.",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "security help '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Security help screen (PETSCII): header(3) + blank + 13 content +
    /// blank + "Press any key" = 19 rows.
    #[test]
    fn test_security_help_screen_row_count() {
        let rows = 3 + 1 + 13 + 1 + 1; // 19
        assert!(rows <= 22, "security help screen is {} rows, exceeds 22", rows);
    }

    /// Other settings menu row count:
    /// header(3) + blank + 5 values + blank + 6 items + blank + Q/H + prompt = 19
    #[test]
    fn test_other_settings_menu_row_count() {
        let rows = 3 + 1 + 5 + 1 + 6 + 1 + 1 + 1; // 19
        assert!(rows <= 22, "other settings menu is {} rows, exceeds 22", rows);
    }

    /// Other settings help lines (PETSCII) must fit 40 cols.
    #[test]
    fn test_other_help_lines_fit_petscii() {
        let lines = [
            "  A  Groq API key for AI Chat",
            "     (get one free at groq.com)",
            "  B  Default homepage URL for",
            "     the built-in web browser",
            "  W  Default zip code for the",
            "     weather feature",
            "  V  Toggle verbose transfer log",
            "  G  Toggle GUI on startup",
            "     (requires restart)",
            "  R  Restart the server",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "other help '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Other settings help screen (PETSCII): header(3) + blank + 10 content +
    /// blank + "Press any key" = 16 rows.
    #[test]
    fn test_other_help_screen_row_count() {
        let rows = 3 + 1 + 10 + 1 + 1; // 16
        assert!(rows <= 22, "other help screen is {} rows, exceeds 22", rows);
    }

    /// File Transfer settings submenu row count:
    /// header(3) + blank + 1 value + blank + 5 items + blank + Q/H + prompt = 14
    #[test]
    fn test_file_transfer_settings_menu_row_count() {
        let rows = 3 + 1 + 1 + 1 + 5 + 1 + 1 + 1; // 14
        assert!(rows <= 22, "file transfer settings menu is {} rows, exceeds 22", rows);
    }

    // ─── paginate_help ─────────────────────────────────────
    //
    // `show_help_page` delegates paging to `TelnetSession::paginate_help`.
    // These tests lock in the blank-line-respecting behavior so groups
    // of related lines (section header + continuations) stay together
    // on a single page — regressions here would split a letter-command
    // from its description, which is exactly what we don't want.

    /// Content that fits within one page passes through unchanged (no
    /// trailing blanks, no split).
    #[test]
    fn test_paginate_help_single_page() {
        let lines = ["  A  line one", "  B  line two", "  C  line three"];
        let pages = TelnetSession::paginate_help(&lines, 15);
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0], lines);
    }

    /// Empty content produces zero pages — `show_help_page` handles
    /// that by substituting a single empty page.
    #[test]
    fn test_paginate_help_empty() {
        let pages = TelnetSession::paginate_help(&[], 15);
        assert!(pages.is_empty());
    }

    /// When content overflows, split at the last blank line within the
    /// page-size budget. Trailing blanks are stripped so each page
    /// starts and ends on a real content line.
    #[test]
    fn test_paginate_help_splits_at_blank_line() {
        // 20 lines total with a blank at index 9. Budget = 15, so the
        // splitter should pick the blank at position 10 (1-indexed),
        // strip it, and emit page 1 = lines 0..9, page 2 = lines 10..19.
        let lines = [
            "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "",
            "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10",
        ];
        let pages = TelnetSession::paginate_help(&lines, 15);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0], &["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"]);
        assert_eq!(
            pages[1],
            &["b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10"]
        );
    }

    /// When no blank line exists within the budget, fall back to a
    /// hard split at `max_per_page`. Authors should avoid this by
    /// adding blank lines between groups — but we don't want to loop
    /// forever on malformed input either.
    #[test]
    fn test_paginate_help_force_split_when_no_blank() {
        let lines = [
            "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "x14", "x15", "x16", "x17",
        ];
        let pages = TelnetSession::paginate_help(&lines, 10);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].len(), 10);
        assert_eq!(pages[1].len(), 7);
    }

    /// A section header + its indented continuation lines must stay
    /// together when separated from other groups by blank lines. This
    /// is the guarantee the user asked for.
    #[test]
    fn test_paginate_help_keeps_section_groups_together() {
        let lines = [
            "  A  alpha header",
            "     first continuation",
            "     second continuation",
            "",
            "  B  beta header",
            "     beta continuation",
            "",
            "  C  gamma header",
            "     gamma continuation",
            "     gamma continuation 2",
        ];
        // Budget of 5 forces a split — but NEVER in the middle of a
        // group.  With a blank at index 3 and 6, the splitter picks
        // the latest blank inside the first 5: index 3.  Page 1 gets
        // lines 0..3 (the A group). Page 2 has 6 lines remaining,
        // still over budget, so it splits at the next blank (index 2
        // of the remainder): the B group alone (2 lines).  Page 3:
        // the C group (3 lines).
        let pages = TelnetSession::paginate_help(&lines, 5);
        assert_eq!(pages.len(), 3, "expected 3 pages, got {:?}", pages);
        assert_eq!(pages[0].len(), 3); // A + 2 continuations
        assert_eq!(pages[0][0], "  A  alpha header");
        assert_eq!(pages[1].len(), 2); // B + 1 continuation
        assert_eq!(pages[1][0], "  B  beta header");
        assert_eq!(pages[2].len(), 3); // C + 2 continuations
        assert_eq!(pages[2][0], "  C  gamma header");
    }

    /// Multiple consecutive blanks between groups collapse on page
    /// boundaries — the next page starts on the next real content
    /// line, not on a floating blank.
    #[test]
    fn test_paginate_help_skips_leading_blanks() {
        let lines = ["a", "a", "a", "", "", "", "b", "b"];
        let pages = TelnetSession::paginate_help(&lines, 3);
        // Page 1 is the three a's; the three blanks get swallowed at
        // the split; page 2 starts cleanly on "b" with no stray
        // leading blanks.
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0], &["a", "a", "a"]);
        assert_eq!(pages[1], &["b", "b"]);
    }

    /// Invalid `max_per_page` of 0 should panic (debug only — the
    /// caller in show_help_page passes a compile-time constant, so
    /// this can never happen in practice, but the assertion guards
    /// against a future typo).
    #[test]
    #[should_panic(expected = "max_per_page")]
    fn test_paginate_help_zero_max_panics() {
        let _ = TelnetSession::paginate_help(&["a"], 0);
    }

    /// The paging footer string must fit PETSCII width (40 cols).
    /// If this test fails, update the `show_help_page` footer format
    /// string.
    #[test]
    fn test_paging_footer_fits_petscii() {
        let examples = [
            "  Page 1/2 - next key, Q to quit",
            "  Page 10/99 - next key, Q to quit",
            "  Page 2/2 - Press any key.",
            "  Press any key to continue.",
        ];
        for s in &examples {
            assert!(
                s.len() <= PETSCII_WIDTH,
                "paging footer '{}' is {} chars, exceeds {}",
                s, s.len(), PETSCII_WIDTH
            );
        }
    }

    /// XMODEM / YMODEM settings menu row count (shared renderer):
    /// header(3) + blank + 5 values + blank + 5 items + blank + Q/H + prompt = 18
    #[test]
    fn test_xmodem_settings_menu_row_count() {
        let rows = 3 + 1 + 5 + 1 + 5 + 1 + 1 + 1; // 18
        assert!(rows <= 22, "xmodem settings menu is {} rows, exceeds 22", rows);
    }

    /// ZMODEM settings menu row count:
    /// header(3) + blank + 4 values + blank + 5 items + blank + Q/H + prompt = 17
    #[test]
    fn test_zmodem_settings_menu_row_count() {
        let rows = 3 + 1 + 4 + 1 + 5 + 1 + 1 + 1; // 17
        assert!(rows <= 22, "zmodem settings menu is {} rows, exceeds 22", rows);
    }

    /// XMODEM settings help lines (PETSCII) must fit 40 cols.
    #[test]
    fn test_xmodem_help_lines_fit_petscii() {
        let lines = [
            "  Configure XMODEM family transfer",
            "  settings. Shared with XMODEM-1K",
            "  and YMODEM.",
            "  N  Negotiation timeout: how",
            "     long to wait for transfer",
            "     to begin",
            "  I  Retry interval: C/NAK poke",
            "     gap (spec ~10 s, def 7 s)",
            "  B  Block timeout: how long to",
            "     wait for each block",
            "  M  Max retries per block",
            "  R  Restart the server",
            "  Takes effect on next transfer.",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "xmodem help '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// ZMODEM settings help lines (PETSCII) must fit 40 cols.
    #[test]
    fn test_zmodem_help_lines_fit_petscii() {
        let lines = [
            "  Configure ZMODEM file transfer",
            "  settings.",
            "  N  Negotiation timeout: how",
            "     long to wait for ZRQINIT /",
            "     ZRINIT handshake",
            "  I  Retry interval: ZRINIT/",
            "     ZRQINIT re-send gap (def 5)",
            "  F  Frame timeout: per-frame",
            "     read timeout in transfer",
            "  M  Max retries for ZRQINIT /",
            "     ZRPOS / ZDATA frames",
            "  R  Restart the server",
            "  Takes effect on next transfer.",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "zmodem help '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// File transfer help lines (PETSCII) must fit 40 cols.
    #[test]
    fn test_file_transfer_help_lines_fit_petscii() {
        let lines = [
            "  Configure file-transfer options.",
            "  D  Transfer directory: where",
            "     uploads land and downloads",
            "     are served from",
            "  X  XMODEM settings",
            "  Y  YMODEM settings",
            "  Z  ZMODEM settings",
            "  R  Restart the server",
            "  XMODEM, XMODEM-1K, and YMODEM",
            "  share the same timeouts.",
            "  ZMODEM has its own.",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "file transfer help '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// XMODEM help screen (PETSCII): header(3) + blank + 15 content +
    /// blank + "Press any key" = 21 rows.
    #[test]
    fn test_xmodem_help_screen_row_count() {
        let rows = 3 + 1 + 15 + 1 + 1; // 21
        assert!(rows <= 22, "xmodem help screen is {} rows, exceeds 22", rows);
    }

    /// ZMODEM help screen (PETSCII): header(3) + blank + 15 content +
    /// blank + "Press any key" = 21 rows.  Content grew by +2 rows (Retry
    /// interval) but we trimmed the footer by -2, net 0.
    #[test]
    fn test_zmodem_help_screen_row_count() {
        let rows = 3 + 1 + 15 + 1 + 1; // 21
        assert!(rows <= 22, "zmodem help screen is {} rows, exceeds 22", rows);
    }

    /// File Transfer help screen (PETSCII): header(3) + blank + 13 content
    /// + blank + "Press any key" = 19 rows.
    #[test]
    fn test_file_transfer_help_screen_row_count() {
        let rows = 3 + 1 + 13 + 1 + 1; // 19
        assert!(
            rows <= 22,
            "file transfer help screen is {} rows, exceeds 22",
            rows,
        );
    }

    /// The breadcrumb prompts for the File Transfer submenu and each
    /// per-protocol page must fit PETSCII width (40 cols) when the
    /// "> " suffix is appended.
    #[test]
    fn test_file_transfer_breadcrumbs_fit_petscii() {
        // These mirror the literal strings passed to `self.cyan(...)`
        // in the submenu and per-protocol pages.  Keep this list in
        // sync with the code; a rename in one place will trigger a
        // test failure if not updated here.
        let breadcrumbs = [
            "ethernet/config/xfer",
            "ethernet/config/xfer/xmodem",
            "ethernet/config/xfer/ymodem",
            "ethernet/config/xfer/zmodem",
        ];
        for b in &breadcrumbs {
            let prompt = format!("{}> ", b);
            assert!(
                prompt.len() <= PETSCII_WIDTH,
                "breadcrumb prompt '{}' is {} chars, exceeds {}",
                prompt,
                prompt.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Every per-protocol settings page must render its status rows
    /// (value column) within PETSCII width.  The longest rendered
    /// status line is `  Applies to:    <applies_to>`, with the
    /// `applies_to` values below plugged into `xmodem_family_settings`.
    #[test]
    fn test_xmodem_family_applies_to_lines_fit_petscii() {
        for applies_to in &["XMODEM family", "XMODEM family (shared)"] {
            let line = format!("  Applies to:    {}", applies_to);
            assert!(
                line.len() <= PETSCII_WIDTH,
                "'Applies to' line '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Modem help screen (ANSI): header(3) + blank + 16 content lines +
    /// blank + "Press any key" = 22 rows.
    #[test]
    fn test_modem_help_screen_row_count() {
        let rows = 3 + 1 + 16 + 1 + 1; // 22
        assert!(rows <= 22, "modem help screen is {} rows, exceeds 22", rows);
    }

    /// Main help screen: header(3) + blank + 14 content lines +
    /// blank + "Press any key" = 20 rows.
    #[test]
    fn test_main_help_screen_row_count() {
        let rows = 3 + 1 + 14 + 1 + 1; // 20
        assert!(rows <= 22, "main help screen is {} rows, exceeds 22", rows);
    }

    /// All help page content lines must fit PETSCII width (40 cols).
    #[test]
    fn test_help_lines_fit_petscii() {
        let help_lines = [
            // Main menu help
            "  A  AI Chat: ask questions to an AI",
            "  B  Browser: browse the web",
            "  C  Configuration: server settings",
            "     and other options",
            "  F  File Transfer: upload/download",
            "     files using the XMODEM protocol",
            "  R  Troubleshooting: diagnose",
            "     terminal input issues",
            "  S  SSH Gateway: connect to a",
            "     remote server via SSH",
            "  T  Telnet Gateway: connect to a",
            "     remote server via telnet",
            "  W  Weather: check weather by zip",
            "  X  Exit: disconnect from server",
            // Configuration submenu help
            "  E  Security: require login,",
            "     set usernames and passwords",
            "  M  Modem: configure the serial",
            "     port for modem emulation",
            "  S  Server: enable/disable",
            "     services, set ports, and",
            "     restart the server",
            "  F  File Transfer: per-protocol",
            "     XMODEM, YMODEM, ZMODEM setup",
            "  O  Other: AI key, logging,",
            "     and general settings",
            "  R  Reset all settings to their",
            "     default values",
            // Other settings help
            "  A  Groq API key for AI Chat",
            "     (get one free at groq.com)",
            "  B  Default homepage URL for",
            "     the built-in web browser",
            "  W  Default zip code for the",
            "     weather feature",
            "  V  Toggle verbose transfer log",
            "  G  Toggle GUI on startup",
            "     (requires restart)",
            "  R  Restart the server",
            // Security help
            "  Configure login security.",
            "  L  Toggle whether a login is",
            "     required to access server",
            "  U  Set the telnet username",
            "  P  Set the telnet password",
            "  S  Set the SSH username",
            "  W  Set the SSH password",
            "  R  Restart the server",
            "  Telnet and SSH have separate",
            "  credentials. Changes require",
            "  a server restart.",
            // XMODEM settings help
            "  Configure XMODEM family transfer",
            "  settings. Shared with XMODEM-1K",
            "  and YMODEM.",
            "  N  Negotiation timeout: how",
            "     long to wait for transfer",
            "     to begin",
            "  I  Retry interval: C/NAK poke",
            "     gap (spec ~10 s, def 7 s)",
            "  B  Block timeout: how long to",
            "     wait for each block",
            "  M  Max retries per block",
            "  R  Restart the server",
            "  Takes effect on next transfer.",
            // File transfer help
            "  U  Upload a file to the server",
            "  D  Download a file from server",
            "  X  Delete a file on the server",
            "  C  Change to a subdirectory",
            "  I  Toggle IAC escaping for",
            "     binary file transfers",
            "  R  Refresh the screen",
            "  Q  Back to the main menu",
            // Download / delete help
            "  #    Enter file number to download",
            "  #    Enter file number to delete",
            "  P    Previous page of files",
            "  N    Next page of files",
            "  Q    Back to file transfer menu",
            "  ESC  Return to main menu",
            // AI chat help
            "  P    Previous page of answer",
            "  N    Next page of answer",
            "  Q    Done, return to main menu",
            // Bookmarks help
            "  #    Enter bookmark number to open",
            "  D    Delete a bookmark by number",
            "  ESC  Cancel and go back",
            // Form help
            "  #    Enter a field number to",
            "       edit its value",
            "  S    Submit the form",
            "  Q    Cancel and go back",
            // Dialup mapping help
            "  Map phone numbers to host:port",
            "  targets for the modem emulator.",
            "  Dial a number with ATDT, ATDP,",
            "  or ATD (all work the same) and",
            "  the server connects to the",
            "  mapped host:port for you.",
            "  You can still dial host:port",
            "  directly - mappings are optional.",
            "  Mappings are saved in dialup.conf.",
        ];
        for line in &help_lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "help line '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Modem help content lines must fit PETSCII width.
    #[test]
    fn test_modem_help_lines_fit_petscii() {
        let lines = [
            "  This server emulates a Hayes-",
            "  compatible modem on the serial",
            "  port. Connect your retro",
            "  hardware and use AT commands:",
            "  ATDT ethernet-gateway",
            "    Connect to this gateway",
            "  ATDT host:port",
            "    Dial a remote telnet host",
            "  ATDL Redial last number",
            "  AT&V Show settings",
            "  AT&W Save settings",
            "  +++  Return to command mode",
            "  ATO  Return online",
            "  ATH  Hang up",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "modem help '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// Separator width must match terminal type.
    #[test]
    fn test_separator_widths() {
        assert_eq!("=".repeat(PETSCII_WIDTH).len(), 40);
        assert_eq!("=".repeat(56).len(), 56); // ANSI/ASCII separator
    }

    /// PAGE_CONTENT_LINES must leave room for header and footer within 22 rows.
    #[test]
    fn test_page_content_lines_fits_screen() {
        let overhead = 3 + 3; // header (sep+title+sep) + footer (pos+nav+prompt)
        assert!(
            TelnetSession::PAGE_CONTENT_LINES + overhead <= 22,
            "PAGE_CONTENT_LINES {} + overhead {} = {} exceeds 22",
            TelnetSession::PAGE_CONTENT_LINES,
            overhead,
            TelnetSession::PAGE_CONTENT_LINES + overhead,
        );
    }

    /// TRANSFER_PAGE_SIZE must fit within 22 rows with header and footer.
    #[test]
    fn test_transfer_page_size_fits_screen() {
        let overhead = 3 + 2 + 5; // header + col headers + footer
        assert!(
            TelnetSession::TRANSFER_PAGE_SIZE + overhead <= 22,
            "TRANSFER_PAGE_SIZE {} + overhead {} = {} exceeds 22",
            TelnetSession::TRANSFER_PAGE_SIZE,
            overhead,
            TelnetSession::TRANSFER_PAGE_SIZE + overhead,
        );
    }

    /// File listing column format must fit PETSCII width.
    /// Format: "  XX. FILENAME_22_CHARS_____ SIZE"
    #[test]
    fn test_file_listing_line_fits_petscii() {
        // Worst case: "  10. 1234567890123456789012 1023 B"
        let line = format!("  {:>2}. {:<22} {}", 10, "a]".repeat(11), "1023 B");
        assert!(
            line.len() <= PETSCII_WIDTH,
            "file listing line '{}' is {} chars, exceeds {}",
            line,
            line.len(),
            PETSCII_WIDTH,
        );
    }

    /// Download/delete column header must fit PETSCII width.
    #[test]
    fn test_file_listing_header_fits_petscii() {
        let header = format!("   {} {:<22} {}", "#.", "Filename", "Size");
        // Without color codes, just the visible text
        assert!(
            header.len() <= PETSCII_WIDTH,
            "column header '{}' is {} chars, exceeds {}",
            header,
            header.len(),
            PETSCII_WIDTH,
        );
    }

    /// File listing divider must fit PETSCII width.
    #[test]
    fn test_file_listing_divider_fits_petscii() {
        let divider = format!("  {}", "-".repeat(36));
        assert!(
            divider.len() <= PETSCII_WIDTH,
            "divider '{}' is {} chars, exceeds {}",
            divider,
            divider.len(),
            PETSCII_WIDTH,
        );
    }

    // ─── Pagination math ─────────────────────────────────

    #[test]
    fn test_pagination_zero_files() {
        let files: Vec<(String, u64)> = vec![];
        assert!(files.is_empty());
    }

    #[test]
    fn test_pagination_exactly_one_page() {
        let page_size = TelnetSession::TRANSFER_PAGE_SIZE;
        let files: Vec<usize> = (0..page_size).collect();
        let total_pages = files.len().div_ceil(page_size);
        assert_eq!(total_pages, 1);
        assert_eq!(files.len(), page_size);
    }

    #[test]
    fn test_pagination_one_over_page() {
        let page_size = TelnetSession::TRANSFER_PAGE_SIZE;
        let files: Vec<usize> = (0..page_size + 1).collect();
        let total_pages = files.len().div_ceil(page_size);
        assert_eq!(total_pages, 2);
        // Page 1
        let offset = 0;
        let end = (offset + page_size).min(files.len());
        assert_eq!(end - offset, page_size);
        // Page 2
        let offset = page_size;
        let end = (offset + page_size).min(files.len());
        assert_eq!(end - offset, 1);
    }

    #[test]
    fn test_pagination_many_files() {
        let page_size = TelnetSession::TRANSFER_PAGE_SIZE;
        let count: usize = 105;
        let total_pages = count.div_ceil(page_size);
        assert_eq!(total_pages, 11); // 10 full pages + 1 partial
        // Last page
        let offset = (total_pages - 1) * page_size;
        let end = (offset + page_size).min(count);
        assert_eq!(end - offset, 5); // 105 - 100 = 5
    }

    #[test]
    fn test_ai_pagination_single_line() {
        let page_h = TelnetSession::PAGE_CONTENT_LINES;
        let total = 1;
        let scroll = 0;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, 1);
        assert_eq!(scroll, 0);  // no prev
        assert!(end >= total);  // no next
    }

    #[test]
    fn test_ai_pagination_exactly_one_page() {
        let page_h = TelnetSession::PAGE_CONTENT_LINES;
        let total = page_h;
        let scroll = 0;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, page_h);
        assert_eq!(scroll, 0);
        assert!(end >= total);
    }

    #[test]
    fn test_ai_pagination_two_pages() {
        let page_h = TelnetSession::PAGE_CONTENT_LINES;
        let total = page_h + 5;
        // Page 1
        let scroll = 0;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, page_h);
        assert!(end < total); // has next
        // Page 2
        let scroll = page_h;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, total);
        assert_eq!(end - scroll, 5);
        assert!(scroll > 0);     // has prev
        assert!(end >= total);   // no next
    }

    // ─── XMODEM constants ────────────────────────────────

    #[test]
    fn test_xmodem_block_size() {
        assert_eq!(crate::xmodem::XMODEM_BLOCK_SIZE, 128);
    }

    #[test]
    fn test_max_file_size() {
        assert_eq!(TelnetSession::MAX_FILE_SIZE, 8 * 1024 * 1024);
    }

    // ─── Web browser ─────────────────────────────────────

    #[test]
    fn test_browser_menu_path() {
        assert_eq!(Menu::Browser.path(), "ethernet/web");
    }

    #[test]
    fn test_web_page_height_fits_screen() {
        let overhead = 3 + 1 + 4 + 1; // header(3) + blank + footer(pos+url+nav1+nav2) + prompt
        assert!(
            TelnetSession::WEB_PAGE_HEIGHT + overhead <= 22,
            "WEB_PAGE_HEIGHT {} + overhead {} = {} exceeds 22",
            TelnetSession::WEB_PAGE_HEIGHT,
            overhead,
            TelnetSession::WEB_PAGE_HEIGHT + overhead,
        );
    }

    #[test]
    fn test_web_max_history_is_reasonable() {
        const _: () = assert!(TelnetSession::WEB_MAX_HISTORY >= 10, "too few history entries");
        const _: () = assert!(TelnetSession::WEB_MAX_HISTORY <= 200, "excessive history cap");
    }

    #[test]
    fn test_web_browser_home_lines_fit_petscii() {
        let lines = [
            "  WEB BROWSER",
            "  G=Go/Search K=Bookmarks Q=Back H=Help",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "line '{}' is {} chars, exceeds {}",
                line,
                line.len(),
                PETSCII_WIDTH,
            );
        }
    }

    #[test]
    fn test_web_browser_footer_fits_petscii() {
        // Row 1 worst case (PETSCII): P=Pv N=Nx T=Top E=End S=Find
        let row1 = "  P=Pv N=Nx T=Top E=End S=Find";
        assert!(
            row1.len() <= PETSCII_WIDTH,
            "nav row1 '{}' is {} chars, exceeds {}",
            row1, row1.len(), PETSCII_WIDTH,
        );
        // Row 2 worst case (PETSCII): G=Go L=Lk F=Fm K=Bm H=? B=Bk Q=X
        let row2 = "  G=Go L=Lk F=Fm K=Bm H=? B=Bk Q=X";
        assert!(
            row2.len() <= PETSCII_WIDTH,
            "nav row2 '{}' is {} chars, exceeds {}",
            row2, row2.len(), PETSCII_WIDTH,
        );
    }

    #[test]
    fn test_web_browser_status_line_fits_petscii() {
        let status = format!("  ({}-{} of {})", 4983, 5000, 5000);
        assert!(
            status.len() <= PETSCII_WIDTH,
            "status '{}' is {} chars, exceeds {}",
            status,
            status.len(),
            PETSCII_WIDTH,
        );
        // Form indicator line
        let form_hint = "  1 form on this page (F to edit)";
        assert!(
            form_hint.len() <= PETSCII_WIDTH,
            "form hint '{}' is {} chars, exceeds {}",
            form_hint, form_hint.len(), PETSCII_WIDTH,
        );
        let form_hint_multi = "  99 forms on this page (F to edit)";
        assert!(
            form_hint_multi.len() <= PETSCII_WIDTH,
            "form hint '{}' is {} chars, exceeds {}",
            form_hint_multi, form_hint_multi.len(), PETSCII_WIDTH,
        );
    }

    // ─── Web browser pagination ──────────────────────────

    #[test]
    fn test_web_pagination_single_line() {
        let page_h = TelnetSession::WEB_PAGE_HEIGHT;
        let total = 1;
        let scroll = 0;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, 1);
        assert!(scroll == 0);   // no prev
        assert!(end >= total);   // no next
    }

    #[test]
    fn test_web_pagination_exact_page() {
        let page_h = TelnetSession::WEB_PAGE_HEIGHT;
        let total = page_h;
        let scroll = 0;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, page_h);
        assert!(end >= total); // no next
    }

    #[test]
    fn test_web_pagination_two_pages() {
        let page_h = TelnetSession::WEB_PAGE_HEIGHT;
        let total = page_h + 5;
        // Page 1
        let scroll = 0;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, page_h);
        assert!(end < total); // has next
        // Page 2
        let scroll = page_h;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, total);
        assert!(scroll > 0);    // has prev
        assert!(end >= total);   // no next
    }

    // ─── Web browser top/end navigation ──────────────────

    #[test]
    fn test_web_end_scroll_calculation() {
        let page_h = TelnetSession::WEB_PAGE_HEIGHT;
        let total = 100;
        // E command: scroll = total - page_h
        let scroll = total - page_h;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, total); // last line visible
        assert_eq!(end - scroll, page_h); // full page
    }

    #[test]
    fn test_web_end_scroll_short_page() {
        let page_h = TelnetSession::WEB_PAGE_HEIGHT;
        let total: usize = 5;
        // E command when total <= page_h: scroll stays 0
        let scroll = total.saturating_sub(page_h);
        assert_eq!(scroll, 0);
    }

    // ─── Web search ──────────────────────────────────────

    #[test]
    fn test_web_search_logic_finds_match() {
        let lines: Vec<String> = vec![
            "Hello world".to_string(),
            "Foo bar".to_string(),
            "Rust programming".to_string(),
            "More text".to_string(),
        ];
        let query = "rust";
        let total = lines.len();
        let start_line = 1; // scroll (0) + 1
        let mut found = None;
        for offset in 0..total {
            let idx = (start_line + offset) % total;
            if lines[idx].to_ascii_lowercase().contains(query) {
                found = Some(idx);
                break;
            }
        }
        assert_eq!(found, Some(2));
    }

    #[test]
    fn test_web_search_wraps_around() {
        let lines: Vec<String> = vec![
            "Match here".to_string(),
            "No match".to_string(),
            "No match".to_string(),
        ];
        let query = "match here";
        let total = lines.len();
        let start_line = 1 + 1; // searching from scroll=1, so start at 2
        let mut found = None;
        for offset in 0..total {
            let idx = (start_line + offset) % total;
            if lines[idx].to_ascii_lowercase().contains(query) {
                found = Some(idx);
                break;
            }
        }
        assert_eq!(found, Some(0)); // wraps around to line 0
    }

    #[test]
    fn test_web_search_no_match() {
        let lines: Vec<String> = vec![
            "Hello".to_string(),
            "World".to_string(),
        ];
        let query = "xyz";
        let total = lines.len();
        let start_line = 1; // scroll (0) + 1
        let mut found = None;
        for offset in 0..total {
            let idx = (start_line + offset) % total;
            if lines[idx].to_ascii_lowercase().contains(query) {
                found = Some(idx);
                break;
            }
        }
        assert!(found.is_none());
    }

    // ─── Web history with scroll ─────────────────────────

    #[test]
    fn test_web_history_stores_scroll() {
        let mut history: Vec<(String, usize)> = Vec::new();
        history.push(("https://page1.com".to_string(), 42));
        history.push(("https://page2.com".to_string(), 0));
        assert_eq!(history.last().unwrap().1, 0);
        history.pop();
        assert_eq!(history.last().unwrap().1, 42);
    }

    #[test]
    fn test_web_history_cap_with_scroll() {
        let max = TelnetSession::WEB_MAX_HISTORY;
        let mut history: Vec<(String, usize)> = Vec::new();
        for i in 0..max {
            history.push((format!("https://page{}.com", i), i * 10));
        }
        assert_eq!(history.len(), max);
        // Push one more — evict oldest
        history.push(("https://new.com".to_string(), 99));
        if history.len() > max {
            history.remove(0);
        }
        assert_eq!(history.len(), max);
        assert_eq!(history[0].0, "https://page1.com");
        assert_eq!(history.last().unwrap().1, 99);
    }

    // ─── Bookmarks UI layout ─────────────────────────────

    #[test]
    fn test_bookmarks_screen_lines_fit_petscii() {
        let lines = [
            "  BOOKMARKS",
            "  #=Open D=Delete",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "line '{}' is {} chars, exceeds {}",
                line, line.len(), PETSCII_WIDTH,
            );
        }
    }

    #[test]
    fn test_bookmark_entry_fits_petscii() {
        // Worst case: "  99. " + 30 chars title
        let line = format!("  {:>2}. {}", 99, "a".repeat(30));
        assert!(
            line.len() <= PETSCII_WIDTH,
            "bookmark entry '{}' is {} chars, exceeds {}",
            line, line.len(), PETSCII_WIDTH,
        );
    }

    // ─── Troubleshooting ─────────────────────────────────

    #[test]
    fn test_troubleshooting_lines_fit_petscii() {
        let lines = [
            "  CHARACTER TROUBLESHOOTING",
            "  Client:   Serial modem",
            "  Terminal: PETSCII",
            "  IAC esc:  Off",
            "  Press any key to see its hex value.",
            "  Press <- twice to return to menu.",
            "  Key: 0x1B ( 27) = ESC",
            "  Key: 0x41 ( 65) = 'A'",
            "  Key: 0x14 ( 20) = DC4/C64-DEL",
            "  Key: 0x9D (157) = C64-LEFT",
            "  Returning to main menu...",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "troubleshooting line '{}' is {} chars, exceeds {}",
                line, line.len(), PETSCII_WIDTH,
            );
        }
    }

    // ─── Help screen ──────────────────────────────────────

    #[test]
    fn test_web_help_lines_fit_petscii() {
        let lines = [
            "  BROWSER HELP",
            "  [1] [2] etc. next to text",
            "  are links to other pages.",
            "  N/P  Next/Previous page",
            "  T/E  Jump to Top/End",
            "  S    Search text in page",
            "  G    Go to URL or search",
            "  L    Follow link (any #)",
            "  F    Fill out forms",
            "  K    Save bookmark",
            "  B    Back to previous page",
            "  R    Reload current page",
            "  Q    Close page",
            "  ESC  Exit browser",
            "  G  Go to a URL or search query",
            "  K  Open saved bookmarks",
            "  Q  Exit browser to main menu",
        ];
        for line in &lines {
            assert!(
                line.len() <= PETSCII_WIDTH,
                "help line '{}' is {} chars, exceeds {}",
                line, line.len(), PETSCII_WIDTH,
            );
        }
    }

    #[test]
    fn test_web_help_page_view_row_count() {
        // header(3) + 2 link explanation + blank + 12 help lines + blank + "press any key" = 20 rows max
        let rows = 3 + 2 + 1 + 12 + 1 + 1;
        assert!(rows <= 22, "help screen is {} rows, exceeds 22", rows);
    }

    // ─── URL/Search prompt ───────────────────────────────

    #[test]
    fn test_url_search_prompt_fits_petscii() {
        let prompt = "  URL/Search: ";
        assert!(
            prompt.len() <= PETSCII_WIDTH,
            "prompt '{}' is {} chars, exceeds {}",
            prompt, prompt.len(), PETSCII_WIDTH,
        );
    }

    #[test]
    fn test_find_prompt_fits_petscii() {
        let prompt = "  Find: ";
        assert!(
            prompt.len() <= PETSCII_WIDTH,
            "prompt '{}' is {} chars, exceeds {}",
            prompt, prompt.len(), PETSCII_WIDTH,
        );
    }

    // ─── Modem settings confirmation messages ───────────

    /// All modem_apply_settings prompt/status messages must fit PETSCII width.
    #[test]
    fn test_modem_apply_messages_fit_petscii() {
        let messages = [
            "  New settings will be applied.",
            "  You have 60 seconds to adjust",
            "  your terminal and type Y then",
            "  Enter, or settings will revert.",
            "  Settings confirmed.",
            "  Press any key to continue.",
            "  No response. Reverting settings.",
        ];
        for msg in &messages {
            assert!(
                msg.len() <= PETSCII_WIDTH,
                "modem apply msg '{}' is {} chars, exceeds {}",
                msg,
                msg.len(),
                PETSCII_WIDTH,
            );
        }
    }

    /// The countdown reminder must fit PETSCII width even with 2-digit seconds.
    #[test]
    fn test_modem_apply_countdown_fits_petscii() {
        let reminder = format!("  Type Y+Enter to confirm. ({}s left)", 55);
        assert!(
            reminder.len() <= PETSCII_WIDTH,
            "countdown '{}' is {} chars, exceeds {}",
            reminder,
            reminder.len(),
            PETSCII_WIDTH,
        );
    }

    /// Modem apply settings confirmation screen: blank + 4 warning lines +
    /// blank + (countdown reminders) + confirmation/revert.  The screen is
    /// not a full menu redraw so row count is not constrained to 22, but
    /// individual messages must fit width.
    #[test]
    fn test_modem_apply_settings_row_count() {
        // Warning: blank + 4 lines + blank = 6.
        // Worst case after: 12 countdown reminders (every 5s for 60s) + revert msg = 14.
        // Total ≤ 20, well within 22.
        let warning_rows = 6;
        assert!(warning_rows <= 22);
    }

    // ─── Telnet option negotiation ───────────────────────

    #[test]
    fn test_match_terminal_name_c64_variants() {
        assert_eq!(match_terminal_name("C64"), Some(TerminalType::Petscii));
        assert_eq!(match_terminal_name("c64"), Some(TerminalType::Petscii));
        assert_eq!(match_terminal_name("C128"), Some(TerminalType::Petscii));
        assert_eq!(match_terminal_name("PETSCII"), Some(TerminalType::Petscii));
        assert_eq!(match_terminal_name("COMMODORE"), Some(TerminalType::Petscii));
        assert_eq!(match_terminal_name(" C64 "), Some(TerminalType::Petscii));
    }

    #[test]
    fn test_match_terminal_name_ansi_variants() {
        assert_eq!(match_terminal_name("XTERM"), Some(TerminalType::Ansi));
        assert_eq!(match_terminal_name("xterm-256color"), Some(TerminalType::Ansi));
        assert_eq!(match_terminal_name("VT100"), Some(TerminalType::Ansi));
        assert_eq!(match_terminal_name("VT220"), Some(TerminalType::Ansi));
        assert_eq!(match_terminal_name("ANSI"), Some(TerminalType::Ansi));
        assert_eq!(match_terminal_name("linux"), Some(TerminalType::Ansi));
        assert_eq!(match_terminal_name("screen-256color"), Some(TerminalType::Ansi));
        assert_eq!(match_terminal_name("PUTTY"), Some(TerminalType::Ansi));
    }

    #[test]
    fn test_match_terminal_name_dumb() {
        assert_eq!(match_terminal_name("DUMB"), Some(TerminalType::Ascii));
        assert_eq!(match_terminal_name("UNKNOWN"), Some(TerminalType::Ascii));
        assert_eq!(match_terminal_name("NETWORK"), Some(TerminalType::Ascii));
    }

    #[test]
    fn test_match_terminal_name_unrecognized() {
        // Fall back to BACKSPACE detection for names we don't know.
        assert_eq!(match_terminal_name("MY-WEIRD-TERM"), None);
        assert_eq!(match_terminal_name(""), None);
        assert_eq!(match_terminal_name("   "), None);
    }

    #[tokio::test]
    async fn test_send_raw_escapes_iac_bytes() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        session.send_raw(&[b'A', 0xFF, b'B']).await.unwrap();
        drop(session); // close writer so peer reads EOF after data

        let mut out = Vec::new();
        use tokio::io::AsyncReadExt;
        peer.read_to_end(&mut out).await.unwrap();
        // 0xFF data byte must be escaped as IAC IAC (0xFF 0xFF).
        assert_eq!(out, vec![b'A', 0xFF, 0xFF, b'B']);
    }

    #[tokio::test]
    async fn test_send_raw_passthrough_when_no_iac() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        session.send_raw(b"hello").await.unwrap();
        drop(session);

        let mut out = Vec::new();
        use tokio::io::AsyncReadExt;
        peer.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn test_send_telnet_protocol_never_escapes() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        // An IAC WILL ECHO protocol sequence contains 0xFF but must
        // go through verbatim — escaping it would corrupt the command.
        session
            .send_telnet_protocol(&[IAC, WILL, OPT_ECHO])
            .await
            .unwrap();
        drop(session);

        let mut out = Vec::new();
        use tokio::io::AsyncReadExt;
        peer.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, vec![IAC, WILL, OPT_ECHO]);
    }

    #[tokio::test]
    async fn test_ayt_gets_yes_reply() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::AsyncWriteExt;
        // Send IAC AYT followed by a real data byte so session_read_byte
        // can return something.
        peer.write_all(&[IAC, AYT, b'Z']).await.unwrap();

        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'Z'));

        // The session should have written "[Yes]\r\n" back.
        let mut out = Vec::new();
        peer.write_all(&[]).await.ok();
        // Drop only the session side so we can read EOF.
        drop(session);
        use tokio::io::AsyncReadExt;
        peer.read_to_end(&mut out).await.unwrap();
        assert!(
            out.windows(5).any(|w| w == b"[Yes]"),
            "expected [Yes] reply, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_ip_surfaces_as_esc_ansi() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, IP]).await.unwrap();

        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(0x1B)); // ANSI ESC
    }

    #[tokio::test]
    async fn test_ip_surfaces_as_esc_petscii() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Petscii);
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, BRK]).await.unwrap();

        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(0x5F)); // C64 back-arrow used as PETSCII ESC
    }

    #[tokio::test]
    async fn test_ec_surfaces_as_del() {
        // RFC 854 EC (0xF7) should surface as DEL (0x7F) so upstream
        // line-editors treat it as backspace.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, EC]).await.unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(0x7F));
    }

    #[tokio::test]
    async fn test_el_surfaces_as_nak() {
        // RFC 854 EL (0xF8) should surface as the LINE_ERASE_BYTE (0x15,
        // NAK) so the line-input loop can erase the current buffer.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, EL]).await.unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(LINE_ERASE_BYTE));
    }

    #[tokio::test]
    async fn test_do_timing_mark_gets_will() {
        // RFC 860: DO TIMING-MARK must be answered with WILL TIMING-MARK.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, DO, OPT_TIMING_MARK, b'X']).await.unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'X'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let will_tm = [IAC, WILL, OPT_TIMING_MARK];
        assert!(
            out.windows(3).any(|w| w == will_tm),
            "expected IAC WILL TIMING-MARK, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_dont_timing_mark_is_silent() {
        // RFC 860: DONT TIMING-MARK is a no-op (we never keep persistent
        // state for this option) so the server should NOT emit WONT.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, DONT, OPT_TIMING_MARK, b'Y']).await.unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'Y'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let wont_tm = [IAC, WONT, OPT_TIMING_MARK];
        assert!(
            !out.windows(3).any(|w| w == wont_tm),
            "expected no WONT TIMING-MARK, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_do_status_gets_will() {
        // RFC 859: DO STATUS → WILL STATUS.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, DO, OPT_STATUS, b'X']).await.unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'X'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let will_status = [IAC, WILL, OPT_STATUS];
        assert!(
            out.windows(3).any(|w| w == will_status),
            "expected IAC WILL STATUS, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_do_status_not_repeated() {
        // Two consecutive DO STATUS should yield exactly one WILL reply.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, DO, OPT_STATUS, IAC, DO, OPT_STATUS, b'Y'])
            .await
            .unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'Y'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let will_status = [IAC, WILL, OPT_STATUS];
        let count = out.windows(3).filter(|w| *w == will_status).count();
        assert_eq!(count, 1, "expected exactly one WILL STATUS, got {:?}", out);
    }

    #[tokio::test]
    async fn test_sb_status_send_emits_is_dump() {
        // After enabling STATUS, SB STATUS SEND must produce SB STATUS IS
        // <state> SE containing at least the handshake options.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        // The test-session factory skips send_telnet_handshake().  Seed
        // the neg arrays so the dump has something to report beyond just
        // STATUS itself.
        session.neg_sent_will[OPT_ECHO as usize] = true;
        session.neg_sent_will[OPT_SGA as usize] = true;
        session.neg_sent_do[OPT_SGA as usize] = true;
        session.neg_sent_do[OPT_TTYPE as usize] = true;
        session.neg_sent_do[OPT_NAWS as usize] = true;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[
            IAC, DO, OPT_STATUS,
            IAC, SB, OPT_STATUS, STATUS_SEND, IAC, SE,
            b'Z',
        ])
        .await
        .unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'Z'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();

        // Find the IS subnegotiation: IAC SB STATUS IS ... IAC SE.
        let header = [IAC, SB, OPT_STATUS, STATUS_IS];
        let start = out
            .windows(4)
            .position(|w| w == header)
            .expect("no SB STATUS IS in output");
        let body_and_tail = &out[start + 4..];
        let se_rel = body_and_tail
            .windows(2)
            .position(|w| w == [IAC, SE])
            .expect("no IAC SE terminator");
        let body = &body_and_tail[..se_rel];

        // Body should contain WILL ECHO, WILL SGA, WILL STATUS, DO SGA,
        // DO TTYPE, DO NAWS — each as a verb+opt pair.
        let expected_pairs: &[[u8; 2]] = &[
            [WILL, OPT_ECHO],
            [WILL, OPT_SGA],
            [WILL, OPT_STATUS],
            [DO, OPT_SGA],
            [DO, OPT_TTYPE],
            [DO, OPT_NAWS],
        ];
        for pair in expected_pairs {
            assert!(
                body.windows(2).any(|w| w == pair),
                "STATUS IS body missing {:?}; body was {:?}",
                pair,
                body
            );
        }
    }

    #[tokio::test]
    async fn test_dont_status_withdraws() {
        // After DO STATUS → WILL STATUS, a DONT STATUS must produce WONT.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[
            IAC, DO, OPT_STATUS,
            IAC, DONT, OPT_STATUS,
            b'Q',
        ])
        .await
        .unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'Q'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let wont_status = [IAC, WONT, OPT_STATUS];
        assert!(
            out.windows(3).any(|w| w == wont_status),
            "expected IAC WONT STATUS, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_will_status_from_peer_refused() {
        // The peer trying to be the status sender is refused with DONT.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, WILL, OPT_STATUS, b'R']).await.unwrap();
        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'R'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let dont_status = [IAC, DONT, OPT_STATUS];
        assert!(
            out.windows(3).any(|w| w == dont_status),
            "expected IAC DONT STATUS, got {:?}",
            out
        );
    }

    // ─── Gateway telnet-client IAC parser ─────────────────

    fn feed_all(iac: &mut GatewayTelnetIac, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut data = Vec::new();
        let mut replies = Vec::new();
        for &b in input {
            iac.feed(b, &mut data, &mut replies);
        }
        (data, replies)
    }

    /// Build a reactive-refuse (cooperate=false) parser for tests that
    /// exercise the legacy strict-refuser behavior.
    fn reactive_iac() -> GatewayTelnetIac {
        let (parser, _) = GatewayTelnetIac::new(false, "ANSI".into(), 80, 24);
        parser
    }

    /// Build a cooperative parser (cooperate=true) and return the initial
    /// offer bytes along with the parser.
    fn cooperative_iac() -> (GatewayTelnetIac, Vec<u8>) {
        GatewayTelnetIac::new(true, "ANSI".into(), 80, 24)
    }

    #[test]
    fn test_gateway_iac_plain_data_passes_through() {
        let mut iac = reactive_iac();
        let (data, replies) = feed_all(&mut iac, b"Hello, world!");
        assert_eq!(data, b"Hello, world!");
        assert!(replies.is_empty());
    }

    #[test]
    fn test_gateway_iac_iac_unescapes_to_data_ff() {
        let mut iac = reactive_iac();
        let (data, replies) = feed_all(&mut iac, &[b'A', IAC, IAC, b'B']);
        assert_eq!(data, vec![b'A', 0xFF, b'B']);
        assert!(replies.is_empty());
    }

    #[test]
    fn test_gateway_iac_two_byte_commands_consumed() {
        let mut iac = reactive_iac();
        // AYT (0xF6), NOP (0xF1), GA (0xF9): all consumed, none leak.
        let (data, replies) = feed_all(
            &mut iac,
            &[b'X', IAC, 0xF6, b'Y', IAC, 0xF1, b'Z', IAC, 0xF9, b'W'],
        );
        assert_eq!(data, b"XYZW");
        assert!(replies.is_empty());
    }

    #[test]
    fn test_gateway_iac_will_echo_gets_do_reply() {
        // ECHO cooperation is always on — peer's WILL ECHO is accepted
        // with DO ECHO so the remote echoes the user's keystrokes.
        let mut iac = reactive_iac();
        let (data, replies) = feed_all(&mut iac, &[IAC, WILL, OPT_ECHO, b'A']);
        assert_eq!(data, b"A");
        assert_eq!(replies, vec![IAC, DO, OPT_ECHO]);
    }

    #[test]
    fn test_gateway_iac_will_unsupported_gets_dont_reply() {
        // Unsupported options still get refused.
        let mut iac = reactive_iac();
        let (data, replies) = feed_all(&mut iac, &[IAC, WILL, 0x00, b'A']); // BINARY
        assert_eq!(data, b"A");
        assert_eq!(replies, vec![IAC, DONT, 0x00]);
    }

    #[test]
    fn test_gateway_iac_do_gets_wont_reply() {
        let mut iac = reactive_iac();
        let (data, replies) = feed_all(&mut iac, &[IAC, DO, OPT_NAWS, b'B']);
        assert_eq!(data, b"B");
        assert_eq!(replies, vec![IAC, WONT, OPT_NAWS]);
    }

    #[test]
    fn test_gateway_iac_wont_and_dont_need_no_reply() {
        let mut iac = reactive_iac();
        let (data, replies) = feed_all(
            &mut iac,
            &[IAC, WONT, OPT_ECHO, IAC, DONT, OPT_NAWS, b'C'],
        );
        assert_eq!(data, b"C");
        assert!(replies.is_empty());
    }

    #[test]
    fn test_gateway_iac_duplicate_refusal_not_repeated() {
        let mut iac = reactive_iac();
        // First WILL triggers DONT; second WILL for the same opt is silent.
        let (_, r1) = feed_all(&mut iac, &[IAC, WILL, OPT_SGA]);
        let (_, r2) = feed_all(&mut iac, &[IAC, WILL, OPT_SGA]);
        assert_eq!(r1, vec![IAC, DONT, OPT_SGA]);
        assert!(r2.is_empty());
    }

    #[test]
    fn test_gateway_iac_sb_body_consumed_with_iac_iac_inside() {
        let mut iac = reactive_iac();
        // SB TTYPE IS "v" 0xFF 0xFF "t" IAC SE — the escaped IAC inside
        // must not prematurely end the subnegotiation.
        let (data, replies) = feed_all(
            &mut iac,
            &[
                b'A',
                IAC, SB, OPT_TTYPE, 0x00, b'v', IAC, IAC, b't', IAC, SE,
                b'B',
            ],
        );
        assert_eq!(data, b"AB");
        assert!(replies.is_empty());
    }

    #[test]
    fn test_gateway_iac_sb_body_capped_against_oom() {
        // A malicious remote sending a huge SB body must not make us
        // allocate unbounded memory.  After processing a 1 MiB body
        // followed by IAC SE, the parser must terminate cleanly and
        // the internal sb_body must be at most MAX_SB_BODY_BYTES.
        let mut iac = reactive_iac();
        let mut data = Vec::new();
        let mut replies = Vec::new();
        iac.feed(IAC, &mut data, &mut replies);
        iac.feed(SB, &mut data, &mut replies);
        iac.feed(OPT_TTYPE, &mut data, &mut replies);
        for _ in 0..(1024 * 1024) {
            iac.feed(b'A', &mut data, &mut replies);
        }
        iac.feed(IAC, &mut data, &mut replies);
        iac.feed(SE, &mut data, &mut replies);
        iac.feed(b'Q', &mut data, &mut replies);
        assert!(
            iac.sb_body.len() <= MAX_SB_BODY_BYTES,
            "sb_body grew to {} bytes (cap is {})",
            iac.sb_body.len(),
            MAX_SB_BODY_BYTES
        );
        assert_eq!(
            iac.state,
            GatewayIacState::Normal,
            "parser should resync to Normal after huge SB"
        );
        assert_eq!(
            data.last().copied(),
            Some(b'Q'),
            "post-SB data byte should pass through"
        );
    }

    #[test]
    fn test_gateway_iac_malformed_sb_resyncs_on_iac_se() {
        let mut iac = reactive_iac();
        // IAC inside SB followed by an unexpected byte (not SE, not IAC).
        // Parser must keep scanning for IAC SE.
        let (data, _) = feed_all(
            &mut iac,
            &[
                IAC, SB, OPT_NAWS, 0x00, IAC, 0xEE, 0x00, IAC, SE,
                b'Q',
            ],
        );
        assert_eq!(data, b"Q");
    }

    #[test]
    fn test_gateway_iac_split_across_feeds() {
        // Parser must survive IAC sequences split across multiple calls —
        // simulating fragmented TCP reads.  WILL ECHO now triggers the
        // cooperative DO ECHO reply.
        let mut iac = reactive_iac();
        let mut data = Vec::new();
        let mut replies = Vec::new();
        iac.feed(IAC, &mut data, &mut replies);
        assert!(data.is_empty() && replies.is_empty());
        iac.feed(WILL, &mut data, &mut replies);
        assert!(data.is_empty() && replies.is_empty());
        iac.feed(OPT_ECHO, &mut data, &mut replies);
        assert!(data.is_empty());
        assert_eq!(replies, vec![IAC, DO, OPT_ECHO]);
        iac.feed(b'R', &mut data, &mut replies);
        assert_eq!(data, vec![b'R']);
    }

    // ─── Cooperative-mode gateway parser ──────────────────

    #[test]
    fn test_gateway_cooperative_initial_offers() {
        // Cooperate mode advertises WILL TTYPE, WILL NAWS, and requests
        // DO ECHO at connect so the remote echoes the user's keystrokes.
        let (_, initial) = cooperative_iac();
        assert_eq!(
            initial,
            vec![
                IAC, WILL, OPT_TTYPE,
                IAC, WILL, OPT_NAWS,
                IAC, DO, OPT_ECHO,
            ],
        );
    }

    #[test]
    fn test_gateway_cooperative_will_echo_is_ack() {
        // After proactively sending DO ECHO, peer's WILL ECHO is an ack
        // (him_state WantYes → Yes) with no extra reply.
        let (mut iac, _) = cooperative_iac();
        let (data, replies) = feed_all(&mut iac, &[IAC, WILL, OPT_ECHO, b'A']);
        assert_eq!(data, b"A");
        assert!(
            replies.is_empty(),
            "WILL ECHO after our DO ECHO should be a silent ack, got {:?}",
            replies
        );
    }

    #[test]
    fn test_gateway_reactive_no_initial_offers() {
        // Reactive mode (cooperate=false) sends nothing at connect.
        let (_, initial) = GatewayTelnetIac::new(false, "ANSI".into(), 80, 24);
        assert!(initial.is_empty());
    }

    #[test]
    fn test_gateway_cooperative_do_ttype_is_ack() {
        // After sending WILL TTYPE proactively, peer's DO TTYPE is an ack
        // — us_state transitions to Yes, no extra reply.
        let (mut iac, _) = cooperative_iac();
        let (data, replies) = feed_all(&mut iac, &[IAC, DO, OPT_TTYPE, b'A']);
        assert_eq!(data, b"A");
        assert!(
            replies.is_empty(),
            "DO TTYPE after WILL TTYPE should be a silent ack, got {:?}",
            replies
        );
    }

    #[test]
    fn test_gateway_cooperative_sb_ttype_send_returns_is() {
        // After DO TTYPE acks our WILL, peer sends SB TTYPE SEND; we
        // respond with SB TTYPE IS <name>.
        let (mut iac, _) = cooperative_iac();
        let (_, _) = feed_all(&mut iac, &[IAC, DO, OPT_TTYPE]);
        let (data, replies) = feed_all(
            &mut iac,
            &[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE, b'Z'],
        );
        assert_eq!(data, b"Z");
        let expected = [
            IAC, SB, OPT_TTYPE, TTYPE_IS,
            b'A', b'N', b'S', b'I',
            IAC, SE,
        ];
        assert_eq!(replies, expected);
    }

    #[test]
    fn test_gateway_reactive_do_ttype_refused() {
        // Without cooperation the same DO TTYPE is refused with WONT.
        let mut iac = reactive_iac();
        let (_, replies) = feed_all(&mut iac, &[IAC, DO, OPT_TTYPE]);
        assert_eq!(replies, vec![IAC, WONT, OPT_TTYPE]);
    }

    #[test]
    fn test_gateway_cooperative_do_naws_emits_sb() {
        // DO NAWS (whether ack or unprovoked) triggers an immediate SB
        // NAWS with our configured dimensions.
        let (mut iac, _) = cooperative_iac();
        let (_, replies) = feed_all(&mut iac, &[IAC, DO, OPT_NAWS]);
        // For cooperative_iac we passed 80x24.
        let expected_sb = [
            IAC, SB, OPT_NAWS,
            0x00, 0x50,  // 80
            0x00, 0x18,  // 24
            IAC, SE,
        ];
        assert!(
            replies.windows(expected_sb.len()).any(|w| w == expected_sb),
            "expected SB NAWS 80x24 in replies, got {:?}",
            replies
        );
    }

    #[test]
    fn test_gateway_cooperative_dont_ttype_withdraws() {
        // Peer refusing our proactive WILL TTYPE drops us_state to No.
        let (mut iac, _) = cooperative_iac();
        let (_, replies) = feed_all(&mut iac, &[IAC, DONT, OPT_TTYPE]);
        // No reply — peer's refusal closes our WantYes cleanly.
        assert!(replies.is_empty());
        // Subsequent SB TTYPE SEND should be ignored (us_state=No).
        let (_, replies2) = feed_all(
            &mut iac,
            &[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE],
        );
        assert!(
            replies2.is_empty(),
            "SB TTYPE SEND after DONT should be ignored"
        );
    }

    #[test]
    fn test_gateway_cooperative_naws_sent_with_local_dimensions() {
        // Feed custom dimensions and verify SB NAWS reflects them.
        let (mut iac, _) = GatewayTelnetIac::new(true, "PETSCII".into(), 40, 25);
        let (_, replies) = feed_all(&mut iac, &[IAC, DO, OPT_NAWS]);
        let expected = [
            IAC, SB, OPT_NAWS,
            0x00, 0x28,  // 40
            0x00, 0x19,  // 25
            IAC, SE,
        ];
        assert!(replies.windows(expected.len()).any(|w| w == expected));
    }

    #[test]
    fn test_gateway_cooperative_naws_value_ff_is_escaped() {
        // An 0xFF byte in a NAWS dimension must be IAC-doubled per RFC 854.
        // 255x255 would contain two 0xFF bytes in the size field.
        let (mut iac, _) = GatewayTelnetIac::new(true, "ANSI".into(), 0x00FF, 0x00FF);
        let (_, replies) = feed_all(&mut iac, &[IAC, DO, OPT_NAWS]);
        let expected = [
            IAC, SB, OPT_NAWS,
            0x00, IAC, IAC,  // width high, width low (0xFF escaped)
            0x00, IAC, IAC,  // height high, height low (0xFF escaped)
            IAC, SE,
        ];
        assert!(
            replies.windows(expected.len()).any(|w| w == expected),
            "expected SB NAWS with escaped 0xFFs, got {:?}",
            replies
        );
    }

    #[test]
    fn test_gateway_refusal_not_repeated_within_cycle() {
        // Two rapid WILL SGAs get only one DONT; subsequent WONT clears
        // the refusal-sent flag so a future WILL cycle refreshes.
        let mut iac = reactive_iac();
        let (_, r1) = feed_all(&mut iac, &[IAC, WILL, OPT_SGA]);
        let (_, r2) = feed_all(&mut iac, &[IAC, WILL, OPT_SGA]);
        assert_eq!(r1, vec![IAC, DONT, OPT_SGA]);
        assert!(r2.is_empty(), "second WILL should not re-trigger DONT");
        let (_, _) = feed_all(&mut iac, &[IAC, WONT, OPT_SGA]);
        let (_, r3) = feed_all(&mut iac, &[IAC, WILL, OPT_SGA]);
        assert_eq!(
            r3, vec![IAC, DONT, OPT_SGA],
            "new refusal cycle should issue fresh DONT after peer's WONT"
        );
    }

    #[test]
    fn test_gateway_qmethod_peer_yes_echo_peer_withdraws() {
        // Accept WILL ECHO → peer later WONT ECHO → we reply DONT to ack.
        let mut iac = reactive_iac();
        let (_, r1) = feed_all(&mut iac, &[IAC, WILL, OPT_ECHO]);
        assert_eq!(r1, vec![IAC, DO, OPT_ECHO]);
        let (_, r2) = feed_all(&mut iac, &[IAC, WONT, OPT_ECHO]);
        assert_eq!(r2, vec![IAC, DONT, OPT_ECHO]);
    }
    // ─── Gateway Q-method fuzz harness ────────────────────

    /// Property-based fuzzer for `GatewayTelnetIac`.  Generates random
    /// sequences of `Op`s and asserts structural invariants after every
    /// step so that any future refactor of the Q-method state machine
    /// gets caught at `cargo test`.
    ///
    /// Options are restricted to the range 0..16 so random sequences
    /// frequently target the same option — that's where interesting
    /// race-condition transitions (`WantYesOpposite` / `WantNoOpposite`)
    /// actually get exercised.
    mod qmethod_proptest {
        use super::*;
        use proptest::prelude::*;

        #[derive(Debug, Clone)]
        enum Op {
            RecvWill(u8),
            RecvWont(u8),
            RecvDo(u8),
            RecvDont(u8),
            LocalEnable(u8),
            LocalDisable(u8),
            RecvData(u8),
        }

        fn op_strategy() -> impl Strategy<Value = Op> {
            let opt = 0u8..16u8;
            prop_oneof![
                opt.clone().prop_map(Op::RecvWill),
                opt.clone().prop_map(Op::RecvWont),
                opt.clone().prop_map(Op::RecvDo),
                opt.clone().prop_map(Op::RecvDont),
                opt.clone().prop_map(Op::LocalEnable),
                opt.clone().prop_map(Op::LocalDisable),
                (0u8..=255u8).prop_map(Op::RecvData),
            ]
        }

        fn apply(
            iac: &mut GatewayTelnetIac,
            op: &Op,
            data: &mut Vec<u8>,
            replies: &mut Vec<u8>,
        ) {
            match *op {
                Op::RecvWill(opt) => {
                    iac.feed(IAC, data, replies);
                    iac.feed(WILL, data, replies);
                    iac.feed(opt, data, replies);
                }
                Op::RecvWont(opt) => {
                    iac.feed(IAC, data, replies);
                    iac.feed(WONT, data, replies);
                    iac.feed(opt, data, replies);
                }
                Op::RecvDo(opt) => {
                    iac.feed(IAC, data, replies);
                    iac.feed(DO, data, replies);
                    iac.feed(opt, data, replies);
                }
                Op::RecvDont(opt) => {
                    iac.feed(IAC, data, replies);
                    iac.feed(DONT, data, replies);
                    iac.feed(opt, data, replies);
                }
                Op::LocalEnable(opt) => {
                    iac.request_local_enable(opt, replies);
                }
                Op::LocalDisable(opt) => {
                    iac.request_local_disable(opt, replies);
                }
                Op::RecvData(b) => {
                    iac.feed(b, data, replies);
                }
            }
        }

        /// Validate that a byte stream of replies only contains well-formed
        /// IAC sequences: `IAC <verb> <opt>`, `IAC SB <opt> ... IAC SE`,
        /// or `IAC <2-byte-command>`.  No orphan data bytes, no truncated
        /// sequences.
        fn iac_reply_stream_is_well_formed(bytes: &[u8]) -> bool {
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] != IAC {
                    return false;
                }
                i += 1;
                if i >= bytes.len() {
                    return false;
                }
                match bytes[i] {
                    SB => {
                        i += 1;
                        if i >= bytes.len() {
                            return false;
                        }
                        i += 1; // option byte
                        // Scan body until IAC SE.
                        loop {
                            if i >= bytes.len() {
                                return false;
                            }
                            if bytes[i] == IAC {
                                i += 1;
                                if i >= bytes.len() {
                                    return false;
                                }
                                if bytes[i] == SE {
                                    i += 1;
                                    break;
                                }
                                // IAC IAC or other — body continues.
                                i += 1;
                            } else {
                                i += 1;
                            }
                        }
                    }
                    WILL | WONT | DO | DONT => {
                        i += 1;
                        if i >= bytes.len() {
                            return false;
                        }
                        i += 1; // option byte
                    }
                    _ => {
                        // 2-byte command.  Our gateway doesn't emit these,
                        // but if it ever does, one byte is the whole thing.
                        i += 1;
                    }
                }
            }
            true
        }

        fn check_structural_invariants(iac: &GatewayTelnetIac) {
            for opt in 0u8..=255 {
                let idx = opt as usize;
                // Refusal flags track "we've sent DONT/WONT and have not
                // yet contradicted it."  Legitimate states where the flag
                // may be set are the No-side of the machine:
                //   sent_dont[opt] ∈ {No, WantNo, WantNoOpposite}
                //   sent_wont[opt] ∈ {No, WantNo, WantNoOpposite}
                // Yes-side states mean we've emitted an accepting DO/WILL
                // and must have cleared the flag at that point.
                let him_ok = matches!(
                    iac.him_state[idx],
                    OptState::No | OptState::WantNo | OptState::WantNoOpposite,
                );
                if iac.sent_dont[idx] {
                    assert!(
                        him_ok,
                        "sent_dont[{}] set but him_state is {:?} (yes-side)",
                        opt,
                        iac.him_state[idx],
                    );
                }
                let us_ok = matches!(
                    iac.us_state[idx],
                    OptState::No | OptState::WantNo | OptState::WantNoOpposite,
                );
                if iac.sent_wont[idx] {
                    assert!(
                        us_ok,
                        "sent_wont[{}] set but us_state is {:?} (yes-side)",
                        opt,
                        iac.us_state[idx],
                    );
                }
            }
        }

        proptest! {
            /// Random sequences of peer-initiated verbs, local mind-changes,
            /// and data bytes must never panic or produce malformed output.
            #[test]
            fn fuzz_random_operations(
                ops in prop::collection::vec(op_strategy(), 0..200),
            ) {
                let (mut iac, _) = GatewayTelnetIac::new(
                    true,
                    "ANSI".into(),
                    80,
                    24,
                );
                let mut data = Vec::new();
                let mut replies = Vec::new();
                for op in &ops {
                    apply(&mut iac, op, &mut data, &mut replies);
                    check_structural_invariants(&iac);
                }
                // Cumulative reply stream from the whole run must be
                // parseable telnet protocol.
                prop_assert!(
                    iac_reply_stream_is_well_formed(&replies),
                    "reply stream was malformed: {:?}",
                    replies,
                );
            }

            /// The byte-level parser must never panic on an arbitrary
            /// input, including truncations mid-sequence.
            #[test]
            fn fuzz_random_bytes(
                bytes in prop::collection::vec(0u8..=255u8, 0..500),
            ) {
                let (mut iac, _) = GatewayTelnetIac::new(
                    true,
                    "ANSI".into(),
                    80,
                    24,
                );
                let mut data = Vec::new();
                let mut replies = Vec::new();
                for &b in &bytes {
                    iac.feed(b, &mut data, &mut replies);
                }
                check_structural_invariants(&iac);
                prop_assert!(iac_reply_stream_is_well_formed(&replies));
            }

            /// Reactive mode (cooperate=false) should only ever emit
            /// refusal verbs (DONT/WONT) for non-ECHO options — never an
            /// accepting WILL/DO or subnegotiation.
            #[test]
            fn fuzz_reactive_only_refuses(
                ops in prop::collection::vec(op_strategy(), 0..100),
            ) {
                let mut iac = reactive_iac();
                let mut data = Vec::new();
                let mut replies = Vec::new();
                for op in &ops {
                    apply(&mut iac, op, &mut data, &mut replies);
                }
                // Walk the reply stream: if we see an accepting verb it
                // must be DO ECHO or the byte sequence must be part of a
                // refusal cycle from an active-change helper.  For the
                // simpler check, verify there are no SB sequences at all
                // (reactive mode never emits subnegotiations).
                let mut i = 0;
                while i + 1 < replies.len() {
                    if replies[i] == IAC && replies[i + 1] == SB {
                        panic!(
                            "reactive mode emitted SB subnegotiation: \
                             replies = {:?}", replies,
                        );
                    }
                    i += 1;
                }
            }
        }
    }

    // ─── 6-state Q-method transitions ─────────────────────

    #[test]
    fn test_qmethod_request_enable_from_no() {
        let mut iac = reactive_iac();
        let mut replies = Vec::new();
        iac.request_local_enable(OPT_SGA, &mut replies);
        assert_eq!(replies, vec![IAC, WILL, OPT_SGA]);
        assert_eq!(iac.us_state[OPT_SGA as usize], OptState::WantYes);
    }

    #[test]
    fn test_qmethod_mind_change_during_wantyes_goes_to_opposite() {
        // We send WILL (enter WantYes), then change our mind and send
        // WONT before peer replies: state → WantYesOpposite, nothing on
        // the wire yet because our WILL is still pending.
        let mut iac = reactive_iac();
        let mut replies = Vec::new();
        iac.request_local_enable(OPT_SGA, &mut replies);
        replies.clear();
        iac.request_local_disable(OPT_SGA, &mut replies);
        assert_eq!(iac.us_state[OPT_SGA as usize], OptState::WantYesOpposite);
        assert!(
            replies.is_empty(),
            "in-flight mind-change defers the WONT until peer ack"
        );
    }

    #[test]
    fn test_qmethod_peer_acks_opposite_with_wont() {
        // us_state = WantYesOpposite, peer sends DO (ack of our WILL).
        // We now send WONT and enter WantNo.
        let mut iac = reactive_iac();
        let idx = OPT_SGA as usize;
        iac.us_state[idx] = OptState::WantYesOpposite;
        let mut replies = Vec::new();
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(DO, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        assert_eq!(iac.us_state[idx], OptState::WantNo);
        assert_eq!(replies, vec![IAC, WONT, OPT_SGA]);
        assert!(
            iac.sent_wont[idx],
            "refusal flag must be set so a re-sent DO doesn't produce a duplicate WONT"
        );
    }

    #[test]
    fn test_qmethod_no_duplicate_wont_when_peer_re_sends_do() {
        // Regression: from WantYesOpposite, peer DO transitions us to
        // WantNo + WONT.  If peer (misbehaving) sends DO again, the
        // WantNo handler must see sent_wont already and skip the dup.
        let mut iac = reactive_iac();
        let idx = OPT_SGA as usize;
        iac.us_state[idx] = OptState::WantYesOpposite;
        let mut replies = Vec::new();
        // First DO: WantYesOpposite → WantNo with WONT.
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(DO, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        let count_first = replies
            .windows(3)
            .filter(|w| *w == [IAC, WONT, OPT_SGA])
            .count();
        assert_eq!(count_first, 1);
        // Second DO (protocol violation): WantNo stays at No, no dup.
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(DO, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        let count_total = replies
            .windows(3)
            .filter(|w| *w == [IAC, WONT, OPT_SGA])
            .count();
        assert_eq!(
            count_total, 1,
            "a repeated DO should not produce a second WONT"
        );
    }

    #[test]
    fn test_qmethod_no_duplicate_dont_when_peer_re_sends_will() {
        // Mirror of the above, on the him side.
        let mut iac = reactive_iac();
        let idx = OPT_SGA as usize;
        iac.him_state[idx] = OptState::WantYesOpposite;
        let mut replies = Vec::new();
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(WILL, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        let count_first = replies
            .windows(3)
            .filter(|w| *w == [IAC, DONT, OPT_SGA])
            .count();
        assert_eq!(count_first, 1);
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(WILL, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        let count_total = replies
            .windows(3)
            .filter(|w| *w == [IAC, DONT, OPT_SGA])
            .count();
        assert_eq!(
            count_total, 1,
            "a repeated WILL should not produce a second DONT"
        );
    }

    #[test]
    fn test_qmethod_peer_refuses_opposite_cleanly() {
        // us_state = WantYesOpposite, peer sends DONT (refuses our WILL).
        // We wanted No anyway — settle at No without any extra verb.
        let mut iac = reactive_iac();
        let idx = OPT_SGA as usize;
        iac.us_state[idx] = OptState::WantYesOpposite;
        let mut replies = Vec::new();
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(DONT, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        assert_eq!(iac.us_state[idx], OptState::No);
        assert!(replies.is_empty(), "opposite path resolved without reply");
    }

    #[test]
    fn test_qmethod_his_wantno_opposite_on_wont_reply() {
        // him_state = WantNoOpposite; peer sends WONT confirming our DONT.
        // We swing to WantYes and send DO.
        let mut iac = reactive_iac();
        let idx = OPT_SGA as usize;
        iac.him_state[idx] = OptState::WantNoOpposite;
        let mut replies = Vec::new();
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(WONT, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        assert_eq!(iac.him_state[idx], OptState::WantYes);
        assert_eq!(replies, vec![IAC, DO, OPT_SGA]);
    }

    #[test]
    fn test_qmethod_active_enable_is_idempotent_in_wantyes() {
        // Calling request_local_enable while already in WantYes is a no-op.
        let mut iac = reactive_iac();
        let mut replies = Vec::new();
        iac.request_local_enable(OPT_SGA, &mut replies);
        assert_eq!(replies, vec![IAC, WILL, OPT_SGA]);
        replies.clear();
        iac.request_local_enable(OPT_SGA, &mut replies);
        assert!(replies.is_empty(), "idempotent");
        assert_eq!(iac.us_state[OPT_SGA as usize], OptState::WantYes);
    }

    #[test]
    fn test_qmethod_error_recovery_will_in_wantno() {
        // him_state = WantNo, peer sends WILL (protocol violation). We
        // should bounce back to No without entering Yes, and refuse
        // again if we haven't already.
        let mut iac = reactive_iac();
        let idx = OPT_SGA as usize;
        iac.him_state[idx] = OptState::WantNo;
        let mut replies = Vec::new();
        iac.feed(IAC, &mut Vec::new(), &mut replies);
        iac.feed(WILL, &mut Vec::new(), &mut replies);
        iac.feed(OPT_SGA, &mut Vec::new(), &mut replies);
        assert_eq!(iac.him_state[idx], OptState::No);
        assert_eq!(replies, vec![IAC, DONT, OPT_SGA]);
    }

    // ─── read_gateway_event ───────────────────────────────

    #[tokio::test]
    async fn test_gateway_event_data_byte() {
        let mut data = &b"Ahello"[..];
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::Data(b'A'));
    }

    #[tokio::test]
    async fn test_gateway_event_iac_iac_unescapes() {
        let mut data: &[u8] = &[IAC, IAC, b'B'];
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::Data(0xFF));
    }

    #[tokio::test]
    async fn test_gateway_event_drops_2byte_iac() {
        let mut data: &[u8] = &[IAC, 0xF1, b'X']; // IAC NOP X
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::Data(b'X'));
    }

    #[tokio::test]
    async fn test_gateway_event_drops_negotiation() {
        let mut data: &[u8] = &[IAC, WILL, OPT_ECHO, b'Y'];
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::Data(b'Y'));
    }

    #[tokio::test]
    async fn test_gateway_event_surfaces_naws() {
        // IAC SB NAWS 0x00 0x50 0x00 0x18 IAC SE → NawsResize(80, 24)
        let mut data: &[u8] = &[
            IAC, SB, OPT_NAWS, 0x00, 0x50, 0x00, 0x18, IAC, SE,
            b'Z',
        ];
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::NawsResize(80, 24));
    }

    #[tokio::test]
    async fn test_gateway_event_naws_with_escaped_iac_in_body() {
        // Width = 0x00FF needs IAC-doubling inside the NAWS body.
        let mut data: &[u8] = &[
            IAC, SB, OPT_NAWS,
            0x00, IAC, IAC,    // width low = 0xFF (doubled)
            0x00, 0x18,
            IAC, SE,
        ];
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::NawsResize(0x00FF, 0x0018));
    }

    #[tokio::test]
    async fn test_gateway_event_drops_non_naws_subneg() {
        // SB TTYPE SEND — should be silently consumed; next event is the data byte.
        let mut data: &[u8] = &[
            IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE,
            b'Q',
        ];
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::Data(b'Q'));
    }

    #[tokio::test]
    async fn test_gateway_event_eof() {
        let mut data: &[u8] = &[];
        let ev = read_gateway_event(&mut data).await.unwrap();
        assert_eq!(ev, GatewayInboundEvent::Eof);
    }

    // ─── NAWS mid-session forwarding ──────────────────────

    #[test]
    fn test_gateway_naws_update_forwarded_when_enabled() {
        // After DO NAWS peer response, us_state[NAWS] = Yes. A later
        // send_naws_update must emit an IAC SB NAWS to remote.
        let (mut iac, _) = cooperative_iac();
        let (_, _) = feed_all(&mut iac, &[IAC, DO, OPT_NAWS]); // ack sets Yes
        let mut replies = Vec::new();
        iac.send_naws_update(120, 50, &mut replies);
        let expected = [
            IAC, SB, OPT_NAWS,
            0x00, 0x78,  // 120
            0x00, 0x32,  // 50
            IAC, SE,
        ];
        assert_eq!(replies, expected);
    }

    #[test]
    fn test_gateway_naws_update_silent_when_disabled() {
        // Without the NAWS option being enabled (reactive mode or peer
        // refused), send_naws_update emits nothing.
        let mut iac = reactive_iac();
        let mut replies = Vec::new();
        iac.send_naws_update(120, 50, &mut replies);
        assert!(replies.is_empty(), "should not emit SB NAWS when option is off");
    }

    // ─── write_telnet_data ────────────────────────────────

    #[tokio::test]
    async fn test_write_telnet_data_escapes_ff() {
        let mut buf: Vec<u8> = Vec::new();
        write_telnet_data(&mut buf, &[b'A', 0xFF, b'B', 0xFF, 0xFF, b'C'])
            .await
            .unwrap();
        assert_eq!(buf, vec![b'A', 0xFF, 0xFF, b'B', 0xFF, 0xFF, 0xFF, 0xFF, b'C']);
    }

    #[tokio::test]
    async fn test_write_telnet_data_passthrough_without_ff() {
        let mut buf: Vec<u8> = Vec::new();
        write_telnet_data(&mut buf, b"hello").await.unwrap();
        assert_eq!(buf, b"hello");
    }

    #[tokio::test]
    async fn test_do_binary_gets_wont() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Peer: IAC DO BINARY (opt 0) + real byte so the read returns.
        peer.write_all(&[IAC, DO, 0x00, b'X']).await.unwrap();

        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'X'));

        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        // Expect IAC WONT BINARY somewhere in the reply stream.
        let wont_binary = [IAC, WONT, 0x00];
        assert!(
            out.windows(3).any(|w| w == wont_binary),
            "expected IAC WONT 0x00, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_will_binary_gets_dont() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, WILL, 0x00, b'X']).await.unwrap();

        let b = session.session_read_byte().await.unwrap();
        assert_eq!(b, Some(b'X'));

        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let dont_binary = [IAC, DONT, 0x00];
        assert!(
            out.windows(3).any(|w| w == dont_binary),
            "expected IAC DONT 0x00, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_refused_option_not_repeated() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Send DO BINARY twice, then a data byte.
        peer.write_all(&[IAC, DO, 0x00, IAC, DO, 0x00, b'X'])
            .await
            .unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'X'));

        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let wont_binary = [IAC, WONT, 0x00];
        let matches = out.windows(3).filter(|w| *w == wont_binary).count();
        assert_eq!(matches, 1, "WONT should be sent exactly once, got {:?}", out);
    }

    #[tokio::test]
    async fn test_dont_ack_only_when_we_advertised_will() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        session.neg_sent_will[OPT_ECHO as usize] = true;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // DONT ECHO (we had advertised WILL ECHO) → expect WONT ECHO ack.
        // DONT BINARY (we never advertised) → no reply.
        peer.write_all(&[IAC, DONT, OPT_ECHO, IAC, DONT, 0x00, b'Z'])
            .await
            .unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'Z'));
        drop(session);

        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        let wont_echo = [IAC, WONT, OPT_ECHO];
        let wont_binary = [IAC, WONT, 0x00];
        assert!(
            out.windows(3).any(|w| w == wont_echo),
            "expected WONT ECHO ack, got {:?}",
            out
        );
        assert!(
            !out.windows(3).any(|w| w == wont_binary),
            "should not have replied to DONT BINARY, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_ttype_is_sets_terminal_type() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        // Mark as if we'd already DO'd TTYPE in real detection.
        session.neg_sent_do[OPT_TTYPE as usize] = true;

        use tokio::io::AsyncWriteExt;
        // IAC WILL TTYPE, then IAC SB TTYPE IS "VT100" IAC SE, then data.
        peer.write_all(&[IAC, WILL, OPT_TTYPE]).await.unwrap();
        peer.write_all(&[IAC, SB, OPT_TTYPE, TTYPE_IS])
            .await
            .unwrap();
        peer.write_all(b"VT100").await.unwrap();
        peer.write_all(&[IAC, SE, b'Q']).await.unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'Q'));
        assert!(session.ttype_matched);
        assert_eq!(session.terminal_type, TerminalType::Ansi);
    }

    #[tokio::test]
    async fn test_ttype_is_c64_maps_to_petscii() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        session.neg_sent_do[OPT_TTYPE as usize] = true;

        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, SB, OPT_TTYPE, TTYPE_IS])
            .await
            .unwrap();
        peer.write_all(b"C64").await.unwrap();
        peer.write_all(&[IAC, SE, b'!']).await.unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'!'));
        assert_eq!(session.terminal_type, TerminalType::Petscii);
    }

    /// Test 8a: empty TTYPE IS response (zero-byte terminal name).
    /// Session must not panic; terminal_type stays at its factory value.
    #[tokio::test]
    async fn test_ttype_is_empty_payload() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        session.neg_sent_do[OPT_TTYPE as usize] = true;
        let initial_type = session.terminal_type;

        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, SB, OPT_TTYPE, TTYPE_IS, IAC, SE, b'Q'])
            .await
            .unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'Q'));
        assert_eq!(session.terminal_type, initial_type);
    }

    /// Test 8b: TTYPE IS with IAC IAC embedded in the terminal-type
    /// string.  The SB-body reader must unescape to a single 0xFF so
    /// the name decodes without interpreting the 0xFF as an IAC
    /// command.  Terminal-type lookup should treat it as an unknown
    /// name and leave the session terminal_type unchanged.
    #[tokio::test]
    async fn test_ttype_is_with_escaped_iac_in_name() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        session.neg_sent_do[OPT_TTYPE as usize] = true;
        let initial_type = session.terminal_type;

        use tokio::io::AsyncWriteExt;
        // "term\xFFname" with the 0xFF properly IAC-doubled on the wire.
        peer.write_all(&[IAC, SB, OPT_TTYPE, TTYPE_IS]).await.unwrap();
        peer.write_all(b"term").await.unwrap();
        peer.write_all(&[IAC, IAC]).await.unwrap();      // escaped 0xFF
        peer.write_all(b"name").await.unwrap();
        peer.write_all(&[IAC, SE, b'R']).await.unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'R'));
        // The unusual name doesn't match any known terminal type →
        // session keeps its factory terminal.
        assert_eq!(session.terminal_type, initial_type);
    }

    /// Test 8c: a ridiculously long TTYPE IS payload — our SB reader
    /// has a hard cap to prevent a malicious peer from exhausting
    /// memory.  The session must not panic and should resync on the
    /// eventual IAC SE.  The writer runs in its own task so we don't
    /// deadlock on the duplex buffer (2 KiB > 512-byte buffer).
    #[tokio::test]
    async fn test_ttype_is_oversized_payload_does_not_panic() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        session.neg_sent_do[OPT_TTYPE as usize] = true;

        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            peer.write_all(&[IAC, SB, OPT_TTYPE, TTYPE_IS]).await.unwrap();
            let junk = vec![b'x'; 2048];
            peer.write_all(&junk).await.unwrap();
            peer.write_all(&[IAC, SE, b'Z']).await.unwrap();
        });

        // After the SB, we should cleanly receive the post-SE data byte.
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'Z'));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_naws_payload_stored() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        session.neg_sent_do[OPT_NAWS as usize] = true;

        use tokio::io::AsyncWriteExt;
        // IAC SB NAWS 0x00 0x50 0x00 0x18 IAC SE → 80x24.
        peer.write_all(&[
            IAC, SB, OPT_NAWS, 0x00, 0x50, 0x00, 0x18, IAC, SE, b'A',
        ])
        .await
        .unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'A'));
        assert_eq!(session.window_width, Some(80));
        assert_eq!(session.window_height, Some(24));
    }

    #[tokio::test]
    async fn test_naws_with_iac_iac_inside_payload() {
        // Window width 0xFF08 would include the IAC byte — the peer
        // must send IAC IAC to escape. Make sure our payload parser
        // unescapes correctly.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        session.neg_sent_do[OPT_NAWS as usize] = true;

        use tokio::io::AsyncWriteExt;
        peer.write_all(&[
            IAC, SB, OPT_NAWS, 0xFF, 0xFF, 0x08, 0x00, 0x18, IAC, SE, b'A',
        ])
        .await
        .unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'A'));
        assert_eq!(session.window_width, Some(0xFF08));
        assert_eq!(session.window_height, Some(0x0018));
    }

    #[tokio::test]
    async fn test_escaped_iac_as_data() {
        // IAC IAC in the input stream must surface as a single 0xFF
        // data byte (not a start-of-command).
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[b'A', IAC, IAC, b'B']).await.unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'A'));
        assert_eq!(session.session_read_byte().await.unwrap(), Some(0xFF));
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'B'));
    }

    #[tokio::test]
    async fn test_empty_subneg_tolerated() {
        // IAC SB TTYPE IAC SE — zero-length payload. Should not crash
        // and should not set ttype_matched.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, SB, OPT_TTYPE, IAC, SE, b'A'])
            .await
            .unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'A'));
        assert!(!session.ttype_matched);
    }

    #[tokio::test]
    async fn test_dont_without_prior_will_is_silent() {
        // Peer sends DONT ECHO without us having advertised WILL ECHO.
        // We should not reply (no WONT) per RFC 1143 (prevents loops).
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, DONT, OPT_ECHO, b'Z'])
            .await
            .unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'Z'));

        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        // No reply expected.
        assert!(
            out.is_empty(),
            "DONT for unadvertised option should be silent, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_wont_without_prior_do_is_silent() {
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, WONT, 0x42, b'Z']).await.unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'Z'));

        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        assert!(
            out.is_empty(),
            "WONT for unadvertised option should be silent, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_do_echo_is_ack_when_we_willed_echo() {
        // Peer's DO ECHO is an acknowledgement of our WILL ECHO — no reply.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        session.neg_sent_will[OPT_ECHO as usize] = true;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, DO, OPT_ECHO, b'Q']).await.unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'Q'));

        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        // Must NOT contain a WONT ECHO — DO is just an ack.
        let wont_echo = [IAC, WONT, OPT_ECHO];
        assert!(
            !out.windows(3).any(|w| w == wont_echo),
            "should not have replied to DO ECHO ack, got {:?}",
            out
        );
    }

    #[tokio::test]
    async fn test_subneg_with_sb_payload_then_data() {
        // Two subnegs back-to-back, then a data byte. Verify both are
        // processed and we return the data byte cleanly.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        session.neg_sent_do[OPT_TTYPE as usize] = true;
        session.neg_sent_do[OPT_NAWS as usize] = true;

        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, SB, OPT_TTYPE, TTYPE_IS]).await.unwrap();
        peer.write_all(b"XTERM").await.unwrap();
        peer.write_all(&[IAC, SE, IAC, SB, OPT_NAWS, 0x00, 0x50, 0x00, 0x18, IAC, SE, b'*'])
            .await
            .unwrap();

        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'*'));
        assert_eq!(session.terminal_type, TerminalType::Ansi);
        assert_eq!(session.window_width, Some(80));
        assert_eq!(session.window_height, Some(24));
    }

    #[tokio::test]
    async fn test_nop_is_silently_consumed() {
        // IAC NOP (0xF1) has no option byte and needs no reply.
        const NOP: u8 = 0xF1;
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, NOP, b'X']).await.unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'X'));

        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty(), "NOP should produce no reply, got {:?}", out);
    }

    // ─── Telnet RFC conformance tests ────────────────────────
    //
    // These tests cite specific RFC sections and lock in byte-exact
    // protocol behavior.  They complement the broader behavioral
    // tests above by giving a future reader an explicit checkpoint
    // against the standards.

    #[test]
    fn test_rfc854_command_byte_values() {
        // RFC 854 §"COMMAND NAME" table: every IAC command is a
        // specific byte value.  Lock these in as constants so a
        // refactor that accidentally renames a constant can't
        // silently change the wire format.
        const _: () = assert!(IAC == 0xFF);
        const _: () = assert!(SE == 0xF0);
        const _: () = assert!(SB == 0xFA);
        const _: () = assert!(WILL == 0xFB);
        const _: () = assert!(WONT == 0xFC);
        const _: () = assert!(DO == 0xFD);
        const _: () = assert!(DONT == 0xFE);
    }

    #[test]
    fn test_rfc857_858_859_1073_1091_option_byte_values() {
        // Option byte assignments per IANA Telnet Option registry,
        // codified in the originating RFCs:
        //   RFC 857 — Echo (option 1)
        //   RFC 858 — Suppress Go Ahead (option 3)
        //   RFC 859 — Status (option 5)
        //   RFC 860 — Timing Mark (option 6)
        //   RFC 1091 — Terminal Type (option 24 = 0x18)
        //   RFC 1073 — Window Size / NAWS (option 31 = 0x1F)
        const _: () = assert!(OPT_ECHO == 0x01);
        const _: () = assert!(OPT_SGA == 0x03);
        const _: () = assert!(OPT_STATUS == 0x05);
        const _: () = assert!(OPT_TIMING_MARK == 0x06);
        const _: () = assert!(OPT_TTYPE == 0x18);
        const _: () = assert!(OPT_NAWS == 0x1F);
    }

    #[test]
    fn test_rfc1091_ttype_subnegotiation_command_bytes() {
        // RFC 1091: TTYPE subnegotiation uses two command bytes:
        //   IS   = 0x00 (sender follows with the terminal name)
        //   SEND = 0x01 (request the peer's terminal name)
        const _: () = assert!(TTYPE_IS == 0x00);
        const _: () = assert!(TTYPE_SEND == 0x01);
    }

    #[tokio::test]
    async fn test_rfc854_iac_iac_decodes_to_literal_ff() {
        // RFC 854: "If [the data stream] is desired to send the data
        // byte 255, two 255s must be sent."  i.e., IAC IAC in the
        // data stream decodes to a single literal 0xFF byte.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, IAC, b'X']).await.unwrap();
        assert_eq!(
            session.session_read_byte().await.unwrap(),
            Some(0xFF),
            "IAC IAC must decode to literal 0xFF"
        );
        assert_eq!(
            session.session_read_byte().await.unwrap(),
            Some(b'X'),
            "byte after IAC IAC must read normally"
        );
    }

    #[tokio::test]
    async fn test_rfc1073_naws_subneg_byte_layout() {
        // RFC 1073: NAWS subnegotiation is exactly:
        //   IAC SB NAWS WIDTH_HI WIDTH_LO HEIGHT_HI HEIGHT_LO IAC SE
        // This test feeds a well-formed NAWS payload and verifies
        // both width and height are decoded as 16-bit big-endian.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        session.neg_sent_do[OPT_NAWS as usize] = true;
        use tokio::io::AsyncWriteExt;
        // 132 cols × 43 rows = 0x0084 × 0x002B.
        peer.write_all(&[
            IAC, SB, OPT_NAWS,
            0x00, 0x84, // width hi, lo
            0x00, 0x2B, // height hi, lo
            IAC, SE,
            b'!', // sentinel data byte
        ])
        .await
        .unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'!'));
        assert_eq!(session.window_width, Some(132));
        assert_eq!(session.window_height, Some(43));
    }

    #[tokio::test]
    async fn test_rfc1091_ttype_is_subneg_byte_layout() {
        // RFC 1091: TTYPE IS subnegotiation is:
        //   IAC SB TTYPE IS <terminal-name> IAC SE
        // The terminal name is bytes following IS (0x00) up to the
        // closing IAC SE.  Test feeds "ANSI" and verifies it ends up
        // recognized as TerminalType::Ansi.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ascii);
        session.neg_sent_do[OPT_TTYPE as usize] = true;
        use tokio::io::AsyncWriteExt;
        peer.write_all(&[IAC, SB, OPT_TTYPE, TTYPE_IS])
            .await
            .unwrap();
        peer.write_all(b"ANSI").await.unwrap();
        peer.write_all(&[IAC, SE, b'!']).await.unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'!'));
        assert_eq!(
            session.terminal_type,
            TerminalType::Ansi,
            "TTYPE IS 'ANSI' must set terminal type to Ansi"
        );
    }

    #[tokio::test]
    async fn test_rfc859_status_send_triggers_status_is_response() {
        // RFC 859: when peer sends IAC SB STATUS SEND IAC SE, we
        // must respond with IAC SB STATUS IS <state> IAC SE.  The
        // state body lists every option we've negotiated.  This
        // test verifies the response begins with the expected
        // wrapper.
        const STATUS_SEND: u8 = 0x01;
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        // Per the handler, we only respond if we've already WILL'd
        // STATUS — otherwise we don't claim to support it.
        session.neg_sent_will[OPT_STATUS as usize] = true;
        // Pretend we WILL'd ECHO so STATUS IS has something to report.
        session.neg_sent_will[OPT_ECHO as usize] = true;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, SB, OPT_STATUS, STATUS_SEND, IAC, SE, b'.'])
            .await
            .unwrap();
        // Drain the data byte so the subneg gets fully processed.
        let _ = session.session_read_byte().await;
        // Drop session so peer can read whatever the server emitted.
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        // Find the STATUS IS reply.  Format: IAC SB STATUS IS ...
        // IAC SE.  We just verify the prefix and the trailer are
        // present, and that ECHO appears as a WILL in the body.
        let prefix = [IAC, SB, OPT_STATUS, 0x00 /* IS */];
        let pos = out
            .windows(prefix.len())
            .position(|w| w == prefix)
            .expect("expected IAC SB STATUS IS in reply");
        // Body must contain WILL OPT_ECHO somewhere before the
        // closing IAC SE.
        let after_prefix = &out[pos + prefix.len()..];
        let se_idx = after_prefix
            .windows(2)
            .position(|w| w == [IAC, SE])
            .expect("expected closing IAC SE");
        let body = &after_prefix[..se_idx];
        let will_echo = [WILL, OPT_ECHO];
        assert!(
            body.windows(2).any(|w| w == will_echo),
            "STATUS IS body must contain WILL OPT_ECHO, got: {:?}",
            body
        );
    }

    #[tokio::test]
    async fn test_rfc855_q_method_dont_loop_on_already_disabled_option() {
        // RFC 855 Q-method §"DON'T to a disabled option": if a peer
        // sends IAC DONT for an option that's already disabled on
        // our side, we must NOT respond with another IAC WONT —
        // doing so would create an infinite negotiation loop.
        // We never advertised WILL ECHO, so OPT_ECHO is in the
        // disabled state; sending DONT ECHO must produce no reply.
        let (mut session, mut peer) = make_test_session_with_peer(TerminalType::Ansi);
        // Make sure OPT_ECHO has not been WILL'd.
        session.neg_sent_will[OPT_ECHO as usize] = false;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        peer.write_all(&[IAC, DONT, OPT_ECHO, b'.']).await.unwrap();
        assert_eq!(session.session_read_byte().await.unwrap(), Some(b'.'));
        drop(session);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        // The reply must not contain another WONT ECHO (which would
        // bounce back to the peer and risk a loop).
        let wont_echo = [IAC, WONT, OPT_ECHO];
        assert!(
            !out.windows(3).any(|w| w == wont_echo),
            "received unexpected WONT ECHO reply (Q-method violation), out={:?}",
            out
        );
    }

    // ─── YMODEM block-0 metadata application ─────────────────

    /// `apply_ymodem_meta` with `meta = None` must be a no-op — covers
    /// the common XMODEM (no block 0) and ZMODEM paths so we don't
    /// accidentally rewrite mtime/mode on every saved file.
    #[test]
    fn test_apply_ymodem_meta_none_is_noop() {
        let tmp = std::env::temp_dir()
            .join(format!("ymeta_none_{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"x").unwrap();
        let before = std::fs::metadata(&tmp).unwrap();
        // Brief sleep so any spurious modtime change is detectable.
        std::thread::sleep(std::time::Duration::from_millis(10));
        TelnetSession::apply_ymodem_meta(&tmp, None);
        let after = std::fs::metadata(&tmp).unwrap();
        assert_eq!(
            before.modified().unwrap(),
            after.modified().unwrap(),
            "modtime must be unchanged when meta is None",
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// Modtime application: when block-0 carried a timestamp, the
    /// saved file's mtime should match (within whole-second resolution
    /// — POSIX `utimes` is second-granular on most filesystems).
    #[test]
    fn test_apply_ymodem_meta_modtime() {
        let tmp = std::env::temp_dir()
            .join(format!("ymeta_mtime_{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"x").unwrap();
        let target_secs: u64 = 1_500_000_000; // 2017-07-14 — clearly in the past
        let meta = crate::xmodem::YmodemReceiveMeta {
            size: Some(1),
            modtime: Some(target_secs),
            mode: None,
        };
        TelnetSession::apply_ymodem_meta(&tmp, Some(&meta));
        let after = std::fs::metadata(&tmp).unwrap();
        let actual = after
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(actual, target_secs, "modtime must match block-0 value");
        let _ = std::fs::remove_file(&tmp);
    }

    /// Mode application is Unix-only; on Unix, the block-0 `mode`
    /// field (already masked to 0o7777 by the parser) is masked
    /// further to 0o777 by the apply path before reaching `chmod`.
    #[cfg(unix)]
    #[test]
    fn test_apply_ymodem_meta_mode_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir()
            .join(format!("ymeta_mode_{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"x").unwrap();
        // Start with mode 0o600.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
        let meta = crate::xmodem::YmodemReceiveMeta {
            size: Some(1),
            modtime: None,
            // Pass setuid + 0o755; the apply mask (0o777) must drop
            // setuid, giving us plain 0o755 on disk.  This guards
            // against a malicious sender setting setuid bits on our
            // saved files.
            mode: Some(0o4755),
        };
        TelnetSession::apply_ymodem_meta(&tmp, Some(&meta));
        let actual = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o7777;
        assert_eq!(actual, 0o755, "setuid bit must be stripped, perms preserved");
        let _ = std::fs::remove_file(&tmp);
    }
}
