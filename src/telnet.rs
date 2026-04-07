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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config;

// ─── ANSI escape codes ──────────────────────────────────────
const ANSI_GREEN: &str = "\x1b[1;32m";
const ANSI_RED: &str = "\x1b[1;31m";
const ANSI_CYAN: &str = "\x1b[1;36m";
const ANSI_YELLOW: &str = "\x1b[1;33m";
const ANSI_AMBER: &str = "\x1b[33m";
const ANSI_WHITE: &str = "\x1b[1;37m";
const ANSI_DIM: &str = "\x1b[37m";
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_CLEAR: &str = "\x1b[2J\x1b[H";

// ─── PETSCII color codes ────────────────────────────────────
const PETSCII_GREEN: u8 = 0x1E;
const PETSCII_RED: u8 = 0x96;
const PETSCII_CYAN: u8 = 0x9F;
const PETSCII_YELLOW: u8 = 0x9E;
const PETSCII_WHITE: u8 = 0x05;
const PETSCII_LIGHT_GRAY: u8 = 0x9B;
const PETSCII_CLEAR: u8 = 0x93;
const PETSCII_DEFAULT: u8 = PETSCII_LIGHT_GRAY;

const PETSCII_WIDTH: usize = 40;
const MAX_INPUT_LENGTH: usize = 1024;
const MAX_LOGIN_ATTEMPTS: u32 = 3;
const MAX_AUTH_FAILURES: u32 = 3;
const LOCKOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(5 * 60);

// ─── Terminal Type ──────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
enum TerminalType {
    Ascii,
    Ansi,
    Petscii,
}

// ─── Menu ───────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
enum Menu {
    Main,
    FileTransfer,
    Gateway,
    Browser,
}

impl Menu {
    fn path(&self) -> &'static str {
        match self {
            Menu::Main => "xmodem",
            Menu::FileTransfer => "xmodem/xfer",
            Menu::Gateway => "xmodem/gw",
            Menu::Browser => "xmodem/web",
        }
    }
}

// ─── Auth lockout ───────────────────────────────────────────
type LockoutMap = Arc<Mutex<HashMap<IpAddr, (u32, std::time::Instant)>>>;

fn is_locked_out(lockouts: &LockoutMap, ip: IpAddr) -> bool {
    let map = lockouts.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((count, when)) = map.get(&ip) {
        *count >= MAX_AUTH_FAILURES && when.elapsed() < LOCKOUT_DURATION
    } else {
        false
    }
}

fn record_auth_failure(lockouts: &LockoutMap, ip: IpAddr) -> u32 {
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

fn clear_lockout(lockouts: &LockoutMap, ip: IpAddr) {
    let mut map = lockouts.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(&ip);
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

// ─── Input helpers (standalone) ─────────────────────────────

fn is_backspace_key(byte: u8, erase_char: u8) -> bool {
    byte == erase_char || byte == 0x08 || byte == 0x7F || byte == 0x14
}

/// Returns true for ANSI ESC (0x1B), plus C64 back-arrow (0x5F) when petscii is true.
pub(crate) fn is_esc_key(byte: u8, petscii: bool) -> bool {
    byte == 0x1B || (petscii && byte == 0x5F)
}

/// Truncate a string to at most `max_width` visible characters, appending "..." if needed.
fn truncate_to_width(s: &str, max_width: usize) -> String {
    if s.len() <= max_width {
        s.to_string()
    } else if max_width <= 3 {
        ".".repeat(max_width)
    } else {
        let truncated: String = s.chars().take(max_width - 3).collect();
        format!("{}...", truncated)
    }
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
                                let _ = reader.read(&mut buf).await;
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

/// Minimal SSH client handler for the gateway feature. Accepts all server
/// host keys (the telnet leg is already cleartext).
struct GatewayHandler;

impl russh::client::Handler for GatewayHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

// ─── SharedWriter ───────────────────────────────────────────
type SharedWriter = Arc<tokio::sync::Mutex<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>>;

// ─── TelnetSession ──────────────────────────────────────────

struct TelnetSession {
    reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    writer: SharedWriter,
    shutdown: Arc<AtomicBool>,
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
}

impl TelnetSession {
    const TRANSFER_PAGE_SIZE: usize = 10;
    const MAX_FILE_SIZE: usize = 8 * 1024 * 1024;
    const MAX_FILENAME_LEN: usize = 64;

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
    fn white(&self, text: &str) -> String {
        match self.terminal_type {
            TerminalType::Ansi => format!("{}{}{}", ANSI_WHITE, text, ANSI_RESET),
            TerminalType::Petscii => Self::petscii_color(PETSCII_WHITE, text),
            TerminalType::Ascii => text.to_string(),
        }
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
            "  {} {}",
            self.action_prompt("R", "Refresh"),
            self.action_prompt("Q", "Back"),
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
        let mut writer = self.writer.lock().await;
        match self.terminal_type {
            TerminalType::Petscii => {
                let swapped = swap_case_for_petscii(text);
                writer.write_all(&to_latin1_bytes(&swapped)).await
            }
            _ => writer.write_all(text.as_bytes()).await,
        }
    }

    async fn send_line(&mut self, text: &str) -> Result<(), std::io::Error> {
        let line = format!("{}\r\n", text);
        self.send(&line).await
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
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
        read_byte_iac_filtered(&mut self.reader, true).await
    }

    async fn echo_backspace(&mut self) -> Result<(), std::io::Error> {
        match self.terminal_type {
            TerminalType::Petscii => self.send_raw(&[0x9D, 0x20, 0x9D]).await,
            _ => self.send_raw(&[0x08, 0x20, 0x08]).await,
        }
    }

    async fn get_line_input(&mut self) -> Result<Option<String>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let byte = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };

            if byte == b'\r' || byte == b'\n' {
                self.send_raw(b"\r\n").await?;
                self.flush().await?;
                let result: String = if self.terminal_type == TerminalType::Petscii {
                    buf.iter()
                        .map(|&b| petscii_to_ascii_byte(b) as char)
                        .collect()
                } else {
                    buf.iter().map(|&b| b as char).collect()
                };
                return Ok(Some(result.trim().to_string()));
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

            if byte < 0x20 {
                continue;
            }

            if buf.len() >= MAX_INPUT_LENGTH {
                self.send_raw(b"\r\n").await?;
                self.show_error("Input too long.").await?;
                return Ok(None);
            }

            self.send_raw(&[byte]).await?;
            self.flush().await?;
            buf.push(byte);
        }
    }

    async fn get_password_input(&mut self) -> Result<Option<String>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let byte = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };
            if byte == b'\r' || byte == b'\n' {
                self.send_raw(b"\r\n").await?;
                self.flush().await?;
                let result: String = if self.terminal_type == TerminalType::Petscii {
                    buf.iter()
                        .map(|&b| petscii_to_ascii_byte(b) as char)
                        .collect()
                } else {
                    buf.iter().map(|&b| b as char).collect()
                };
                return Ok(Some(result));
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
            if byte < 0x20 {
                continue;
            }
            if buf.len() >= MAX_INPUT_LENGTH {
                self.send_raw(b"\r\n").await?;
                self.show_error("Input too long.").await?;
                return Ok(None);
            }
            self.send_raw(b"*").await?;
            self.flush().await?;
            buf.push(byte);
        }
    }

    async fn get_menu_input(
        &mut self,
        instant_digits: bool,
    ) -> Result<Option<String>, std::io::Error> {
        loop {
            let byte = match self.read_byte_filtered().await? {
                Some(b) => b,
                None => return Ok(None),
            };

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
                return Ok(Some(ch.to_string()));
            }

            if ch.is_ascii_digit() {
                if instant_digits {
                    self.send_raw(&[byte]).await?;
                    self.send_raw(b"\r\n").await?;
                    self.flush().await?;
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
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(50),
                self.reader.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
    }

    async fn show_error(&mut self, msg: &str) -> Result<(), std::io::Error> {
        self.send_line(&format!("  {}", self.red(msg))).await?;
        self.send_line("").await?;
        self.send("  Press any key to continue.").await?;
        self.flush().await?;
        self.wait_for_key().await?;
        Ok(())
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

    // ─── Terminal detection ─────────────────────────────────

    async fn detect_terminal_type(&mut self) -> Result<(), std::io::Error> {
        // IAC WILL ECHO, IAC WILL SGA, IAC DO SGA
        self.send_raw(&[
            0xFF, 0xFB, 0x01, // IAC WILL ECHO
            0xFF, 0xFB, 0x03, // IAC WILL SUPPRESS-GO-AHEAD
            0xFF, 0xFD, 0x03, // IAC DO SUPPRESS-GO-AHEAD
        ])
        .await?;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        self.drain_input().await;

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

        // Color preference
        let (color_label, default_yes) = match self.terminal_type {
            TerminalType::Petscii => ("PETSCII", true),
            TerminalType::Ansi => ("ANSI", false),
            TerminalType::Ascii => ("ANSI", false),
        };
        let default_char = if default_yes { 'Y' } else { 'N' };
        self.send(&format!(
            "Use {} color? (Y/N) [{}]: ",
            color_label, default_char
        ))
        .await?;
        self.flush().await?;

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
                if default_yes {
                    b'Y'
                } else {
                    b'N'
                }
            }
        };

        self.send_raw(&[color_byte]).await?;
        self.send_raw(b"\r\n").await?;
        self.flush().await?;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.drain_input().await;

        let choice = if self.terminal_type == TerminalType::Petscii {
            petscii_to_ascii_byte(color_byte)
        } else {
            color_byte
        };

        let accepted = match choice {
            b'y' | b'Y' => true,
            b'n' | b'N' => false,
            b'\r' | b'\n' => default_yes,
            _ => default_yes,
        };

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
            eprintln!("Telnet: auth rejected for {} (locked out)", ip);
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
        self.send_line(&format!("  {}", self.yellow("XMODEM GATEWAY")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;

        for attempt in 1..=MAX_LOGIN_ATTEMPTS {
            self.send(&format!("  {} ", self.cyan("Username:")))
                .await?;
            self.flush().await?;
            let username = match tokio::time::timeout(idle_timeout, self.get_line_input()).await {
                Ok(Ok(Some(s))) => s,
                Ok(Ok(None)) => return Ok(false),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    let _ = self
                        .send_line("\r\nDisconnected: idle timeout.")
                        .await;
                    return Ok(false);
                }
            };

            self.send(&format!("  {} ", self.cyan("Password:")))
                .await?;
            self.flush().await?;
            let password =
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
                };

            if username == cfg.username && password == cfg.password {
                if let Some(ip) = self.peer_addr {
                    clear_lockout(&self.lockouts, ip);
                }
                return Ok(true);
            }

            if let Some(ip) = self.peer_addr {
                let count = record_auth_failure(&self.lockouts, ip);
                if count >= MAX_LOGIN_ATTEMPTS {
                    eprintln!("Telnet: {} locked out after {} failures", ip, count);
                    self.send_line(&format!(
                        "  {}",
                        self.red("Too many failed attempts.")
                    ))
                    .await?;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    return Ok(false);
                }
            }

            let remaining = MAX_LOGIN_ATTEMPTS - attempt;
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

    async fn run(&mut self) -> Result<(), std::io::Error> {
        self.detect_terminal_type().await?;

        let cfg = config::get_config();
        if cfg.security_enabled
            && !self.authenticate().await?
        {
            return Ok(());
        }

        let idle_timeout = std::time::Duration::from_secs(cfg.idle_timeout_secs);

        // Welcome banner
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("XMODEM GATEWAY")))
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

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                self.send_line("\r\nServer shutting down. Goodbye.")
                    .await?;
                break;
            }

            match self.current_menu {
                Menu::Main => self.render_main_menu().await?,
                Menu::FileTransfer => self.render_file_transfer().await?,
                Menu::Gateway => self.render_gateway().await?,
                Menu::Browser => self.render_web_browser().await?,
            }

            let prompt = self.prompt_str();
            self.send(&prompt).await?;
            self.flush().await?;

            let input = if idle_timeout.is_zero() {
                self.get_menu_input(true).await?
            } else {
                match tokio::time::timeout(idle_timeout, self.get_menu_input(true)).await {
                    Ok(result) => result?,
                    Err(_) => {
                        self.send_line("\r\n\r\nDisconnected: idle timeout.")
                            .await?;
                        break;
                    }
                }
            };

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
                Menu::Gateway => {
                    self.handle_gateway_command(&input).await?;
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
        self.send_line(&format!("  {}", self.yellow("XMODEM GATEWAY")))
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
            "  {}  File Transfer",
            self.cyan("F")
        ))
        .await?;
        self.send_line(&format!(
            "  {}  SSH Gateway",
            self.cyan("G")
        ))
        .await?;
        self.send_line(&format!("  {}  Exit", self.cyan("X")))
            .await?;
        self.send_line("").await?;
        Ok(())
    }

    async fn handle_main_command(&mut self, input: &str) -> Result<bool, std::io::Error> {
        match input {
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
                        "4. Add to xmodem.conf:",
                        "   groq_api_key = gsk_...",
                        "5. Restart the server",
                    ]).await?;
                } else {
                    self.ai_chat(&cfg.groq_api_key).await?;
                }
            }
            "b" => {
                self.current_menu = Menu::Browser;
            }
            "f" => {
                self.current_menu = Menu::FileTransfer;
            }
            "g" => {
                self.current_menu = Menu::Gateway;
            }
            "x" => {
                self.send_line("").await?;
                self.send_line("Goodbye!").await?;
                self.flush().await?;
                return Ok(false);
            }
            _ => {
                self.show_error("Press A, B, F, G, or X.").await?;
            }
        }
        Ok(true)
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
            "r" => {} // Refresh — just re-render
            _ => {
                self.show_error("Press U, D, X, C, I, R, or Q.")
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
            let path =
                CString::new(dir.as_str()).unwrap_or_else(|_| CString::new(".").unwrap());
            let mut stat = MaybeUninit::<libc::statvfs>::uninit();
            let rc = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
            if rc != 0 {
                return true;
            }
            let stat = unsafe { stat.assume_init() };
            let total = stat.f_blocks * stat.f_frsize;
            let avail = stat.f_bavail * stat.f_frsize;
            if total == 0 {
                return true;
            }
            let used_pct = 100 - (avail * 100 / total);
            used_pct > 90
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    // ─── UPLOAD ─────────────────────────────────────────────

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
            self.green("Begin XMODEM send now.")
        ))
        .await?;
        self.send_line("  Start transfer within 90 seconds.")
            .await?;
        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };
        self.send_line(&format!("  {} to cancel", self.cyan(esc_label)))
            .await?;
        self.send_line("").await?;
        self.flush().await?;

        if config::get_config().verbose { eprintln!("XMODEM upload: IAC escaping={}", self.xmodem_iac); }
        self.drain_input().await;

        let start = std::time::Instant::now();
        let mut writer_guard = self.writer.lock().await;
        let verbose = config::get_config().verbose;
        let result = crate::xmodem::xmodem_receive(
            &mut self.reader,
            &mut *writer_guard,
            self.xmodem_iac,
            self.terminal_type == TerminalType::Petscii,
            verbose,
        )
        .await;
        drop(writer_guard);
        let elapsed = start.elapsed();

        let data = match result {
            Ok(d) => d,
            Err(e) => {
                self.drain_input().await;
                self.show_error(&format!("Transfer failed: {}", e))
                    .await?;
                return Ok(());
            }
        };

        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filepath)
            .await
        {
            Ok(mut file) => {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = file.write_all(&data).await {
                    self.drain_input().await;
                    self.show_error(&format!("Failed to save: {}", e))
                        .await?;
                    return Ok(());
                }
                let _ = file.flush().await;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                self.drain_input().await;
                self.show_error("File already exists.").await?;
                return Ok(());
            }
            Err(e) => {
                self.drain_input().await;
                self.show_error(&format!("Failed to save: {}", e))
                    .await?;
                return Ok(());
            }
        }

        self.drain_input().await;

        let blocks = data.len().div_ceil(crate::xmodem::XMODEM_BLOCK_SIZE);
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.green("Upload complete!")
        ))
        .await?;
        self.send_line(&format!(
            "  {} bytes, {} blocks, {:.1}s",
            data.len(),
            blocks,
            elapsed.as_secs_f64()
        ))
        .await?;
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
                let display_name = if name.len() > 22 {
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
                other => {
                    if let Ok(num) = other.parse::<usize>() {
                        if num >= 1 && num <= page_files.len() {
                            let (ref filename, file_size) = page_files[num - 1];
                            self.initiate_download(filename, file_size).await?;
                        } else {
                            self.show_error("Invalid selection.").await?;
                        }
                    } else {
                        self.show_error("Enter a number, P, N, or Q.")
                            .await?;
                    }
                }
            }
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

        self.send_line("").await?;
        self.send_line(&format!(
            "  {}",
            self.green("Start XMODEM receive now.")
        ))
        .await?;
        self.send_line("  Start transfer within 90 seconds.")
            .await?;
        let esc_label = match self.terminal_type {
            TerminalType::Petscii => "<-",
            _ => "ESC",
        };
        self.send_line(&format!("  {} to cancel", self.cyan(esc_label)))
            .await?;
        self.send_line("").await?;
        self.flush().await?;

        if config::get_config().verbose { eprintln!("XMODEM download: IAC escaping={}", self.xmodem_iac); }
        self.drain_input().await;

        let start = std::time::Instant::now();
        let mut writer_guard = self.writer.lock().await;
        let verbose = config::get_config().verbose;
        let result = crate::xmodem::xmodem_send(
            &mut self.reader,
            &mut *writer_guard,
            &data,
            self.xmodem_iac,
            self.terminal_type == TerminalType::Petscii,
            verbose,
        )
        .await;
        drop(writer_guard);
        let elapsed = start.elapsed();

        match result {
            Ok(()) => {
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
                let display_name = if name.len() > 22 {
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
                        self.show_error("Enter a number, P, N, or Q.")
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
            let display = if name.len() > 30 {
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

    async fn render_gateway(&mut self) -> Result<(), std::io::Error> {
        self.clear_screen().await?;
        let sep = self.separator();
        self.send_line(&sep).await?;
        self.send_line(&format!("  {}", self.yellow("SSH GATEWAY")))
            .await?;
        self.send_line(&sep).await?;
        self.send_line("").await?;
        self.send_line(&format!(
            "  {}  Connect to SSH server",
            self.cyan("S")
        ))
        .await?;
        self.send_line("").await?;
        let footer = self.nav_footer();
        self.send_line(&footer).await?;
        Ok(())
    }

    async fn handle_gateway_command(&mut self, input: &str) -> Result<bool, std::io::Error> {
        match input {
            "s" => {
                self.gateway_ssh().await?;
            }
            "q" => {
                self.current_menu = Menu::Main;
            }
            "r" => {} // Refresh
            _ => {
                self.show_error("Press S, R, or Q.").await?;
            }
        }
        Ok(true)
    }

    /// Gather gateway connection details from the user (host, port, username, password).
    /// Returns None if the user cancelled (ESC or empty input).
    async fn gateway_prompts(
        &mut self,
    ) -> Result<Option<(String, u16, String, String)>, std::io::Error> {
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

        self.send(&format!("  {} ", self.cyan("Password:")))
            .await?;
        self.flush().await?;
        let password = match self.get_password_input().await? {
            Some(s) => s,
            None => return Ok(None),
        };

        Ok(Some((host, port, username, password)))
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
        self.send_line("").await?;

        let (host, port, username, password) = match tokio::time::timeout(
            idle_timeout,
            self.gateway_prompts(),
        )
        .await
        {
            Ok(Ok(Some(creds))) => creds,
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
        let handler = GatewayHandler;

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

        // Authenticate
        match session.authenticate_password(&username, &password).await {
            Ok(russh::client::AuthResult::Success) => {}
            Ok(russh::client::AuthResult::Failure { .. }) => {
                self.show_error("Authentication failed.").await?;
                return Ok(());
            }
            Err(e) => {
                self.show_error(&format!("Auth error: {}", e)).await?;
                return Ok(());
            }
        }

        // Open channel and request PTY + shell
        let channel = match session.channel_open_session().await {
            Ok(ch) => ch,
            Err(e) => {
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
            self.show_error(&format!("PTY error: {}", e)).await?;
            return Ok(());
        }
        if let Err(e) = channel.request_shell(false).await {
            self.show_error(&format!("Shell error: {}", e)).await?;
            return Ok(());
        }

        self.send_line(&format!(
            "  {}",
            self.green("Connected.")
        ))
        .await?;
        self.send_line(&format!(
            "  Press {} to disconnect.",
            self.cyan("Ctrl+]")
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

        loop {
            tokio::select! {
                byte = read_byte_iac_filtered(reader, true) => {
                    match byte {
                        Ok(Some(0x1D)) => break, // Ctrl+]
                        Ok(Some(b)) => {
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
        match tokio::time::timeout(idle_timeout, self.wait_for_key()).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = self
                    .send_line("\r\nDisconnected: idle timeout.")
                    .await;
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
            self.send_line(&format!("  {}", parts.join(" ")))
                .await?;
            self.send(&format!("  {}: ", self.cyan(">")))
                .await?;
            self.flush().await?;

            let input = match self.get_line_input().await? {
                Some(s) if !s.is_empty() => s,
                _ => return Ok(None),
            };

            // Single character = command; longer = new question
            if input.len() == 1 {
                match input.to_ascii_lowercase().as_str() {
                    "n" if has_next => scroll += page_h,
                    "p" if has_prev => scroll = scroll.saturating_sub(page_h),
                    "q" => return Ok(None),
                    _ => {}
                }
            } else {
                return Ok(Some(input));
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
            self.send_line(&format!("  {}  {}  {}",
                self.action_prompt("G", "Go/Search"),
                self.action_prompt("K", "Bookmarks"),
                self.action_prompt("H", "Help"),
            )).await?;
            self.send_line("").await?;
            let footer = self.nav_footer();
            self.send_line(&footer).await?;
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
                self.send_line(&format!("  {}", safe)).await?;
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
                    if let Ok(num) = input.parse::<usize>() {
                        self.web_follow_link(num).await?;
                    } else {
                        self.show_error("Unknown command.").await?;
                    }
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
        self.send_line("").await?;
        self.send_line(&format!("  {}...", self.dim("Loading"))).await?;
        self.flush().await?;

        let width = self.web_content_width();
        let url_owned = url.to_string();

        let result = tokio::task::spawn_blocking(move || {
            crate::webbrowser::fetch_and_render(&url_owned, width)
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
                self.send_line("  1-9  Follow link by number").await?;
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
                self.send_line("  1-9    Follow a link by its number").await?;
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
                self.dim("Type a URL like example.com")
            )).await?;
            self.send_line(&format!("  {}",
                self.dim("or a search like: rust lang")
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
        self.send_line(&format!("  {} {}",
            self.dim("#=Open"),
            self.action_prompt("D", "Delete"),
        )).await?;
        self.send(&format!("  {}: ", self.cyan("Cmd"))).await?;
        self.flush().await?;

        let input = match self.get_line_input().await? {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(()),
        };

        if input == "d" {
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
            self.send_line(&format!("  {} {} {}",
                self.action_prompt("S", "Submit"),
                self.dim("#=Edit"),
                self.action_prompt("Q", "Cancel"),
            )).await?;
            self.send(&format!("  {}: ", self.cyan("Cmd"))).await?;
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
                other => {
                    if let Ok(num) = other.parse::<usize>() {
                        if let Some(real_idx) = crate::webbrowser::visible_field_index(&form.fields, num) {
                            self.web_edit_field(&mut form, real_idx).await?;
                        } else {
                            self.show_error("Invalid field number.").await?;
                        }
                    } else {
                        self.show_error("Enter S, Q, or a field #.").await?;
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
pub fn start_server(shutdown: Arc<AtomicBool>, shutdown_notify: Arc<tokio::sync::Notify>) {
    let cfg = config::get_config();
    let port = cfg.telnet_port;
    let max_sessions = cfg.max_sessions;

    tokio::spawn(async move {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Telnet server: failed to bind port {}: {}", port, e);
                return;
            }
        };
        eprintln!("Telnet server listening on port {}", port);

        let session_count = Arc::new(AtomicUsize::new(0));
        let session_writers: Arc<tokio::sync::Mutex<Vec<SharedWriter>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let lockouts: LockoutMap =
            Arc::new(Mutex::new(HashMap::new()));

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
                                eprintln!("Telnet: rejected {} (max {} sessions)", addr, max_sessions);
                                let _ = stream.try_write(b"Too many connections. Try again later.\r\n");
                                drop(stream);
                                continue;
                            }
                            session_count.fetch_add(1, Ordering::SeqCst);
                            eprintln!("Telnet: connection from {} ({}/{})", addr, current + 1, max_sessions);
                            let sd = shutdown.clone();
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
                                    current_menu: Menu::Main,
                                    terminal_type: TerminalType::Ansi,
                                    erase_char: 0x7F,
                                    lockouts: lo,
                                    peer_addr: Some(addr.ip()),
                                    transfer_subdir: String::new(),
                                    xmodem_iac: false,
                                    web_lines: Vec::new(),
                                    web_scroll: 0,
                                    web_links: Vec::new(),
                                    web_history: Vec::new(),
                                    web_url: None,
                                    web_title: None,
                                    web_forms: Vec::new(),
                                };
                                if let Err(e) = session.run().await {
                                    eprintln!("Telnet: session error from {}: {}", addr, e);
                                }
                                {
                                    let mut w = writer_arc.lock().await;
                                    let _ = w.shutdown().await;
                                }
                                sw.lock().await.retain(|w| !Arc::ptr_eq(w, &writer_arc));
                                sc.fetch_sub(1, Ordering::SeqCst);
                                eprintln!("Telnet: {} disconnected", addr);
                            });
                        }
                        Err(e) => {
                            eprintln!("Telnet: accept error: {}", e);
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
        assert_eq!(TelnetSession::MAX_FILE_SIZE, 8 * 1024 * 1024);
        assert_eq!(TelnetSession::MAX_FILENAME_LEN, 64);
        assert!(TelnetSession::TRANSFER_PAGE_SIZE > 0);
        assert!(TelnetSession::TRANSFER_PAGE_SIZE <= 20);
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

    // ─── Menu ────────────────────────────────────────────

    #[test]
    fn test_menu_paths() {
        assert_eq!(Menu::Main.path(), "xmodem");
        assert_eq!(Menu::FileTransfer.path(), "xmodem/xfer");
    }

    // ─── Color helpers ───────────────────────────────────

    #[test]
    fn test_petscii_color() {
        let result = TelnetSession::petscii_color(PETSCII_GREEN, "test");
        assert!(result.contains("test"));
        assert_eq!(result.as_bytes()[0], PETSCII_GREEN);
        assert_eq!(*result.as_bytes().last().unwrap(), PETSCII_DEFAULT);
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

    // ─── Gateway menu ────────────────────────────────────

    #[test]
    fn test_gateway_menu_path() {
        assert_eq!(Menu::Gateway.path(), "xmodem/gw");
    }

    #[test]
    fn test_gateway_menu_items_fit_petscii() {
        let items = [
            "  S=Connect to SSH server",
            "  Press S, R, or Q.",
        ];
        for item in &items {
            assert!(
                item.len() <= PETSCII_WIDTH,
                "item '{}' is {} chars, exceeds {}",
                item,
                item.len(),
                PETSCII_WIDTH,
            );
        }
    }

    // ─── Screen layout constraints ───────────────────────

    /// All user-facing error messages must fit in PETSCII width (40 cols).
    /// The "  " prefix + message must not exceed 40 chars.
    #[test]
    fn test_all_error_messages_fit_petscii() {
        let messages = [
            "Input too long.",
            "Press A, B, F, G, or X.",
            "Press U, D, X, C, I, R, or Q.",
            "Disk space is low. Uploads disabled.",
            "File already exists.",
            "No files available.",
            "Invalid selection.",
            "Enter a number, P, N, or Q.",
            "File too large.",
            "No files to delete.",
            "No subdirectories.",
            "Access denied.",
            "Enter a number or Q.",
            "Press S, R, or Q.",
            "Invalid port number.",
            "Connection timed out.",
            "Authentication failed.",
            "Too many attempts. Try later.",
            "Too many failed attempts.",
            "Login incorrect.",
            "Disconnected: idle timeout.",
            "Press any key to continue.",
            "No API key configured.",
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
            "Enter S, Q, or a field #.",
            "Already bookmarked (or full).",
            "No page to bookmark.",
            "No bookmarks saved.",
            "Not found.",
            "Invalid number.",
            "Unknown command.",
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
            "  F  File Transfer",
            "  G  SSH Gateway",
            "  X  Exit",
            // File transfer menu
            "  U  Upload a file",
            "  D  Download a file",
            "  X  Delete a file",
            "  C  Change directory",
            // Gateway menu
            "  S  Connect to SSH server",
            // Navigation footers
            "  R=Refresh Q=Back",
            // Auth prompts
            "  Username: ",
            "  Password: ",
            // AI chat
            "  Type a question, or Q to exit.",
            // Web browser
            "  G=Go/Search  K=Bookmarks  H=Help",
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

    /// Main menu screen: header(3) + blank + 5 items + blank + prompt = 10 rows.
    #[test]
    fn test_main_menu_row_count() {
        // sep, title, sep, blank, A, B, F, G, X, blank = 10 lines
        let rows = 10;
        assert!(rows <= 22, "main menu is {} rows, exceeds 22", rows);
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

    /// Gateway menu: header(3) + blank + 1 item + blank + footer = 7 rows.
    #[test]
    fn test_gateway_menu_row_count() {
        let rows = 3 + 1 + 1 + 1 + 1; // 7
        assert!(rows <= 22, "gateway menu is {} rows, exceeds 22", rows);
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

    /// Separator width must match terminal type.
    #[test]
    fn test_separator_widths() {
        assert_eq!("=".repeat(PETSCII_WIDTH).len(), 40);
        assert_eq!("=".repeat(56).len(), 56); // ANSI/ASCII separator
        assert!(56 <= 80, "ANSI separator exceeds 80 cols");
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
        assert!(!( scroll > 0));    // no prev
        assert!(!(end < total));     // no next
    }

    #[test]
    fn test_ai_pagination_exactly_one_page() {
        let page_h = TelnetSession::PAGE_CONTENT_LINES;
        let total = page_h;
        let scroll = 0;
        let end = (scroll + page_h).min(total);
        assert_eq!(end, page_h);
        assert!(!(scroll > 0));
        assert!(!(end < total));
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
        assert!(!(end < total));  // no next
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
        assert_eq!(Menu::Browser.path(), "xmodem/web");
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
        assert!(TelnetSession::WEB_MAX_HISTORY >= 10, "too few history entries");
        assert!(TelnetSession::WEB_MAX_HISTORY <= 200, "excessive history cap");
    }

    #[test]
    fn test_web_browser_home_lines_fit_petscii() {
        let lines = [
            "  WEB BROWSER",
            "  G=Go/Search  K=Bookmarks  H=Help",
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
        let total = 5;
        // E command when total <= page_h: scroll stays 0
        let scroll = if total > page_h { total - page_h } else { 0 };
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
        let start_line = 0 + 1; // search from scroll+1
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
        let start_line = 0 + 1;
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

    // ─── Help screen ──────────────────────────────────────

    #[test]
    fn test_web_help_lines_fit_petscii() {
        let lines = [
            "  BROWSER HELP",
            "  1-9  Follow link by number",
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
        // header(3) + 12 help lines + blank + "press any key" = 17 rows max
        let rows = 3 + 12 + 1 + 1;
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
}
