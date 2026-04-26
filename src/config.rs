//! Configuration file management.
//!
//! Reads/writes a simple key=value config file (`egateway.conf`). If the file
//! does not exist at startup it is created with sensible defaults. Unknown
//! keys are silently ignored; missing keys are filled with defaults and the
//! file is rewritten.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use crate::logger::glog;

/// Name of the configuration file (lives next to the binary).
pub const CONFIG_FILE: &str = "egateway.conf";

// ─── Defaults ──────────────────────────────────────────────
const DEFAULT_TELNET_ENABLED: bool = true;
const DEFAULT_TELNET_PORT: u16 = 2323;
/// Default for the outgoing Telnet Gateway's cooperative negotiation.
/// Off by default so dialing raw-TCP-on-port-23 services (legacy MUDs,
/// hand-rolled BBS software) still works — those services don't speak
/// telnet and would see our IAC offers as garbage.  Enable when the
/// destinations you dial are genuine telnet servers.
const DEFAULT_TELNET_GATEWAY_NEGOTIATE: bool = false;
/// Default for the outgoing Telnet Gateway's protocol-layer override.
/// Off by default (smart mode) so the gateway parses telnet IAC in both
/// directions.  When true, the gateway treats the remote as a raw TCP
/// byte stream — no IAC escape on outbound, no IAC parse on inbound —
/// which is the last-resort escape hatch for destinations that clearly
/// aren't telnet at all.
const DEFAULT_TELNET_GATEWAY_RAW: bool = false;
const DEFAULT_ENABLE_CONSOLE: bool = true;
const DEFAULT_SECURITY_ENABLED: bool = false;
const DEFAULT_USERNAME: &str = "admin";
const DEFAULT_PASSWORD: &str = "changeme";
const DEFAULT_TRANSFER_DIR: &str = "transfer";
const DEFAULT_MAX_SESSIONS: usize = 50;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900; // 15 minutes
const DEFAULT_GROQ_API_KEY: &str = "";
const DEFAULT_BROWSER_HOMEPAGE: &str = "http://telnetbible.com";
const DEFAULT_WEATHER_ZIP: &str = "";
const DEFAULT_VERBOSE: bool = false;
const DEFAULT_SERIAL_ENABLED: bool = false;
const DEFAULT_SERIAL_PORT: &str = "";
const DEFAULT_SERIAL_BAUD: u32 = 9600;
const DEFAULT_SERIAL_DATABITS: u8 = 8;
const DEFAULT_SERIAL_PARITY: &str = "none";
const DEFAULT_SERIAL_STOPBITS: u8 = 1;
const DEFAULT_SERIAL_FLOWCONTROL: &str = "none";
const DEFAULT_XMODEM_NEGOTIATION_TIMEOUT: u64 = 45;
const DEFAULT_XMODEM_BLOCK_TIMEOUT: u64 = 20;
const DEFAULT_XMODEM_MAX_RETRIES: usize = 10;
/// How long the XMODEM/YMODEM receiver waits between successive
/// `C` / NAK pokes during the initial handshake.  Christensen's original
/// XMODEM.DOC and Forsberg's reference implementations use ~10 s; 7 s is
/// a compromise that starts quickly when the sender misses a poke but
/// avoids stockpiling extras in a slow-starting sender's input buffer.
const DEFAULT_XMODEM_NEGOTIATION_RETRY_INTERVAL: u64 = 7;
/// ZMODEM negotiation timeout: how long the sender/receiver keeps
/// retrying ZRQINIT / ZRINIT before giving up.  Analogous to the
/// XMODEM negotiation timeout but for ZMODEM's handshake frames.
const DEFAULT_ZMODEM_NEGOTIATION_TIMEOUT: u64 = 45;
/// ZMODEM per-frame read timeout in seconds.  Applied once a transfer
/// has started — bounds how long we wait for the next header after
/// sending a response frame.
const DEFAULT_ZMODEM_FRAME_TIMEOUT: u64 = 30;
/// ZMODEM max retries for ZRQINIT, ZRPOS, and ZDATA frames.
const DEFAULT_ZMODEM_MAX_RETRIES: u32 = 10;
/// Seconds between successive ZRINIT / ZRQINIT re-sends during the
/// ZMODEM negotiation handshake.  Analogous to the XMODEM family's
/// C-retry interval: long enough that a slow-starting peer doesn't
/// stockpile extras, short enough that a dropped poke doesn't stall
/// the session for long.  The per-session budget is still bounded by
/// `zmodem_negotiation_timeout`.
const DEFAULT_ZMODEM_NEGOTIATION_RETRY_INTERVAL: u64 = 5;
/// Kermit negotiation timeout: how long the sender/receiver keeps
/// retrying the Send-Init handshake before giving up.
const DEFAULT_KERMIT_NEGOTIATION_TIMEOUT: u64 = 45;
/// Kermit per-packet read timeout in seconds — bounds how long we
/// wait for the next response after sending a packet.
const DEFAULT_KERMIT_PACKET_TIMEOUT: u64 = 10;
/// Kermit max retries per packet (NAK / timeout retransmits).
const DEFAULT_KERMIT_MAX_RETRIES: u32 = 5;
/// Kermit advertised max packet length (10..=9024).  4096 strikes a
/// balance between throughput and re-transmit cost on a flaky line.
const DEFAULT_KERMIT_MAX_PACKET_LENGTH: u16 = 4096;
/// Kermit sliding-window size (1..=31).  1 is stop-and-wait; 4 is a
/// conservative streaming-friendly default.
const DEFAULT_KERMIT_WINDOW_SIZE: u8 = 4;
/// Kermit block-check type advertised: 1 = 6-bit checksum, 2 = 12-bit
/// checksum, 3 = CRC-16/KERMIT.  Default 3 (strongest).
const DEFAULT_KERMIT_BLOCK_CHECK_TYPE: u8 = 3;
const DEFAULT_KERMIT_LONG_PACKETS: bool = true;
const DEFAULT_KERMIT_SLIDING_WINDOWS: bool = true;
/// Streaming Kermit: peer skips ACKing each packet on reliable links
/// (TCP/SSH).  Default true; turn off only if your remote side bridges
/// into an unreliable serial line.
const DEFAULT_KERMIT_STREAMING: bool = true;
const DEFAULT_KERMIT_ATTRIBUTE_PACKETS: bool = true;
const DEFAULT_KERMIT_REPEAT_COMPRESSION: bool = true;
/// Kermit 8th-bit quoting policy: "auto" (only when peer asks),
/// "on" (always), "off" (never).
const DEFAULT_KERMIT_8BIT_QUOTE: &str = "auto";
/// Kermit per-session telnet IAC escape — separate from XMODEM's
/// `xmodem_iac` so an operator can run telnet ↔ raw-bytes Kermit
/// transfers independently of the XMODEM family setting.
const DEFAULT_KERMIT_IAC_ESCAPE: bool = false;
const DEFAULT_SERIAL_ECHO: bool = true;
const DEFAULT_SERIAL_VERBOSE: bool = true;
const DEFAULT_SERIAL_QUIET: bool = false;
/// Default S-register values (S0–S26), comma-separated for config storage.
/// S7 is 15 (not the Hayes 50) — gateway-friendly carrier wait.  S13–S24
/// are reserved-zero placeholders; S25 (DTR detect 50 ms) and S26 (RTS/CTS
/// delay 10 ms) match Hayes.  Older config files with only 13 values are
/// still accepted: missing indices fall back to defaults.
const DEFAULT_SERIAL_S_REGS: &str =
    "5,0,43,13,10,8,2,15,2,6,14,95,50,0,0,0,0,0,0,0,0,0,0,0,0,5,1";
/// ATX4 — emit the full extended result-code set (Hayes default).
const DEFAULT_SERIAL_X_CODE: u8 = 4;
/// AT&D0 — ignore DTR (gateway-friendly; Hayes default is &D2).
const DEFAULT_SERIAL_DTR_MODE: u8 = 0;
/// AT&K0 — no modem-level flow control (gateway-friendly; Hayes default is &K3).
/// Physical port flow control is still controlled by `serial_flowcontrol`.
const DEFAULT_SERIAL_FLOW_MODE: u8 = 0;
/// AT&C1 — DCD reflects carrier state (Hayes default).
const DEFAULT_SERIAL_DCD_MODE: u8 = 1;
const DEFAULT_SSH_ENABLED: bool = false;
const DEFAULT_SSH_PORT: u16 = 2222;
const DEFAULT_SSH_USERNAME: &str = "admin";
const DEFAULT_SSH_PASSWORD: &str = "changeme";
/// Default SSH-gateway authentication mode: "key" uses the gateway's
/// auto-generated Ed25519 client key; "password" prompts the operator
/// for a remote password on each connect.  Password is the default
/// because most remote SSH accounts accept passwords out of the box —
/// key mode requires the operator to first install the gateway's
/// public key on the remote's `~/.ssh/authorized_keys`.
const DEFAULT_SSH_GATEWAY_AUTH: &str = "password";

/// Runtime configuration loaded from `egateway.conf`.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Enable the telnet server. Set to false for SSH-only access.
    pub telnet_enabled: bool,
    pub telnet_port: u16,
    /// When true, the outgoing Telnet Gateway proactively offers
    /// `WILL TTYPE` / `WILL NAWS` at connect time and accepts
    /// `DO TTYPE` / `DO NAWS` requests from the remote.  ECHO cooperation
    /// is independent and always on.  Default false to preserve
    /// compatibility with raw-TCP services on port 23.
    pub telnet_gateway_negotiate: bool,
    /// When true, the Telnet Gateway disables its telnet-IAC layer
    /// entirely and treats the remote as raw TCP.  Intended for
    /// destinations that clearly aren't telnet (some legacy MUDs, custom
    /// BBS software).  Supersedes `telnet_gateway_negotiate` — when raw
    /// is on, there is no negotiation to do.
    pub telnet_gateway_raw: bool,
    /// Show the GUI configuration/console window on startup.
    pub enable_console: bool,
    pub security_enabled: bool,
    pub username: String,
    pub password: String,
    pub transfer_dir: String,
    pub max_sessions: usize,
    pub idle_timeout_secs: u64,
    /// Groq API key. If empty, AI chat is disabled.
    pub groq_api_key: String,
    /// Browser homepage URL. If empty, browser opens to a blank prompt.
    pub browser_homepage: String,
    /// Last-used weather zip code. If empty, user is prompted without a default.
    pub weather_zip: String,
    /// Enable verbose XMODEM protocol logging to stderr.
    pub verbose: bool,
    /// XMODEM negotiation timeout in seconds.  Shared with XMODEM-1K
    /// and YMODEM — they use the same protocol code path.
    pub xmodem_negotiation_timeout: u64,
    /// XMODEM per-block timeout in seconds.  Shared with XMODEM-1K
    /// and YMODEM.
    pub xmodem_block_timeout: u64,
    /// XMODEM maximum retries per block.  Shared with XMODEM-1K and YMODEM.
    pub xmodem_max_retries: usize,
    /// Seconds between successive `C` / NAK pokes during the initial
    /// XMODEM/YMODEM negotiation handshake.  Shared with XMODEM-1K and
    /// YMODEM.  Kept short enough to recover quickly on lost pokes,
    /// long enough that a slow-starting sender doesn't stockpile extras.
    pub xmodem_negotiation_retry_interval: u64,
    /// ZMODEM negotiation timeout in seconds.
    pub zmodem_negotiation_timeout: u64,
    /// ZMODEM per-frame read timeout in seconds.
    pub zmodem_frame_timeout: u64,
    /// ZMODEM max retries for ZRQINIT / ZRPOS / ZDATA frames.
    pub zmodem_max_retries: u32,
    /// Seconds between ZRINIT / ZRQINIT re-sends during the ZMODEM
    /// negotiation handshake.  Analogous to
    /// `xmodem_negotiation_retry_interval` for the XMODEM family.
    pub zmodem_negotiation_retry_interval: u64,
    /// Kermit negotiation timeout (Send-Init handshake) in seconds.
    pub kermit_negotiation_timeout: u64,
    /// Kermit per-packet read timeout in seconds.
    pub kermit_packet_timeout: u64,
    /// Kermit max retries per packet.
    pub kermit_max_retries: u32,
    /// Advertised max packet length in our Send-Init (10..=9024).
    pub kermit_max_packet_length: u16,
    /// Sliding window size advertised (1..=31).  1 = stop-and-wait.
    pub kermit_window_size: u8,
    /// Block-check type advertised (1=6-bit, 2=12-bit, 3=CRC-16/KERMIT).
    pub kermit_block_check_type: u8,
    /// Advertise long-packets capability.
    pub kermit_long_packets: bool,
    /// Advertise sliding-window capability.
    pub kermit_sliding_windows: bool,
    /// Advertise streaming capability.  Auto-degrades to sliding/stop-
    /// and-wait if the peer doesn't advertise it.
    pub kermit_streaming: bool,
    /// Advertise attribute-packet (A) support.
    pub kermit_attribute_packets: bool,
    /// Use repeat-count compression.
    pub kermit_repeat_compression: bool,
    /// 8th-bit quoting policy: "auto" / "on" / "off".
    pub kermit_8bit_quote: String,
    /// Telnet IAC escape during Kermit transfers.
    pub kermit_iac_escape: bool,
    /// Enable serial modem emulation.
    pub serial_enabled: bool,
    /// Serial port device (e.g. /dev/ttyUSB0, COM3). Empty = not configured.
    pub serial_port: String,
    /// Serial baud rate.
    pub serial_baud: u32,
    /// Serial data bits (5, 6, 7, or 8).
    pub serial_databits: u8,
    /// Serial parity: "none", "odd", or "even".
    pub serial_parity: String,
    /// Serial stop bits (1 or 2).
    pub serial_stopbits: u8,
    /// Serial flow control: "none", "hardware", or "software".
    pub serial_flowcontrol: String,
    /// Saved modem echo setting (AT&W persists, ATZ restores).
    pub serial_echo: bool,
    /// Saved modem verbose/numeric mode (AT&W persists, ATZ restores).
    pub serial_verbose: bool,
    /// Saved modem quiet mode (AT&W persists, ATZ restores).
    pub serial_quiet: bool,
    /// Saved S-register values as comma-separated decimal (AT&W persists, ATZ restores).
    pub serial_s_regs: String,
    /// Saved ATX result-code level (0-4). AT&W persists, ATZ restores.
    pub serial_x_code: u8,
    /// Saved AT&D DTR-handling mode (0-3). AT&W persists, ATZ restores.
    pub serial_dtr_mode: u8,
    /// Saved AT&K flow-control mode (0-4). AT&W persists, ATZ restores.
    pub serial_flow_mode: u8,
    /// Saved AT&C DCD mode (0-1). AT&W persists, ATZ restores.
    pub serial_dcd_mode: u8,
    /// Stored phone-number slots (AT&Zn=s sets, ATDSn dials).  Four slots,
    /// persisted by AT&W and restored by ATZ.  Empty string = unset.
    pub serial_stored_numbers: [String; 4],
    /// Enable SSH server interface.
    pub ssh_enabled: bool,
    /// SSH server port.
    pub ssh_port: u16,
    /// SSH login username (independent of telnet credentials).
    pub ssh_username: String,
    /// SSH login password (independent of telnet credentials).
    pub ssh_password: String,
    /// Authentication mode used when the operator connects to a remote
    /// SSH server through the outbound SSH Gateway.  Accepted values:
    /// "key" (uses the gateway's auto-generated Ed25519 client key) or
    /// "password" (prompts for the remote password each time).
    pub ssh_gateway_auth: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            telnet_enabled: DEFAULT_TELNET_ENABLED,
            telnet_port: DEFAULT_TELNET_PORT,
            telnet_gateway_negotiate: DEFAULT_TELNET_GATEWAY_NEGOTIATE,
            telnet_gateway_raw: DEFAULT_TELNET_GATEWAY_RAW,
            enable_console: DEFAULT_ENABLE_CONSOLE,
            security_enabled: DEFAULT_SECURITY_ENABLED,
            username: DEFAULT_USERNAME.into(),
            password: DEFAULT_PASSWORD.into(),
            transfer_dir: DEFAULT_TRANSFER_DIR.into(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            groq_api_key: DEFAULT_GROQ_API_KEY.into(),
            browser_homepage: DEFAULT_BROWSER_HOMEPAGE.into(),
            weather_zip: DEFAULT_WEATHER_ZIP.into(),
            verbose: DEFAULT_VERBOSE,
            xmodem_negotiation_timeout: DEFAULT_XMODEM_NEGOTIATION_TIMEOUT,
            xmodem_block_timeout: DEFAULT_XMODEM_BLOCK_TIMEOUT,
            xmodem_max_retries: DEFAULT_XMODEM_MAX_RETRIES,
            xmodem_negotiation_retry_interval: DEFAULT_XMODEM_NEGOTIATION_RETRY_INTERVAL,
            zmodem_negotiation_timeout: DEFAULT_ZMODEM_NEGOTIATION_TIMEOUT,
            zmodem_frame_timeout: DEFAULT_ZMODEM_FRAME_TIMEOUT,
            zmodem_max_retries: DEFAULT_ZMODEM_MAX_RETRIES,
            zmodem_negotiation_retry_interval: DEFAULT_ZMODEM_NEGOTIATION_RETRY_INTERVAL,
            kermit_negotiation_timeout: DEFAULT_KERMIT_NEGOTIATION_TIMEOUT,
            kermit_packet_timeout: DEFAULT_KERMIT_PACKET_TIMEOUT,
            kermit_max_retries: DEFAULT_KERMIT_MAX_RETRIES,
            kermit_max_packet_length: DEFAULT_KERMIT_MAX_PACKET_LENGTH,
            kermit_window_size: DEFAULT_KERMIT_WINDOW_SIZE,
            kermit_block_check_type: DEFAULT_KERMIT_BLOCK_CHECK_TYPE,
            kermit_long_packets: DEFAULT_KERMIT_LONG_PACKETS,
            kermit_sliding_windows: DEFAULT_KERMIT_SLIDING_WINDOWS,
            kermit_streaming: DEFAULT_KERMIT_STREAMING,
            kermit_attribute_packets: DEFAULT_KERMIT_ATTRIBUTE_PACKETS,
            kermit_repeat_compression: DEFAULT_KERMIT_REPEAT_COMPRESSION,
            kermit_8bit_quote: DEFAULT_KERMIT_8BIT_QUOTE.into(),
            kermit_iac_escape: DEFAULT_KERMIT_IAC_ESCAPE,
            serial_enabled: DEFAULT_SERIAL_ENABLED,
            serial_port: DEFAULT_SERIAL_PORT.into(),
            serial_baud: DEFAULT_SERIAL_BAUD,
            serial_databits: DEFAULT_SERIAL_DATABITS,
            serial_parity: DEFAULT_SERIAL_PARITY.into(),
            serial_stopbits: DEFAULT_SERIAL_STOPBITS,
            serial_flowcontrol: DEFAULT_SERIAL_FLOWCONTROL.into(),
            serial_echo: DEFAULT_SERIAL_ECHO,
            serial_verbose: DEFAULT_SERIAL_VERBOSE,
            serial_quiet: DEFAULT_SERIAL_QUIET,
            serial_s_regs: DEFAULT_SERIAL_S_REGS.into(),
            serial_x_code: DEFAULT_SERIAL_X_CODE,
            serial_dtr_mode: DEFAULT_SERIAL_DTR_MODE,
            serial_flow_mode: DEFAULT_SERIAL_FLOW_MODE,
            serial_dcd_mode: DEFAULT_SERIAL_DCD_MODE,
            serial_stored_numbers: [
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ],
            ssh_enabled: DEFAULT_SSH_ENABLED,
            ssh_port: DEFAULT_SSH_PORT,
            ssh_username: DEFAULT_SSH_USERNAME.into(),
            ssh_password: DEFAULT_SSH_PASSWORD.into(),
            ssh_gateway_auth: DEFAULT_SSH_GATEWAY_AUTH.into(),
        }
    }
}

/// Global config singleton. Protected by a Mutex so it can be updated at
/// runtime (e.g. when `update_config_value` persists a changed setting).
static CONFIG: Mutex<Option<Config>> = Mutex::new(None);

/// Get a clone of the current configuration.
pub fn get_config() -> Config {
    let guard = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    guard.clone().unwrap_or_default()
}

/// Load (or create) the configuration file and store it in the global singleton.
pub fn load_or_create_config() -> Config {
    let cfg = if Path::new(CONFIG_FILE).exists() {
        let cfg = read_config_file(CONFIG_FILE);
        // Rewrite to ensure all keys are present
        write_config_file(CONFIG_FILE, &cfg);
        cfg
    } else {
        let cfg = Config::default();
        write_config_file(CONFIG_FILE, &cfg);
        glog!("Created default configuration: {}", CONFIG_FILE);
        cfg
    };

    let mut guard = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(cfg.clone());
    cfg
}

/// Parse a config file into a `Config`.
fn read_config_file(path: &str) -> Config {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            glog!("Warning: could not read {}: {}", path, e);
            return Config::default();
        }
    };

    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Config {
        telnet_enabled: map
            .get("telnet_enabled")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_TELNET_ENABLED),
        telnet_port: map
            .get("telnet_port")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u16| v >= 1)
            .unwrap_or(DEFAULT_TELNET_PORT),
        telnet_gateway_negotiate: map
            .get("telnet_gateway_negotiate")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_TELNET_GATEWAY_NEGOTIATE),
        telnet_gateway_raw: map
            .get("telnet_gateway_raw")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_TELNET_GATEWAY_RAW),
        enable_console: map
            .get("enable_console")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_ENABLE_CONSOLE),
        security_enabled: map
            .get("security_enabled")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_SECURITY_ENABLED),
        username: map
            .get("username")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_USERNAME.into()),
        password: map
            .get("password")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_PASSWORD.into()),
        transfer_dir: map
            .get("transfer_dir")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_TRANSFER_DIR.into()),
        max_sessions: map
            .get("max_sessions")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &usize| v >= 1)
            .unwrap_or(DEFAULT_MAX_SESSIONS),
        idle_timeout_secs: map
            .get("idle_timeout_secs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS),
        groq_api_key: map
            .get("groq_api_key")
            .cloned()
            .unwrap_or_else(|| DEFAULT_GROQ_API_KEY.into()),
        browser_homepage: map
            .get("browser_homepage")
            .cloned()
            .unwrap_or_else(|| DEFAULT_BROWSER_HOMEPAGE.into()),
        weather_zip: map
            .get("weather_zip")
            .cloned()
            .unwrap_or_else(|| DEFAULT_WEATHER_ZIP.into()),
        verbose: map
            .get("verbose")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_VERBOSE),
        xmodem_negotiation_timeout: map
            .get("xmodem_negotiation_timeout")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_XMODEM_NEGOTIATION_TIMEOUT),
        xmodem_block_timeout: map
            .get("xmodem_block_timeout")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_XMODEM_BLOCK_TIMEOUT),
        xmodem_max_retries: map
            .get("xmodem_max_retries")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &usize| v >= 1)
            .unwrap_or(DEFAULT_XMODEM_MAX_RETRIES),
        xmodem_negotiation_retry_interval: map
            .get("xmodem_negotiation_retry_interval")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_XMODEM_NEGOTIATION_RETRY_INTERVAL),
        zmodem_negotiation_timeout: map
            .get("zmodem_negotiation_timeout")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_ZMODEM_NEGOTIATION_TIMEOUT),
        zmodem_frame_timeout: map
            .get("zmodem_frame_timeout")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_ZMODEM_FRAME_TIMEOUT),
        zmodem_max_retries: map
            .get("zmodem_max_retries")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u32| v >= 1)
            .unwrap_or(DEFAULT_ZMODEM_MAX_RETRIES),
        zmodem_negotiation_retry_interval: map
            .get("zmodem_negotiation_retry_interval")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_ZMODEM_NEGOTIATION_RETRY_INTERVAL),
        kermit_negotiation_timeout: map
            .get("kermit_negotiation_timeout")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_KERMIT_NEGOTIATION_TIMEOUT),
        kermit_packet_timeout: map
            .get("kermit_packet_timeout")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u64| v >= 1)
            .unwrap_or(DEFAULT_KERMIT_PACKET_TIMEOUT),
        kermit_max_retries: map
            .get("kermit_max_retries")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u32| v >= 1)
            .unwrap_or(DEFAULT_KERMIT_MAX_RETRIES),
        kermit_max_packet_length: map
            .get("kermit_max_packet_length")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u16| (10..=9024).contains(&v))
            .unwrap_or(DEFAULT_KERMIT_MAX_PACKET_LENGTH),
        kermit_window_size: map
            .get("kermit_window_size")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u8| (1..=31).contains(&v))
            .unwrap_or(DEFAULT_KERMIT_WINDOW_SIZE),
        kermit_block_check_type: map
            .get("kermit_block_check_type")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u8| matches!(v, 1..=3))
            .unwrap_or(DEFAULT_KERMIT_BLOCK_CHECK_TYPE),
        kermit_long_packets: map
            .get("kermit_long_packets")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_KERMIT_LONG_PACKETS),
        kermit_sliding_windows: map
            .get("kermit_sliding_windows")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_KERMIT_SLIDING_WINDOWS),
        kermit_streaming: map
            .get("kermit_streaming")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_KERMIT_STREAMING),
        kermit_attribute_packets: map
            .get("kermit_attribute_packets")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_KERMIT_ATTRIBUTE_PACKETS),
        kermit_repeat_compression: map
            .get("kermit_repeat_compression")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_KERMIT_REPEAT_COMPRESSION),
        kermit_8bit_quote: map
            .get("kermit_8bit_quote")
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| matches!(v.as_str(), "auto" | "on" | "off"))
            .unwrap_or_else(|| DEFAULT_KERMIT_8BIT_QUOTE.into()),
        kermit_iac_escape: map
            .get("kermit_iac_escape")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_KERMIT_IAC_ESCAPE),
        serial_enabled: map
            .get("serial_enabled")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_SERIAL_ENABLED),
        serial_port: map
            .get("serial_port")
            .cloned()
            .unwrap_or_else(|| DEFAULT_SERIAL_PORT.into()),
        serial_baud: map
            .get("serial_baud")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u32| v >= 300)
            .unwrap_or(DEFAULT_SERIAL_BAUD),
        serial_databits: map
            .get("serial_databits")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u8| matches!(v, 5..=8))
            .unwrap_or(DEFAULT_SERIAL_DATABITS),
        serial_parity: map
            .get("serial_parity")
            .filter(|v| matches!(v.as_str(), "none" | "odd" | "even"))
            .cloned()
            .unwrap_or_else(|| DEFAULT_SERIAL_PARITY.into()),
        serial_stopbits: map
            .get("serial_stopbits")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u8| v == 1 || v == 2)
            .unwrap_or(DEFAULT_SERIAL_STOPBITS),
        serial_flowcontrol: map
            .get("serial_flowcontrol")
            .filter(|v| matches!(v.as_str(), "none" | "hardware" | "software"))
            .cloned()
            .unwrap_or_else(|| DEFAULT_SERIAL_FLOWCONTROL.into()),
        serial_echo: map
            .get("serial_echo")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_SERIAL_ECHO),
        serial_verbose: map
            .get("serial_verbose")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_SERIAL_VERBOSE),
        serial_quiet: map
            .get("serial_quiet")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_SERIAL_QUIET),
        serial_s_regs: map
            .get("serial_s_regs")
            .cloned()
            .unwrap_or_else(|| DEFAULT_SERIAL_S_REGS.into()),
        serial_x_code: map
            .get("serial_x_code")
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|&v| v <= 4)
            .unwrap_or(DEFAULT_SERIAL_X_CODE),
        serial_dtr_mode: map
            .get("serial_dtr_mode")
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|&v| v <= 3)
            .unwrap_or(DEFAULT_SERIAL_DTR_MODE),
        serial_flow_mode: map
            .get("serial_flow_mode")
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|&v| v <= 4)
            .unwrap_or(DEFAULT_SERIAL_FLOW_MODE),
        serial_dcd_mode: map
            .get("serial_dcd_mode")
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|&v| v <= 1)
            .unwrap_or(DEFAULT_SERIAL_DCD_MODE),
        serial_stored_numbers: [
            map.get("serial_stored_0").cloned().unwrap_or_default(),
            map.get("serial_stored_1").cloned().unwrap_or_default(),
            map.get("serial_stored_2").cloned().unwrap_or_default(),
            map.get("serial_stored_3").cloned().unwrap_or_default(),
        ],
        ssh_enabled: map
            .get("ssh_enabled")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_SSH_ENABLED),
        ssh_port: map
            .get("ssh_port")
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u16| v >= 1)
            .unwrap_or(DEFAULT_SSH_PORT),
        ssh_username: map
            .get("ssh_username")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_SSH_USERNAME.into()),
        ssh_password: map
            .get("ssh_password")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_SSH_PASSWORD.into()),
        ssh_gateway_auth: map
            .get("ssh_gateway_auth")
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| matches!(v.as_str(), "key" | "password"))
            .unwrap_or_else(|| DEFAULT_SSH_GATEWAY_AUTH.into()),
    }
}

/// Sanitize a config value by stripping newlines and carriage returns.
fn sanitize_value(s: &str) -> String {
    s.chars().filter(|&c| c != '\n' && c != '\r').collect()
}

/// Save a full `Config` to disk and update the global singleton.
/// Used by the GUI save button.
///
/// Holds the `CONFIG` mutex across the write so that a concurrent
/// `update_config_values` (from a session-side toggle, e.g. the Telnet
/// Gateway's raw-mode toggle) can't race and clobber our write with its
/// own re-read-then-write.
pub fn save_config(cfg: &Config) {
    let mut guard = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    write_config_file(CONFIG_FILE, cfg);
    *guard = Some(cfg.clone());
}

/// Write the config file with comments.
fn write_config_file(path: &str, cfg: &Config) {
    let content = format!(
        "\
# Ethernet Gateway Configuration
#
# This file is auto-generated if it does not exist.
# Edit values below to customise the server.

# Telnet server: set to false to disable (SSH-only mode)
telnet_enabled = {}

# Telnet server port
telnet_port = {}

# Outgoing Telnet Gateway cooperative negotiation.
# When true, the gateway offers WILL TTYPE / WILL NAWS at connect and
# accepts DO TTYPE / DO NAWS requests from the remote server.  Leave this
# false if you dial raw-TCP services (legacy MUDs, hand-rolled BBSes that
# don't implement the telnet protocol) — those would see the IAC offers
# as garbage bytes.  ECHO cooperation is always on regardless of this
# setting (raw-TCP services never send WILL ECHO).
telnet_gateway_negotiate = {}

# Outgoing Telnet Gateway raw-TCP escape hatch.
# When true, the gateway bypasses its entire telnet-IAC layer and treats
# the remote as a raw TCP byte stream.  Last-resort override for
# destinations that clearly aren't telnet at all.  Supersedes
# telnet_gateway_negotiate (there's nothing to negotiate in raw mode).
# Toggleable from the Telnet Gateway menu.
telnet_gateway_raw = {}

# Show the GUI configuration/console window on startup.
# Set to false when running as a headless service.
enable_console = {}

# Security: set to true to require username/password login
security_enabled = {}

# Credentials (only used when security_enabled = true)
username = {}
password = {}

# Directory for file transfers (relative to working directory)
transfer_dir = {}

# Maximum concurrent telnet sessions
max_sessions = {}

# Idle session timeout in seconds (0 = no timeout)
idle_timeout_secs = {}

# Groq API key for AI Chat (get one at https://console.groq.com/keys)
# Leave empty to disable AI Chat.
groq_api_key = {}

# Browser homepage URL (loaded automatically when entering the browser)
# Leave empty to start with a blank prompt.
browser_homepage = {}

# Last-used weather zip code (updated automatically when you check weather)
weather_zip = {}

# Verbose logging: set to true for detailed XMODEM protocol diagnostics
verbose = {}

# XMODEM-family protocol timeouts (apply to XMODEM, XMODEM-1K, and YMODEM).
# xmodem_negotiation_timeout:      seconds to wait for the peer to start sending.
# xmodem_block_timeout:            seconds to wait for each data block.
# xmodem_max_retries:              retry limit per block.
# xmodem_negotiation_retry_interval: seconds between C/NAK pokes during
#                                    the initial handshake (spec suggests 10 s,
#                                    default 7 s).
xmodem_negotiation_timeout = {}
xmodem_block_timeout = {}
xmodem_max_retries = {}
xmodem_negotiation_retry_interval = {}

# ZMODEM protocol tunables.
# zmodem_negotiation_timeout:       seconds to wait for ZRQINIT / ZRINIT handshake.
# zmodem_frame_timeout:             seconds to wait for each header / subpacket.
# zmodem_max_retries:               retry limit for ZRQINIT / ZRPOS / ZDATA frames.
# zmodem_negotiation_retry_interval: seconds between ZRINIT / ZRQINIT re-sends
#                                    during the handshake (default 5 s).
zmodem_negotiation_timeout = {}
zmodem_frame_timeout = {}
zmodem_max_retries = {}
zmodem_negotiation_retry_interval = {}

# Kermit protocol tunables.
# kermit_negotiation_timeout:  seconds to wait for the Send-Init handshake.
# kermit_packet_timeout:       seconds to wait for each packet response.
# kermit_max_retries:          retry limit per packet on NAK / timeout.
# kermit_max_packet_length:    advertised MAXL (10..=9024).  Long packets are
#                              negotiated separately; values >94 require the
#                              peer to also support extended-length packets.
# kermit_window_size:          sliding-window depth (1..=31).  1 = stop-and-wait.
# kermit_block_check_type:     1 = 6-bit checksum, 2 = 12-bit, 3 = CRC-16/KERMIT.
# kermit_long_packets:         advertise long-packet capability.
# kermit_sliding_windows:      advertise sliding-window capability.
# kermit_streaming:            advertise streaming-Kermit (no per-packet ACKs).
#                              Big speed win on TCP/SSH; turn this off only if
#                              your remote side bridges into an unreliable
#                              serial line (some WiFi modems do this).
# kermit_attribute_packets:    advertise A-packet (file metadata) support.
# kermit_repeat_compression:   use repeat-count compression (RLE).
# kermit_8bit_quote:           auto (only when peer asks), on, or off.
# kermit_iac_escape:           apply telnet IAC escaping during transfers.
kermit_negotiation_timeout = {}
kermit_packet_timeout = {}
kermit_max_retries = {}
kermit_max_packet_length = {}
kermit_window_size = {}
kermit_block_check_type = {}
kermit_long_packets = {}
kermit_sliding_windows = {}
kermit_streaming = {}
kermit_attribute_packets = {}
kermit_repeat_compression = {}
kermit_8bit_quote = {}
kermit_iac_escape = {}

# Serial modem emulation (Hayes AT commands)
# Set serial_enabled = true and configure the port to activate.
serial_enabled = {}

# Serial port device (e.g. /dev/ttyUSB0 on Linux, COM3 on Windows)
# Leave empty if not configured. Use the Modem Emulator menu to detect ports.
serial_port = {}

# Serial port parameters
serial_baud = {}
serial_databits = {}
serial_parity = {}
serial_stopbits = {}
serial_flowcontrol = {}

# Saved modem settings (written by AT&W, restored by ATZ)
serial_echo = {}
serial_verbose = {}
serial_quiet = {}
serial_s_regs = {}

# Hayes extended command state (written by AT&W, restored by ATZ)
# serial_x_code:    ATX level 0-4 (4 = all extended result codes, Hayes default)
# serial_dtr_mode:  AT&D 0-3 (0 = ignore DTR, gateway-friendly default)
# serial_flow_mode: AT&K 0-4 (0 = no flow control at modem layer,
#                   gateway-friendly default; physical port flow control
#                   is still controlled by serial_flowcontrol above)
# serial_dcd_mode:  AT&C 0-1 (1 = DCD reflects carrier, Hayes default)
serial_x_code = {}
serial_dtr_mode = {}
serial_flow_mode = {}
serial_dcd_mode = {}

# Hayes stored phone-number slots (AT&Zn=s sets, ATDSn dials).  Empty = unset.
serial_stored_0 = {}
serial_stored_1 = {}
serial_stored_2 = {}
serial_stored_3 = {}

# SSH server interface (encrypted access to the gateway)
# Set ssh_enabled = true to activate. Uses its own credentials.
ssh_enabled = {}

# SSH server port
ssh_port = {}

# SSH credentials (independent of telnet credentials)
ssh_username = {}
ssh_password = {}

# Authentication mode for the OUTBOUND SSH Gateway (the menu item that
# proxies to a remote SSH server).  Values:
#   key      — use the gateway's built-in Ed25519 client key.  Copy the
#              public half (shown in the GUI Server > More popup, or
#              extract with `ssh-keygen -y -f ethernet_gateway_ssh_key`)
#              into the remote's ~/.ssh/authorized_keys first.
#   password — prompt the operator for the remote account's password on
#              each connect.  No key is offered.
ssh_gateway_auth = {}
",
        cfg.telnet_enabled,
        cfg.telnet_port,
        cfg.telnet_gateway_negotiate,
        cfg.telnet_gateway_raw,
        cfg.enable_console,
        cfg.security_enabled,
        sanitize_value(&cfg.username),
        sanitize_value(&cfg.password),
        sanitize_value(&cfg.transfer_dir),
        cfg.max_sessions,
        cfg.idle_timeout_secs,
        sanitize_value(&cfg.groq_api_key),
        sanitize_value(&cfg.browser_homepage),
        sanitize_value(&cfg.weather_zip),
        cfg.verbose,
        cfg.xmodem_negotiation_timeout,
        cfg.xmodem_block_timeout,
        cfg.xmodem_max_retries,
        cfg.xmodem_negotiation_retry_interval,
        cfg.zmodem_negotiation_timeout,
        cfg.zmodem_frame_timeout,
        cfg.zmodem_max_retries,
        cfg.zmodem_negotiation_retry_interval,
        cfg.kermit_negotiation_timeout,
        cfg.kermit_packet_timeout,
        cfg.kermit_max_retries,
        cfg.kermit_max_packet_length,
        cfg.kermit_window_size,
        cfg.kermit_block_check_type,
        cfg.kermit_long_packets,
        cfg.kermit_sliding_windows,
        cfg.kermit_streaming,
        cfg.kermit_attribute_packets,
        cfg.kermit_repeat_compression,
        sanitize_value(&cfg.kermit_8bit_quote),
        cfg.kermit_iac_escape,
        cfg.serial_enabled,
        sanitize_value(&cfg.serial_port),
        cfg.serial_baud,
        cfg.serial_databits,
        sanitize_value(&cfg.serial_parity),
        cfg.serial_stopbits,
        sanitize_value(&cfg.serial_flowcontrol),
        cfg.serial_echo,
        cfg.serial_verbose,
        cfg.serial_quiet,
        sanitize_value(&cfg.serial_s_regs),
        cfg.serial_x_code,
        cfg.serial_dtr_mode,
        cfg.serial_flow_mode,
        cfg.serial_dcd_mode,
        sanitize_value(&cfg.serial_stored_numbers[0]),
        sanitize_value(&cfg.serial_stored_numbers[1]),
        sanitize_value(&cfg.serial_stored_numbers[2]),
        sanitize_value(&cfg.serial_stored_numbers[3]),
        cfg.ssh_enabled,
        cfg.ssh_port,
        sanitize_value(&cfg.ssh_username),
        sanitize_value(&cfg.ssh_password),
        sanitize_value(&cfg.ssh_gateway_auth),
    );

    // Write to a per-PID temporary file, chmod it to owner-only, then
    // rename into place.  The PID suffix avoids clobbering another
    // instance's tmp file in the same working directory and closes a
    // small TOCTOU window against symlink tricks on a shared path.
    // Setting the mode *before* the rename means the file is never
    // visible at its final path with default-umask permissions — the
    // config holds plaintext credentials (telnet password, SSH
    // password, Groq API key).  Windows users on multi-user systems
    // should place the binary in a per-user folder to get equivalent
    // NTFS ACL protection.
    let tmp = format!("{}.{}.tmp", path, std::process::id());
    let write_result = std::fs::write(&tmp, &content).and_then(|()| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &tmp,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        std::fs::rename(&tmp, path)
    });
    if let Err(e) = write_result {
        glog!("Warning: could not write {}: {}", path, e);
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Update a single key in the config file and the in-memory singleton.
/// Reads the current file, updates the key, writes it back, and refreshes
/// the global config so that subsequent `get_config()` calls see the change.
pub fn update_config_value(key: &str, value: &str) {
    update_config_values(&[(key, value)]);
}

/// Update multiple keys in a single read-modify-write cycle.
/// Holds the global CONFIG lock for the entire operation to prevent
/// concurrent callers from overwriting each other's changes.
pub fn update_config_values(pairs: &[(&str, &str)]) {
    let mut guard = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = if Path::new(CONFIG_FILE).exists() {
        read_config_file(CONFIG_FILE)
    } else {
        Config::default()
    };
    for &(key, value) in pairs {
        apply_config_key(&mut cfg, key, value);
    }
    write_config_file(CONFIG_FILE, &cfg);
    *guard = Some(cfg);
}

/// Apply a single key-value pair to a Config struct.
fn apply_config_key(cfg: &mut Config, key: &str, value: &str) {
    match key {
        "telnet_enabled" => cfg.telnet_enabled = value.eq_ignore_ascii_case("true"),
        "telnet_port" => {
            if let Ok(v) = value.parse::<u16>() && v >= 1 {
                cfg.telnet_port = v;
            }
        }
        "telnet_gateway_negotiate" => {
            cfg.telnet_gateway_negotiate = value.eq_ignore_ascii_case("true");
        }
        "telnet_gateway_raw" => {
            cfg.telnet_gateway_raw = value.eq_ignore_ascii_case("true");
        }
        "enable_console" => cfg.enable_console = value.eq_ignore_ascii_case("true"),
        "security_enabled" => cfg.security_enabled = value.eq_ignore_ascii_case("true"),
        "username" => cfg.username = value.to_string(),
        "password" => cfg.password = value.to_string(),
        "transfer_dir" => cfg.transfer_dir = value.to_string(),
        "max_sessions" => {
            if let Ok(v) = value.parse::<usize>() && v >= 1 {
                cfg.max_sessions = v;
            }
        }
        "idle_timeout_secs" => {
            if let Ok(v) = value.parse() {
                cfg.idle_timeout_secs = v;
            }
        }
        "groq_api_key" => cfg.groq_api_key = value.to_string(),
        "browser_homepage" => cfg.browser_homepage = value.to_string(),
        "weather_zip" => cfg.weather_zip = value.to_string(),
        "verbose" => cfg.verbose = value.eq_ignore_ascii_case("true"),
        "xmodem_negotiation_timeout" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.xmodem_negotiation_timeout = v;
            }
        }
        "xmodem_block_timeout" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.xmodem_block_timeout = v;
            }
        }
        "xmodem_max_retries" => {
            if let Ok(v) = value.parse::<usize>() && v >= 1 {
                cfg.xmodem_max_retries = v;
            }
        }
        "xmodem_negotiation_retry_interval" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.xmodem_negotiation_retry_interval = v;
            }
        }
        "zmodem_negotiation_timeout" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.zmodem_negotiation_timeout = v;
            }
        }
        "zmodem_frame_timeout" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.zmodem_frame_timeout = v;
            }
        }
        "zmodem_max_retries" => {
            if let Ok(v) = value.parse::<u32>() && v >= 1 {
                cfg.zmodem_max_retries = v;
            }
        }
        "zmodem_negotiation_retry_interval" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.zmodem_negotiation_retry_interval = v;
            }
        }
        "kermit_negotiation_timeout" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.kermit_negotiation_timeout = v;
            }
        }
        "kermit_packet_timeout" => {
            if let Ok(v) = value.parse::<u64>() && v >= 1 {
                cfg.kermit_packet_timeout = v;
            }
        }
        "kermit_max_retries" => {
            if let Ok(v) = value.parse::<u32>() && v >= 1 {
                cfg.kermit_max_retries = v;
            }
        }
        "kermit_max_packet_length" => {
            if let Ok(v) = value.parse::<u16>() && (10..=9024).contains(&v) {
                cfg.kermit_max_packet_length = v;
            }
        }
        "kermit_window_size" => {
            if let Ok(v) = value.parse::<u8>() && (1..=31).contains(&v) {
                cfg.kermit_window_size = v;
            }
        }
        "kermit_block_check_type" => {
            if let Ok(v) = value.parse::<u8>() && matches!(v, 1..=3) {
                cfg.kermit_block_check_type = v;
            }
        }
        "kermit_long_packets" => {
            cfg.kermit_long_packets = value.eq_ignore_ascii_case("true");
        }
        "kermit_sliding_windows" => {
            cfg.kermit_sliding_windows = value.eq_ignore_ascii_case("true");
        }
        "kermit_streaming" => {
            cfg.kermit_streaming = value.eq_ignore_ascii_case("true");
        }
        "kermit_attribute_packets" => {
            cfg.kermit_attribute_packets = value.eq_ignore_ascii_case("true");
        }
        "kermit_repeat_compression" => {
            cfg.kermit_repeat_compression = value.eq_ignore_ascii_case("true");
        }
        "kermit_8bit_quote" => {
            let lower = value.trim().to_ascii_lowercase();
            if matches!(lower.as_str(), "auto" | "on" | "off") {
                cfg.kermit_8bit_quote = lower;
            }
        }
        "kermit_iac_escape" => {
            cfg.kermit_iac_escape = value.eq_ignore_ascii_case("true");
        }
        "serial_enabled" => cfg.serial_enabled = value.eq_ignore_ascii_case("true"),
        "serial_port" => cfg.serial_port = value.to_string(),
        "serial_baud" => {
            if let Ok(v) = value.parse::<u32>() && v >= 300 {
                cfg.serial_baud = v;
            }
        }
        "serial_databits" => {
            if let Ok(v) = value.parse::<u8>() && matches!(v, 5..=8) {
                cfg.serial_databits = v;
            }
        }
        "serial_parity" => {
            if matches!(value, "none" | "odd" | "even") {
                cfg.serial_parity = value.to_string();
            }
        }
        "serial_stopbits" => {
            if let Ok(v) = value.parse::<u8>() && (v == 1 || v == 2) {
                cfg.serial_stopbits = v;
            }
        }
        "serial_flowcontrol" => {
            if matches!(value, "none" | "hardware" | "software") {
                cfg.serial_flowcontrol = value.to_string();
            }
        }
        "serial_echo" => cfg.serial_echo = value.eq_ignore_ascii_case("true"),
        "serial_verbose" => cfg.serial_verbose = value.eq_ignore_ascii_case("true"),
        "serial_quiet" => cfg.serial_quiet = value.eq_ignore_ascii_case("true"),
        "serial_s_regs" => cfg.serial_s_regs = value.to_string(),
        "serial_x_code" => {
            if let Ok(v) = value.parse::<u8>() && v <= 4 {
                cfg.serial_x_code = v;
            }
        }
        "serial_dtr_mode" => {
            if let Ok(v) = value.parse::<u8>() && v <= 3 {
                cfg.serial_dtr_mode = v;
            }
        }
        "serial_flow_mode" => {
            if let Ok(v) = value.parse::<u8>() && v <= 4 {
                cfg.serial_flow_mode = v;
            }
        }
        "serial_dcd_mode" => {
            if let Ok(v) = value.parse::<u8>() && v <= 1 {
                cfg.serial_dcd_mode = v;
            }
        }
        "serial_stored_0" => cfg.serial_stored_numbers[0] = value.to_string(),
        "serial_stored_1" => cfg.serial_stored_numbers[1] = value.to_string(),
        "serial_stored_2" => cfg.serial_stored_numbers[2] = value.to_string(),
        "serial_stored_3" => cfg.serial_stored_numbers[3] = value.to_string(),
        "ssh_enabled" => cfg.ssh_enabled = value.eq_ignore_ascii_case("true"),
        "ssh_port" => {
            if let Ok(v) = value.parse::<u16>() && v >= 1 {
                cfg.ssh_port = v;
            }
        }
        "ssh_username" => cfg.ssh_username = value.to_string(),
        "ssh_password" => cfg.ssh_password = value.to_string(),
        "ssh_gateway_auth" => {
            let lower = value.trim().to_ascii_lowercase();
            if matches!(lower.as_str(), "key" | "password") {
                cfg.ssh_gateway_auth = lower;
            }
        }
        _ => {}
    }
}

// ─── Dialup mapping (dialup.conf) ─────────────────────────

/// Name of the dialup mapping file (lives next to the binary).
pub const DIALUP_FILE: &str = "dialup.conf";

/// A single dialup mapping: phone number → host:port.
#[derive(Debug, Clone, PartialEq)]
pub struct DialupEntry {
    pub number: String,
    pub host: String,
    pub port: u16,
}

/// Load all dialup mappings from `dialup.conf`.
/// If the file does not exist, creates it with a default starter entry.
pub fn load_dialup_mappings() -> Vec<DialupEntry> {
    if !Path::new(DIALUP_FILE).exists() {
        let defaults = vec![DialupEntry {
            number: "1234567".into(),
            host: "telnetbible.com".into(),
            port: 6400,
        }];
        save_dialup_mappings(&defaults);
        glog!("Created default dialup mapping: {}", DIALUP_FILE);
        return defaults;
    }
    let content = match std::fs::read_to_string(DIALUP_FILE) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_dialup_mappings(&content)
}

/// Parse dialup mappings from file content.
fn parse_dialup_mappings(content: &str) -> Vec<DialupEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((number, target)) = trimmed.split_once('=') {
            let number = number.trim().to_string();
            let target = target.trim();
            if number.is_empty() || target.is_empty() {
                continue;
            }
            let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
                match p.parse::<u16>() {
                    Ok(port) if port > 0 => (h.to_string(), port),
                    _ => (target.to_string(), 23),
                }
            } else {
                (target.to_string(), 23)
            };
            entries.push(DialupEntry { number, host, port });
        }
    }
    entries
}

/// Save all dialup mappings to `dialup.conf`.
pub fn save_dialup_mappings(entries: &[DialupEntry]) {
    let mut content = String::from(
        "# Dialup Mapping\n\
         #\n\
         # Map phone numbers to host:port targets.\n\
         # Format: number = host:port\n\
         #\n\
         # Example:\n\
         # 5551234 = bbs.example.com:23\n\
         \n",
    );
    for entry in entries {
        content.push_str(&format!("{} = {}:{}\n", entry.number, entry.host, entry.port));
    }
    let tmp = format!("{}.{}.tmp", DIALUP_FILE, std::process::id());
    if let Err(e) = std::fs::write(&tmp, &content).and_then(|()| std::fs::rename(&tmp, DIALUP_FILE)) {
        glog!("Warning: could not write {}: {}", DIALUP_FILE, e);
        let _ = std::fs::remove_file(&tmp);
    } else {
        // Restrict to owner-only on Unix — the mapping file reveals
        // the host/port pairs the operator has configured, which is a
        // meaningful privacy signal other local users shouldn't have.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                DIALUP_FILE,
                std::fs::Permissions::from_mode(0o600),
            );
        }
    }
}

/// Normalize a phone number to digits only for comparison.
/// e.g. "(555) 123-4567" → "5551234567"
pub fn normalize_phone_number(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Look up a phone number in the dialup mappings.
/// Returns the host:port string if found, or None.
pub fn lookup_dialup_number(number: &str) -> Option<String> {
    let normalized = normalize_phone_number(number);
    if normalized.is_empty() {
        return None;
    }
    let entries = load_dialup_mappings();
    for entry in &entries {
        if normalize_phone_number(&entry.number) == normalized {
            return Some(format!("{}:{}", entry.host, entry.port));
        }
    }
    None
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert!(cfg.telnet_enabled);
        assert_eq!(cfg.telnet_port, 2323);
        assert!(!cfg.telnet_gateway_negotiate);
        assert!(!cfg.telnet_gateway_raw);
        assert!(cfg.enable_console);
        assert!(!cfg.security_enabled);
        assert_eq!(cfg.username, "admin");
        assert_eq!(cfg.password, "changeme");
        assert_eq!(cfg.transfer_dir, "transfer");
        assert_eq!(cfg.max_sessions, 50);
        assert_eq!(cfg.idle_timeout_secs, 900);
        assert_eq!(cfg.groq_api_key, "");
        assert_eq!(cfg.browser_homepage, "http://telnetbible.com");
        assert_eq!(cfg.weather_zip, "");
        assert!(!cfg.verbose);
        assert_eq!(cfg.xmodem_negotiation_timeout, 45);
        assert_eq!(cfg.xmodem_block_timeout, 20);
        assert_eq!(cfg.xmodem_max_retries, 10);
        assert_eq!(cfg.xmodem_negotiation_retry_interval, 7);
        assert_eq!(cfg.zmodem_negotiation_timeout, 45);
        assert_eq!(cfg.zmodem_frame_timeout, 30);
        assert_eq!(cfg.zmodem_max_retries, 10);
        assert_eq!(cfg.zmodem_negotiation_retry_interval, 5);
        assert_eq!(cfg.kermit_negotiation_timeout, 45);
        assert_eq!(cfg.kermit_packet_timeout, 10);
        assert_eq!(cfg.kermit_max_retries, 5);
        assert_eq!(cfg.kermit_max_packet_length, 4096);
        assert_eq!(cfg.kermit_window_size, 4);
        assert_eq!(cfg.kermit_block_check_type, 3);
        assert!(cfg.kermit_long_packets);
        assert!(cfg.kermit_sliding_windows);
        assert!(cfg.kermit_streaming);
        assert!(cfg.kermit_attribute_packets);
        assert!(cfg.kermit_repeat_compression);
        assert_eq!(cfg.kermit_8bit_quote, "auto");
        assert!(!cfg.kermit_iac_escape);
        assert!(!cfg.serial_enabled);
        assert_eq!(cfg.serial_port, "");
        assert_eq!(cfg.serial_baud, 9600);
        assert_eq!(cfg.serial_databits, 8);
        assert_eq!(cfg.serial_parity, "none");
        assert_eq!(cfg.serial_stopbits, 1);
        assert_eq!(cfg.serial_flowcontrol, "none");
        assert!(cfg.serial_echo);
        assert!(cfg.serial_verbose);
        assert!(!cfg.serial_quiet);
        assert_eq!(
            cfg.serial_s_regs,
            "5,0,43,13,10,8,2,15,2,6,14,95,50,0,0,0,0,0,0,0,0,0,0,0,0,5,1"
        );
        assert_eq!(cfg.serial_x_code, 4);
        assert_eq!(cfg.serial_dtr_mode, 0);
        assert_eq!(cfg.serial_flow_mode, 0);
        assert_eq!(cfg.serial_dcd_mode, 1);
        assert_eq!(cfg.serial_stored_numbers, [
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]);
        assert!(!cfg.ssh_enabled);
        assert_eq!(cfg.ssh_port, 2222);
        assert_eq!(cfg.ssh_username, "admin");
        assert_eq!(cfg.ssh_password, "changeme");
    }

    #[test]
    fn test_read_config_file() {
        let dir = std::env::temp_dir().join("xmodem_test_read_cfg");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# comment line").unwrap();
        writeln!(f, "telnet_port = 9999").unwrap();
        writeln!(f, "security_enabled = true").unwrap();
        writeln!(f, "username = myuser").unwrap();
        writeln!(f, "password = mypass").unwrap();
        writeln!(f, "transfer_dir = files").unwrap();
        writeln!(f, "max_sessions = 10").unwrap();
        writeln!(f, "idle_timeout_secs = 300").unwrap();
        writeln!(f, "unknown_key = ignored").unwrap();
        drop(f);

        let cfg = read_config_file(path.to_str().unwrap());
        assert_eq!(cfg.telnet_port, 9999);
        assert!(cfg.security_enabled);
        assert_eq!(cfg.username, "myuser");
        assert_eq!(cfg.password, "mypass");
        assert_eq!(cfg.transfer_dir, "files");
        assert_eq!(cfg.max_sessions, 10);
        assert_eq!(cfg.idle_timeout_secs, 300);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_config_missing_keys_use_defaults() {
        let dir = std::env::temp_dir().join("xmodem_test_missing_keys");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("partial.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "telnet_port = 4444").unwrap();
        drop(f);

        let cfg = read_config_file(path.to_str().unwrap());
        assert_eq!(cfg.telnet_port, 4444);
        assert!(!cfg.security_enabled);
        assert_eq!(cfg.username, "admin");
        assert_eq!(cfg.transfer_dir, "transfer");
        // SSH fields should also get defaults when missing from file
        assert!(!cfg.ssh_enabled);
        assert_eq!(cfg.ssh_port, 2222);
        assert_eq!(cfg.ssh_username, "admin");
        assert_eq!(cfg.ssh_password, "changeme");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_config_invalid_port_uses_default() {
        let dir = std::env::temp_dir().join("xmodem_test_bad_port");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "telnet_port = notanumber").unwrap();
        drop(f);

        let cfg = read_config_file(path.to_str().unwrap());
        assert_eq!(cfg.telnet_port, DEFAULT_TELNET_PORT);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test 7: a config file with malformed content — lines without
    /// `=`, garbage tokens, junk values — must not panic.  Every key
    /// should fall back to its default.
    #[test]
    fn test_read_config_malformed_file_falls_back_to_defaults() {
        let dir = std::env::temp_dir().join("xmodem_test_malformed");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("garbage.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        // A mix of malformed constructs a hostile or buggy editor
        // might leave behind.
        writeln!(f, "this line has no equals sign").unwrap();
        writeln!(f, "= value_with_no_key").unwrap();
        writeln!(f, "telnet_port = ").unwrap();           // empty value
        writeln!(f, "telnet_port = -99999999999").unwrap(); // overflow
        writeln!(f, "max_sessions = banana").unwrap();
        writeln!(f, "security_enabled = maybe").unwrap();
        writeln!(f, "serial_baud = 0").unwrap();            // below min
        writeln!(f, "serial_databits = 42").unwrap();       // out of valid range
        writeln!(f, "serial_parity = quantum").unwrap();    // invalid enum
        writeln!(f, "###").unwrap();                        // comment-ish
        writeln!(f, "\x00\x01\x02binary junk").unwrap();
        writeln!(f).unwrap();                                // blank
        writeln!(f, "     ").unwrap();
        drop(f);

        let cfg = read_config_file(path.to_str().unwrap());
        // Every field must hold its default — nothing the malformed
        // file offered was acceptable.
        let defaults = Config::default();
        assert_eq!(cfg.telnet_port, defaults.telnet_port);
        assert_eq!(cfg.max_sessions, defaults.max_sessions);
        assert_eq!(cfg.security_enabled, defaults.security_enabled);
        assert_eq!(cfg.serial_baud, defaults.serial_baud);
        assert_eq!(cfg.serial_databits, defaults.serial_databits);
        assert_eq!(cfg.serial_parity, defaults.serial_parity);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test 7b: reading a config file that doesn't exist returns the
    /// full default Config without panicking.
    #[test]
    fn test_read_config_missing_file_returns_defaults() {
        let cfg = read_config_file("/nonexistent/path/that/does/not/exist.conf");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn test_write_and_reread_config() {
        let dir = std::env::temp_dir().join("xmodem_test_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roundtrip.conf");

        let original = Config {
            telnet_enabled: false,
            telnet_port: 1234,
            telnet_gateway_negotiate: true,
            telnet_gateway_raw: true,
            enable_console: true,
            security_enabled: true,
            username: "bob".into(),
            password: "secret".into(),
            transfer_dir: "myfiles".into(),
            max_sessions: 5,
            idle_timeout_secs: 60,
            groq_api_key: "gsk_test123".into(),
            browser_homepage: "https://example.com".into(),
            weather_zip: "90210".into(),
            verbose: true,
            xmodem_negotiation_timeout: 120,
            xmodem_block_timeout: 30,
            xmodem_max_retries: 15,
            xmodem_negotiation_retry_interval: 9,
            zmodem_negotiation_timeout: 90,
            zmodem_frame_timeout: 45,
            zmodem_max_retries: 7,
            zmodem_negotiation_retry_interval: 8,
            kermit_negotiation_timeout: 60,
            kermit_packet_timeout: 12,
            kermit_max_retries: 8,
            kermit_max_packet_length: 2048,
            kermit_window_size: 8,
            kermit_block_check_type: 2,
            kermit_long_packets: false,
            kermit_sliding_windows: false,
            kermit_streaming: false,
            kermit_attribute_packets: false,
            kermit_repeat_compression: false,
            kermit_8bit_quote: "on".into(),
            kermit_iac_escape: true,
            serial_enabled: true,
            serial_port: "/dev/ttyUSB0".into(),
            serial_baud: 115200,
            serial_databits: 7,
            serial_parity: "even".into(),
            serial_stopbits: 2,
            serial_flowcontrol: "hardware".into(),
            serial_echo: false,
            serial_verbose: false,
            serial_quiet: true,
            serial_s_regs: "1,0,43,13,10,8,2,50,2,6,14,95,50".into(),
            serial_x_code: 3,
            serial_dtr_mode: 2,
            serial_flow_mode: 3,
            serial_dcd_mode: 0,
            serial_stored_numbers: [
                "5551234".into(),
                "example.com:23".into(),
                String::new(),
                "9W,5551212".into(),
            ],
            ssh_enabled: true,
            ssh_port: 2222,
            ssh_username: "sshuser".into(),
            ssh_password: "sshpass".into(),
            ssh_gateway_auth: "password".into(),
        };
        write_config_file(path.to_str().unwrap(), &original);
        let loaded = read_config_file(path.to_str().unwrap());

        assert_eq!(loaded.telnet_enabled, original.telnet_enabled);
        assert_eq!(loaded.telnet_port, original.telnet_port);
        assert_eq!(
            loaded.telnet_gateway_negotiate,
            original.telnet_gateway_negotiate
        );
        assert_eq!(loaded.telnet_gateway_raw, original.telnet_gateway_raw);
        assert_eq!(loaded.enable_console, original.enable_console);
        assert_eq!(loaded.security_enabled, original.security_enabled);
        assert_eq!(loaded.username, original.username);
        assert_eq!(loaded.password, original.password);
        assert_eq!(loaded.transfer_dir, original.transfer_dir);
        assert_eq!(loaded.max_sessions, original.max_sessions);
        assert_eq!(loaded.idle_timeout_secs, original.idle_timeout_secs);
        assert_eq!(loaded.groq_api_key, original.groq_api_key);
        assert_eq!(loaded.browser_homepage, original.browser_homepage);
        assert_eq!(loaded.weather_zip, original.weather_zip);
        assert_eq!(loaded.verbose, original.verbose);
        assert_eq!(loaded.xmodem_negotiation_timeout, original.xmodem_negotiation_timeout);
        assert_eq!(loaded.xmodem_block_timeout, original.xmodem_block_timeout);
        assert_eq!(loaded.xmodem_max_retries, original.xmodem_max_retries);
        assert_eq!(
            loaded.xmodem_negotiation_retry_interval,
            original.xmodem_negotiation_retry_interval
        );
        assert_eq!(loaded.zmodem_negotiation_timeout, original.zmodem_negotiation_timeout);
        assert_eq!(loaded.zmodem_frame_timeout, original.zmodem_frame_timeout);
        assert_eq!(loaded.zmodem_max_retries, original.zmodem_max_retries);
        assert_eq!(
            loaded.zmodem_negotiation_retry_interval,
            original.zmodem_negotiation_retry_interval
        );
        assert_eq!(
            loaded.kermit_negotiation_timeout,
            original.kermit_negotiation_timeout
        );
        assert_eq!(loaded.kermit_packet_timeout, original.kermit_packet_timeout);
        assert_eq!(loaded.kermit_max_retries, original.kermit_max_retries);
        assert_eq!(
            loaded.kermit_max_packet_length,
            original.kermit_max_packet_length
        );
        assert_eq!(loaded.kermit_window_size, original.kermit_window_size);
        assert_eq!(
            loaded.kermit_block_check_type,
            original.kermit_block_check_type
        );
        assert_eq!(loaded.kermit_long_packets, original.kermit_long_packets);
        assert_eq!(
            loaded.kermit_sliding_windows,
            original.kermit_sliding_windows
        );
        assert_eq!(loaded.kermit_streaming, original.kermit_streaming);
        assert_eq!(
            loaded.kermit_attribute_packets,
            original.kermit_attribute_packets
        );
        assert_eq!(
            loaded.kermit_repeat_compression,
            original.kermit_repeat_compression
        );
        assert_eq!(loaded.kermit_8bit_quote, original.kermit_8bit_quote);
        assert_eq!(loaded.kermit_iac_escape, original.kermit_iac_escape);
        assert_eq!(loaded.serial_enabled, original.serial_enabled);
        assert_eq!(loaded.serial_port, original.serial_port);
        assert_eq!(loaded.serial_baud, original.serial_baud);
        assert_eq!(loaded.serial_databits, original.serial_databits);
        assert_eq!(loaded.serial_parity, original.serial_parity);
        assert_eq!(loaded.serial_stopbits, original.serial_stopbits);
        assert_eq!(loaded.serial_flowcontrol, original.serial_flowcontrol);
        assert_eq!(loaded.serial_echo, original.serial_echo);
        assert_eq!(loaded.serial_verbose, original.serial_verbose);
        assert_eq!(loaded.serial_quiet, original.serial_quiet);
        assert_eq!(loaded.serial_s_regs, original.serial_s_regs);
        assert_eq!(loaded.serial_x_code, original.serial_x_code);
        assert_eq!(loaded.serial_dtr_mode, original.serial_dtr_mode);
        assert_eq!(loaded.serial_flow_mode, original.serial_flow_mode);
        assert_eq!(loaded.serial_dcd_mode, original.serial_dcd_mode);
        assert_eq!(loaded.serial_stored_numbers, original.serial_stored_numbers);
        assert_eq!(loaded.ssh_enabled, original.ssh_enabled);
        assert_eq!(loaded.ssh_port, original.ssh_port);
        assert_eq!(loaded.ssh_username, original.ssh_username);
        assert_eq!(loaded.ssh_password, original.ssh_password);
        assert_eq!(loaded.ssh_gateway_auth, original.ssh_gateway_auth);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_security_enabled_case_insensitive() {
        let dir = std::env::temp_dir().join("xmodem_test_bool_case");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("case.conf");

        for val in &["TRUE", "True", "true"] {
            std::fs::write(&path, format!("security_enabled = {}", val)).unwrap();
            let cfg = read_config_file(path.to_str().unwrap());
            assert!(cfg.security_enabled, "Failed for value: {}", val);
        }

        for val in &["false", "False", "no", "0", ""] {
            std::fs::write(&path, format!("security_enabled = {}", val)).unwrap();
            let cfg = read_config_file(path.to_str().unwrap());
            assert!(!cfg.security_enabled, "Should be false for value: {}", val);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_nonexistent_file_returns_defaults() {
        let cfg = read_config_file("/tmp/xmodem_nonexistent_12345.conf");
        assert_eq!(cfg.telnet_port, DEFAULT_TELNET_PORT);
        assert!(!cfg.security_enabled);
    }

    #[test]
    fn test_empty_config_file_returns_defaults() {
        let dir = std::env::temp_dir().join("xmodem_test_empty");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.conf");
        std::fs::write(&path, "").unwrap();

        let cfg = read_config_file(path.to_str().unwrap());
        assert_eq!(cfg.telnet_port, DEFAULT_TELNET_PORT);
        assert_eq!(cfg.transfer_dir, DEFAULT_TRANSFER_DIR);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_apply_config_key_serial_fields() {
        let mut cfg = Config::default();

        apply_config_key(&mut cfg, "serial_enabled", "true");
        assert!(cfg.serial_enabled);

        apply_config_key(&mut cfg, "serial_enabled", "false");
        assert!(!cfg.serial_enabled);

        apply_config_key(&mut cfg, "serial_port", "/dev/ttyS0");
        assert_eq!(cfg.serial_port, "/dev/ttyS0");

        apply_config_key(&mut cfg, "serial_baud", "115200");
        assert_eq!(cfg.serial_baud, 115200);

        apply_config_key(&mut cfg, "serial_databits", "7");
        assert_eq!(cfg.serial_databits, 7);

        // Invalid databits should be ignored
        apply_config_key(&mut cfg, "serial_databits", "9");
        assert_eq!(cfg.serial_databits, 7);

        apply_config_key(&mut cfg, "serial_parity", "even");
        assert_eq!(cfg.serial_parity, "even");

        // Invalid parity should be ignored
        apply_config_key(&mut cfg, "serial_parity", "bogus");
        assert_eq!(cfg.serial_parity, "even");

        apply_config_key(&mut cfg, "serial_stopbits", "2");
        assert_eq!(cfg.serial_stopbits, 2);

        // Invalid stopbits should be ignored
        apply_config_key(&mut cfg, "serial_stopbits", "3");
        assert_eq!(cfg.serial_stopbits, 2);

        apply_config_key(&mut cfg, "serial_flowcontrol", "hardware");
        assert_eq!(cfg.serial_flowcontrol, "hardware");

        // Invalid flow should be ignored
        apply_config_key(&mut cfg, "serial_flowcontrol", "bogus");
        assert_eq!(cfg.serial_flowcontrol, "hardware");
    }

    #[test]
    fn test_apply_config_key_unknown_key_ignored() {
        let mut cfg = Config::default();
        let baud_before = cfg.serial_baud;
        apply_config_key(&mut cfg, "nonexistent_key", "value");
        assert_eq!(cfg.serial_baud, baud_before);
    }

    #[test]
    fn test_apply_config_key_weather_zip() {
        let mut cfg = Config::default();
        apply_config_key(&mut cfg, "weather_zip", "90210");
        assert_eq!(cfg.weather_zip, "90210");
    }

    #[test]
    fn test_apply_config_key_ssh_fields() {
        let mut cfg = Config::default();

        apply_config_key(&mut cfg, "ssh_enabled", "true");
        assert!(cfg.ssh_enabled);

        apply_config_key(&mut cfg, "ssh_enabled", "false");
        assert!(!cfg.ssh_enabled);

        apply_config_key(&mut cfg, "ssh_port", "3333");
        assert_eq!(cfg.ssh_port, 3333);

        // Invalid port should be ignored
        apply_config_key(&mut cfg, "ssh_port", "notanumber");
        assert_eq!(cfg.ssh_port, 3333);

        apply_config_key(&mut cfg, "ssh_username", "sshuser");
        assert_eq!(cfg.ssh_username, "sshuser");

        apply_config_key(&mut cfg, "ssh_password", "sshpass");
        assert_eq!(cfg.ssh_password, "sshpass");
    }

    #[test]
    fn test_apply_config_key_telnet_fields() {
        let mut cfg = Config::default();

        apply_config_key(&mut cfg, "telnet_enabled", "false");
        assert!(!cfg.telnet_enabled);

        apply_config_key(&mut cfg, "telnet_enabled", "true");
        assert!(cfg.telnet_enabled);

        apply_config_key(&mut cfg, "telnet_port", "8080");
        assert_eq!(cfg.telnet_port, 8080);

        // Invalid port should be ignored
        apply_config_key(&mut cfg, "telnet_port", "notanumber");
        assert_eq!(cfg.telnet_port, 8080);

        apply_config_key(&mut cfg, "enable_console", "false");
        assert!(!cfg.enable_console);

        apply_config_key(&mut cfg, "enable_console", "true");
        assert!(cfg.enable_console);
    }

    #[test]
    fn test_apply_config_key_security_fields() {
        let mut cfg = Config::default();

        apply_config_key(&mut cfg, "security_enabled", "true");
        assert!(cfg.security_enabled);
        apply_config_key(&mut cfg, "security_enabled", "false");
        assert!(!cfg.security_enabled);

        apply_config_key(&mut cfg, "username", "myuser");
        assert_eq!(cfg.username, "myuser");

        apply_config_key(&mut cfg, "password", "mypass");
        assert_eq!(cfg.password, "mypass");
    }

    #[test]
    fn test_apply_config_key_xmodem_fields() {
        let mut cfg = Config::default();

        apply_config_key(&mut cfg, "transfer_dir", "/tmp/files");
        assert_eq!(cfg.transfer_dir, "/tmp/files");

        apply_config_key(&mut cfg, "xmodem_negotiation_timeout", "60");
        assert_eq!(cfg.xmodem_negotiation_timeout, 60);

        apply_config_key(&mut cfg, "xmodem_block_timeout", "30");
        assert_eq!(cfg.xmodem_block_timeout, 30);

        apply_config_key(&mut cfg, "xmodem_max_retries", "15");
        assert_eq!(cfg.xmodem_max_retries, 15);

        apply_config_key(&mut cfg, "xmodem_negotiation_retry_interval", "9");
        assert_eq!(cfg.xmodem_negotiation_retry_interval, 9);
        // Zero rejected (min 1)
        apply_config_key(&mut cfg, "xmodem_negotiation_retry_interval", "0");
        assert_eq!(cfg.xmodem_negotiation_retry_interval, 9);

        // Invalid values should be ignored
        apply_config_key(&mut cfg, "xmodem_negotiation_timeout", "notanumber");
        assert_eq!(cfg.xmodem_negotiation_timeout, 60);

        apply_config_key(&mut cfg, "zmodem_negotiation_timeout", "90");
        assert_eq!(cfg.zmodem_negotiation_timeout, 90);

        apply_config_key(&mut cfg, "zmodem_frame_timeout", "45");
        assert_eq!(cfg.zmodem_frame_timeout, 45);

        apply_config_key(&mut cfg, "zmodem_max_retries", "7");
        assert_eq!(cfg.zmodem_max_retries, 7);

        apply_config_key(&mut cfg, "zmodem_negotiation_retry_interval", "8");
        assert_eq!(cfg.zmodem_negotiation_retry_interval, 8);
        apply_config_key(&mut cfg, "zmodem_negotiation_retry_interval", "0");
        assert_eq!(cfg.zmodem_negotiation_retry_interval, 8);

        // Invalid zmodem values ignored; zero also rejected (min >=1)
        apply_config_key(&mut cfg, "zmodem_frame_timeout", "0");
        assert_eq!(cfg.zmodem_frame_timeout, 45);
        apply_config_key(&mut cfg, "zmodem_max_retries", "abc");
        assert_eq!(cfg.zmodem_max_retries, 7);
        apply_config_key(&mut cfg, "zmodem_negotiation_timeout", "0");
        assert_eq!(cfg.zmodem_negotiation_timeout, 90);
        apply_config_key(&mut cfg, "zmodem_negotiation_timeout", "-5");
        assert_eq!(cfg.zmodem_negotiation_timeout, 90);
    }

    /// The zmodem_* defaults must match the values that were hardcoded
    /// as `FRAME_TIMEOUT_SECS` / `Z*_MAX_RETRIES` constants in zmodem.rs
    /// before those became runtime-configurable.  If someone ever tweaks
    /// these defaults they should do so deliberately — the assertion
    /// below forces that decision to be explicit rather than accidental.
    #[test]
    fn test_zmodem_defaults_match_previously_hardcoded_values() {
        let cfg = Config::default();
        assert_eq!(
            cfg.zmodem_negotiation_timeout, 45,
            "default must match xmodem_negotiation_timeout which was the prior source"
        );
        assert_eq!(
            cfg.zmodem_frame_timeout, 30,
            "default must match the previously-hardcoded FRAME_TIMEOUT_SECS"
        );
        assert_eq!(
            cfg.zmodem_max_retries, 10,
            "default must match the previously-hardcoded Z*_MAX_RETRIES"
        );
    }

    /// Reading a config file that includes zmodem keys must round-trip
    /// those keys into the Config struct.  Separate from the full
    /// write/reread test so a failure here localizes to zmodem parsing.
    #[test]
    fn test_read_config_parses_zmodem_keys() {
        let dir = std::env::temp_dir().join("xmodem_test_zmodem_keys");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("z.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        use std::io::Write;
        writeln!(f, "zmodem_negotiation_timeout = 77").unwrap();
        writeln!(f, "zmodem_frame_timeout = 22").unwrap();
        writeln!(f, "zmodem_max_retries = 4").unwrap();
        drop(f);

        let cfg = read_config_file(path.to_str().unwrap());
        assert_eq!(cfg.zmodem_negotiation_timeout, 77);
        assert_eq!(cfg.zmodem_frame_timeout, 22);
        assert_eq!(cfg.zmodem_max_retries, 4);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When zmodem keys are absent from the file, defaults kick in.
    /// Covers the rollout case where an existing egateway.conf predates
    /// the zmodem_* additions.
    #[test]
    fn test_read_config_missing_zmodem_keys_fall_back_to_defaults() {
        let dir = std::env::temp_dir().join("xmodem_test_zmodem_missing");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("legacy.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        use std::io::Write;
        // Pre-zmodem config: only the xmodem-family keys.
        writeln!(f, "xmodem_negotiation_timeout = 99").unwrap();
        drop(f);

        let cfg = read_config_file(path.to_str().unwrap());
        let defaults = Config::default();
        assert_eq!(cfg.xmodem_negotiation_timeout, 99);
        assert_eq!(cfg.zmodem_negotiation_timeout, defaults.zmodem_negotiation_timeout);
        assert_eq!(cfg.zmodem_frame_timeout, defaults.zmodem_frame_timeout);
        assert_eq!(cfg.zmodem_max_retries, defaults.zmodem_max_retries);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_apply_config_key_other_fields() {
        let mut cfg = Config::default();

        apply_config_key(&mut cfg, "groq_api_key", "gsk_test123");
        assert_eq!(cfg.groq_api_key, "gsk_test123");

        apply_config_key(&mut cfg, "browser_homepage", "http://example.com");
        assert_eq!(cfg.browser_homepage, "http://example.com");

        apply_config_key(&mut cfg, "verbose", "true");
        assert!(cfg.verbose);
        apply_config_key(&mut cfg, "verbose", "false");
        assert!(!cfg.verbose);

        apply_config_key(&mut cfg, "max_sessions", "100");
        assert_eq!(cfg.max_sessions, 100);

        apply_config_key(&mut cfg, "idle_timeout_secs", "1800");
        assert_eq!(cfg.idle_timeout_secs, 1800);
    }

    // ─── sanitize_value ─────────────────────────────────

    #[test]
    fn test_sanitize_value_clean() {
        assert_eq!(sanitize_value("hello"), "hello");
    }

    #[test]
    fn test_sanitize_value_strips_newlines() {
        assert_eq!(sanitize_value("line1\nline2"), "line1line2");
    }

    #[test]
    fn test_sanitize_value_strips_cr() {
        assert_eq!(sanitize_value("line1\rline2"), "line1line2");
    }

    #[test]
    fn test_sanitize_value_strips_crlf() {
        assert_eq!(sanitize_value("a\r\nb"), "ab");
    }

    #[test]
    fn test_sanitize_value_empty() {
        assert_eq!(sanitize_value(""), "");
    }

    // ─── Dialup mapping tests ─────────────────────────────

    #[test]
    fn test_parse_dialup_mappings_basic() {
        let content = "5551234 = bbs.example.com:23\n8675309 = retro.host:2323\n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].number, "5551234");
        assert_eq!(entries[0].host, "bbs.example.com");
        assert_eq!(entries[0].port, 23);
        assert_eq!(entries[1].number, "8675309");
        assert_eq!(entries[1].host, "retro.host");
        assert_eq!(entries[1].port, 2323);
    }

    #[test]
    fn test_parse_dialup_mappings_default_port() {
        let content = "5551234 = bbs.example.com\n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "bbs.example.com");
        assert_eq!(entries[0].port, 23);
    }

    #[test]
    fn test_parse_dialup_mappings_comments_and_blanks() {
        let content = "# A comment\n\n5551234 = host:80\n  # Another comment\n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].number, "5551234");
    }

    #[test]
    fn test_parse_dialup_mappings_empty() {
        let entries = parse_dialup_mappings("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_dialup_mappings_skip_invalid() {
        let content = "= host:80\n5551234 =\nno_equals_sign\n";
        let entries = parse_dialup_mappings(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_dialup_mappings_port_zero_defaults() {
        let content = "5551234 = bbs.example.com:0\n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 1);
        // Port 0 is invalid, so the whole "host:0" is treated as the host
        // and port defaults to 23
        assert_eq!(entries[0].port, 23);
    }

    #[test]
    fn test_parse_dialup_mappings_port_overflow() {
        let content = "5551234 = host:99999\n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 1);
        // Port overflow fails u16 parse, entire target treated as host
        assert_eq!(entries[0].port, 23);
    }

    #[test]
    fn test_dialup_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("xmodem_test_dialup_rt");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("dialup_rt.conf");
        let path = file.to_str().unwrap();

        let entries = vec![
            DialupEntry { number: "5551234".into(), host: "bbs.example.com".into(), port: 23 },
            DialupEntry { number: "8675309".into(), host: "retro.host".into(), port: 2323 },
        ];

        // Write manually to the temp file
        let mut content = String::new();
        for e in &entries {
            content.push_str(&format!("{} = {}:{}\n", e.number, e.host, e.port));
        }
        std::fs::write(path, &content).unwrap();

        // Parse it back
        let loaded = parse_dialup_mappings(&std::fs::read_to_string(path).unwrap());
        assert_eq!(loaded, entries);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_dialup_mappings_whitespace_tolerance() {
        let content = "  5551234  =  bbs.example.com:23  \n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].number, "5551234");
        assert_eq!(entries[0].host, "bbs.example.com");
        assert_eq!(entries[0].port, 23);
    }

    // ─── normalize_phone_number ─────────────────────────

    #[test]
    fn test_normalize_phone_number_digits_only() {
        assert_eq!(normalize_phone_number("5551234"), "5551234");
    }

    #[test]
    fn test_normalize_phone_number_strips_formatting() {
        assert_eq!(normalize_phone_number("555-1234"), "5551234");
        assert_eq!(normalize_phone_number("(800) 555-1234"), "8005551234");
        assert_eq!(normalize_phone_number("+1-800-555-1234"), "18005551234");
    }

    #[test]
    fn test_normalize_phone_number_empty() {
        assert_eq!(normalize_phone_number(""), "");
        assert_eq!(normalize_phone_number("---"), "");
    }

    // ─── lookup matching ──────────────────────────────────

    #[test]
    fn test_lookup_dialup_normalized_matching() {
        // "555-5555" should match an entry stored as "5555555"
        let content = "5555555 = bbs.example.com:23\n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            normalize_phone_number("555-5555"),
            normalize_phone_number(&entries[0].number)
        );
    }

    #[test]
    fn test_lookup_dialup_formatted_entry_matches_plain() {
        // Entry stored as "555-1234" should match input "5551234"
        let content = "555-1234 = bbs.example.com:23\n";
        let entries = parse_dialup_mappings(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            normalize_phone_number("5551234"),
            normalize_phone_number(&entries[0].number)
        );
    }

    #[test]
    fn test_lookup_empty_normalized_returns_none() {
        // A number with no digits should never match anything
        let normalized = normalize_phone_number("---");
        assert!(normalized.is_empty());
    }

    #[test]
    fn test_default_dialup_entry() {
        // The default starter entry should be 1234567 -> telnetbible.com:6400
        let default = DialupEntry {
            number: "1234567".into(),
            host: "telnetbible.com".into(),
            port: 6400,
        };
        assert_eq!(default.number, "1234567");
        assert_eq!(default.host, "telnetbible.com");
        assert_eq!(default.port, 6400);
    }
}
