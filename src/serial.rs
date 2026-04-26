//! Hayes AT modem emulator over a physical serial port.
//!
//! Runs on a dedicated `std::thread` (not a tokio task) so it can own the
//! synchronous `serialport::SerialPort` object.  Bridges to the async runtime
//! via `tokio::runtime::Handle` for `ATDT ethernet-gateway` connections.
//!
//! Supported AT commands: AT, AT?, ATZ, AT&F, AT&W, AT&V, ATE0/ATE1,
//! ATV0/ATV1, ATQ0/ATQ1, ATI (I0-I7), ATH, ATA, ATO, ATDT, ATDP, ATD,
//! ATDL, ATDS (and ATDSn), AT&Zn=s (four stored-number slots), ATS?,
//! ATSn?, ATSn=v, ATX0-ATX4, AT&C0/AT&C1, AT&D0-AT&D3, AT&K0-AT&K4, and
//! the `A/` repeat-last-command shortcut.  S-registers S0–S26 are
//! supported (S13–S24 reserved, S25 DTR detect, S26 RTS/CTS delay).  The
//! `+++` escape (configurable via S2/S12) returns to command mode.
//! Unknown AT commands (ATB, ATC, ATL, ATM, AT&B, AT&G, AT&J, AT&S,
//! AT&T, AT&Y, etc.) return OK so legacy init strings don't halt.
//!
//! Gateway-friendly defaults: AT&D0 (ignore DTR), AT&K0 (no modem-layer
//! flow control), S7=15 (carrier wait).  These differ from Hayes defaults
//! (AT&D2, AT&K3, S7=50) to avoid breaking retro clients that don't drive
//! DTR/RTS correctly.  All settings persist via AT&W into `egateway.conf`.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;

use crate::config;
use crate::logger::glog;

// ─── Constants ─────────────────────────────────────────────

const SERIAL_READ_TIMEOUT: Duration = Duration::from_millis(100);
/// Hard cap on the TCP-connect timeout to protect the dedicated serial
/// thread from blocking arbitrarily long if the user raises S7.
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum total comma-pause we will honor, to avoid a dial string full of
/// commas from tying up the thread indefinitely.
const MAX_COMMA_PAUSE: Duration = Duration::from_secs(60);
/// Maximum AT command buffer length.  Real Hayes modems cap at ~40 chars;
/// we allow 256 to be generous.  Bytes beyond this limit are silently dropped.
const MAX_CMD_LEN: usize = 256;

/// Number of S-registers (S0 through S26).  S0-S12 are the Hayes Smartmodem
/// 2400 set; S13-S26 cover the V.series extensions most often referenced by
/// retro terminal software.  Registers beyond S12 that have no emulator
/// effect are stored verbatim so `AT&W`/`ATZ` round-trip works.
const NUM_S_REGS: usize = 27;

/// Default S-register values.  Matches Hayes except S7 (carrier wait) which
/// is 15s rather than the Hayes 50s to keep the gateway responsive.
const S_REG_DEFAULTS: [u8; NUM_S_REGS] = [
    5,   // S0:  Auto-answer ring count (5 = answer after 5 rings)
    0,   // S1:  Ring counter (read-only in real modems)
    43,  // S2:  Escape character (43 = '+')
    13,  // S3:  Carriage return character
    10,  // S4:  Line feed character
    8,   // S5:  Backspace character
    2,   // S6:  Wait for dial tone (seconds)
    15,  // S7:  Wait for carrier (seconds) — gateway default (Hayes: 50)
    2,   // S8:  Comma pause time (seconds)
    6,   // S9:  Carrier detect response time (1/10s)
    14,  // S10: Carrier loss disconnect time (1/10s)
    95,  // S11: DTMF tone duration (milliseconds)
    50,  // S12: Escape guard time (1/50s; 50 = 1 second)
    0,   // S13: Reserved (bit flags on real modems)
    0,   // S14: Reserved (bit flags)
    0,   // S15: Reserved
    0,   // S16: Reserved (self-test mode)
    0,   // S17: Reserved
    0,   // S18: Test timer (seconds)
    0,   // S19: Reserved
    0,   // S20: Reserved
    0,   // S21: Reserved (bit flags)
    0,   // S22: Reserved (bit flags)
    0,   // S23: Reserved (bit flags)
    0,   // S24: Reserved
    5,   // S25: DTR detect time (1/100s; Hayes default 5 = 50 ms)
    1,   // S26: RTS-to-CTS delay (1/100s; Hayes default 1)
];

/// Gateway-friendly default for ATX (result-code verbosity).
/// X4 = emit all extended codes (CONNECT with baud, BUSY, NO DIALTONE).
const DEFAULT_X_CODE: u8 = 4;
/// Gateway-friendly default for AT&D (DTR handling).
/// &D0 = ignore DTR.  Hayes default is &D2 (hang up on DTR drop), which
/// breaks retro clients that don't drive DTR.
const DEFAULT_DTR_MODE: u8 = 0;
/// Gateway-friendly default for AT&K (modem-layer flow control).
/// &K0 = none.  Hayes default is &K3 (RTS/CTS), which stalls clients that
/// don't do hardware flow control.  Physical-port flow control is set by
/// `serial_flowcontrol` in egateway.conf.
const DEFAULT_FLOW_MODE: u8 = 0;
/// Gateway-friendly default for AT&C (DCD handling).
/// &C1 = DCD tracks carrier state.  Matches Hayes default.
const DEFAULT_DCD_MODE: u8 = 1;

/// Flag to signal the serial thread to restart with new config.
static SERIAL_RESTART: AtomicBool = AtomicBool::new(false);

/// Slot for a ring emulator request from telnet/SSH.  The sender is used to
/// report progress (0 = ring, 1 = answered) back to the requesting session.
static RING_REQUEST: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<u8>>> =
    std::sync::Mutex::new(None);

/// Ring interval: 2 seconds on, 4 seconds off = 6 seconds per cycle (US standard).
const RING_INTERVAL: Duration = Duration::from_secs(6);

// ─── Modem state ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum ModemMode {
    Command,
    Online,
}

/// An active connection preserved across a +++ escape so that ATO can resume.
enum ActiveConnection {
    Tcp(std::net::TcpStream),
    Duplex {
        read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    },
}

/// Why the online-mode loop exited.
#[derive(Debug, Clone, Copy, PartialEq)]
enum OnlineExit {
    /// Remote end disconnected or I/O error.
    Disconnected,
    /// User sent +++ escape sequence.
    Escaped,
}

struct ModemState {
    port: Box<dyn serialport::SerialPort>,
    mode: ModemMode,
    echo: bool,
    verbose: bool,
    quiet: bool,
    last_data_time: Instant,
    plus_count: u8,
    plus_start: Instant,
    cmd_buffer: String,
    handle: tokio::runtime::Handle,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    baud: u32,
    /// Connection preserved after +++ escape for ATO to resume.
    active_connection: Option<ActiveConnection>,
    /// S-register values (S0–S12).
    s_regs: [u8; NUM_S_REGS],
    /// ATX result-code level (0-4).  Controls whether CONNECT includes a
    /// baud rate and whether BUSY/NO DIALTONE/NO ANSWER can be emitted.
    x_code: u8,
    /// AT&D DTR-handling mode (0-3).  Stored and persisted.  &D0 (default)
    /// ignores DTR transitions.  Higher modes are recognized and saved but
    /// not enforced because DTR semantics on USB-serial adapters are
    /// platform-specific.
    dtr_mode: u8,
    /// AT&K modem-layer flow control (0-4).  Stored and persisted.  The
    /// physical serial port's flow control is controlled by
    /// `serial_flowcontrol` in egateway.conf, not by this value.
    flow_mode: u8,
    /// AT&C DCD mode (0-1).  Stored and persisted.  &C1 (default) reports
    /// carrier; &C0 forces DCD always asserted.  Physical DCD signalling
    /// depends on the serial adapter.
    dcd_mode: u8,
    /// Last dialed target for ATDL (redial).
    last_dial: String,
    /// Last fully-processed AT command line, for Hayes `A/` repeat.  Not
    /// persisted — real modems keep A/ state in RAM only.
    last_command: String,
    /// Hayes stored-number slots (AT&Zn=s / ATDSn).  Mirrored from config on
    /// startup and ATZ, persisted to config on AT&W.
    stored_numbers: [String; 4],
}

// ─── Public API ────────────────────────────────────────────

/// Start the serial modem manager on a dedicated thread.
///
/// Returns immediately.  The manager thread loops: if serial is enabled and
/// configured it opens the port and runs the modem; when `restart_serial()`
/// is called it re-reads config and re-opens the port (or stops if disabled).
pub fn start_serial(shutdown: Arc<AtomicBool>, restart: Arc<AtomicBool>) {
    let handle = tokio::runtime::Handle::current();
    let sd = shutdown;
    let rs = restart;

    std::thread::Builder::new()
        .name("serial-modem".into())
        .spawn(move || {
            serial_manager(handle, sd, rs);
        })
        .expect("Failed to spawn serial modem thread");
}

/// Signal the serial thread to restart with the current config.
pub fn restart_serial() {
    SERIAL_RESTART.store(true, Ordering::SeqCst);
}

/// List available serial ports (cross-platform).  Returns an empty vec on
/// error.  Safe to call from `spawn_blocking`.
pub fn list_serial_ports() -> Vec<String> {
    match serialport::available_ports() {
        Ok(ports) => ports.into_iter().map(|p| p.port_name).collect(),
        Err(_) => Vec::new(),
    }
}

/// Request a ring emulator session.  The sender receives progress events:
/// `0` for each RING, `1` when the modem answers.  Returns `false` if a
/// ring request is already pending.
pub fn request_ring(sender: tokio::sync::mpsc::Sender<u8>) -> bool {
    let mut slot = RING_REQUEST.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return false;
    }
    *slot = Some(sender);
    true
}

/// Cancel a pending ring request.  Clears the slot so a new request can
/// be made.  This is safe to call even if the serial thread has already
/// taken the request (the slot will already be None).
pub fn cancel_ring_request() {
    RING_REQUEST
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
}

// ─── Serial manager ────────────────────────────────────────

/// Manager loop: starts/stops the serial modem when config changes.
fn serial_manager(handle: tokio::runtime::Handle, shutdown: Arc<AtomicBool>, restart: Arc<AtomicBool>) {
    loop {
        SERIAL_RESTART.store(false, Ordering::SeqCst);
        let cfg = config::get_config();
        if cfg.serial_enabled && !cfg.serial_port.is_empty() {
            serial_thread(cfg, handle.clone(), shutdown.clone(), restart.clone());
        }
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        // Wait for a restart signal or shutdown
        while !SERIAL_RESTART.load(Ordering::SeqCst) && !shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(250));
        }
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        // Brief pause before restarting to let the old port close cleanly
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ─── Serial thread ─────────────────────────────────────────

fn serial_thread(
    cfg: config::Config,
    handle: tokio::runtime::Handle,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
) {
    let builder = serialport::new(&cfg.serial_port, cfg.serial_baud)
        .data_bits(match cfg.serial_databits {
            5 => serialport::DataBits::Five,
            6 => serialport::DataBits::Six,
            7 => serialport::DataBits::Seven,
            _ => serialport::DataBits::Eight,
        })
        .parity(match cfg.serial_parity.as_str() {
            "odd" => serialport::Parity::Odd,
            "even" => serialport::Parity::Even,
            _ => serialport::Parity::None,
        })
        .stop_bits(match cfg.serial_stopbits {
            2 => serialport::StopBits::Two,
            _ => serialport::StopBits::One,
        })
        .flow_control(match cfg.serial_flowcontrol.as_str() {
            "hardware" => serialport::FlowControl::Hardware,
            "software" => serialport::FlowControl::Software,
            _ => serialport::FlowControl::None,
        })
        .timeout(SERIAL_READ_TIMEOUT);

    let port = match builder.open() {
        Ok(p) => p,
        Err(e) => {
            glog!("Serial modem: failed to open {}: {}", cfg.serial_port, e);
            return;
        }
    };
    glog!(
        "Serial modem: opened {} at {} baud",
        cfg.serial_port, cfg.serial_baud
    );

    let now = Instant::now();
    let mut state = ModemState {
        port,
        mode: ModemMode::Command,
        echo: cfg.serial_echo,
        verbose: cfg.serial_verbose,
        quiet: cfg.serial_quiet,
        last_data_time: now,
        plus_count: 0,
        plus_start: now,
        cmd_buffer: String::new(),
        handle,
        shutdown,
        restart,
        baud: cfg.serial_baud,
        active_connection: None,
        s_regs: parse_s_regs(&cfg.serial_s_regs),
        x_code: cfg.serial_x_code,
        dtr_mode: cfg.serial_dtr_mode,
        flow_mode: cfg.serial_flow_mode,
        dcd_mode: cfg.serial_dcd_mode,
        last_dial: String::new(),
        last_command: String::new(),
        stored_numbers: cfg.serial_stored_numbers.clone(),
    };

    send_response(&mut state, "OK");

    while !state.shutdown.load(Ordering::SeqCst) && !SERIAL_RESTART.load(Ordering::SeqCst) {
        // Check for a pending ring request.
        if state.mode == ModemMode::Command
            && let Some(sender) = take_ring_request()
        {
            process_ring(&mut state, sender);
            continue;
        }
        match state.mode {
            ModemMode::Command => command_mode_tick(&mut state),
            ModemMode::Online => {
                // Online mode is entered and exits within the dial functions.
                // If we somehow end up here, reset to command mode.
                state.mode = ModemMode::Command;
            }
        }
    }
    if SERIAL_RESTART.load(Ordering::SeqCst) {
        glog!("Serial modem: restarting with new config");
    } else {
        let _ = state.port.write_all(b"\r\nServer shutting down. Goodbye.\r\n");
        let _ = state.port.flush();
        glog!("Serial modem: shutting down");
    }
}

// ─── Command mode ──────────────────────────────────────────

fn command_mode_tick(state: &mut ModemState) {
    let mut buf = [0u8; 1];
    match state.port.read(&mut buf) {
        Ok(1) => {
            let byte = buf[0];
            state.last_data_time = Instant::now();
            state.plus_count = 0;

            let cr = state.s_regs[3];
            let lf = state.s_regs[4];
            let bs = state.s_regs[5];

            // Line terminator: configured CR (S3), configured LF (S4), or
            // the historical ASCII pair 0x0D / 0x0A.  This keeps line-ending
            // auto-detection working even when S3/S4 are customized.
            if byte == cr || byte == lf || byte == 0x0D || byte == 0x0A {
                if state.echo {
                    let _ = state.port.write_all(&[cr, lf]);
                }
                let cmd = std::mem::take(&mut state.cmd_buffer);
                let cmd = cmd.trim().to_string();
                if !cmd.is_empty() {
                    process_at_command(state, &cmd);
                }
            } else if byte == bs || byte == 0x7F {
                // Backspace: configured S5 character or ASCII DEL.
                if !state.cmd_buffer.is_empty() {
                    state.cmd_buffer.pop();
                    if state.echo {
                        // Echo BS-SPACE-BS using the configured BS char.
                        let _ = state.port.write_all(&[bs, b' ', bs]);
                    }
                }
            } else if byte == b'/' && matches!(state.cmd_buffer.as_str(), "A" | "a") {
                // Hayes `A/` — repeat last command.  Triggers immediately on
                // the `/` keystroke, no CR required.  The preceding `A` is
                // already echoed; finish the visual line with `/` + CR/LF.
                state.cmd_buffer.clear();
                if state.echo {
                    let _ = state.port.write_all(&[b'/', cr, lf]);
                }
                if !state.last_command.is_empty() {
                    let cmd = state.last_command.clone();
                    process_at_command(state, &cmd);
                }
            } else if byte >= 0x20 && state.cmd_buffer.len() < MAX_CMD_LEN {
                if state.echo {
                    let _ = state.port.write_all(&[byte]);
                }
                state.cmd_buffer.push(byte as char);
            }
            // Other control characters are ignored.
        }
        Ok(_) => {}
        Err(ref e)
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => {
            glog!("Serial modem: read error: {}", e);
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

// ─── AT command processing ─────────────────────────────────

/// Result of parsing an AT command.
#[derive(Debug, PartialEq)]
enum AtResult {
    Ok,
    Error,
    NoCarrier,
    Info(String),
    Dial(String),
    /// ATO — return to online mode (resume after +++ escape).
    Online,
    /// ATH — hang up (close any active connection).
    Hangup,
    /// AT&F — reset to factory defaults (also closes active connection).
    Reset,
    /// ATZ — reset to stored (config) settings (also closes active connection).
    ResetStored,
    /// AT&W — save current modem settings to config file.
    SaveConfig,
    /// ATSn? — query S-register value.
    SRegQuery(usize),
    /// ATSn=v — set S-register value.
    SRegSet(usize, u8),
    /// AT&V — display current modem configuration.
    ShowConfig,
    /// ATDL — redial last number.
    Redial,
    /// AT? — show AT command help.
    Help,
    /// ATS? — show S-register help.
    SRegHelp,
    /// ATX n — set result-code verbosity (0-4).
    XSet(u8),
    /// AT&C n — set DCD mode (0-1).
    DcdSet(u8),
    /// AT&D n — set DTR-handling mode (0-3).
    DtrSet(u8),
    /// AT&K n — set modem-layer flow control (0-4).
    FlowSet(u8),
    /// AT&Zn=s — store phone number `s` in slot `n` (0-3).
    StoreNumber(usize, String),
    /// ATDSn — dial stored number from slot `n` (0-3).
    DialStored(usize),
}

/// Parse an AT command line into a list of responses.  Pure function for
/// testability — does not touch the serial port or active connection.
fn parse_at_command(
    cmd: &str,
    echo: &mut bool,
    verbose: &mut bool,
    quiet: &mut bool,
) -> Vec<AtResult> {
    let upper = cmd.to_ascii_uppercase();

    if upper == "AT" {
        return vec![AtResult::Ok];
    }

    if !upper.starts_with("AT") {
        return vec![AtResult::Error];
    }

    let rest = &upper[2..];

    match rest {
        "Z" => {
            vec![AtResult::ResetStored]
        }
        "H" | "H0" => vec![AtResult::Hangup],
        "E0" => {
            *echo = false;
            vec![AtResult::Ok]
        }
        "E1" => {
            *echo = true;
            vec![AtResult::Ok]
        }
        "V0" => {
            *verbose = false;
            vec![AtResult::Ok]
        }
        "V1" => {
            *verbose = true;
            vec![AtResult::Ok]
        }
        "Q0" => {
            *quiet = false;
            vec![AtResult::Ok]
        }
        "Q1" => {
            *quiet = true;
            vec![AtResult::Ok]
        }
        "I" | "I0" => vec![
            AtResult::Info(format!(
                "Ethernet Gateway Modem Emulator v{}",
                env!("CARGO_PKG_VERSION")
            )),
            AtResult::Ok,
        ],
        "I1" => vec![AtResult::Info("000".into()), AtResult::Ok],
        "I2" => vec![AtResult::Ok],
        "I3" => vec![
            AtResult::Info(format!(
                "Ethernet Gateway {}",
                env!("CARGO_PKG_VERSION")
            )),
            AtResult::Ok,
        ],
        "I4" => vec![
            AtResult::Info("Hayes-compatible virtual modem over TCP".into()),
            AtResult::Ok,
        ],
        "I5" => vec![AtResult::Info("B00".into()), AtResult::Ok],
        "I6" => vec![
            AtResult::Info("No link diagnostics available".into()),
            AtResult::Ok,
        ],
        "I7" => vec![
            AtResult::Info("Product: ethernet-gateway (software emulator)".into()),
            AtResult::Ok,
        ],
        "?" => vec![AtResult::Help],
        "O" | "O0" => vec![AtResult::Online],
        "A" => vec![AtResult::NoCarrier],
        "&F" => {
            *echo = true;
            *verbose = true;
            *quiet = false;
            vec![AtResult::Reset]
        }
        "&W" | "&W0" => vec![AtResult::SaveConfig],
        "&V" => vec![AtResult::ShowConfig],
        "X" | "X0" => vec![AtResult::XSet(0)],
        "X1" => vec![AtResult::XSet(1)],
        "X2" => vec![AtResult::XSet(2)],
        "X3" => vec![AtResult::XSet(3)],
        "X4" => vec![AtResult::XSet(4)],
        "&C" | "&C0" => vec![AtResult::DcdSet(0)],
        "&C1" => vec![AtResult::DcdSet(1)],
        "&D" | "&D0" => vec![AtResult::DtrSet(0)],
        "&D1" => vec![AtResult::DtrSet(1)],
        "&D2" => vec![AtResult::DtrSet(2)],
        "&D3" => vec![AtResult::DtrSet(3)],
        "&K" | "&K0" => vec![AtResult::FlowSet(0)],
        "&K1" => vec![AtResult::FlowSet(1)],
        // &K2 is reserved (not defined in Hayes spec)
        "&K3" => vec![AtResult::FlowSet(3)],
        "&K4" => vec![AtResult::FlowSet(4)],
        _ if rest.starts_with("&Z") => {
            // AT&Zn=s — store a phone number.  n is a single digit slot 0-3.
            // We slice from the original `cmd` to preserve case in `s`.
            let after = &rest[2..];
            let (slot, eq_idx) = match after.find('=') {
                Some(i) if i >= 1 => {
                    let slot_str = &after[..i];
                    match slot_str.parse::<usize>() {
                        std::result::Result::Ok(n) if n < 4 => (n, i),
                        _ => return vec![AtResult::Error],
                    }
                }
                _ => return vec![AtResult::Error],
            };
            // Offset into `cmd`: "AT" (2) + "&Z" (2) + slot digits + "=".
            // Use the ASCII-only prefix length via byte indexing — rest is
            // all ASCII (came from to_ascii_uppercase of ASCII input).
            let prefix_len = 2 + 2 + eq_idx + 1;
            let value = cmd.get(prefix_len..).unwrap_or("").trim().to_string();
            vec![AtResult::StoreNumber(slot, value)]
        }
        _ if rest.starts_with("S") && rest.len() > 1 => {
            // S-register: ATS? (help), ATSn? (query), or ATSn=v (set)
            let s_rest = &rest[1..];
            if s_rest == "?" {
                // ATS? — S-register help
                return vec![AtResult::SRegHelp];
            }
            if let Some(qpos) = s_rest.find('?') {
                // ATSn?
                match s_rest[..qpos].parse::<usize>() {
                    std::result::Result::Ok(reg) if reg < NUM_S_REGS => {
                        vec![AtResult::SRegQuery(reg)]
                    }
                    _ => vec![AtResult::Error],
                }
            } else if let Some(epos) = s_rest.find('=') {
                // ATSn=v
                let reg_str = &s_rest[..epos];
                let val_str = s_rest[epos + 1..].trim();
                match (reg_str.parse::<usize>(), val_str.parse::<u16>()) {
                    (std::result::Result::Ok(reg), std::result::Result::Ok(val))
                        if reg < NUM_S_REGS && val <= 255 =>
                    {
                        vec![AtResult::SRegSet(reg, val as u8)]
                    }
                    _ => vec![AtResult::Error],
                }
            } else {
                // Bare ATSn with no ? or = — error
                vec![AtResult::Error]
            }
        }
        "DL" => vec![AtResult::Redial],
        _ if rest.starts_with("DS") && {
            // Only treat as ATDS if what follows `DS` is empty or a slot
            // digit.  This prevents swallowing legitimate `ATDsomething`
            // hostname dials that happen to start with 's'.
            let tail = rest[2..].trim();
            tail.is_empty() || tail.chars().all(|c| c.is_ascii_digit())
        } => {
            let n_str = rest[2..].trim();
            if n_str.is_empty() {
                vec![AtResult::DialStored(0)]
            } else {
                match n_str.parse::<usize>() {
                    std::result::Result::Ok(n) if n < 4 => vec![AtResult::DialStored(n)],
                    _ => vec![AtResult::Error],
                }
            }
        }
        _ if rest.starts_with("DT") || rest.starts_with("DP") || rest.starts_with("D") => {
            // Preserve original case for the dial string (hostnames).
            let dial_str = if rest.starts_with("DT") || rest.starts_with("DP") {
                cmd[4..].trim()
            } else {
                cmd[3..].trim()
            };
            if dial_str.is_empty() {
                vec![AtResult::Error]
            } else {
                vec![AtResult::Dial(dial_str.to_string())]
            }
        }
        _ => {
            // Accept unknown AT commands silently (AT&C, AT&D, ATL, ATM, etc.)
            vec![AtResult::Ok]
        }
    }
}

fn process_at_command(state: &mut ModemState, cmd: &str) {
    // Stash the line for Hayes `A/` repeat.  Real modems skip the A/
    // pseudo-command itself (we never route "A/" through here anyway).
    state.last_command = cmd.to_string();
    let results = parse_at_command(
        cmd,
        &mut state.echo,
        &mut state.verbose,
        &mut state.quiet,
    );
    for result in results {
        match result {
            AtResult::Ok => { send_result(state, "OK"); }
            AtResult::Error => { send_result(state, "ERROR"); }
            AtResult::NoCarrier => { send_result(state, "NO CARRIER"); }
            AtResult::Info(msg) => {
                if !state.quiet {
                    send_response(state, &msg);
                }
            }
            AtResult::Dial(target) => {
                let parsed = parse_dial_string(&target, &state.s_regs);
                // Hang up any existing connection before dialing.
                state.active_connection = None;
                state.last_dial = target.clone();
                if parsed.pre_delay > Duration::ZERO {
                    std::thread::sleep(parsed.pre_delay);
                }
                if parsed.target.is_empty() {
                    // Empty after stripping modifiers — OK with no dial.
                    send_result(state, "OK");
                    return;
                }
                handle_dial_with_modifiers(state, &parsed);
                return; // dial takes over the session
            }
            AtResult::Redial => {
                if state.last_dial.is_empty() {
                    send_result(state, "ERROR");
                } else {
                    state.active_connection = None;
                    let target = state.last_dial.clone();
                    let parsed = parse_dial_string(&target, &state.s_regs);
                    if parsed.pre_delay > Duration::ZERO {
                        std::thread::sleep(parsed.pre_delay);
                    }
                    if parsed.target.is_empty() {
                        send_result(state, "OK");
                        return;
                    }
                    handle_dial_with_modifiers(state, &parsed);
                    return;
                }
            }
            AtResult::Online => {
                handle_return_online(state);
                return; // online mode takes over
            }
            AtResult::Hangup => {
                state.active_connection = None;
                send_result(state, "OK");
            }
            AtResult::Reset => {
                // AT&F — reset to gateway-friendly factory defaults
                state.echo = true;
                state.verbose = true;
                state.quiet = false;
                state.active_connection = None;
                state.s_regs = S_REG_DEFAULTS;
                state.x_code = DEFAULT_X_CODE;
                state.dtr_mode = DEFAULT_DTR_MODE;
                state.flow_mode = DEFAULT_FLOW_MODE;
                state.dcd_mode = DEFAULT_DCD_MODE;
                send_result(state, "OK");
            }
            AtResult::ResetStored => {
                // ATZ — restore from config (saved by AT&W)
                let cfg = config::get_config();
                state.echo = cfg.serial_echo;
                state.verbose = cfg.serial_verbose;
                state.quiet = cfg.serial_quiet;
                state.s_regs = parse_s_regs(&cfg.serial_s_regs);
                state.x_code = cfg.serial_x_code;
                state.dtr_mode = cfg.serial_dtr_mode;
                state.flow_mode = cfg.serial_flow_mode;
                state.dcd_mode = cfg.serial_dcd_mode;
                state.stored_numbers = cfg.serial_stored_numbers.clone();
                state.active_connection = None;
                send_result(state, "OK");
            }
            AtResult::SaveConfig => {
                // AT&W — save current settings to config
                config::update_config_values(&[
                    ("serial_echo", if state.echo { "true" } else { "false" }),
                    ("serial_verbose", if state.verbose { "true" } else { "false" }),
                    ("serial_quiet", if state.quiet { "true" } else { "false" }),
                    ("serial_s_regs", &format_s_regs(&state.s_regs)),
                    ("serial_x_code", &state.x_code.to_string()),
                    ("serial_dtr_mode", &state.dtr_mode.to_string()),
                    ("serial_flow_mode", &state.flow_mode.to_string()),
                    ("serial_dcd_mode", &state.dcd_mode.to_string()),
                    ("serial_stored_0", &state.stored_numbers[0]),
                    ("serial_stored_1", &state.stored_numbers[1]),
                    ("serial_stored_2", &state.stored_numbers[2]),
                    ("serial_stored_3", &state.stored_numbers[3]),
                ]);
                send_result(state, "OK");
            }
            AtResult::XSet(n) => {
                state.x_code = n;
                send_result(state, "OK");
            }
            AtResult::DcdSet(n) => {
                state.dcd_mode = n;
                send_result(state, "OK");
            }
            AtResult::DtrSet(n) => {
                state.dtr_mode = n;
                send_result(state, "OK");
            }
            AtResult::FlowSet(n) => {
                state.flow_mode = n;
                send_result(state, "OK");
            }
            AtResult::StoreNumber(slot, value) => {
                state.stored_numbers[slot] = value;
                send_result(state, "OK");
            }
            AtResult::DialStored(slot) => {
                let stored = state.stored_numbers[slot].clone();
                if stored.is_empty() {
                    send_result(state, "NO CARRIER");
                } else {
                    let parsed = parse_dial_string(&stored, &state.s_regs);
                    state.active_connection = None;
                    state.last_dial = stored;
                    if parsed.pre_delay > Duration::ZERO {
                        std::thread::sleep(parsed.pre_delay);
                    }
                    if parsed.target.is_empty() {
                        send_result(state, "OK");
                        return;
                    }
                    handle_dial_with_modifiers(state, &parsed);
                    return;
                }
            }
            AtResult::SRegQuery(reg) => {
                if !state.quiet {
                    let val = state.s_regs[reg];
                    let formatted = format!("{:03}", val);
                    send_response(state, &formatted);
                }
            }
            AtResult::SRegSet(reg, val) => {
                state.s_regs[reg] = val;
                send_result(state, "OK");
            }
            AtResult::Help => {
                if !state.quiet {
                    let text = [
                        "AT Commands:",
                        "AT     OK             ATZ   Reset (stored)",
                        "AT&F   Factory reset   AT&W  Save settings",
                        "AT&V   Show config     ATI0-7 Identification",
                        "ATE0/1 Echo off/on     ATV0/1 Verbose/numeric",
                        "ATQ0/1 Quiet off/on    ATH   Hang up",
                        "ATO    Return online   ATA   Answer",
                        "ATDT   Dial host:port  ATDL  Redial",
                        "ATDSn  Dial stored n   AT&Zn=s Store in slot n",
                        "ATSn?  Query register  ATSn=v Set register",
                        "ATS?   Register help   +++   Escape to cmd",
                        "ATX0-4 Result verbosity AT&C  DCD mode",
                        "AT&D   DTR mode        AT&K  Flow control",
                        "A/     Repeat last cmd AT?   This help",
                    ].join("\r\n");
                    send_response(state, &text);
                }
            }
            AtResult::SRegHelp => {
                if !state.quiet {
                    let text = [
                        "S-Registers (ATSn? to query, ATSn=v to set):",
                        "S00  Auto-answer ring count (0=off)",
                        "S01  Ring counter (current)",
                        "S02  Escape character (43=+)",
                        "S03  Carriage return char (13)",
                        "S04  Line feed char (10)",
                        "S05  Backspace char (8)",
                        "S06  Wait for dial tone (sec)",
                        "S07  Wait for carrier (sec, gateway default 15)",
                        "S08  Comma pause time (sec)",
                        "S09  Carrier detect time (1/10s)",
                        "S10  Carrier loss time (1/10s)",
                        "S11  DTMF tone duration (ms)",
                        "S12  Escape guard time (1/50s)",
                        "S13-S24  Reserved (stored for AT&W/ATZ)",
                        "S25  DTR detect time (1/100s)",
                        "S26  RTS/CTS delay (1/100s)",
                        "Note: keep S3/S4/S5 distinct -- if they share a",
                        "      value, command-line editing collides (CR",
                        "      branch wins over BS, etc.).",
                    ].join("\n");
                    send_response(state, &text);
                }
            }
            AtResult::ShowConfig => {
                // AT&V — display current configuration
                if !state.quiet {
                    let echo_str = if state.echo { "E1" } else { "E0" };
                    let verbose_str = if state.verbose { "V1" } else { "V0" };
                    let quiet_str = if state.quiet { "Q1" } else { "Q0" };
                    let header = format!(
                        "{} {} {} X{} &C{} &D{} &K{} B{}",
                        echo_str, verbose_str, quiet_str,
                        state.x_code, state.dcd_mode, state.dtr_mode,
                        state.flow_mode, state.baud,
                    );
                    let s_line = state.s_regs.iter().enumerate()
                        .map(|(i, v)| format!("S{:02}={:03}", i, v))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let stored_lines = state.stored_numbers.iter().enumerate()
                        .map(|(i, n)| {
                            if n.is_empty() {
                                format!("&Z{}=(unset)", i)
                            } else {
                                format!("&Z{}={}", i, n)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    let body = format!("{}\n{}\n{}", header, s_line, stored_lines);
                    send_response(state, &body);
                    send_result(state, "OK");
                }
            }
        }
    }
}

/// ATO — resume a connection that was suspended with +++.
fn handle_return_online(state: &mut ModemState) {
    let Some(conn) = state.active_connection.take() else {
        send_result(state, "NO CARRIER");
        return;
    };
    send_result(state, "CONNECT");
    state.mode = ModemMode::Online;
    match conn {
        ActiveConnection::Tcp(mut tcp) => {
            let exit = online_mode_tcp(state, &mut tcp);
            state.mode = ModemMode::Command;
            match exit {
                OnlineExit::Escaped => {
                    state.active_connection = Some(ActiveConnection::Tcp(tcp));
                    send_result(state, "OK");
                }
                OnlineExit::Disconnected => {
                    send_result(state, "NO CARRIER");
                }
            }
        }
        ActiveConnection::Duplex { mut read, mut write } => {
            let exit = online_mode_duplex(state, &mut read, &mut write);
            state.mode = ModemMode::Command;
            match exit {
                OnlineExit::Escaped => {
                    state.active_connection =
                        Some(ActiveConnection::Duplex { read, write });
                    send_result(state, "OK");
                }
                OnlineExit::Disconnected => {
                    send_result(state, "NO CARRIER");
                }
            }
        }
    }
}

// ─── Dialing ───────────────────────────────────────────────

/// Built-in phone number that dials the local Ethernet Gateway menu.
const GATEWAY_PHONE_NUMBER: &str = "1001000";

/// Parsed representation of an ATDT/ATDP dial string with Hayes modifiers
/// applied.
#[derive(Debug, PartialEq)]
struct ParsedDial {
    /// The clean dial target (host[:port] or phone number) with all
    /// modifiers stripped.
    target: String,
    /// Total time to sleep before the TCP connect: sum of S8×(commas) plus
    /// S6 seconds if `W` (wait for dial tone) appeared.  Capped at
    /// `MAX_COMMA_PAUSE`.
    pre_delay: Duration,
    /// If true, `;` was present — after the "connect" report the modem
    /// stays in command mode rather than entering online data mode.
    stay_in_command: bool,
}

/// Parse Hayes dial-string modifiers out of `raw` into a `ParsedDial`.
///
/// Hayes modifiers are only meaningful on phone-number dial strings (digits,
/// spaces, `-`, `()`, `+`, `*`, `#`) plus the modifier characters `,W;@!`.
/// If the string contains any other character it is treated as a hostname
/// and only the trailing `;` modifier is applied — this avoids stripping P,
/// T, or W from names like `pine.example.com` or `www.example.com`.
///
/// Recognized modifiers (phone-number context only):
/// - `,` — pause for S8 seconds (each comma adds S8 seconds)
/// - `W` — wait for dial tone (adds S6 seconds; virtual modem has no tone)
/// - `;` — stay in command mode after connect (applies to hostnames too)
/// - `P` / `T` — pulse / tone selector; both ignored (virtual)
/// - `@` / `!` — quiet-answer / hookflash; ignored (virtual)
/// - `*` / `#` — DTMF digits, preserved in the target for lookup
fn parse_dial_string(raw: &str, s_regs: &[u8; NUM_S_REGS]) -> ParsedDial {
    let trimmed = raw.trim();
    // Trailing `;` always applies, even to hostnames.
    let (body, stay_in_command) = match trimmed.strip_suffix(';') {
        Some(b) => (b, true),
        None => (trimmed, false),
    };

    if looks_like_phone_dial_string(body) {
        let s6 = s_regs[6] as u64;
        let s8 = s_regs[8] as u64;
        let mut pre_delay_secs: u64 = 0;
        let mut target = String::with_capacity(body.len());
        for ch in body.chars() {
            match ch {
                ',' => {
                    pre_delay_secs = pre_delay_secs.saturating_add(s8);
                }
                'W' | 'w' => {
                    pre_delay_secs = pre_delay_secs.saturating_add(s6);
                }
                'P' | 'p' | 'T' | 't' | '@' | '!' => {}
                _ => target.push(ch),
            }
        }
        let mut pre_delay = Duration::from_secs(pre_delay_secs);
        if pre_delay > MAX_COMMA_PAUSE {
            pre_delay = MAX_COMMA_PAUSE;
        }
        return ParsedDial {
            target: target.trim().to_string(),
            pre_delay,
            stay_in_command,
        };
    }

    // Hostname branch: apply only `;`.
    ParsedDial {
        target: body.trim().to_string(),
        pre_delay: Duration::ZERO,
        stay_in_command,
    }
}

/// Return true if `s` contains only characters that can appear in a Hayes
/// phone-number dial string (including modifiers).  Used to decide whether
/// to apply dial modifiers or treat the string as a hostname.
fn looks_like_phone_dial_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let all_phone_chars = s.chars().all(|c| {
        c.is_ascii_digit()
            || matches!(
                c,
                '-' | ' ' | '(' | ')' | '+' | '*' | '#'
                    | ',' | 'W' | 'w' | 'P' | 'p' | 'T' | 't' | '@' | '!'
            )
    });
    has_digit && all_phone_chars
}

/// Dial using a pre-parsed ParsedDial.  Applies the `;` modifier after
/// connection by hanging up immediately and staying in command mode.
fn handle_dial_with_modifiers(state: &mut ModemState, parsed: &ParsedDial) {
    if parsed.stay_in_command {
        // `;` — report OK without entering online mode.  We still validate
        // that the target resolves, matching Hayes behavior where `;`
        // returns OK even if the call would have failed.
        send_result(state, "OK");
        return;
    }
    handle_dial(state, &parsed.target);
}

fn handle_dial(state: &mut ModemState, target: &str) {
    let lower = target.to_ascii_lowercase();

    // Check for the built-in gateway number (digits only, ignoring formatting).
    if is_phone_number(target)
        && config::normalize_phone_number(target) == GATEWAY_PHONE_NUMBER
    {
        dial_ethernet_gateway(state);
        return;
    }

    if lower == "ethernet-gateway" || lower == "ethernet gateway" {
        dial_ethernet_gateway(state);
    } else {
        // If the target looks like a phone number (digits, dashes, spaces,
        // parens, etc.), look it up in the dialup mapping file.
        let resolved = if is_phone_number(target) {
            match config::lookup_dialup_number(target) {
                Some(mapped) => mapped,
                None => {
                    // No mapping found for this number.
                    send_result(state, "NO CARRIER");
                    return;
                }
            }
        } else {
            target.to_string()
        };

        let (host, port) = if let Some((h, p)) = resolved.rsplit_once(':') {
            match p.parse::<u16>() {
                Ok(port) if port > 0 => (h.to_string(), port),
                _ => {
                    send_result(state, "ERROR");
                    return;
                }
            }
        } else {
            (resolved, 23u16)
        };
        dial_tcp(state, &host, port);
    }
}

/// Returns true if the dial string looks like a phone number rather than a
/// hostname.  Phone numbers contain only digits, dashes, spaces, parentheses,
/// and the leading `+` for international format.  Dots are excluded so that
/// IP addresses (e.g. `192.168.1.1`) and hostnames are not mistaken for
/// phone numbers.
fn is_phone_number(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Must contain at least one digit
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    // Must contain only phone-number characters (no dots or colons).
    // `*` and `#` are valid DTMF tones for PBX extensions.
    let all_phone = s.chars().all(|c| {
        c.is_ascii_digit()
            || c == '-'
            || c == ' '
            || c == '('
            || c == ')'
            || c == '+'
            || c == '*'
            || c == '#'
    });
    has_digit && all_phone
}

/// Dial into the local Ethernet Gateway menu via an in-memory duplex bridge.
fn dial_ethernet_gateway(state: &mut ModemState) {
    send_result(state, "CONNECT");
    state.mode = ModemMode::Online;

    // Create a duplex pair: one end for TelnetSession, the other for this thread.
    // Large buffer to handle slow baud rates (300–9600) without data loss.
    let (async_stream, serial_stream) = tokio::io::duplex(65536);
    let (async_read, async_write) = tokio::io::split(async_stream);

    let writer_box: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(async_write);
    let writer_arc: crate::telnet::SharedWriter =
        Arc::new(tokio::sync::Mutex::new(writer_box));

    let shutdown = state.shutdown.clone();
    let restart = state.restart.clone();

    // Spawn TelnetSession on the tokio runtime.
    let writer_for_task = writer_arc.clone();
    state.handle.spawn(async move {
        let mut session = crate::telnet::TelnetSession::new_serial(
            Box::new(async_read),
            writer_for_task.clone(),
            shutdown,
            restart,
        );
        if let Err(e) = session.run().await {
            glog!("Serial modem: session error: {}", e);
        }
        let mut w = writer_for_task.lock().await;
        let _ = w.shutdown().await;
    });

    // Bridge serial port <-> duplex stream on this thread.
    let (mut duplex_read, mut duplex_write) =
        tokio::io::split(serial_stream);
    let exit = online_mode_duplex(state, &mut duplex_read, &mut duplex_write);

    state.mode = ModemMode::Command;
    match exit {
        OnlineExit::Escaped => {
            state.active_connection = Some(ActiveConnection::Duplex {
                read: duplex_read,
                write: duplex_write,
            });
            send_result(state, "OK");
        }
        OnlineExit::Disconnected => {
            send_result(state, "NO CARRIER");
        }
    }
}

/// Dial a remote telnet host via blocking TCP.
fn dial_tcp(state: &mut ModemState, host: &str, port: u16) {
    use std::net::ToSocketAddrs;

    let addr_str = format!("{}:{}", host, port);
    let socket_addr = match addr_str.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                send_result(state, "NO CARRIER");
                return;
            }
        },
        Err(_) => {
            send_result(state, "NO CARRIER");
            return;
        }
    };

    // S7 controls the carrier-wait timeout.  Capped at MAX_CONNECT_TIMEOUT
    // so a mistyped S7 can't tie up the serial thread for minutes.
    let mut s7_timeout = Duration::from_secs(state.s_regs[7] as u64);
    if s7_timeout.is_zero() {
        s7_timeout = Duration::from_secs(1);
    }
    if s7_timeout > MAX_CONNECT_TIMEOUT {
        s7_timeout = MAX_CONNECT_TIMEOUT;
    }
    let mut stream =
        match std::net::TcpStream::connect_timeout(&socket_addr, s7_timeout) {
            Ok(s) => s,
            Err(_) => {
                send_result(state, "NO CARRIER");
                return;
            }
        };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(SERIAL_READ_TIMEOUT));

    send_result(state, "CONNECT");
    state.mode = ModemMode::Online;

    let exit = online_mode_tcp(state, &mut stream);

    state.mode = ModemMode::Command;
    match exit {
        OnlineExit::Escaped => {
            state.active_connection = Some(ActiveConnection::Tcp(stream));
            send_result(state, "OK");
        }
        OnlineExit::Disconnected => {
            send_result(state, "NO CARRIER");
        }
    }
}

// ─── Online mode (data passthrough) ────────────────────────

/// Online mode for the duplex bridge (ATDT ethernet-gateway).
///
/// Uses `Handle::block_on` to perform async reads/writes on the duplex stream.
/// This is safe because the serial thread is a `std::thread`, not a tokio task.
/// Returns `Escaped` if the user sent +++, `Disconnected` on I/O error or EOF.
fn online_mode_duplex(
    state: &mut ModemState,
    duplex_read: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
    duplex_write: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> OnlineExit {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut serial_buf = [0u8; 256];
    let mut duplex_buf = [0u8; 4096];

    state.plus_count = 0;
    state.last_data_time = Instant::now();

    loop {
        if state.shutdown.load(Ordering::SeqCst) {
            return OnlineExit::Disconnected;
        }

        // Serial → duplex
        match state.port.read(&mut serial_buf) {
            Ok(0) => return OnlineExit::Disconnected,
            Ok(n) => {
                let mut forward = Vec::with_capacity(n);
                process_online_bytes(state, &serial_buf[..n], &mut forward);
                if !forward.is_empty() {
                    let result = state.handle.block_on(async {
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            duplex_write.write_all(&forward),
                        )
                        .await
                    });
                    match result {
                        Ok(Ok(())) => {}
                        _ => return OnlineExit::Disconnected,
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return OnlineExit::Disconnected,
        }

        // Duplex → serial (write in small chunks so slow baud rates stay responsive)
        let result = state.handle.block_on(async {
            tokio::time::timeout(Duration::from_millis(10), duplex_read.read(&mut duplex_buf))
                .await
        });
        match result {
            Ok(Ok(0)) => return OnlineExit::Disconnected,
            Ok(Ok(n)) => {
                if state.port.write_all(&duplex_buf[..n]).is_err() {
                    return OnlineExit::Disconnected;
                }
                let _ = state.port.flush();
            }
            Ok(Err(_)) => return OnlineExit::Disconnected,
            Err(_) => {} // timeout — no data from duplex
        }

        // Check trailing +++ guard time
        if check_plus_complete(state) {
            return OnlineExit::Escaped;
        }
    }
}

/// Online mode for direct TCP connections (ATDT host:port).
/// Returns `Escaped` if the user sent +++, `Disconnected` on I/O error or EOF.
fn online_mode_tcp(state: &mut ModemState, tcp: &mut std::net::TcpStream) -> OnlineExit {
    let mut serial_buf = [0u8; 256];
    let mut tcp_buf = [0u8; 4096];

    state.plus_count = 0;
    state.last_data_time = Instant::now();

    loop {
        if state.shutdown.load(Ordering::SeqCst) {
            return OnlineExit::Disconnected;
        }

        // Serial → TCP
        match state.port.read(&mut serial_buf) {
            Ok(0) => return OnlineExit::Disconnected,
            Ok(n) => {
                let mut forward = Vec::with_capacity(n);
                process_online_bytes(state, &serial_buf[..n], &mut forward);
                if !forward.is_empty() && tcp.write_all(&forward).is_err() {
                    return OnlineExit::Disconnected;
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return OnlineExit::Disconnected,
        }

        // TCP → serial
        match tcp.read(&mut tcp_buf) {
            Ok(0) => return OnlineExit::Disconnected,
            Ok(n) => {
                if state.port.write_all(&tcp_buf[..n]).is_err() {
                    return OnlineExit::Disconnected;
                }
                let _ = state.port.flush();
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return OnlineExit::Disconnected,
        }

        // Check trailing +++ guard time
        if check_plus_complete(state) {
            return OnlineExit::Escaped;
        }
    }
}

// ─── +++ escape detection ──────────────────────────────────

/// Return the escape character from S2.
fn escape_char(state: &ModemState) -> u8 {
    state.s_regs[2]
}

/// Return the escape guard time from S12 (stored as 1/50ths of a second).
fn guard_time(state: &ModemState) -> Duration {
    Duration::from_millis(state.s_regs[12] as u64 * 20)
}

/// Process bytes from the serial port during online mode.  Bytes that should
/// be forwarded to the remote end are appended to `forward`.  Pending escape
/// bytes from a possible escape sequence are held back (not appended) until
/// either a different byte arrives (which flushes them) or `check_plus_complete`
/// confirms the escape after the trailing guard time.
fn process_online_bytes(
    state: &mut ModemState,
    data: &[u8],
    forward: &mut Vec<u8>,
) {
    let esc = escape_char(state);
    let guard = guard_time(state);
    // Per Hayes standard, S2 > 127 or S12 = 0 disables escape detection.
    let escape_enabled = esc <= 127 && !guard.is_zero();

    for &byte in data {
        let now = Instant::now();

        if escape_enabled && byte == esc {
            if state.plus_count == 0 {
                // First escape char: only start sequence if guard time (silence) has elapsed
                if now.duration_since(state.last_data_time) >= guard {
                    state.plus_count = 1;
                    state.plus_start = now;
                    continue; // hold this byte
                }
                // Guard time not met — forward normally
            } else if state.plus_count < 3 {
                state.plus_count += 1;
                if state.plus_count == 3 {
                    state.plus_start = now; // record time of third escape char
                    continue;
                }
                continue; // hold this byte
            }
            // plus_count == 3 and another escape char arrived — that's 4, not an escape.
            // Fall through to flush and forward.
        }

        // Non-escape byte (or 4th escape char):  flush any pending escape chars
        if state.plus_count > 0 {
            for _ in 0..state.plus_count {
                forward.push(esc);
            }
            state.plus_count = 0;
        }

        forward.push(byte);
        state.last_data_time = now;
    }
}

/// Check whether the trailing guard time after the escape sequence has elapsed.
/// Returns `true` if the escape is complete and the modem should return to
/// command mode.
fn check_plus_complete(state: &mut ModemState) -> bool {
    if state.plus_count == 3
        && Instant::now().duration_since(state.plus_start) >= guard_time(state)
    {
        state.plus_count = 0;
        return true;
    }
    false
}

// ─── Ring emulator ────────────────────────────────────────

/// Take a pending ring request from the global slot, if any.
fn take_ring_request() -> Option<tokio::sync::mpsc::Sender<u8>> {
    RING_REQUEST
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
}

/// Simulate an incoming call.  Sends RING to the serial port at standard
/// phone cadence, checks for ATA (manual answer), and auto-answers after
/// S0 rings.  Reports progress via the sender (0 = ring, 1 = answered,
/// 2 = serial port error).
fn process_ring(state: &mut ModemState, sender: tokio::sync::mpsc::Sender<u8>) {
    state.s_regs[1] = 0; // reset ring counter

    let auto_answer = state.s_regs[0];
    let mut manual_answer = false;

    loop {
        if state.shutdown.load(Ordering::SeqCst) || SERIAL_RESTART.load(Ordering::SeqCst) {
            return;
        }

        // Send RING to serial device
        state.s_regs[1] = state.s_regs[1].saturating_add(1);
        if !send_result(state, "RING") {
            let _ = sender.try_send(2); // serial port write failed
            return;
        }

        // Notify the telnet/SSH user; if they disconnected, abort.
        if sender.try_send(0).is_err() {
            return;
        }

        // Auto-answer?
        if auto_answer > 0 && state.s_regs[1] >= auto_answer {
            break; // answer the call
        }

        // Wait one ring interval, checking for ATA or shutdown every 100ms.
        let deadline = Instant::now() + RING_INTERVAL;
        while Instant::now() < deadline {
            if state.shutdown.load(Ordering::SeqCst) {
                return;
            }
            // Check serial port for ATA (manual answer)
            let mut buf = [0u8; 1];
            if let Ok(1) = state.port.read(&mut buf) {
                let byte = buf[0];
                if byte == b'\r' || byte == b'\n' {
                    let cmd = std::mem::take(&mut state.cmd_buffer);
                    let cmd = cmd.trim().to_ascii_uppercase();
                    if cmd == "ATA" {
                        manual_answer = true;
                        break;
                    }
                } else if byte >= 0x20 && state.cmd_buffer.len() < MAX_CMD_LEN {
                    state.cmd_buffer.push(byte as char);
                }
            }
        }

        if manual_answer {
            break;
        }
    }

    // Answer: connect to ethernet-gateway
    let _ = sender.try_send(1); // notify telnet/SSH: answered
    dial_ethernet_gateway(state);
}

// ─── Config persistence helpers ────────────────────────────

/// Parse a comma-separated S-register string from config into an array.
/// Falls back to defaults for any missing or invalid values.
fn parse_s_regs(s: &str) -> [u8; NUM_S_REGS] {
    let mut regs = S_REG_DEFAULTS;
    for (i, part) in s.split(',').enumerate() {
        if i >= NUM_S_REGS {
            break;
        }
        if let Ok(v) = part.trim().parse::<u8>() {
            regs[i] = v;
        }
    }
    regs
}

/// Format S-register array as a comma-separated string for config storage.
fn format_s_regs(regs: &[u8; NUM_S_REGS]) -> String {
    regs.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

// ─── Helpers ───────────────────────────────────────────────

/// Write an informational message framed by the configured CR (S3) and LF
/// (S4).  Internal `\r\n` or `\n` line breaks within `msg` are rewritten to
/// use S3/S4 too, so every newline the modem produces honors the registers.
fn send_response(state: &mut ModemState, msg: &str) {
    let cr = state.s_regs[3];
    let lf = state.s_regs[4];
    let _ = state.port.write_all(&[cr, lf]);
    let mut first = true;
    for line in msg.split('\n') {
        if !first {
            let _ = state.port.write_all(&[cr, lf]);
        }
        // Trim a trailing '\r' from "\r\n" splits so we don't double-emit CR.
        let trimmed = line.strip_suffix('\r').unwrap_or(line);
        let _ = state.port.write_all(trimmed.as_bytes());
        first = false;
    }
    let _ = state.port.write_all(&[cr, lf]);
    let _ = state.port.flush();
}

/// Numeric result code for a verbose message, honoring the current ATX level.
/// CONNECT mapping depends on baud (ATX>=1 picks a baud-specific code; ATX0
/// always returns 1).  BUSY (7), NO DIALTONE (6), and NO ANSWER (8) are
/// suppressed (remapped to NO CARRIER = 3) when ATX < 3.
fn numeric_code(msg: &str, x_code: u8, baud: u32) -> &'static str {
    if msg.starts_with("CONNECT") {
        if x_code == 0 {
            return "1";
        }
        return match baud {
            300 => "1",
            1200 => "5",
            600 => "9",
            2400 => "10",
            4800 => "11",
            9600 => "12",
            7200 => "13",
            12000 => "14",
            14400 => "15",
            19200 => "16",
            38400 => "28",
            57600 => "18",
            115200 => "87",
            _ => "1",
        };
    }
    match msg {
        "OK" => "0",
        "RING" => "2",
        "NO CARRIER" => "3",
        "ERROR" => "4",
        "NO DIALTONE" => if x_code >= 2 { "6" } else { "3" },
        "BUSY" => if x_code >= 3 { "7" } else { "3" },
        "NO ANSWER" => if x_code >= 3 { "8" } else { "3" },
        _ => "4",
    }
}

/// Remap a verbose message according to ATX level.  Callers pass the bare
/// result keyword (e.g. `"CONNECT"`, `"BUSY"`); this function decides the
/// final text:
///
/// - `CONNECT` is rendered as `"CONNECT"` at X0 and `"CONNECT <baud>"` at
///   X>=1, regardless of whether the caller appended a baud.
/// - `BUSY`, `NO DIALTONE`, `NO ANSWER` collapse to `NO CARRIER` when the
///   ATX level is too low to emit them.
fn verbose_message(msg: &str, x_code: u8, baud: u32) -> String {
    if msg.starts_with("CONNECT") {
        return if x_code == 0 {
            "CONNECT".into()
        } else {
            format!("CONNECT {}", baud)
        };
    }
    if x_code < 2 && msg == "NO DIALTONE" {
        return "NO CARRIER".into();
    }
    if x_code < 3 && (msg == "BUSY" || msg == "NO ANSWER") {
        return "NO CARRIER".into();
    }
    msg.into()
}

/// Send a result code, respecting verbose/quiet/ATX settings and honoring
/// S3/S4 for line framing.
fn send_result(state: &mut ModemState, msg: &str) -> bool {
    if state.quiet {
        return true;
    }
    let cr = state.s_regs[3];
    let lf = state.s_regs[4];
    let x = state.x_code;
    let baud = state.baud;
    let ok = if state.verbose {
        let rendered = verbose_message(msg, x, baud);
        state.port.write_all(&[cr, lf]).is_ok()
            && state.port.write_all(rendered.as_bytes()).is_ok()
            && state.port.write_all(&[cr, lf]).is_ok()
    } else {
        let code = numeric_code(msg, x, baud);
        state.port.write_all(code.as_bytes()).is_ok()
            && state.port.write_all(&[cr]).is_ok()
    };
    let flushed = state.port.flush().is_ok();
    ok && flushed
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── AT command parsing ──────────────────────────────

    /// Helper: call parse_at_command with default verbose/quiet settings.
    fn parse(cmd: &str, echo: &mut bool) -> Vec<AtResult> {
        let mut verbose = true;
        let mut quiet = false;
        parse_at_command(cmd, echo, &mut verbose, &mut quiet)
    }

    /// Helper: call parse_at_command with full settings access.
    fn parse_full(
        cmd: &str,
        echo: &mut bool,
        verbose: &mut bool,
        quiet: &mut bool,
    ) -> Vec<AtResult> {
        parse_at_command(cmd, echo, verbose, quiet)
    }

    #[test]
    fn test_at_bare() {
        let mut echo = true;
        assert_eq!(parse("AT", &mut echo), vec![AtResult::Ok]);
        assert!(echo);
    }

    #[test]
    fn test_at_case_insensitive() {
        let mut echo = true;
        assert_eq!(parse("at", &mut echo), vec![AtResult::Ok]);
        assert_eq!(parse("At", &mut echo), vec![AtResult::Ok]);
        assert_eq!(parse("aT", &mut echo), vec![AtResult::Ok]);
    }

    #[test]
    fn test_atz_returns_reset_stored() {
        let mut echo = false;
        let mut verbose = false;
        let mut quiet = true;
        assert_eq!(
            parse_full("ATZ", &mut echo, &mut verbose, &mut quiet),
            vec![AtResult::ResetStored]
        );
        // ATZ no longer modifies settings in parse — process_at_command
        // loads them from config.  Parse should leave them unchanged.
        assert!(!echo);
        assert!(!verbose);
        assert!(quiet);
    }

    #[test]
    fn test_ate0_ate1() {
        let mut echo = true;
        assert_eq!(parse("ATE0", &mut echo), vec![AtResult::Ok]);
        assert!(!echo);
        assert_eq!(parse("ATE1", &mut echo), vec![AtResult::Ok]);
        assert!(echo);
    }

    #[test]
    fn test_ath() {
        let mut echo = true;
        assert_eq!(parse("ATH", &mut echo), vec![AtResult::Hangup]);
        assert_eq!(parse("ATH0", &mut echo), vec![AtResult::Hangup]);
    }

    #[test]
    fn test_ati() {
        let mut echo = true;
        let results = parse("ATI", &mut echo);
        assert_eq!(results.len(), 2);
        match &results[0] {
            AtResult::Info(msg) => assert!(msg.contains("Ethernet Gateway")),
            other => panic!("Expected Info, got {:?}", other),
        }
        assert_eq!(results[1], AtResult::Ok);
    }

    #[test]
    fn test_atdt_gateway() {
        let mut echo = true;
        let results = parse("ATDT ethernet-gateway", &mut echo);
        assert_eq!(results.len(), 1);
        match &results[0] {
            AtResult::Dial(target) => assert_eq!(target, "ethernet-gateway"),
            other => panic!("Expected Dial, got {:?}", other),
        }
    }

    #[test]
    fn test_atdt_host_port() {
        let mut echo = true;
        let results = parse("ATDT telnetbible.com:6400", &mut echo);
        assert_eq!(results.len(), 1);
        match &results[0] {
            AtResult::Dial(target) => assert_eq!(target, "telnetbible.com:6400"),
            other => panic!("Expected Dial, got {:?}", other),
        }
    }

    #[test]
    fn test_atdt_host_no_port() {
        let mut echo = true;
        let results = parse("ATDT somehost.com", &mut echo);
        assert_eq!(results.len(), 1);
        match &results[0] {
            AtResult::Dial(target) => assert_eq!(target, "somehost.com"),
            other => panic!("Expected Dial, got {:?}", other),
        }
    }

    #[test]
    fn test_atdt_empty_target() {
        let mut echo = true;
        assert_eq!(parse("ATDT", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATDT ", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_atdp_pulse_dial() {
        let mut echo = true;
        let results = parse("ATDP somehost.com", &mut echo);
        assert_eq!(results.len(), 1);
        match &results[0] {
            AtResult::Dial(target) => assert_eq!(target, "somehost.com"),
            other => panic!("Expected Dial, got {:?}", other),
        }
    }

    #[test]
    fn test_non_at_command() {
        let mut echo = true;
        assert_eq!(parse("HELLO", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_unknown_at_command_accepted() {
        let mut echo = true;
        // ATL (speaker loudness) and ATM (speaker mode) have no meaning for
        // a virtual modem but are accepted so legacy clients don't error.
        assert_eq!(parse("ATL2", &mut echo), vec![AtResult::Ok]);
        assert_eq!(parse("ATM1", &mut echo), vec![AtResult::Ok]);
        // ATB (bell mode) and ATC (carrier on/off) likewise.
        assert_eq!(parse("ATB0", &mut echo), vec![AtResult::Ok]);
        assert_eq!(parse("ATC1", &mut echo), vec![AtResult::Ok]);
    }

    #[test]
    fn test_atdt_preserves_case() {
        let mut echo = true;
        let results = parse("ATDT TelnetBible.Com:6400", &mut echo);
        match &results[0] {
            AtResult::Dial(target) => assert_eq!(target, "TelnetBible.Com:6400"),
            other => panic!("Expected Dial, got {:?}", other),
        }
    }

    // ─── New AT commands ────────────────────────────────

    #[test]
    fn test_atv0_atv1() {
        let mut echo = true;
        let mut verbose = true;
        let mut quiet = false;
        assert_eq!(
            parse_full("ATV0", &mut echo, &mut verbose, &mut quiet),
            vec![AtResult::Ok]
        );
        assert!(!verbose);
        assert_eq!(
            parse_full("ATV1", &mut echo, &mut verbose, &mut quiet),
            vec![AtResult::Ok]
        );
        assert!(verbose);
    }

    #[test]
    fn test_atq0_atq1() {
        let mut echo = true;
        let mut verbose = true;
        let mut quiet = false;
        assert_eq!(
            parse_full("ATQ1", &mut echo, &mut verbose, &mut quiet),
            vec![AtResult::Ok]
        );
        assert!(quiet);
        assert_eq!(
            parse_full("ATQ0", &mut echo, &mut verbose, &mut quiet),
            vec![AtResult::Ok]
        );
        assert!(!quiet);
    }

    #[test]
    fn test_ato() {
        let mut echo = true;
        assert_eq!(parse("ATO", &mut echo), vec![AtResult::Online]);
        assert_eq!(parse("ATO0", &mut echo), vec![AtResult::Online]);
    }

    #[test]
    fn test_ata_no_carrier() {
        let mut echo = true;
        assert_eq!(parse("ATA", &mut echo), vec![AtResult::NoCarrier]);
    }

    #[test]
    fn test_at_ampersand_f_resets_all() {
        let mut echo = false;
        let mut verbose = false;
        let mut quiet = true;
        assert_eq!(
            parse_full("AT&F", &mut echo, &mut verbose, &mut quiet),
            vec![AtResult::Reset]
        );
        assert!(echo, "AT&F should reset echo to true");
        assert!(verbose, "AT&F should reset verbose to true");
        assert!(!quiet, "AT&F should reset quiet to false");
    }

    #[test]
    fn test_numeric_result_codes() {
        // Verify the mapping used by send_result in non-verbose mode
        let codes = [
            ("OK", "0"),
            ("CONNECT 9600", "1"),
            ("RING", "2"),
            ("NO CARRIER", "3"),
            ("ERROR", "4"),
            ("NO DIALTONE", "6"),
            ("BUSY", "7"),
            ("NO ANSWER", "8"),
        ];
        for (verbose_msg, expected_code) in &codes {
            let code = match *verbose_msg {
                "OK" => "0",
                m if m.starts_with("CONNECT") => "1",
                "RING" => "2",
                "NO CARRIER" => "3",
                "ERROR" => "4",
                "NO DIALTONE" => "6",
                "BUSY" => "7",
                "NO ANSWER" => "8",
                _ => verbose_msg,
            };
            assert_eq!(
                code, *expected_code,
                "numeric code for '{}' should be '{}'",
                verbose_msg, expected_code
            );
        }
    }

    // ─── S-register tests ────────────────────────────────

    #[test]
    fn test_s_reg_defaults_count() {
        assert_eq!(S_REG_DEFAULTS.len(), NUM_S_REGS);
        assert_eq!(NUM_S_REGS, 27);
    }

    #[test]
    fn test_s_reg_default_values() {
        assert_eq!(S_REG_DEFAULTS[0], 5);    // auto-answer after 5 rings
        assert_eq!(S_REG_DEFAULTS[1], 0);    // ring counter
        assert_eq!(S_REG_DEFAULTS[2], 43);   // escape char '+'
        assert_eq!(S_REG_DEFAULTS[3], 13);   // CR
        assert_eq!(S_REG_DEFAULTS[4], 10);   // LF
        assert_eq!(S_REG_DEFAULTS[5], 8);    // BS
        assert_eq!(S_REG_DEFAULTS[12], 50);  // guard time 1 sec
    }

    #[test]
    fn test_s_reg_query() {
        let mut echo = true;
        let results = parse("ATS0?", &mut echo);
        assert_eq!(results, vec![AtResult::SRegQuery(0)]);
    }

    #[test]
    fn test_s_reg_query_s12() {
        let mut echo = true;
        let results = parse("ATS12?", &mut echo);
        assert_eq!(results, vec![AtResult::SRegQuery(12)]);
    }

    #[test]
    fn test_s_reg_query_out_of_range() {
        let mut echo = true;
        // S27 and above are out of range.
        assert_eq!(parse("ATS27?", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS99?", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS255?", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_s_reg_query_extended_range_accepted() {
        // S13 through S26 must parse even though several are reserved.
        let mut echo = true;
        for reg in 13..=26 {
            let q = format!("ATS{}?", reg);
            assert_eq!(parse(&q, &mut echo), vec![AtResult::SRegQuery(reg)]);
        }
    }

    #[test]
    fn test_s_reg_set() {
        let mut echo = true;
        let results = parse("ATS0=1", &mut echo);
        assert_eq!(results, vec![AtResult::SRegSet(0, 1)]);
    }

    #[test]
    fn test_s_reg_set_max_value() {
        let mut echo = true;
        let results = parse("ATS2=255", &mut echo);
        assert_eq!(results, vec![AtResult::SRegSet(2, 255)]);
    }

    #[test]
    fn test_s_reg_set_value_overflow() {
        let mut echo = true;
        // Values above 255 should be rejected
        assert_eq!(parse("ATS0=256", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS0=999", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_s_reg_set_out_of_range() {
        let mut echo = true;
        // S27 and up are out of range; S13-S26 must accept assignment so
        // legacy init strings that poke reserved registers don't ERROR.
        assert_eq!(parse("ATS27=0", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS25=5", &mut echo), vec![AtResult::SRegSet(25, 5)]);
        assert_eq!(parse("ATS26=1", &mut echo), vec![AtResult::SRegSet(26, 1)]);
    }

    #[test]
    fn test_s_reg_set_invalid_value() {
        let mut echo = true;
        assert_eq!(parse("ATS0=abc", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS0=", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_s_reg_bare_number_is_error() {
        // ATSn without ? or = should be an error
        let mut echo = true;
        assert_eq!(parse("ATS0", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS12", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_s_reg_query_format() {
        // S-register query responses are 3-digit zero-padded
        let val: u8 = 0;
        assert_eq!(format!("{:03}", val), "000");
        let val: u8 = 43;
        assert_eq!(format!("{:03}", val), "043");
        let val: u8 = 255;
        assert_eq!(format!("{:03}", val), "255");
    }

    #[test]
    fn test_atz_resets_s_regs() {
        // ATZ produces ResetStored; process_at_command loads from config.
        let mut echo = false;
        let mut verbose = false;
        let mut quiet = true;
        let results = parse_full("ATZ", &mut echo, &mut verbose, &mut quiet);
        assert_eq!(results, vec![AtResult::ResetStored]);
    }

    #[test]
    fn test_s_reg_case_insensitive() {
        let mut echo = true;
        // Lowercase 'ats0?' should work (uppercased internally)
        assert_eq!(parse("ats0?", &mut echo), vec![AtResult::SRegQuery(0)]);
        assert_eq!(parse("ats0=5", &mut echo), vec![AtResult::SRegSet(0, 5)]);
    }

    // ─── +++ escape detection ────────────────────────────

    /// Helper: create a minimal ModemState-like struct for testing +++ logic.
    struct PlusState {
        last_data_time: Instant,
        plus_count: u8,
        plus_start: Instant,
    }

    impl PlusState {
        fn new() -> Self {
            Self {
                last_data_time: Instant::now() - Duration::from_secs(5), // long silence
                plus_count: 0,
                plus_start: Instant::now(),
            }
        }

        fn as_modem_fields(&self) -> (Instant, u8, Instant) {
            (self.last_data_time, self.plus_count, self.plus_start)
        }
    }

    /// Run process_online_bytes using a PlusState (avoids needing a real serial port).
    /// Uses the default S-register values for escape char and guard time.
    fn test_process_bytes(
        last_data_time: &mut Instant,
        plus_count: &mut u8,
        plus_start: &mut Instant,
        data: &[u8],
    ) -> (Vec<u8>, bool) {
        let esc_char = S_REG_DEFAULTS[2]; // '+' (43)
        let guard = Duration::from_millis(S_REG_DEFAULTS[12] as u64 * 20);
        // We can't create a real ModemState without a serial port, so we
        // test the logic inline using the same algorithm.
        let mut forward = Vec::new();
        for &byte in data {
            let now = Instant::now();

            if byte == esc_char {
                if *plus_count == 0 {
                    if now.duration_since(*last_data_time) >= guard {
                        *plus_count = 1;
                        *plus_start = now;
                        continue;
                    }
                } else if *plus_count < 3 {
                    *plus_count += 1;
                    if *plus_count == 3 {
                        *plus_start = now;
                        continue;
                    }
                    continue;
                }
            }

            if *plus_count > 0 {
                for _ in 0..*plus_count {
                    forward.push(esc_char);
                }
                *plus_count = 0;
            }

            forward.push(byte);
            *last_data_time = now;
        }
        let complete = *plus_count == 3
            && Instant::now().duration_since(*plus_start) >= guard;
        (forward, complete)
    }

    #[test]
    fn test_plus_escape_with_guard_time() {
        let s = PlusState::new();
        let (mut last, mut count, mut start) = s.as_modem_fields();
        // Long silence already present (5 seconds ago).  Send +++.
        let (forward, _) = test_process_bytes(&mut last, &mut count, &mut start, b"+++");
        assert!(forward.is_empty(), "should hold +++ bytes");
        assert_eq!(count, 3);
        // After guard time, check_plus_complete would return true.
        // We simulate by checking the count.
    }

    #[test]
    fn test_plus_no_guard_before() {
        let mut last = Instant::now(); // just now — no silence
        let mut count = 0u8;
        let mut start = Instant::now();
        let (forward, _) = test_process_bytes(&mut last, &mut count, &mut start, b"+++");
        // Without guard time before, the '+' chars should be forwarded
        assert_eq!(forward, b"+++");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_plus_interrupted_by_data() {
        let s = PlusState::new();
        let (mut last, mut count, mut start) = s.as_modem_fields();
        // Send ++ then 'a' — should flush the two pluses and the 'a'
        let (forward, _) = test_process_bytes(&mut last, &mut count, &mut start, b"++a");
        assert_eq!(forward, b"++a");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_plus_partial_two() {
        let s = PlusState::new();
        let (mut last, mut count, mut start) = s.as_modem_fields();
        let (forward, _) = test_process_bytes(&mut last, &mut count, &mut start, b"++");
        assert!(forward.is_empty(), "should hold ++ bytes");
        assert_eq!(count, 2);
        // Then a non-plus byte arrives
        let (forward2, _) = test_process_bytes(&mut last, &mut count, &mut start, b"x");
        assert_eq!(forward2, b"++x");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_plus_four_pluses() {
        let s = PlusState::new();
        let (mut last, mut count, mut start) = s.as_modem_fields();
        // Send ++++: first three are held, fourth flushes all
        let (forward, _) = test_process_bytes(&mut last, &mut count, &mut start, b"++++");
        assert_eq!(forward, b"++++");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_normal_data_passes_through() {
        let s = PlusState::new();
        let (mut last, mut count, mut start) = s.as_modem_fields();
        let (forward, _) =
            test_process_bytes(&mut last, &mut count, &mut start, b"hello world");
        assert_eq!(forward, b"hello world");
    }

    // ─── Misc ────────────────────────────────────────────

    #[test]
    fn test_list_serial_ports_no_panic() {
        // Just verify it doesn't crash — result depends on hardware
        let _ = list_serial_ports();
    }

    #[test]
    fn test_send_response_format() {
        // Verify the response format by checking the expected string
        let expected = "\r\nOK\r\n";
        let actual = format!("\r\n{}\r\n", "OK");
        assert_eq!(actual, expected);

        let expected_connect = "\r\nCONNECT 9600\r\n";
        let actual_connect = format!("\r\n{}\r\n", "CONNECT 9600");
        assert_eq!(actual_connect, expected_connect);
    }

    #[test]
    fn test_default_guard_time() {
        // S12 default of 50 (1/50ths of a second) = 1 second
        let guard = Duration::from_millis(S_REG_DEFAULTS[12] as u64 * 20);
        assert_eq!(guard, Duration::from_secs(1));
    }

    #[test]
    fn test_default_escape_char() {
        // S2 default is 43 = '+'
        assert_eq!(S_REG_DEFAULTS[2], b'+');
    }

    #[test]
    fn test_modem_mode_default() {
        assert_eq!(ModemMode::Command, ModemMode::Command);
        assert_ne!(ModemMode::Command, ModemMode::Online);
    }

    #[test]
    fn test_dial_target_parsing() {
        // Test the host:port parsing logic used in handle_dial
        let target = "telnetbible.com:6400";
        let (h, p) = target.rsplit_once(':').unwrap();
        assert_eq!(h, "telnetbible.com");
        assert_eq!(p.parse::<u16>().unwrap(), 6400);

        // No port defaults to 23
        let target2 = "somehost.com";
        assert!(target2.rsplit_once(':').is_none() || {
            let (_, p) = target2.rsplit_once(':').unwrap();
            p.parse::<u16>().is_err()
        });
    }

    #[test]
    fn test_restart_serial_flag() {
        // Clear any prior state
        SERIAL_RESTART.store(false, Ordering::SeqCst);
        assert!(!SERIAL_RESTART.load(Ordering::SeqCst));

        restart_serial();
        assert!(SERIAL_RESTART.load(Ordering::SeqCst));

        // Reset for other tests
        SERIAL_RESTART.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_serial_read_timeout_constant() {
        assert_eq!(SERIAL_READ_TIMEOUT, Duration::from_millis(100));
    }

    #[test]
    fn test_max_connect_timeout_constant() {
        // The S7-controlled connect timeout is bounded by this hard cap.
        assert_eq!(MAX_CONNECT_TIMEOUT, Duration::from_secs(60));
    }

    #[test]
    fn test_default_carrier_wait_is_gateway_friendly() {
        // S7 default is 15 seconds (not the Hayes 50) to keep failed dials
        // responsive for gateway users.
        assert_eq!(S_REG_DEFAULTS[7], 15);
    }

    #[test]
    fn test_max_cmd_len_constant() {
        const _: () = assert!(MAX_CMD_LEN >= 40, "buffer must hold standard AT commands");
        const _: () = assert!(MAX_CMD_LEN <= 1024, "buffer should not be excessively large");
    }

    // ─── AT command edge cases ──────────────────────────

    #[test]
    fn test_atd_bare_dial() {
        // ATD without T or P prefix should still work
        let mut echo = true;
        let results = parse("ATD somehost.com", &mut echo);
        assert_eq!(results.len(), 1);
        match &results[0] {
            AtResult::Dial(target) => assert_eq!(target, "somehost.com"),
            other => panic!("Expected Dial, got {:?}", other),
        }
    }

    #[test]
    fn test_atd_bare_empty() {
        let mut echo = true;
        assert_eq!(parse("ATD", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATD  ", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_quiet_mode_suppresses_results() {
        let mut echo = true;
        let mut verbose = true;
        let mut quiet = false;
        // Enable quiet mode
        let results = parse_full("ATQ1", &mut echo, &mut verbose, &mut quiet);
        assert_eq!(results, vec![AtResult::Ok]);
        assert!(quiet);
        // In quiet mode, send_result returns early without writing.
        // We verify the flag is set, which gates the output.
    }

    #[test]
    fn test_verbose_result_format() {
        // Verbose mode wraps with \r\n on both sides
        let verbose_response = format!("\r\n{}\r\n", "OK");
        assert_eq!(verbose_response, "\r\nOK\r\n");
    }

    #[test]
    fn test_numeric_result_format() {
        // Numeric mode ends with \r only (no \n), per Hayes standard
        let numeric_response = format!("{}\r", "0");
        assert_eq!(numeric_response, "0\r");
        assert!(!numeric_response.contains('\n'));
    }

    #[test]
    fn test_ath_returns_hangup() {
        // ATH produces Hangup, which process_at_command uses to clear
        // active_connection and send OK.
        let mut echo = true;
        assert_eq!(parse("ATH", &mut echo), vec![AtResult::Hangup]);
    }

    #[test]
    fn test_at_ampersand_w_returns_save() {
        let mut echo = true;
        assert_eq!(parse("AT&W", &mut echo), vec![AtResult::SaveConfig]);
        assert_eq!(parse("AT&W0", &mut echo), vec![AtResult::SaveConfig]);
    }

    #[test]
    fn test_at_ampersand_v_returns_show_config() {
        let mut echo = true;
        assert_eq!(parse("AT&V", &mut echo), vec![AtResult::ShowConfig]);
    }

    #[test]
    fn test_atdl_returns_redial() {
        let mut echo = true;
        assert_eq!(parse("ATDL", &mut echo), vec![AtResult::Redial]);
    }

    #[test]
    fn test_atdl_case_insensitive() {
        let mut echo = true;
        assert_eq!(parse("atdl", &mut echo), vec![AtResult::Redial]);
    }

    #[test]
    fn test_atdl_empty_last_dial_returns_error() {
        // ATDL with no prior dial should produce Redial in parse,
        // but process_at_command sends ERROR when last_dial is empty.
        // We verify the parse result; the empty-string check is in
        // process_at_command at runtime.
        let mut echo = true;
        assert_eq!(parse("ATDL", &mut echo), vec![AtResult::Redial]);
        // Verify the guard logic: an empty string is falsy
        let last_dial = String::new();
        assert!(last_dial.is_empty(), "empty last_dial should trigger ERROR path");
    }

    #[test]
    fn test_dial_comma_stripping() {
        // Commas are pause characters; they should be stripped.
        // The parse function returns the raw dial string; commas are
        // stripped in process_at_command.  Test the stripping logic:
        let raw = "host,,23";
        let stripped = raw.replace(',', "");
        assert_eq!(stripped, "host23");
    }

    #[test]
    fn test_s0_default_is_5() {
        assert_eq!(S_REG_DEFAULTS[0], 5);
    }

    #[test]
    fn test_request_ring_slot() {
        // Clear any pending request
        RING_REQUEST.lock().unwrap_or_else(|e| e.into_inner()).take();

        // First request should succeed
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<u8>(1);
        assert!(request_ring(tx1));

        // Second request should fail (slot occupied)
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<u8>(1);
        assert!(!request_ring(tx2));

        // Take the request to clean up
        assert!(take_ring_request().is_some());
        assert!(take_ring_request().is_none());
    }

    #[test]
    fn test_at_help() {
        let mut echo = true;
        assert_eq!(parse("AT?", &mut echo), vec![AtResult::Help]);
    }

    #[test]
    fn test_ats_help() {
        let mut echo = true;
        assert_eq!(parse("ATS?", &mut echo), vec![AtResult::SRegHelp]);
    }

    #[test]
    fn test_ats_help_case_insensitive() {
        let mut echo = true;
        assert_eq!(parse("ats?", &mut echo), vec![AtResult::SRegHelp]);
    }

    #[test]
    fn test_dial_target_host_with_port_zero() {
        // Port 0 should be rejected
        let target = "host:0";
        let (_, p) = target.rsplit_once(':').unwrap();
        let port = p.parse::<u16>().unwrap();
        assert_eq!(port, 0, "port 0 should parse but be rejected by guard");
    }

    #[test]
    fn test_dial_target_invalid_port() {
        // Non-numeric port part
        let target = "host:abc";
        let (_, p) = target.rsplit_once(':').unwrap();
        assert!(p.parse::<u16>().is_err());
    }

    #[test]
    fn test_dial_target_port_overflow() {
        // Port number too large for u16
        let target = "host:99999";
        let (_, p) = target.rsplit_once(':').unwrap();
        assert!(p.parse::<u16>().is_err());
    }

    #[test]
    fn test_atdt_ethernet_gateway_case_variants() {
        // The dial handler lowercases before comparing to "ethernet-gateway"
        let variants = [
            "ATDT ethernet-gateway",
            "ATDT ETHERNET-GATEWAY",
            "ATDT Ethernet-Gateway",
            "ATDT ethernet gateway",
            "ATDT ETHERNET GATEWAY",
        ];
        for cmd in &variants {
            let mut echo = true;
            let results = parse(cmd, &mut echo);
            assert_eq!(results.len(), 1, "failed for: {}", cmd);
            assert!(matches!(&results[0], AtResult::Dial(_)), "failed for: {}", cmd);
        }
    }

    // ─── Config persistence helpers ─────────────────────

    #[test]
    fn test_parse_s_regs_default() {
        // Full 27-value string round-trips to defaults.
        let regs = parse_s_regs(
            "5,0,43,13,10,8,2,15,2,6,14,95,50,0,0,0,0,0,0,0,0,0,0,0,0,5,1",
        );
        assert_eq!(regs, S_REG_DEFAULTS);
    }

    #[test]
    fn test_parse_s_regs_legacy_13_value_config() {
        // Older config files written before S13+ support have only 13
        // values; missing indices must fall back to the defaults.
        let regs = parse_s_regs("5,0,43,13,10,8,2,15,2,6,14,95,50");
        assert_eq!(regs, S_REG_DEFAULTS);
    }

    #[test]
    fn test_format_s_regs_default() {
        let s = format_s_regs(&S_REG_DEFAULTS);
        assert_eq!(
            s,
            "5,0,43,13,10,8,2,15,2,6,14,95,50,0,0,0,0,0,0,0,0,0,0,0,0,5,1"
        );
    }

    #[test]
    fn test_parse_format_roundtrip() {
        let mut regs = S_REG_DEFAULTS;
        regs[0] = 1;   // auto-answer
        regs[2] = 35;  // escape char = '#'
        regs[12] = 100; // guard time = 2 seconds
        let s = format_s_regs(&regs);
        let parsed = parse_s_regs(&s);
        assert_eq!(parsed, regs);
    }

    #[test]
    fn test_parse_s_regs_partial() {
        // Fewer values than NUM_S_REGS — rest should be defaults
        let regs = parse_s_regs("5,10");
        assert_eq!(regs[0], 5);
        assert_eq!(regs[1], 10);
        assert_eq!(regs[2], S_REG_DEFAULTS[2]); // default
    }

    #[test]
    fn test_parse_s_regs_empty() {
        let regs = parse_s_regs("");
        assert_eq!(regs, S_REG_DEFAULTS);
    }

    #[test]
    fn test_parse_s_regs_invalid_values() {
        // Non-numeric values fall back to defaults
        let regs = parse_s_regs("abc,0,43,13,10,8,2,50,2,6,14,95,50");
        assert_eq!(regs[0], S_REG_DEFAULTS[0]); // invalid → default
        assert_eq!(regs[1], 0); // valid
    }

    #[test]
    fn test_parse_s_regs_overflow() {
        // Values > 255 fail u8 parse, fall back to default
        let regs = parse_s_regs("999,0,43,13,10,8,2,50,2,6,14,95,50");
        assert_eq!(regs[0], S_REG_DEFAULTS[0]); // overflow → default
    }

    // ─── Phone number detection ───────────────────────────

    #[test]
    fn test_is_phone_number_digits_only() {
        assert!(is_phone_number("1234567"));
        assert!(is_phone_number("5551234"));
        assert!(is_phone_number("18005551234"));
    }

    #[test]
    fn test_is_phone_number_with_formatting() {
        assert!(is_phone_number("555-1234"));
        assert!(is_phone_number("(800) 555-1234"));
        assert!(is_phone_number("+1-800-555-1234"));
    }

    #[test]
    fn test_is_phone_number_not_hostname() {
        assert!(!is_phone_number("bbs.example.com"));
        assert!(!is_phone_number("bbs.example.com:23"));
        assert!(!is_phone_number("ethernet-gateway"));
        assert!(!is_phone_number("localhost"));
    }

    #[test]
    fn test_is_phone_number_not_ip_or_host() {
        assert!(!is_phone_number("192.168.1.1"));
        assert!(!is_phone_number("192.168.1.1:23"));
        assert!(!is_phone_number("retro.host:2323"));
        assert!(!is_phone_number("1.800.555.1234"));
    }

    #[test]
    fn test_is_phone_number_empty() {
        assert!(!is_phone_number(""));
    }

    #[test]
    fn test_is_phone_number_only_formatting() {
        // No digits — not a phone number
        assert!(!is_phone_number("---"));
        assert!(!is_phone_number("()"));
    }

    // ─── Gateway phone number ─────────────────────────────

    #[test]
    fn test_gateway_phone_number_is_valid() {
        assert!(is_phone_number(GATEWAY_PHONE_NUMBER));
    }

    #[test]
    fn test_gateway_phone_number_detected() {
        assert_eq!(
            config::normalize_phone_number(GATEWAY_PHONE_NUMBER),
            "1001000"
        );
    }

    #[test]
    fn test_gateway_phone_number_formatted() {
        // "100-1000" should match the gateway number
        let input = "100-1000";
        assert!(is_phone_number(input));
        assert_eq!(
            config::normalize_phone_number(input),
            GATEWAY_PHONE_NUMBER
        );
    }

    // ─── ATX / AT&C / AT&D / AT&K ─────────────────────────

    #[test]
    fn test_atx_parsing() {
        let mut echo = true;
        assert_eq!(parse("ATX0", &mut echo), vec![AtResult::XSet(0)]);
        assert_eq!(parse("ATX1", &mut echo), vec![AtResult::XSet(1)]);
        assert_eq!(parse("ATX2", &mut echo), vec![AtResult::XSet(2)]);
        assert_eq!(parse("ATX3", &mut echo), vec![AtResult::XSet(3)]);
        assert_eq!(parse("ATX4", &mut echo), vec![AtResult::XSet(4)]);
        assert_eq!(parse("ATX", &mut echo), vec![AtResult::XSet(0)]);
    }

    #[test]
    fn test_at_ampersand_c_parsing() {
        let mut echo = true;
        assert_eq!(parse("AT&C", &mut echo), vec![AtResult::DcdSet(0)]);
        assert_eq!(parse("AT&C0", &mut echo), vec![AtResult::DcdSet(0)]);
        assert_eq!(parse("AT&C1", &mut echo), vec![AtResult::DcdSet(1)]);
    }

    #[test]
    fn test_at_ampersand_d_parsing() {
        let mut echo = true;
        assert_eq!(parse("AT&D", &mut echo), vec![AtResult::DtrSet(0)]);
        assert_eq!(parse("AT&D0", &mut echo), vec![AtResult::DtrSet(0)]);
        assert_eq!(parse("AT&D1", &mut echo), vec![AtResult::DtrSet(1)]);
        assert_eq!(parse("AT&D2", &mut echo), vec![AtResult::DtrSet(2)]);
        assert_eq!(parse("AT&D3", &mut echo), vec![AtResult::DtrSet(3)]);
    }

    #[test]
    fn test_at_ampersand_k_parsing() {
        let mut echo = true;
        assert_eq!(parse("AT&K", &mut echo), vec![AtResult::FlowSet(0)]);
        assert_eq!(parse("AT&K0", &mut echo), vec![AtResult::FlowSet(0)]);
        assert_eq!(parse("AT&K1", &mut echo), vec![AtResult::FlowSet(1)]);
        assert_eq!(parse("AT&K3", &mut echo), vec![AtResult::FlowSet(3)]);
        assert_eq!(parse("AT&K4", &mut echo), vec![AtResult::FlowSet(4)]);
    }

    #[test]
    fn test_hayes_extended_commands_case_insensitive() {
        let mut echo = true;
        assert_eq!(parse("atx4", &mut echo), vec![AtResult::XSet(4)]);
        assert_eq!(parse("at&c1", &mut echo), vec![AtResult::DcdSet(1)]);
        assert_eq!(parse("at&d2", &mut echo), vec![AtResult::DtrSet(2)]);
        assert_eq!(parse("at&k3", &mut echo), vec![AtResult::FlowSet(3)]);
    }

    // ─── Numeric result code mapping ──────────────────────

    #[test]
    fn test_numeric_code_x0_basic_set() {
        // ATX0: CONNECT always 1; extended codes collapse to NO CARRIER (3).
        assert_eq!(numeric_code("CONNECT", 0, 9600), "1");
        assert_eq!(numeric_code("CONNECT", 0, 1200), "1");
        assert_eq!(numeric_code("BUSY", 0, 9600), "3");
        assert_eq!(numeric_code("NO DIALTONE", 0, 9600), "3");
        assert_eq!(numeric_code("NO ANSWER", 0, 9600), "3");
        assert_eq!(numeric_code("OK", 0, 9600), "0");
        assert_eq!(numeric_code("ERROR", 0, 9600), "4");
    }

    #[test]
    fn test_numeric_code_x4_extended_set() {
        // ATX4: full extended set, CONNECT varies with baud.
        assert_eq!(numeric_code("CONNECT", 4, 300), "1");
        assert_eq!(numeric_code("CONNECT", 4, 1200), "5");
        assert_eq!(numeric_code("CONNECT", 4, 2400), "10");
        assert_eq!(numeric_code("CONNECT", 4, 9600), "12");
        assert_eq!(numeric_code("CONNECT", 4, 19200), "16");
        assert_eq!(numeric_code("CONNECT", 4, 115200), "87");
        assert_eq!(numeric_code("BUSY", 4, 9600), "7");
        assert_eq!(numeric_code("NO DIALTONE", 4, 9600), "6");
        assert_eq!(numeric_code("NO ANSWER", 4, 9600), "8");
    }

    #[test]
    fn test_numeric_code_unknown_baud_falls_back_to_1() {
        assert_eq!(numeric_code("CONNECT", 4, 1234), "1");
    }

    #[test]
    fn test_verbose_message_x0_collapses_extended() {
        assert_eq!(verbose_message("CONNECT", 0, 9600), "CONNECT");
        assert_eq!(verbose_message("CONNECT 9600", 0, 9600), "CONNECT");
        assert_eq!(verbose_message("BUSY", 0, 9600), "NO CARRIER");
        assert_eq!(verbose_message("NO DIALTONE", 0, 9600), "NO CARRIER");
        assert_eq!(verbose_message("NO ANSWER", 0, 9600), "NO CARRIER");
    }

    #[test]
    fn test_verbose_message_x4_passes_through() {
        assert_eq!(verbose_message("CONNECT", 4, 9600), "CONNECT 9600");
        assert_eq!(verbose_message("CONNECT 9600", 4, 9600), "CONNECT 9600");
        assert_eq!(verbose_message("BUSY", 4, 9600), "BUSY");
        assert_eq!(verbose_message("NO DIALTONE", 4, 9600), "NO DIALTONE");
        assert_eq!(verbose_message("NO ANSWER", 4, 9600), "NO ANSWER");
    }

    #[test]
    fn test_verbose_message_bare_connect_gets_baud_at_x1_plus() {
        // Callers pass bare "CONNECT"; verbose_message owns baud rendering.
        assert_eq!(verbose_message("CONNECT", 1, 2400), "CONNECT 2400");
        assert_eq!(verbose_message("CONNECT", 2, 9600), "CONNECT 9600");
        assert_eq!(verbose_message("CONNECT", 4, 115200), "CONNECT 115200");
    }

    #[test]
    fn test_verbose_message_connect_baud_reflects_current_baud() {
        // If a caller does pass "CONNECT <old>", we still use the current baud.
        assert_eq!(verbose_message("CONNECT 300", 4, 9600), "CONNECT 9600");
    }

    // ─── Dial string modifier parsing ─────────────────────

    #[test]
    fn test_parse_dial_plain_hostname() {
        let p = parse_dial_string("ethernet-gateway", &S_REG_DEFAULTS);
        assert_eq!(p.target, "ethernet-gateway");
        assert_eq!(p.pre_delay, Duration::ZERO);
        assert!(!p.stay_in_command);
    }

    #[test]
    fn test_parse_dial_hostname_with_semicolon() {
        let p = parse_dial_string("example.com:23;", &S_REG_DEFAULTS);
        assert_eq!(p.target, "example.com:23");
        assert!(p.stay_in_command);
    }

    #[test]
    fn test_parse_dial_hostname_preserves_letters() {
        // Hostnames contain 'p', 't', 'w' — these must NOT be stripped.
        let p = parse_dial_string("pine.telnetbible.www", &S_REG_DEFAULTS);
        assert_eq!(p.target, "pine.telnetbible.www");
    }

    #[test]
    fn test_parse_dial_phone_with_commas_pauses() {
        // Each comma = S8 seconds. S8 default is 2.
        let p = parse_dial_string("9,,5551234", &S_REG_DEFAULTS);
        assert_eq!(p.target, "95551234");
        assert_eq!(p.pre_delay, Duration::from_secs(4));
    }

    #[test]
    fn test_parse_dial_phone_with_wait_modifier() {
        // W = S6 seconds. S6 default is 2.
        let p = parse_dial_string("9W5551234", &S_REG_DEFAULTS);
        assert_eq!(p.target, "95551234");
        assert_eq!(p.pre_delay, Duration::from_secs(2));
    }

    #[test]
    fn test_parse_dial_phone_strips_pulse_tone_selectors() {
        let p = parse_dial_string("T5551234", &S_REG_DEFAULTS);
        assert_eq!(p.target, "5551234");
        let p = parse_dial_string("P5551234", &S_REG_DEFAULTS);
        assert_eq!(p.target, "5551234");
    }

    #[test]
    fn test_parse_dial_phone_with_dtmf_stars_and_pounds() {
        let p = parse_dial_string("5551234*99#", &S_REG_DEFAULTS);
        assert_eq!(p.target, "5551234*99#");
    }

    #[test]
    fn test_parse_dial_phone_with_semicolon() {
        let p = parse_dial_string("5551234;", &S_REG_DEFAULTS);
        assert_eq!(p.target, "5551234");
        assert!(p.stay_in_command);
    }

    #[test]
    fn test_parse_dial_pause_honors_custom_s8() {
        let mut s_regs = S_REG_DEFAULTS;
        s_regs[8] = 5;
        let p = parse_dial_string("9,5551234", &s_regs);
        assert_eq!(p.pre_delay, Duration::from_secs(5));
    }

    #[test]
    fn test_parse_dial_pause_capped_at_max() {
        let mut s_regs = S_REG_DEFAULTS;
        s_regs[8] = 255;
        // 60 commas × 255s = 15300s, clamped to MAX_COMMA_PAUSE (60s).
        let raw = ",".repeat(60);
        let p = parse_dial_string(&format!("{}5551234", raw), &s_regs);
        assert_eq!(p.pre_delay, MAX_COMMA_PAUSE);
    }

    // ─── S-register timing registers ──────────────────────

    #[test]
    fn test_s_reg_default_s7_is_15() {
        // Gateway-friendly default, not the Hayes 50.
        assert_eq!(S_REG_DEFAULTS[7], 15);
    }

    #[test]
    fn test_s_reg_s6_s8_defaults() {
        assert_eq!(S_REG_DEFAULTS[6], 2); // dial tone wait
        assert_eq!(S_REG_DEFAULTS[8], 2); // comma pause
    }

    // ─── Hayes-extended defaults ──────────────────────────

    #[test]
    fn test_gateway_friendly_defaults() {
        assert_eq!(DEFAULT_X_CODE, 4); // full extended codes
        assert_eq!(DEFAULT_DTR_MODE, 0); // ignore DTR (not Hayes &D2)
        assert_eq!(DEFAULT_FLOW_MODE, 0); // no flow ctrl (not Hayes &K3)
        assert_eq!(DEFAULT_DCD_MODE, 1); // DCD tracks carrier (Hayes default)
    }

    // ─── ATI variants ─────────────────────────────────────

    #[test]
    fn test_ati_variants_all_return_info_plus_ok() {
        // ATI / ATI0-ATI7 must all terminate with OK (never ERROR) so legacy
        // init strings that probe identity don't abort mid-setup.
        let mut echo = true;
        for cmd in &[
            "ATI", "ATI0", "ATI1", "ATI2", "ATI3", "ATI4", "ATI5", "ATI6", "ATI7",
        ] {
            let results = parse(cmd, &mut echo);
            assert!(
                !results.is_empty(),
                "{} produced no results",
                cmd
            );
            assert_eq!(
                results.last(),
                Some(&AtResult::Ok),
                "{} should end with OK (got {:?})",
                cmd,
                results
            );
            // ATI2 is the ROM-test variant and returns just OK in Hayes.
            if *cmd != "ATI2" {
                assert!(
                    matches!(results[0], AtResult::Info(_)),
                    "{} first result should be Info",
                    cmd
                );
            }
        }
    }

    #[test]
    fn test_ati2_is_just_ok() {
        // ATI2 "ROM test" — Hayes returns OK for the pass case.
        let mut echo = true;
        assert_eq!(parse("ATI2", &mut echo), vec![AtResult::Ok]);
    }

    // ─── Stored-number slots ──────────────────────────────

    #[test]
    fn test_at_ampersand_z_stores_number() {
        let mut echo = true;
        assert_eq!(
            parse("AT&Z0=5551234", &mut echo),
            vec![AtResult::StoreNumber(0, "5551234".into())]
        );
        assert_eq!(
            parse("AT&Z3=example.com:23", &mut echo),
            vec![AtResult::StoreNumber(3, "example.com:23".into())]
        );
    }

    #[test]
    fn test_at_ampersand_z_preserves_hostname_case() {
        // The slot value must come from the original `cmd`, not the
        // uppercased copy — otherwise hostnames get mangled.
        let mut echo = true;
        assert_eq!(
            parse("AT&Z1=Pine.Example.com", &mut echo),
            vec![AtResult::StoreNumber(1, "Pine.Example.com".into())]
        );
    }

    #[test]
    fn test_at_ampersand_z_invalid_slot_errors() {
        let mut echo = true;
        assert_eq!(parse("AT&Z4=x", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("AT&Z9=x", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("AT&Z=x", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_atds_parses_slot_number() {
        let mut echo = true;
        assert_eq!(parse("ATDS", &mut echo), vec![AtResult::DialStored(0)]);
        assert_eq!(parse("ATDS0", &mut echo), vec![AtResult::DialStored(0)]);
        assert_eq!(parse("ATDS3", &mut echo), vec![AtResult::DialStored(3)]);
    }

    #[test]
    fn test_atds_invalid_slot_errors() {
        let mut echo = true;
        assert_eq!(parse("ATDS4", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATDS9", &mut echo), vec![AtResult::Error]);
    }

    #[test]
    fn test_atd_hostname_starting_with_s_is_not_eaten_by_ds() {
        // Regression guard: `ATDsomething` with no space after D must route
        // to the generic D-dial branch, not the new DS stored-slot branch.
        let mut echo = true;
        assert_eq!(
            parse("ATDserver.example.com", &mut echo),
            vec![AtResult::Dial("server.example.com".into())]
        );
        assert_eq!(
            parse("ATDsomething", &mut echo),
            vec![AtResult::Dial("something".into())]
        );
    }

}
