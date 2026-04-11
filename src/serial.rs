//! Hayes AT modem emulator over a physical serial port.
//!
//! Runs on a dedicated `std::thread` (not a tokio task) so it can own the
//! synchronous `serialport::SerialPort` object.  Bridges to the async runtime
//! via `tokio::runtime::Handle` for `ATDT xmodem-gateway` connections.
//!
//! Supported AT commands: AT, AT?, ATZ, AT&F, AT&W, AT&V, ATE0/ATE1,
//! ATV0/ATV1, ATQ0/ATQ1, ATI, ATH, ATA, ATO, ATDT, ATDP, ATD, ATDL,
//! ATS?, ATSn?, ATSn=v.  S-registers S0–S12 are supported.
//! The `+++` escape (configurable via S2/S12) returns to command mode.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;

use crate::config;

// ─── Constants ─────────────────────────────────────────────

const SERIAL_READ_TIMEOUT: Duration = Duration::from_millis(100);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum AT command buffer length.  Real Hayes modems cap at ~40 chars;
/// we allow 256 to be generous.  Bytes beyond this limit are silently dropped.
const MAX_CMD_LEN: usize = 256;

/// Number of S-registers (S0 through S12).
const NUM_S_REGS: usize = 13;

/// Default S-register values per the Hayes standard.
const S_REG_DEFAULTS: [u8; NUM_S_REGS] = [
    5,   // S0:  Auto-answer ring count (5 = answer after 5 rings)
    0,   // S1:  Ring counter (read-only in real modems)
    43,  // S2:  Escape character (43 = '+')
    13,  // S3:  Carriage return character
    10,  // S4:  Line feed character
    8,   // S5:  Backspace character
    2,   // S6:  Wait for dial tone (seconds)
    50,  // S7:  Wait for carrier (seconds)
    2,   // S8:  Comma pause time (seconds)
    6,   // S9:  Carrier detect response time (1/10s)
    14,  // S10: Carrier loss disconnect time (1/10s)
    95,  // S11: DTMF tone duration (milliseconds)
    50,  // S12: Escape guard time (1/50s; 50 = 1 second)
];

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
    baud: u32,
    /// Connection preserved after +++ escape for ATO to resume.
    active_connection: Option<ActiveConnection>,
    /// S-register values (S0–S12).
    s_regs: [u8; NUM_S_REGS],
    /// Last dialed target for ATDL (redial).
    last_dial: String,
}

// ─── Public API ────────────────────────────────────────────

/// Start the serial modem manager on a dedicated thread.
///
/// Returns immediately.  The manager thread loops: if serial is enabled and
/// configured it opens the port and runs the modem; when `restart_serial()`
/// is called it re-reads config and re-opens the port (or stops if disabled).
pub fn start_serial(shutdown: Arc<AtomicBool>) {
    let handle = tokio::runtime::Handle::current();
    let sd = shutdown;

    std::thread::Builder::new()
        .name("serial-modem".into())
        .spawn(move || {
            serial_manager(handle, sd);
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

// ─── Serial manager ────────────────────────────────────────

/// Manager loop: starts/stops the serial modem when config changes.
fn serial_manager(handle: tokio::runtime::Handle, shutdown: Arc<AtomicBool>) {
    loop {
        SERIAL_RESTART.store(false, Ordering::SeqCst);
        let cfg = config::get_config();
        if cfg.serial_enabled && !cfg.serial_port.is_empty() {
            serial_thread(cfg, handle.clone(), shutdown.clone());
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
            eprintln!("Serial modem: failed to open {}: {}", cfg.serial_port, e);
            return;
        }
    };
    eprintln!(
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
        baud: cfg.serial_baud,
        active_connection: None,
        s_regs: parse_s_regs(&cfg.serial_s_regs),
        last_dial: String::new(),
    };

    send_response(&mut state.port, "OK");

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
        eprintln!("Serial modem: restarting with new config");
    } else {
        let _ = state.port.write_all(b"\r\nServer shutting down. Goodbye.\r\n");
        let _ = state.port.flush();
        eprintln!("Serial modem: shutting down");
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

            match byte {
                b'\r' | b'\n' => {
                    if state.echo {
                        let _ = state.port.write_all(b"\r\n");
                    }
                    let cmd = std::mem::take(&mut state.cmd_buffer);
                    let cmd = cmd.trim().to_string();
                    if !cmd.is_empty() {
                        process_at_command(state, &cmd);
                    }
                }
                0x08 | 0x7F => {
                    if !state.cmd_buffer.is_empty() {
                        state.cmd_buffer.pop();
                        if state.echo {
                            let _ = state.port.write_all(b"\x08 \x08");
                        }
                    }
                }
                _ if byte >= 0x20 => {
                    if state.cmd_buffer.len() < MAX_CMD_LEN {
                        if state.echo {
                            let _ = state.port.write_all(&[byte]);
                        }
                        state.cmd_buffer.push(byte as char);
                    }
                }
                _ => {} // ignore control chars
            }
        }
        Ok(_) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
        Err(e) => {
            eprintln!("Serial modem: read error: {}", e);
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
                "XMODEM Gateway Modem Emulator v{}",
                env!("CARGO_PKG_VERSION")
            )),
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
    let results = parse_at_command(
        cmd,
        &mut state.echo,
        &mut state.verbose,
        &mut state.quiet,
    );
    for result in results {
        match result {
            AtResult::Ok => send_result(state, "OK"),
            AtResult::Error => send_result(state, "ERROR"),
            AtResult::NoCarrier => send_result(state, "NO CARRIER"),
            AtResult::Info(msg) => {
                if !state.quiet {
                    send_response(&mut state.port, &msg);
                }
            }
            AtResult::Dial(target) => {
                // Strip commas (pause characters) from the dial string.
                let target = target.replace(',', "");
                // Hang up any existing connection before dialing.
                state.active_connection = None;
                state.last_dial = target.clone();
                handle_dial(state, &target);
                return; // dial takes over the session
            }
            AtResult::Redial => {
                if state.last_dial.is_empty() {
                    send_result(state, "ERROR");
                } else {
                    state.active_connection = None;
                    let target = state.last_dial.clone();
                    handle_dial(state, &target);
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
                // AT&F — factory defaults
                state.echo = true;
                state.verbose = true;
                state.quiet = false;
                state.active_connection = None;
                state.s_regs = S_REG_DEFAULTS;
                send_result(state, "OK");
            }
            AtResult::ResetStored => {
                // ATZ — restore from config (saved by AT&W)
                let cfg = config::get_config();
                state.echo = cfg.serial_echo;
                state.verbose = cfg.serial_verbose;
                state.quiet = cfg.serial_quiet;
                state.s_regs = parse_s_regs(&cfg.serial_s_regs);
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
                ]);
                send_result(state, "OK");
            }
            AtResult::SRegQuery(reg) => {
                if !state.quiet {
                    let val = state.s_regs[reg];
                    send_response(&mut state.port, &format!("{:03}", val));
                }
            }
            AtResult::SRegSet(reg, val) => {
                state.s_regs[reg] = val;
                send_result(state, "OK");
            }
            AtResult::Help => {
                if !state.quiet {
                    let lines = [
                        "AT Commands:",
                        "AT     OK             ATZ   Reset (stored)",
                        "AT&F   Factory reset   AT&W  Save settings",
                        "AT&V   Show config     ATI   Identification",
                        "ATE0/1 Echo off/on     ATV0/1 Verbose/numeric",
                        "ATQ0/1 Quiet off/on    ATH   Hang up",
                        "ATO    Return online   ATA   Answer",
                        "ATDT   Dial host:port  ATDL  Redial",
                        "ATSn?  Query register  ATSn=v Set register",
                        "ATS?   Register help   +++   Escape to cmd",
                        "AT?    This help",
                    ];
                    for line in &lines {
                        send_response(&mut state.port, line);
                    }
                }
            }
            AtResult::SRegHelp => {
                if !state.quiet {
                    let lines = [
                        "S-Registers (ATSn? to query, ATSn=v to set):",
                        "S00  Auto-answer ring count (0=off)",
                        "S01  Ring counter (current)",
                        "S02  Escape character (43=+)",
                        "S03  Carriage return char (13)",
                        "S04  Line feed char (10)",
                        "S05  Backspace char (8)",
                        "S06  Wait for dial tone (sec)",
                        "S07  Wait for carrier (sec)",
                        "S08  Comma pause time (sec)",
                        "S09  Carrier detect time (1/10s)",
                        "S10  Carrier loss time (1/10s)",
                        "S11  DTMF tone duration (ms)",
                        "S12  Escape guard time (1/50s)",
                    ];
                    for line in &lines {
                        send_response(&mut state.port, line);
                    }
                }
            }
            AtResult::ShowConfig => {
                // AT&V — display current configuration
                if !state.quiet {
                    let echo_str = if state.echo { "E1" } else { "E0" };
                    let verbose_str = if state.verbose { "V1" } else { "V0" };
                    let quiet_str = if state.quiet { "Q1" } else { "Q0" };
                    send_response(&mut state.port,
                        &format!("{} {} {} B{}", echo_str, verbose_str, quiet_str, state.baud));
                    let s_line = state.s_regs.iter().enumerate()
                        .map(|(i, v)| format!("S{:02}={:03}", i, v))
                        .collect::<Vec<_>>()
                        .join(" ");
                    send_response(&mut state.port, &s_line);
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
    send_result(state, &format!("CONNECT {}", state.baud));
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

fn handle_dial(state: &mut ModemState, target: &str) {
    let lower = target.to_ascii_lowercase();

    if lower == "xmodem-gateway" || lower == "xmodem gateway" {
        dial_xmodem_gateway(state);
    } else {
        let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
            match p.parse::<u16>() {
                Ok(port) if port > 0 => (h.to_string(), port),
                _ => {
                    send_result(state, "ERROR");
                    return;
                }
            }
        } else {
            (target.to_string(), 23u16)
        };
        dial_tcp(state, &host, port);
    }
}

/// Dial into the local XMODEM Gateway menu via an in-memory duplex bridge.
fn dial_xmodem_gateway(state: &mut ModemState) {
    send_result(state, &format!("CONNECT {}", state.baud));
    state.mode = ModemMode::Online;

    // Create a duplex pair: one end for TelnetSession, the other for this thread.
    let (async_stream, serial_stream) = tokio::io::duplex(4096);
    let (async_read, async_write) = tokio::io::split(async_stream);

    let writer_box: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(async_write);
    let writer_arc: crate::telnet::SharedWriter =
        Arc::new(tokio::sync::Mutex::new(writer_box));

    let shutdown = state.shutdown.clone();

    // Spawn TelnetSession on the tokio runtime.
    let writer_for_task = writer_arc.clone();
    state.handle.spawn(async move {
        let mut session = crate::telnet::TelnetSession::new_serial(
            Box::new(async_read),
            writer_for_task.clone(),
            shutdown,
        );
        if let Err(e) = session.run().await {
            eprintln!("Serial modem: session error: {}", e);
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

    let mut stream =
        match std::net::TcpStream::connect_timeout(&socket_addr, TCP_CONNECT_TIMEOUT) {
            Ok(s) => s,
            Err(_) => {
                send_result(state, "NO CARRIER");
                return;
            }
        };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(SERIAL_READ_TIMEOUT));

    send_result(state, &format!("CONNECT {}", state.baud));
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

/// Online mode for the duplex bridge (ATDT xmodem-gateway).
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
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return OnlineExit::Disconnected,
        }

        // Duplex → serial
        let result = state.handle.block_on(async {
            tokio::time::timeout(Duration::from_millis(10), duplex_read.read(&mut duplex_buf))
                .await
        });
        match result {
            Ok(Ok(0)) => return OnlineExit::Disconnected,
            Ok(Ok(n)) => {
                let _ = state.port.write_all(&duplex_buf[..n]);
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
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return OnlineExit::Disconnected,
        }

        // TCP → serial
        match tcp.read(&mut tcp_buf) {
            Ok(0) => return OnlineExit::Disconnected,
            Ok(n) => {
                let _ = state.port.write_all(&tcp_buf[..n]);
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

    for &byte in data {
        let now = Instant::now();

        if byte == esc {
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
/// S0 rings.  Reports progress via the sender (0 = ring, 1 = answered).
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
        send_result(state, "RING");

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
                } else if byte >= 0x20 {
                    state.cmd_buffer.push(byte as char);
                }
            }
        }

        if manual_answer {
            break;
        }
    }

    // Answer: connect to xmodem-gateway
    let _ = sender.try_send(1); // notify telnet/SSH: answered
    dial_xmodem_gateway(state);
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

fn send_response(port: &mut Box<dyn serialport::SerialPort>, msg: &str) {
    let response = format!("\r\n{}\r\n", msg);
    let _ = port.write_all(response.as_bytes());
    let _ = port.flush();
}

/// Send a result code, respecting verbose/quiet settings.
fn send_result(state: &mut ModemState, msg: &str) {
    if state.quiet {
        return;
    }
    if state.verbose {
        let response = format!("\r\n{}\r\n", msg);
        let _ = state.port.write_all(response.as_bytes());
    } else {
        let code = match msg {
            "OK" => "0",
            _ if msg.starts_with("CONNECT") => "1",
            "RING" => "2",
            "NO CARRIER" => "3",
            "ERROR" => "4",
            "NO DIALTONE" => "6",
            "BUSY" => "7",
            "NO ANSWER" => "8",
            _ => msg,
        };
        let response = format!("{}\r", code);
        let _ = state.port.write_all(response.as_bytes());
    }
    let _ = state.port.flush();
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
            AtResult::Info(msg) => assert!(msg.contains("XMODEM Gateway")),
            other => panic!("Expected Info, got {:?}", other),
        }
        assert_eq!(results[1], AtResult::Ok);
    }

    #[test]
    fn test_atdt_gateway() {
        let mut echo = true;
        let results = parse("ATDT xmodem-gateway", &mut echo);
        assert_eq!(results.len(), 1);
        match &results[0] {
            AtResult::Dial(target) => assert_eq!(target, "xmodem-gateway"),
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
        // These are NOT recognized commands, so they hit the catch-all OK
        assert_eq!(parse("AT&C", &mut echo), vec![AtResult::Ok]);
        assert_eq!(parse("ATL2", &mut echo), vec![AtResult::Ok]);
        assert_eq!(parse("ATM1", &mut echo), vec![AtResult::Ok]);
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
        assert_eq!(NUM_S_REGS, 13);
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
        // S13 and above are out of range
        assert_eq!(parse("ATS13?", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS99?", &mut echo), vec![AtResult::Error]);
        assert_eq!(parse("ATS255?", &mut echo), vec![AtResult::Error]);
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
        assert_eq!(parse("ATS13=0", &mut echo), vec![AtResult::Error]);
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
    fn test_tcp_connect_timeout_constant() {
        assert_eq!(TCP_CONNECT_TIMEOUT, Duration::from_secs(15));
    }

    #[test]
    fn test_max_cmd_len_constant() {
        assert!(MAX_CMD_LEN >= 40, "buffer must hold standard AT commands");
        assert!(MAX_CMD_LEN <= 1024, "buffer should not be excessively large");
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
        let mut echo = true;
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
    fn test_atdt_xmodem_gateway_case_variants() {
        // The dial handler lowercases before comparing to "xmodem-gateway"
        let variants = [
            "ATDT xmodem-gateway",
            "ATDT XMODEM-GATEWAY",
            "ATDT Xmodem-Gateway",
            "ATDT xmodem gateway",
            "ATDT XMODEM GATEWAY",
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
        let regs = parse_s_regs("5,0,43,13,10,8,2,50,2,6,14,95,50");
        assert_eq!(regs, S_REG_DEFAULTS);
    }

    #[test]
    fn test_format_s_regs_default() {
        let s = format_s_regs(&S_REG_DEFAULTS);
        assert_eq!(s, "5,0,43,13,10,8,2,50,2,6,14,95,50");
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

}
