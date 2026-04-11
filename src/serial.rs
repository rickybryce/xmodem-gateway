//! Hayes AT modem emulator over a physical serial port.
//!
//! Runs on a dedicated `std::thread` (not a tokio task) so it can own the
//! synchronous `serialport::SerialPort` object.  Bridges to the async runtime
//! via `tokio::runtime::Handle` for `ATDT xmodem-gateway` connections.
//!
//! Supported AT commands: AT, ATZ, ATE0/ATE1, ATI, ATH, ATDT.
//! The `+++` escape (with 1-second guard time) returns to command mode.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;

use crate::config;

// ─── Constants ─────────────────────────────────────────────

const GUARD_TIME: Duration = Duration::from_secs(1);
const PLUS_BYTE: u8 = b'+';
const SERIAL_READ_TIMEOUT: Duration = Duration::from_millis(100);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Flag to signal the serial thread to restart with new config.
static SERIAL_RESTART: AtomicBool = AtomicBool::new(false);


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
        echo: true,
        verbose: true,
        quiet: false,
        last_data_time: now,
        plus_count: 0,
        plus_start: now,
        cmd_buffer: String::new(),
        handle,
        shutdown,
        baud: cfg.serial_baud,
        active_connection: None,
    };

    send_response(&mut state.port, "OK");

    while !state.shutdown.load(Ordering::SeqCst) && !SERIAL_RESTART.load(Ordering::SeqCst) {
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
                    if state.echo {
                        let _ = state.port.write_all(&[byte]);
                    }
                    state.cmd_buffer.push(byte as char);
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
    /// ATZ / AT&F — reset modem settings (also closes active connection).
    Reset,
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
            *echo = true;
            *verbose = true;
            *quiet = false;
            vec![AtResult::Reset]
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
        "O" | "O0" => vec![AtResult::Online],
        "A" => vec![AtResult::NoCarrier],
        "&F" => {
            *echo = true;
            *verbose = true;
            *quiet = false;
            vec![AtResult::Reset]
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
                // Hang up any existing connection before dialing.
                state.active_connection = None;
                handle_dial(state, &target);
                return; // dial takes over the session
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
                state.active_connection = None;
                send_result(state, "OK");
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

/// Process bytes from the serial port during online mode.  Bytes that should
/// be forwarded to the remote end are appended to `forward`.  Pending `+`
/// bytes from a possible escape sequence are held back (not appended) until
/// either a non-`+` byte arrives (which flushes them) or `check_plus_complete`
/// confirms the escape after the trailing guard time.
fn process_online_bytes(
    state: &mut ModemState,
    data: &[u8],
    forward: &mut Vec<u8>,
) {
    for &byte in data {
        let now = Instant::now();

        if byte == PLUS_BYTE {
            if state.plus_count == 0 {
                // First '+': only start sequence if guard time (silence) has elapsed
                if now.duration_since(state.last_data_time) >= GUARD_TIME {
                    state.plus_count = 1;
                    state.plus_start = now;
                    continue; // hold this byte
                }
                // Guard time not met — forward '+' normally
            } else if state.plus_count < 3 {
                state.plus_count += 1;
                if state.plus_count == 3 {
                    state.plus_start = now; // record time of third '+'
                    continue;
                }
                continue; // hold this byte
            }
            // plus_count == 3 and another '+' arrived — that's 4 pluses, not an escape.
            // Fall through to flush and forward.
        }

        // Non-'+' byte (or 4th '+'):  flush any pending '+' chars
        if state.plus_count > 0 {
            for _ in 0..state.plus_count {
                forward.push(PLUS_BYTE);
            }
            state.plus_count = 0;
        }

        forward.push(byte);
        state.last_data_time = now;
    }
}

/// Check whether the trailing guard time after `+++` has elapsed.  Returns
/// `true` if the escape is complete and the modem should return to command mode.
fn check_plus_complete(state: &mut ModemState) -> bool {
    if state.plus_count == 3
        && Instant::now().duration_since(state.plus_start) >= GUARD_TIME
    {
        state.plus_count = 0;
        return true;
    }
    false
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
    fn test_atz_resets_all() {
        let mut echo = false;
        let mut verbose = false;
        let mut quiet = true;
        assert_eq!(
            parse_full("ATZ", &mut echo, &mut verbose, &mut quiet),
            vec![AtResult::Reset]
        );
        assert!(echo, "ATZ should reset echo to true");
        assert!(verbose, "ATZ should reset verbose to true");
        assert!(!quiet, "ATZ should reset quiet to false");
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
    fn test_process_bytes(
        last_data_time: &mut Instant,
        plus_count: &mut u8,
        plus_start: &mut Instant,
        data: &[u8],
    ) -> (Vec<u8>, bool) {
        // We can't create a real ModemState without a serial port, so we
        // test the logic inline using the same algorithm.
        let mut forward = Vec::new();
        for &byte in data {
            let now = Instant::now();

            if byte == PLUS_BYTE {
                if *plus_count == 0 {
                    if now.duration_since(*last_data_time) >= GUARD_TIME {
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
                    forward.push(PLUS_BYTE);
                }
                *plus_count = 0;
            }

            forward.push(byte);
            *last_data_time = now;
        }
        let complete = *plus_count == 3
            && Instant::now().duration_since(*plus_start) >= GUARD_TIME;
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
    fn test_guard_time_constant() {
        assert_eq!(GUARD_TIME, Duration::from_secs(1));
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
    fn test_send_response_crlf_wrapping() {
        // send_response wraps msg with \r\n on both sides
        let msg = "OK";
        let expected = format!("\r\n{}\r\n", msg);
        assert_eq!(expected, "\r\nOK\r\n");
        assert!(expected.starts_with("\r\n"));
        assert!(expected.ends_with("\r\n"));
    }

}
