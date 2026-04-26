//! Binary-level e2e: drives the actual `ethernet-gateway` binary as a
//! subprocess.  Writes a fresh config to a tmpdir, launches the
//! binary, connects via TCP to the telnet port, navigates the menu
//! to the web browser, fetches a page from a localhost HTTP server
//! we also spawn, and asserts on the rendered output.
//!
//! Distinct from the in-process tests in `src/webbrowser.rs` which
//! exercise the rendering pipeline as Rust function calls — this
//! exercises the production binary the way a real telnet user would.
//!
//! Unix-only because the tmpdir + free-port idiom relies on Unix
//! semantics, and the binary's signal handling is POSIX.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn test_binary_telnet_browser_e2e() {
    // 1. Allocate two free ports: one for the binary's telnet
    // server, one for our localhost HTTP server.  We bind, read the
    // port, then drop — there's a small race window before the
    // binary binds the same port, but on a quiet test box it's a
    // non-issue (the kernel is unlikely to hand the same port to
    // a concurrent process within the same millisecond).
    let telnet_port = pick_free_port();
    let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http_listener.local_addr().unwrap().port();

    // 2. Spawn the localhost HTTP server in a background thread.
    // It serves one request, sends a response, and exits.
    let http_thread = std::thread::spawn(move || {
        let (mut stream, _) = http_listener.accept().unwrap();
        // Drain request with a short read timeout.
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        let mut chunk = [0u8; 4096];
        let _ = stream.read(&mut chunk);
        let body = "<html><head><title>Hello E2E</title></head>\
                    <body><p>The binary works end to end.</p></body></html>";
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    });

    // 3. Set up an isolated config in a tmpdir.  The binary auto-
    // creates egateway.conf in its CWD if missing; pre-writing it lets
    // us pin telnet_port, disable GUI/SSH/auth, and point the
    // transfer dir somewhere harmless.
    let tmp = std::env::temp_dir()
        .join(format!("xmodem_binary_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let xfer = tmp.join("xfer");
    std::fs::create_dir_all(&xfer).unwrap();

    let config = format!(
        "telnet_enabled = true\n\
         telnet_port = {}\n\
         ssh_enabled = false\n\
         enable_console = false\n\
         security_enabled = false\n\
         transfer_dir = {}\n",
        telnet_port,
        xfer.display()
    );
    std::fs::write(tmp.join("egateway.conf"), &config).unwrap();

    // 4. Launch the binary.  CARGO_BIN_EXE_<crate> is a compile-time
    // env var Cargo sets for integration tests; access it via env!()
    // (it isn't visible at runtime through std::env::var).
    let binary = env!("CARGO_BIN_EXE_ethernet-gateway");

    let mut child = Command::new(binary)
        .current_dir(&tmp)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn ethernet-gateway");

    // Always reap the child even on panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_session(telnet_port, http_port);
    }));

    let _ = child.kill();
    let _ = child.wait();
    let _ = http_thread.join();
    let _ = std::fs::remove_dir_all(&tmp);

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn run_session(telnet_port: u16, http_port: u16) {
    // 5. Wait for the binary to bind the telnet port (up to 10s).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut conn = loop {
        if Instant::now() > deadline {
            panic!("binary did not bind telnet port {} within 10s", telnet_port);
        }
        match TcpStream::connect(format!("127.0.0.1:{}", telnet_port)) {
            Ok(s) => break s,
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    // 6. Drain the IAC negotiation burst + "Press BACKSPACE..." prompt.
    let banner = drain_until(&mut conn, b"Press BACKSPACE", Duration::from_secs(5));
    assert!(
        contains(&banner, b"Press BACKSPACE"),
        "expected terminal-detect prompt, got {} bytes: {:?}",
        banner.len(),
        printable_excerpt(&banner)
    );

    // 7. Send DEL (0x7F) → server picks ANSI mode.
    conn.write_all(&[0x7F]).unwrap();

    // 8. Drain through "Use ANSI color? (Y/N): ".
    let after_term = drain_until(&mut conn, b"(Y/N)", Duration::from_secs(5));
    assert!(
        contains(&after_term, b"Terminal detected: ANSI"),
        "expected terminal-detection confirmation, got: {:?}",
        printable_excerpt(&after_term)
    );

    // 9. Send 'N' (no color) → drops to Ascii terminal type.  Plain
    // ASCII output makes substring assertions reliable.
    conn.write_all(b"N").unwrap();

    // 10. Drain through the main menu prompt.  In Ascii mode the
    // prompt is exactly "ethernet> " (no ANSI escapes).
    let main_menu = drain_until(&mut conn, b"ethernet> ", Duration::from_secs(5));
    assert!(
        contains(&main_menu, b"ETHERNET GATEWAY"),
        "expected welcome banner, got: {:?}",
        printable_excerpt(&main_menu)
    );

    // 11. Enter the browser menu: send 'b' + CR.
    conn.write_all(b"b\r").unwrap();
    let browser_home =
        drain_until(&mut conn, b"ethernet/web> ", Duration::from_secs(5));
    assert!(
        !browser_home.is_empty(),
        "browser home should produce output"
    );

    // 12. 'g' → URL prompt.
    conn.write_all(b"g\r").unwrap();
    drain_for(&mut conn, Duration::from_millis(500));

    // 13. Send the localhost URL.
    let url = format!("http://127.0.0.1:{}/\r", http_port);
    conn.write_all(url.as_bytes()).unwrap();

    // 14. Drain rendered page output — fetch + render takes a
    // fraction of a second over loopback; 5s is generous.
    let page = drain_until(&mut conn, b"end to end", Duration::from_secs(5));

    // 15. Assert on the rendered content.
    assert!(
        contains(&page, b"Hello E2E"),
        "expected page title 'Hello E2E' in rendered output, got: {:?}",
        printable_excerpt(&page)
    );
    assert!(
        contains(&page, b"end to end"),
        "expected page body text in rendered output, got: {:?}",
        printable_excerpt(&page)
    );
}

/// Bind 127.0.0.1:0, capture the OS-assigned port, drop the
/// listener so the port is free for another process.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Drain bytes from `stream` until either the marker is seen or the
/// timeout expires.  Returns everything read so far.
fn drain_until(stream: &mut TcpStream, marker: &[u8], timeout: Duration) -> Vec<u8> {
    let mut buf = Vec::new();
    let start = Instant::now();
    let mut chunk = [0u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    while start.elapsed() < timeout {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if contains(&buf, marker) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Read timeout fired; loop and check the deadline.
                continue;
            }
            Err(_) => break,
        }
    }
    buf
}

/// Drain whatever's available within `timeout`, with no marker.
fn drain_for(stream: &mut TcpStream, timeout: Duration) -> Vec<u8> {
    drain_until(stream, b"\x00\x00\x00unreachable\x00\x00\x00", timeout)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Convert a byte slice into a printable single-line excerpt for
/// assertion failure messages.  Replaces non-printable bytes with
/// '.' and caps the length at 400 chars so panics stay readable.
fn printable_excerpt(bytes: &[u8]) -> String {
    let len = bytes.len().min(400);
    let s: String = bytes[..len]
        .iter()
        .map(|&b| {
            if (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\r' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if bytes.len() > len {
        format!("{}…(+{} bytes)", s, bytes.len() - len)
    } else {
        s
    }
}
