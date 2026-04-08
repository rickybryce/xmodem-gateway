//! XMODEM File Server
//!
//! A telnet-based XMODEM file transfer server supporting PETSCII, ANSI, and
//! ASCII terminals. Listens on a configurable port (default 2323) and provides
//! upload, download, delete, and directory navigation over XMODEM protocol.
//!
//! Author: Ricky Bryce

mod aichat;
mod config;
mod telnet;
mod webbrowser;
mod xmodem;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    eprintln!("XMODEM Gateway v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Author: Ricky Bryce");
    eprintln!();

    // Load or create config
    let cfg = config::load_or_create_config();
    eprintln!("Config: port={}, security={}, transfer_dir={}",
        cfg.telnet_port, cfg.security_enabled, cfg.transfer_dir);
    if cfg.security_enabled && cfg.password == "changeme" {
        eprintln!("WARNING: Security is enabled with the default password. Change it in {}.", config::CONFIG_FILE);
    }

    // Create transfer directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(&cfg.transfer_dir) {
        eprintln!("Error: could not create transfer directory '{}': {}", cfg.transfer_dir, e);
        std::process::exit(1);
    }

    // Shutdown coordination
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    // Register POSIX signal handlers (SIGINT, SIGTERM, SIGHUP)
    let shutdown_sig = shutdown.clone();
    let notify_sig = shutdown_notify.clone();
    register_signal_handlers(shutdown_sig, notify_sig);

    // Start tokio runtime and telnet server
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    let shutdown_rt = shutdown.clone();
    let notify_rt = shutdown_notify.clone();
    runtime.block_on(async move {
        telnet::start_server(shutdown_rt.clone(), notify_rt.clone());

        // Wait for shutdown signal
        loop {
            if shutdown_rt.load(Ordering::SeqCst) {
                eprintln!("\nShutdown signal received, stopping server...");
                break;
            }
            notify_rt.notified().await;
        }

        // Give sessions a moment to receive the shutdown message
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    });

    eprintln!("Server stopped.");
}

/// Register handlers for SIGINT, SIGTERM, and SIGHUP using signal-hook.
fn register_signal_handlers(shutdown: Arc<AtomicBool>, notify: Arc<tokio::sync::Notify>) {
    use signal_hook::consts::{SIGINT, SIGTERM};

    // signal-hook's flag::register sets the AtomicBool on signal delivery
    signal_hook::flag::register(SIGINT, shutdown.clone())
        .expect("Failed to register SIGINT handler");
    signal_hook::flag::register(SIGTERM, shutdown.clone())
        .expect("Failed to register SIGTERM handler");

    #[cfg(unix)]
    {
        use signal_hook::consts::SIGHUP;
        signal_hook::flag::register(SIGHUP, shutdown.clone())
            .expect("Failed to register SIGHUP handler");
    }

    // Spawn a thread that watches the flag and fires the Notify
    let shutdown_watch = shutdown.clone();
    std::thread::spawn(move || {
        while !shutdown_watch.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        notify.notify_waiters();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_flag_default() {
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_shutdown_flag_set() {
        let flag = Arc::new(AtomicBool::new(false));
        flag.store(true, Ordering::SeqCst);
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_signal_handlers_register() {
        // Verify that signal registration doesn't panic
        let shutdown = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(tokio::sync::Notify::new());
        // This should not panic — signals can be registered multiple times
        register_signal_handlers(shutdown, notify);
    }

    #[test]
    fn test_transfer_dir_creation() {
        let dir = std::env::temp_dir().join("xmodem_test_transfer_dir_main");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!dir.exists());
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
