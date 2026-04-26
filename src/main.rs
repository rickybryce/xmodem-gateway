//! XMODEM File Server
//!
//! A telnet-based XMODEM file transfer server supporting PETSCII, ANSI, and
//! ASCII terminals. Listens on a configurable port (default 2323) and provides
//! upload, download, delete, and directory navigation over XMODEM protocol.
//!
//! Author: Ricky Bryce

mod aichat;
mod config;
mod gui;
mod logger;
mod serial;
mod ssh;
mod telnet;
mod webbrowser;
mod xmodem;
mod zmodem;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use logger::glog;

fn main() {
    logger::init();

    glog!("Ethernet Gateway v{}", env!("CARGO_PKG_VERSION"));
    glog!("Author: Ricky Bryce");
    glog!();

    // Shutdown and restart coordination (persist across restart cycles)
    let shutdown = Arc::new(AtomicBool::new(false));
    let restart = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    // Register POSIX signal handlers (SIGINT, SIGTERM, SIGHUP)
    register_signal_handlers(shutdown.clone(), shutdown_notify.clone());

    loop {
        // Load or create config (re-read from disk on each restart)
        let cfg = config::load_or_create_config();
        glog!("Config: telnet={}, port={}, security={}, transfer_dir={}",
            cfg.telnet_enabled, cfg.telnet_port, cfg.security_enabled, cfg.transfer_dir);
        if !cfg.telnet_enabled && !cfg.ssh_enabled {
            glog!("WARNING: Both telnet and SSH are disabled. No network access is possible.");
            glog!("         Enable at least one service in {}.", config::CONFIG_FILE);
        } else {
            if !cfg.telnet_enabled {
                glog!("Info: Telnet server is disabled. Enable it in {} if needed.", config::CONFIG_FILE);
            }
            if !cfg.ssh_enabled {
                glog!("Info: SSH server is disabled. Enable it in {} if needed.", config::CONFIG_FILE);
            }
        }
        if cfg.security_enabled && cfg.password == "changeme" {
            glog!("WARNING: Security is enabled with the default password. Change it in {}.", config::CONFIG_FILE);
        }

        // Create transfer directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&cfg.transfer_dir) {
            glog!("Error: could not create transfer directory '{}': {}", cfg.transfer_dir, e);
            std::process::exit(1);
        }

        // Start tokio runtime on a worker thread so the main thread is free for the GUI.
        let shutdown_rt = shutdown.clone();
        let restart_rt = restart.clone();
        let notify_rt = shutdown_notify.clone();
        let gui_cfg = cfg.clone();
        let server_handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime");

            runtime.block_on(async move {
                let session_writers: telnet::SessionWriters =
                    Arc::new(tokio::sync::Mutex::new(Vec::new()));
                // One shared lockout map across telnet + SSH so an
                // attacker can't bounce between protocols to reset their
                // attempt counter.
                let lockouts: telnet::LockoutMap = Arc::new(
                    std::sync::Mutex::new(std::collections::HashMap::new()),
                );
                telnet::start_server(
                    shutdown_rt.clone(),
                    restart_rt.clone(),
                    notify_rt.clone(),
                    session_writers.clone(),
                    lockouts.clone(),
                );
                ssh::start_ssh_server(
                    shutdown_rt.clone(),
                    restart_rt.clone(),
                    notify_rt.clone(),
                    session_writers,
                    lockouts,
                );
                serial::start_serial(shutdown_rt.clone(), restart_rt.clone());

                // Wait for shutdown signal
                loop {
                    if shutdown_rt.load(Ordering::SeqCst) {
                        glog!("\nShutdown signal received, stopping server...");
                        break;
                    }
                    notify_rt.notified().await;
                }

                // Give sessions a moment to receive the shutdown message
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            });

            glog!("Server stopped.");
        });

        if gui_cfg.enable_console {
            // GUI blocks the main thread until the window is closed.
            gui::run(gui_cfg, shutdown.clone(), restart.clone());
            if !restart.load(Ordering::SeqCst) {
                // Window closed manually — fall through to headless wait so the server
                // keeps running in the background until Ctrl-C / SIGTERM.
                glog!("Console window closed. Server still running (Ctrl-C to stop).");
            }
        }

        // Headless mode — park the main thread until shutdown signal.
        loop {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // Wait for the server thread to finish.
        shutdown.store(true, Ordering::SeqCst);
        shutdown_notify.notify_waiters();
        let _ = server_handle.join();

        if restart.load(Ordering::SeqCst) {
            // Reset flags and loop back to start fresh
            restart.store(false, Ordering::SeqCst);
            shutdown.store(false, Ordering::SeqCst);
            glog!("Restarting server...");
            glog!();
            continue;
        }

        break;
    }

    glog!("Server stopped.");
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

    // Spawn a thread that watches the flag and fires the Notify.
    // Loops to survive server restarts (flag resets to false between cycles).
    let shutdown_watch = shutdown.clone();
    std::thread::spawn(move || {
        loop {
            while !shutdown_watch.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            notify.notify_waiters();
            // Wait for the flag to be reset (restart) before watching again
            while shutdown_watch.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
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
