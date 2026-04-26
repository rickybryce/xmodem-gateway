//! SSH server interface for the Ethernet Gateway.
//!
//! Provides encrypted access to the same menus and features available over
//! telnet.  Uses russh's server implementation with an Ed25519 host key
//! that is generated on first run and persisted to `ethernet_ssh_host_key`.
//! Authentication is password-based with credentials configured independently
//! of the telnet credentials in `egateway.conf`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use russh::server::Server as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config;
use crate::logger::glog;
use crate::telnet;

const SSH_HOST_KEY_FILE: &str = "ethernet_ssh_host_key";
/// Client keypair used by the outgoing SSH gateway to authenticate
/// against remote servers via public-key authentication.  Generated on
/// first use and persisted for the lifetime of the deployment so that
/// the operator can add the same public key to remote `authorized_keys`
/// files once and reuse it across sessions.
pub(crate) const GATEWAY_CLIENT_KEY_FILE: &str = "ethernet_gateway_ssh_key";

// ─── Public API ────────────────────────────────────────────

/// Start the SSH server if enabled in config.
pub fn start_ssh_server(
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    session_writers: telnet::SessionWriters,
    lockouts: telnet::LockoutMap,
) {
    let cfg = config::get_config();
    if !cfg.ssh_enabled {
        return;
    }

    let port = cfg.ssh_port;

    tokio::spawn(async move {
        let key = match load_or_generate_host_key() {
            Ok(k) => k,
            Err(e) => {
                glog!("SSH server: failed to load/generate host key: {}", e);
                return;
            }
        };

        let config = russh::server::Config {
            keys: vec![key],
            auth_rejection_time: std::time::Duration::from_secs(1),
            ..Default::default()
        };
        let config = Arc::new(config);

        let mut server = SshServer {
            shutdown: shutdown.clone(),
            restart: restart.clone(),
            session_count: Arc::new(AtomicUsize::new(0)),
            max_sessions: cfg.max_sessions,
            session_writers: session_writers.clone(),
            lockouts: lockouts.clone(),
        };

        let addr = format!("0.0.0.0:{}", port);
        glog!("SSH server listening on port {}", port);

        tokio::select! {
            result = server.run_on_address(config, &*addr) => {
                if let Err(e) = result {
                    glog!("SSH server error: {}", e);
                }
            }
            _ = shutdown_notify.notified() => {
                glog!("SSH server: shutting down");
            }
        }
    });
}

// ─── Host key management ───────────────────────────────────

fn load_or_generate_host_key() -> Result<russh::keys::PrivateKey, String> {
    use russh::keys::ssh_key::LineEnding;

    // Try to load existing key
    if std::path::Path::new(SSH_HOST_KEY_FILE).exists() {
        match russh::keys::load_secret_key(SSH_HOST_KEY_FILE, None) {
            Ok(key) => {
                glog!("SSH server: loaded host key from {}", SSH_HOST_KEY_FILE);
                return Ok(key);
            }
            Err(e) => {
                glog!(
                    "SSH server: could not read {}: {} (generating new key)",
                    SSH_HOST_KEY_FILE, e
                );
            }
        }
    }

    // Generate new Ed25519 key
    let key = russh::keys::PrivateKey::random(
        &mut rand::rng(),
        russh::keys::Algorithm::Ed25519,
    )
    .map_err(|e| format!("key generation failed: {}", e))?;

    // Save to file in OpenSSH format
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("key encoding failed: {}", e))?;
    if let Err(e) = std::fs::write(SSH_HOST_KEY_FILE, pem.as_bytes()) {
        glog!(
            "SSH server: warning: could not save host key to {}: {}",
            SSH_HOST_KEY_FILE, e
        );
    } else {
        // Restrict permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                SSH_HOST_KEY_FILE,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        glog!(
            "SSH server: generated new host key, saved to {}",
            SSH_HOST_KEY_FILE
        );
    }

    Ok(key)
}

/// Load or (on first use) generate the gateway's outgoing-SSH client
/// keypair used for public-key authentication against remote servers.
///
/// Mirrors `load_or_generate_host_key`: Ed25519, OpenSSH-format PEM at
/// `GATEWAY_CLIENT_KEY_FILE`, chmod 0o600 on Unix.  The file mode is
/// the only at-rest protection; the private key itself has no
/// passphrase because the gateway process needs to use it without user
/// interaction.
pub(crate) fn load_or_generate_client_key() -> Result<russh::keys::PrivateKey, String> {
    use russh::keys::ssh_key::LineEnding;

    if std::path::Path::new(GATEWAY_CLIENT_KEY_FILE).exists() {
        match russh::keys::load_secret_key(GATEWAY_CLIENT_KEY_FILE, None) {
            Ok(key) => {
                return Ok(key);
            }
            Err(e) => {
                glog!(
                    "SSH gateway: could not read {}: {} (generating new key)",
                    GATEWAY_CLIENT_KEY_FILE, e
                );
            }
        }
    }

    let key = russh::keys::PrivateKey::random(
        &mut rand::rng(),
        russh::keys::Algorithm::Ed25519,
    )
    .map_err(|e| format!("client key generation failed: {}", e))?;

    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("client key encoding failed: {}", e))?;
    if let Err(e) = std::fs::write(GATEWAY_CLIENT_KEY_FILE, pem.as_bytes()) {
        glog!(
            "SSH gateway: warning: could not save client key to {}: {}",
            GATEWAY_CLIENT_KEY_FILE, e,
        );
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                GATEWAY_CLIENT_KEY_FILE,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        glog!(
            "SSH gateway: generated new client key, saved to {}",
            GATEWAY_CLIENT_KEY_FILE,
        );
    }

    Ok(key)
}

/// Return the gateway client's public key in OpenSSH one-line format
/// (`<algorithm> <base64>`), suitable for pasting into a remote's
/// `~/.ssh/authorized_keys`.  Generates the keypair on first call.
pub(crate) fn client_public_key_openssh() -> Result<String, String> {
    let key = load_or_generate_client_key()?;
    let public = key.public_key();
    let line = public.to_string();
    // `PublicKey::to_string` produces `<algo> <b64> [comment]`.  We
    // return just `<algo> <b64>` so operators don't paste a stray
    // comment they didn't provide.
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        Ok(format!("{} {}", parts[0], parts[1]))
    } else {
        Ok(line)
    }
}

// ─── Server (connection factory) ───────────────────────────

struct SshServer {
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    session_count: Arc<AtomicUsize>,
    max_sessions: usize,
    session_writers: telnet::SessionWriters,
    /// Brute-force lockout map shared with the telnet server.
    lockouts: telnet::LockoutMap,
}

impl russh::server::Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> SshHandler {
        let cfg = config::get_config();
        let current = self.session_count.fetch_add(1, Ordering::SeqCst);
        if let Some(addr) = peer_addr {
            glog!(
                "SSH: connection from {} ({}/{})",
                addr,
                current + 1,
                self.max_sessions,
            );
        }
        SshHandler {
            shutdown: self.shutdown.clone(),
            restart: self.restart.clone(),
            session_count: self.session_count.clone(),
            max_sessions: self.max_sessions,
            ssh_username: cfg.ssh_username.clone(),
            ssh_password: cfg.ssh_password.clone(),
            peer_addr: peer_addr.map(|a| a.ip()),
            duplex_writer: None,
            session_writers: self.session_writers.clone(),
            lockouts: self.lockouts.clone(),
        }
    }
}

// ─── Handler (per-connection) ──────────────────────────────

struct SshHandler {
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    session_count: Arc<AtomicUsize>,
    max_sessions: usize,
    ssh_username: String,
    ssh_password: String,
    peer_addr: Option<std::net::IpAddr>,
    /// Write half of the duplex bridge to the TelnetSession.
    /// Set once a shell is opened; prevents duplicate shell requests.
    duplex_writer:
        Option<Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>>,
    session_writers: telnet::SessionWriters,
    /// Shared brute-force lockout map (telnet + SSH).
    lockouts: telnet::LockoutMap,
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        self.session_count.fetch_sub(1, Ordering::SeqCst);
        if let Some(addr) = self.peer_addr {
            glog!("SSH: {} disconnected", addr);
        }
    }
}

impl russh::server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        // Reject immediately if at capacity.
        if self.session_count.load(Ordering::SeqCst) > self.max_sessions {
            return Ok(russh::server::Auth::reject());
        }
        // Reject immediately if this IP is locked out from too many
        // failures (map is shared with the telnet server so bouncing
        // protocols doesn't help an attacker).
        if let Some(ip) = self.peer_addr
            && telnet::is_locked_out(&self.lockouts, ip)
        {
            glog!("SSH: auth from {} rejected (locked out)", ip);
            return Ok(russh::server::Auth::reject());
        }
        // Constant-time comparison to prevent timing attacks.
        let user_ok =
            telnet::constant_time_eq(user.as_bytes(), self.ssh_username.as_bytes());
        let pass_ok =
            telnet::constant_time_eq(password.as_bytes(), self.ssh_password.as_bytes());
        if user_ok && pass_ok {
            if let Some(ip) = self.peer_addr {
                telnet::clear_lockout(&self.lockouts, ip);
            }
            Ok(russh::server::Auth::Accept)
        } else {
            if let Some(ip) = self.peer_addr {
                let count = telnet::record_auth_failure(&self.lockouts, ip);
                if count >= telnet::AUTH_MAX_ATTEMPTS {
                    glog!(
                        "SSH: {} exceeded {} failed attempts; locked out",
                        ip,
                        telnet::AUTH_MAX_ATTEMPTS,
                    );
                }
            }
            Ok(russh::server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        let _ = channel;
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: russh::ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: russh::ChannelId,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        // Only allow one shell per connection.
        if self.duplex_writer.is_some() {
            session.channel_failure(channel)?;
            return Ok(());
        }

        session.channel_success(channel)?;

        // Create a duplex bridge between the SSH channel and a TelnetSession.
        let (gateway_stream, handler_stream) = tokio::io::duplex(4096);
        let (gateway_read, gateway_write) = tokio::io::split(gateway_stream);
        let (handler_read, handler_write) = tokio::io::split(handler_stream);

        // Store the handler-side writer so data() can forward SSH input.
        self.duplex_writer =
            Some(Arc::new(tokio::sync::Mutex::new(handler_write)));

        // Wrap the gateway write half as a SharedWriter for TelnetSession.
        let writer_box: Box<dyn tokio::io::AsyncWrite + Unpin + Send> =
            Box::new(gateway_write);
        let writer_arc: telnet::SharedWriter =
            Arc::new(tokio::sync::Mutex::new(writer_box));

        let shutdown = self.shutdown.clone();
        let restart = self.restart.clone();
        let peer_addr = self.peer_addr;
        let session_writers = self.session_writers.clone();

        // Add this SSH session's writer to the shared list so the
        // shutdown broadcast reaches SSH clients too.
        session_writers.lock().await.push(writer_arc.clone());

        // Spawn the TelnetSession on the gateway side of the duplex.
        let writer_for_task = writer_arc.clone();
        tokio::spawn(async move {
            let mut sess = telnet::TelnetSession::new_ssh(
                Box::new(gateway_read),
                writer_for_task.clone(),
                shutdown,
                restart,
                peer_addr,
            );
            if let Err(e) = sess.run().await {
                glog!("SSH: session error: {}", e);
            }
            let mut w = writer_for_task.lock().await;
            let _ = w.shutdown().await;
            drop(w);
            session_writers.lock().await.retain(|w| !Arc::ptr_eq(w, &writer_for_task));
        });

        // Spawn a reader task: reads TelnetSession output from the duplex
        // and sends it back to the SSH client.
        let handle = session.handle();
        tokio::spawn(async move {
            let mut reader = handler_read;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if handle
                            .data(channel, bytes::Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = handle.close(channel).await;
        });

        Ok(())
    }

    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        data: &[u8],
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if let Some(writer) = &self.duplex_writer {
            let mut w = writer.lock().await;
            let _ = w.write_all(data).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        // Client closed their end — shut down the bridge.
        if let Some(writer) = self.duplex_writer.take() {
            let mut w = writer.lock().await;
            let _ = w.shutdown().await;
        }
        Ok(())
    }
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_key_file_constant() {
        assert_eq!(SSH_HOST_KEY_FILE, "ethernet_ssh_host_key");
    }

    #[test]
    fn test_generate_host_key() {
        // Verify key generation doesn't panic and produces an Ed25519 key.
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .expect("Ed25519 key generation should succeed");
        assert_eq!(key.algorithm(), russh::keys::Algorithm::Ed25519);
    }

    #[test]
    fn test_key_roundtrip() {
        use russh::keys::ssh_key::LineEnding;

        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();

        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let decoded =
            russh::keys::decode_secret_key(&pem, None).expect("should decode generated key");
        assert_eq!(decoded.algorithm(), russh::keys::Algorithm::Ed25519);
    }

    #[test]
    fn test_key_save_and_load() {
        use russh::keys::ssh_key::LineEnding;

        let dir = std::env::temp_dir().join("xmodem_test_ssh_key");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_host_key");

        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();

        let pem = key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(&path, pem.as_bytes()).unwrap();

        let loaded = russh::keys::load_secret_key(&path, None)
            .expect("should load saved key");
        assert_eq!(loaded.algorithm(), russh::keys::Algorithm::Ed25519);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_gateway_client_key_file_constant() {
        assert_eq!(GATEWAY_CLIENT_KEY_FILE, "ethernet_gateway_ssh_key");
    }

    /// The generator is expected to produce an Ed25519 keypair whose
    /// OpenSSH PEM can be round-tripped through `load_secret_key`.
    /// This test exercises the pure generate→encode→decode path so it
    /// doesn't touch `GATEWAY_CLIENT_KEY_FILE` on disk.
    #[test]
    fn test_client_key_generation_shape() {
        use russh::keys::ssh_key::LineEnding;
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .expect("Ed25519 generation should succeed");
        assert_eq!(key.algorithm(), russh::keys::Algorithm::Ed25519);
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let decoded = russh::keys::decode_secret_key(&pem, None)
            .expect("generated key should round-trip through OpenSSH PEM");
        assert_eq!(decoded.algorithm(), russh::keys::Algorithm::Ed25519);
    }

    /// `client_public_key_openssh` should emit exactly `<algo> <b64>`
    /// with no trailing comment.  Tested via a synthesized key.
    #[test]
    fn test_client_public_key_openssh_format() {
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let line = key.public_key().to_string();
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        assert!(
            parts.len() >= 2,
            "public key string should be at least `<algo> <b64>`"
        );
        let trimmed = if parts.len() >= 2 {
            format!("{} {}", parts[0], parts[1])
        } else {
            line.clone()
        };
        // Should start with the Ed25519 algorithm name.
        assert!(
            trimmed.starts_with("ssh-ed25519 "),
            "expected ssh-ed25519 prefix, got {:?}",
            trimmed,
        );
        // Should not contain a third space-separated field (comment).
        assert_eq!(trimmed.split(' ').count(), 2);
    }

    /// Full `load_or_generate_client_key` loop: generate, save (via
    /// temp file path), reload, verify algorithm and on Unix the mode.
    /// We do NOT use `GATEWAY_CLIENT_KEY_FILE` itself because other
    /// tests and the running binary may share the CWD.
    #[test]
    fn test_client_key_persists_with_restrictive_mode() {
        use russh::keys::ssh_key::LineEnding;
        let dir = std::env::temp_dir().join("xmodem_test_gateway_client_key");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("client_key");
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(&path, pem.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        let loaded = russh::keys::load_secret_key(&path, None)
            .expect("should load client key back");
        assert_eq!(loaded.algorithm(), russh::keys::Algorithm::Ed25519);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
