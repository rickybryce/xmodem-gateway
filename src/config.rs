//! Configuration file management.
//!
//! Reads/writes a simple key=value config file (`xmodem.conf`). If the file
//! does not exist at startup it is created with sensible defaults. Unknown
//! keys are silently ignored; missing keys are filled with defaults and the
//! file is rewritten.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

/// Name of the configuration file (lives next to the binary).
pub const CONFIG_FILE: &str = "xmodem.conf";

// ─── Defaults ──────────────────────────────────────────────
const DEFAULT_TELNET_PORT: u16 = 2323;
const DEFAULT_SECURITY_ENABLED: bool = false;
const DEFAULT_USERNAME: &str = "admin";
const DEFAULT_PASSWORD: &str = "changeme";
const DEFAULT_TRANSFER_DIR: &str = "transfer";
const DEFAULT_MAX_SESSIONS: usize = 50;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900; // 15 minutes
const DEFAULT_GROQ_API_KEY: &str = "";
const DEFAULT_BROWSER_HOMEPAGE: &str = "";
const DEFAULT_VERBOSE: bool = false;

/// Runtime configuration loaded from `xmodem.conf`.
#[derive(Debug, Clone)]
pub struct Config {
    pub telnet_port: u16,
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
    /// Enable verbose XMODEM protocol logging to stderr.
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            telnet_port: DEFAULT_TELNET_PORT,
            security_enabled: DEFAULT_SECURITY_ENABLED,
            username: DEFAULT_USERNAME.into(),
            password: DEFAULT_PASSWORD.into(),
            transfer_dir: DEFAULT_TRANSFER_DIR.into(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            groq_api_key: DEFAULT_GROQ_API_KEY.into(),
            browser_homepage: DEFAULT_BROWSER_HOMEPAGE.into(),
            verbose: DEFAULT_VERBOSE,
        }
    }
}

/// Global config singleton, loaded once at startup.
static CONFIG: OnceLock<Config> = OnceLock::new();

/// Get a clone of the current configuration.
pub fn get_config() -> Config {
    CONFIG
        .get_or_init(Config::default)
        .clone()
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
        eprintln!("Created default configuration: {}", CONFIG_FILE);
        cfg
    };

    if CONFIG.set(cfg.clone()).is_err() {
        eprintln!("Warning: config already initialised, ignoring duplicate load");
    }
    cfg
}

/// Parse a config file into a `Config`.
fn read_config_file(path: &str) -> Config {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not read {}: {}", path, e);
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
        telnet_port: map
            .get("telnet_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_TELNET_PORT),
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
        verbose: map
            .get("verbose")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_VERBOSE),
    }
}

/// Sanitize a config value by stripping newlines and carriage returns.
fn sanitize_value(s: &str) -> String {
    s.chars().filter(|&c| c != '\n' && c != '\r').collect()
}

/// Write the config file with comments.
fn write_config_file(path: &str, cfg: &Config) {
    let content = format!(
        "\
# XMODEM Gateway Configuration
#
# This file is auto-generated if it does not exist.
# Edit values below to customise the server.

# Telnet server port
telnet_port = {}

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

# Verbose logging: set to true for detailed XMODEM protocol diagnostics
verbose = {}
",
        cfg.telnet_port,
        cfg.security_enabled,
        sanitize_value(&cfg.username),
        sanitize_value(&cfg.password),
        sanitize_value(&cfg.transfer_dir),
        cfg.max_sessions,
        cfg.idle_timeout_secs,
        sanitize_value(&cfg.groq_api_key),
        sanitize_value(&cfg.browser_homepage),
        cfg.verbose,
    );

    if let Err(e) = std::fs::write(path, content) {
        eprintln!("Warning: could not write {}: {}", path, e);
    }
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.telnet_port, 2323);
        assert!(!cfg.security_enabled);
        assert_eq!(cfg.username, "admin");
        assert_eq!(cfg.password, "changeme");
        assert_eq!(cfg.transfer_dir, "transfer");
        assert_eq!(cfg.max_sessions, 50);
        assert_eq!(cfg.idle_timeout_secs, 900);
        assert_eq!(cfg.groq_api_key, "");
        assert_eq!(cfg.browser_homepage, "");
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

    #[test]
    fn test_write_and_reread_config() {
        let dir = std::env::temp_dir().join("xmodem_test_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roundtrip.conf");

        let original = Config {
            telnet_port: 1234,
            security_enabled: true,
            username: "bob".into(),
            password: "secret".into(),
            transfer_dir: "myfiles".into(),
            max_sessions: 5,
            idle_timeout_secs: 60,
            groq_api_key: "gsk_test123".into(),
            browser_homepage: "https://example.com".into(),
            verbose: true,
        };
        write_config_file(path.to_str().unwrap(), &original);
        let loaded = read_config_file(path.to_str().unwrap());

        assert_eq!(loaded.telnet_port, original.telnet_port);
        assert_eq!(loaded.security_enabled, original.security_enabled);
        assert_eq!(loaded.username, original.username);
        assert_eq!(loaded.password, original.password);
        assert_eq!(loaded.transfer_dir, original.transfer_dir);
        assert_eq!(loaded.max_sessions, original.max_sessions);
        assert_eq!(loaded.idle_timeout_secs, original.idle_timeout_secs);
        assert_eq!(loaded.groq_api_key, original.groq_api_key);
        assert_eq!(loaded.browser_homepage, original.browser_homepage);
        assert_eq!(loaded.verbose, original.verbose);

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
}
