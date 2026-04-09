//! Configuration file management.
//!
//! Reads/writes a simple key=value config file (`xmodem.conf`). If the file
//! does not exist at startup it is created with sensible defaults. Unknown
//! keys are silently ignored; missing keys are filled with defaults and the
//! file is rewritten.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

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
const DEFAULT_WEATHER_ZIP: &str = "";
const DEFAULT_VERBOSE: bool = false;
const DEFAULT_SERIAL_ENABLED: bool = false;
const DEFAULT_SERIAL_PORT: &str = "";
const DEFAULT_SERIAL_BAUD: u32 = 9600;
const DEFAULT_SERIAL_DATABITS: u8 = 8;
const DEFAULT_SERIAL_PARITY: &str = "none";
const DEFAULT_SERIAL_STOPBITS: u8 = 1;
const DEFAULT_SERIAL_FLOWCONTROL: &str = "none";

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
    /// Last-used weather zip code. If empty, user is prompted without a default.
    pub weather_zip: String,
    /// Enable verbose XMODEM protocol logging to stderr.
    pub verbose: bool,
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
            weather_zip: DEFAULT_WEATHER_ZIP.into(),
            verbose: DEFAULT_VERBOSE,
            serial_enabled: DEFAULT_SERIAL_ENABLED,
            serial_port: DEFAULT_SERIAL_PORT.into(),
            serial_baud: DEFAULT_SERIAL_BAUD,
            serial_databits: DEFAULT_SERIAL_DATABITS,
            serial_parity: DEFAULT_SERIAL_PARITY.into(),
            serial_stopbits: DEFAULT_SERIAL_STOPBITS,
            serial_flowcontrol: DEFAULT_SERIAL_FLOWCONTROL.into(),
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
        eprintln!("Created default configuration: {}", CONFIG_FILE);
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
        weather_zip: map
            .get("weather_zip")
            .cloned()
            .unwrap_or_else(|| DEFAULT_WEATHER_ZIP.into()),
        verbose: map
            .get("verbose")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(DEFAULT_VERBOSE),
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

# Last-used weather zip code (updated automatically when you check weather)
weather_zip = {}

# Verbose logging: set to true for detailed XMODEM protocol diagnostics
verbose = {}

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
        sanitize_value(&cfg.weather_zip),
        cfg.verbose,
        cfg.serial_enabled,
        sanitize_value(&cfg.serial_port),
        cfg.serial_baud,
        cfg.serial_databits,
        sanitize_value(&cfg.serial_parity),
        cfg.serial_stopbits,
        sanitize_value(&cfg.serial_flowcontrol),
    );

    // Write to a temporary file and rename into place to prevent partial
    // writes if the process is interrupted or multiple sessions write concurrently.
    let tmp = format!("{}.tmp", path);
    if let Err(e) = std::fs::write(&tmp, &content).and_then(|()| std::fs::rename(&tmp, path)) {
        eprintln!("Warning: could not write {}: {}", path, e);
        // Clean up the temp file if rename failed
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
pub fn update_config_values(pairs: &[(&str, &str)]) {
    let mut cfg = if Path::new(CONFIG_FILE).exists() {
        read_config_file(CONFIG_FILE)
    } else {
        Config::default()
    };
    for &(key, value) in pairs {
        apply_config_key(&mut cfg, key, value);
    }
    write_config_file(CONFIG_FILE, &cfg);
    let mut guard = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(cfg);
}

/// Apply a single key-value pair to a Config struct.
fn apply_config_key(cfg: &mut Config, key: &str, value: &str) {
    match key {
        "weather_zip" => cfg.weather_zip = value.to_string(),
        "serial_enabled" => cfg.serial_enabled = value.eq_ignore_ascii_case("true"),
        "serial_port" => cfg.serial_port = value.to_string(),
        "serial_baud" => {
            if let Ok(v) = value.parse() {
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
        _ => {}
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
        assert_eq!(cfg.weather_zip, "");
        assert!(!cfg.serial_enabled);
        assert_eq!(cfg.serial_port, "");
        assert_eq!(cfg.serial_baud, 9600);
        assert_eq!(cfg.serial_databits, 8);
        assert_eq!(cfg.serial_parity, "none");
        assert_eq!(cfg.serial_stopbits, 1);
        assert_eq!(cfg.serial_flowcontrol, "none");
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
            weather_zip: "90210".into(),
            verbose: true,
            serial_enabled: true,
            serial_port: "/dev/ttyUSB0".into(),
            serial_baud: 115200,
            serial_databits: 7,
            serial_parity: "even".into(),
            serial_stopbits: 2,
            serial_flowcontrol: "hardware".into(),
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
        assert_eq!(loaded.weather_zip, original.weather_zip);
        assert_eq!(loaded.verbose, original.verbose);
        assert_eq!(loaded.serial_enabled, original.serial_enabled);
        assert_eq!(loaded.serial_port, original.serial_port);
        assert_eq!(loaded.serial_baud, original.serial_baud);
        assert_eq!(loaded.serial_databits, original.serial_databits);
        assert_eq!(loaded.serial_parity, original.serial_parity);
        assert_eq!(loaded.serial_stopbits, original.serial_stopbits);
        assert_eq!(loaded.serial_flowcontrol, original.serial_flowcontrol);

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
}
