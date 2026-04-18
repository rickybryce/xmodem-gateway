//! GUI console and configuration editor using egui/eframe.
//!
//! When `enable_console = true` in the config, this window is shown on startup.
//! Closing the window does NOT stop the server — it continues running headless.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui;
use egui::{Color32, Stroke};

use crate::config::{self, Config};
use crate::logger;

// ── Retro amber-on-dark color palette (telnetbible.com inspired) ──

const BG_DARKEST: Color32 = Color32::from_rgb(0x05, 0x0e, 0x1a); // matches logo background
const BG_DARK: Color32 = Color32::from_rgb(0x10, 0x1c, 0x3a);   // panel/frame bg
const BG_MID: Color32 = Color32::from_rgb(0x18, 0x28, 0x48);    // input fields
const BG_LIGHT: Color32 = Color32::from_rgb(0x22, 0x36, 0x5a);  // hover
const BORDER: Color32 = Color32::from_rgb(0x30, 0x45, 0x70);    // blue-gold border
const AMBER: Color32 = Color32::from_rgb(0xe6, 0xb4, 0x22);
const AMBER_BRIGHT: Color32 = Color32::from_rgb(0xff, 0xd7, 0x00);
const AMBER_DIM: Color32 = Color32::from_rgb(0x8b, 0x7a, 0x3a);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(0xd4, 0xc5, 0x90);
const TEXT_INPUT: Color32 = Color32::from_rgb(0xe8, 0xdc, 0xb0);
#[cfg(test)]
const GREEN: Color32 = Color32::from_rgb(0x33, 0xff, 0x33);
const CONSOLE_TEXT: Color32 = Color32::from_rgb(0x33, 0xcc, 0x33);
const SCRIPTURE: Color32 = Color32::from_rgb(0xc0, 0xaa, 0x60);  // lighter amber for verse
const CONSOLE_BG: Color32 = Color32::from_rgb(0x08, 0x12, 0x28); // deeper blue for console
const SELECTION: Color32 = Color32::from_rgb(0x26, 0x4f, 0x78);

/// Launch the GUI window.  Blocks the calling thread until the window is closed.
/// If the GUI fails to start (e.g. missing graphics drivers), logs the error and
/// returns so the server continues running headless.
pub fn run(cfg: Config, shutdown: Arc<AtomicBool>, restart: Arc<AtomicBool>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title(format!("XMODEM Gateway v{}", env!("CARGO_PKG_VERSION")))
                .with_inner_size([990.0, 810.0])
                .with_min_inner_size([640.0, 480.0]),
            ..Default::default()
        };

        eframe::run_native(
            "XMODEM Gateway",
            options,
            Box::new(|cc| {
                egui_extras::install_image_loaders(&cc.egui_ctx);
                Ok(Box::new(App::new(cfg, shutdown, restart)))
            }),
        )
    }));

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => logger::log(format!("GUI could not start: {}", e)),
        Err(_) => logger::log("GUI crashed during startup (possible graphics driver issue)".into()),
    }
}

fn apply_theme(ctx: &egui::Context) {
    // Set absolute font sizes (avoids compounding if theme is re-applied)
    let mut style = (*ctx.global_style()).clone();
    for (text_style, font_id) in style.text_styles.iter_mut() {
        font_id.size = match text_style {
            egui::TextStyle::Small => 13.2,
            egui::TextStyle::Body => 16.8,
            egui::TextStyle::Monospace => 16.8,
            egui::TextStyle::Button => 16.8,
            egui::TextStyle::Heading => 24.0,
            egui::TextStyle::Name(_) => font_id.size,
        };
    }
    ctx.set_global_style(style);

    // Apply retro amber-on-dark visuals
    let mut vis = egui::Visuals::dark();
    vis.dark_mode = true;
    vis.override_text_color = Some(TEXT_PRIMARY);
    vis.selection.bg_fill = SELECTION;
    vis.selection.stroke = Stroke::new(1.0, AMBER);

    vis.window_fill = BG_DARKEST;
    vis.panel_fill = BG_DARKEST;
    vis.faint_bg_color = BG_DARKEST;
    vis.extreme_bg_color = BG_MID; // text input backgrounds

    // Non-interactive widgets (labels, frames)
    vis.widgets.noninteractive.bg_fill = BG_DARK;
    vis.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    vis.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);

    // Inactive widgets (buttons, checkboxes, text inputs at rest)
    vis.widgets.inactive.bg_fill = BG_MID;
    vis.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_INPUT);
    vis.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);

    // Hovered widgets
    vis.widgets.hovered.bg_fill = BG_LIGHT;
    vis.widgets.hovered.fg_stroke = Stroke::new(1.5, AMBER_BRIGHT);
    vis.widgets.hovered.bg_stroke = Stroke::new(1.0, AMBER);

    // Active (clicked) widgets
    vis.widgets.active.bg_fill = BG_LIGHT;
    vis.widgets.active.fg_stroke = Stroke::new(2.0, AMBER_BRIGHT);
    vis.widgets.active.bg_stroke = Stroke::new(1.0, AMBER_BRIGHT);

    // Open widgets (e.g. combo box when expanded)
    vis.widgets.open.bg_fill = BG_MID;
    vis.widgets.open.fg_stroke = Stroke::new(1.0, AMBER);
    vis.widgets.open.bg_stroke = Stroke::new(1.0, AMBER_DIM);

    vis.window_stroke = Stroke::new(1.0, BORDER);

    ctx.set_visuals(vis);
}

/// Get the first non-loopback private IP address of this machine.
fn local_ip() -> String {
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in &ifaces {
            if iface.is_loopback() {
                continue;
            }
            let ip = iface.ip();
            if ip.is_ipv4() {
                return ip.to_string();
            }
        }
    }
    "unknown".into()
}

/// Enumerate available serial ports, returning their device paths.
fn detect_serial_ports() -> Vec<String> {
    match serialport::available_ports() {
        Ok(ports) => ports.into_iter().map(|p| p.port_name).collect(),
        Err(e) => {
            logger::log(format!("Could not detect serial ports: {}", e));
            Vec::new()
        }
    }
}

struct App {
    cfg: Config,
    /// Snapshot of the global config at last sync.  When the global singleton
    /// diverges from this (e.g. a telnet session changed a setting), we know
    /// an external update happened and refresh the GUI fields.
    last_synced_cfg: Config,
    console_lines: Vec<String>,
    theme_applied: bool,
    local_ip: String,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    // String buffers for numeric fields so the user can type freely
    telnet_port_buf: String,
    ssh_port_buf: String,
    max_sessions_buf: String,
    idle_timeout_buf: String,
    negotiation_timeout_buf: String,
    block_timeout_buf: String,
    max_retries_buf: String,
    serial_baud_buf: String,
    // Detected serial ports for the dropdown
    serial_ports: Vec<String>,
    /// Set when the user edits any field; prevents refresh_from_global from
    /// overwriting in-progress edits. Cleared on save.
    dirty: bool,
    /// Whether the Server "More..." popup is open.
    server_popup_open: bool,
    /// Whether the Serial Modem "More..." popup is open.
    serial_popup_open: bool,
}

impl App {
    fn new(cfg: Config, shutdown: Arc<AtomicBool>, restart: Arc<AtomicBool>) -> Self {
        let telnet_port_buf = cfg.telnet_port.to_string();
        let ssh_port_buf = cfg.ssh_port.to_string();
        let max_sessions_buf = cfg.max_sessions.to_string();
        let idle_timeout_buf = cfg.idle_timeout_secs.to_string();
        let negotiation_timeout_buf = cfg.xmodem_negotiation_timeout.to_string();
        let block_timeout_buf = cfg.xmodem_block_timeout.to_string();
        let max_retries_buf = cfg.xmodem_max_retries.to_string();
        let serial_baud_buf = cfg.serial_baud.to_string();
        let serial_ports = detect_serial_ports();
        let last_synced_cfg = cfg.clone();
        Self {
            cfg,
            last_synced_cfg,
            console_lines: Vec::new(),
            theme_applied: false,
            local_ip: local_ip(),
            shutdown,
            restart,
            telnet_port_buf,
            ssh_port_buf,
            max_sessions_buf,
            idle_timeout_buf,
            negotiation_timeout_buf,
            block_timeout_buf,
            max_retries_buf,
            serial_baud_buf,
            serial_ports,
            dirty: false,
            server_popup_open: false,
            serial_popup_open: false,
        }
    }

    fn sync_numeric_fields(&mut self) {
        if let Ok(v) = self.telnet_port_buf.parse::<u16>() && v >= 1 { self.cfg.telnet_port = v; }
        if let Ok(v) = self.ssh_port_buf.parse::<u16>() && v >= 1 { self.cfg.ssh_port = v; }
        if let Ok(v) = self.max_sessions_buf.parse::<usize>() && v >= 1 { self.cfg.max_sessions = v; }
        if let Ok(v) = self.idle_timeout_buf.parse() { self.cfg.idle_timeout_secs = v; }
        if let Ok(v) = self.negotiation_timeout_buf.parse::<u64>() && v >= 1 { self.cfg.xmodem_negotiation_timeout = v; }
        if let Ok(v) = self.block_timeout_buf.parse::<u64>() && v >= 1 { self.cfg.xmodem_block_timeout = v; }
        if let Ok(v) = self.max_retries_buf.parse::<usize>() && v >= 1 { self.cfg.xmodem_max_retries = v; }
        if let Ok(v) = self.serial_baud_buf.parse::<u32>() && v >= 300 { self.cfg.serial_baud = v; }
    }

    fn poll_logs(&mut self) {
        let new_lines = logger::drain();
        if !new_lines.is_empty() {
            self.console_lines.extend(new_lines);
            if self.console_lines.len() > 2000 {
                let excess = self.console_lines.len() - 2000;
                self.console_lines.drain(..excess);
            }
        }
    }

    /// Render the Server frame's primary field rows (telnet/SSH ports,
    /// session cap, idle timeout).  Shared between the main layout and
    /// the Server popup so both stay in sync.
    fn draw_server_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.cfg.telnet_enabled, "Telnet");
            labeled_field(ui, "Port:", &mut self.telnet_port_buf, 50.0);
            ui.add_space(8.0);
            labeled_field(ui, "Sessions:", &mut self.max_sessions_buf, 40.0);
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.cfg.ssh_enabled, "SSH");
            ui.add_space(16.0);
            labeled_field(ui, "Port:", &mut self.ssh_port_buf, 50.0);
            ui.add_space(8.0);
            labeled_field(ui, "Idle (s):", &mut self.idle_timeout_buf, 50.0);
        });
    }

    /// Render the Server frame's advanced options — outbound Telnet and
    /// SSH gateway mode choices.  Shown only in the popup.  These are
    /// persisted server-wide so the gateway menus no longer prompt the
    /// operator for mode/auth on every connect.
    fn draw_server_advanced(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Telnet Gateway").strong().color(AMBER));
        ui.horizontal(|ui| {
            ui.label("Mode:");
            let current = if self.cfg.telnet_gateway_raw {
                "Raw TCP"
            } else {
                "Telnet"
            };
            egui::ComboBox::from_id_salt("telnet_gateway_mode")
                .width(120.0)
                .selected_text(current)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.cfg.telnet_gateway_raw, false, "Telnet");
                    ui.selectable_value(&mut self.cfg.telnet_gateway_raw, true, "Raw TCP");
                });
        });
        ui.add_enabled_ui(!self.cfg.telnet_gateway_raw, |ui| {
            ui.checkbox(
                &mut self.cfg.telnet_gateway_negotiate,
                "Negotiate TTYPE / NAWS with remote (Telnet mode only)",
            );
        });

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(2.0);
        ui.label(egui::RichText::new("SSH Gateway").strong().color(AMBER));
        ui.horizontal(|ui| {
            ui.label("Auth:");
            let display = match self.cfg.ssh_gateway_auth.as_str() {
                "password" => "Password",
                _ => "Key",
            };
            egui::ComboBox::from_id_salt("ssh_gateway_auth")
                .width(120.0)
                .selected_text(display)
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.cfg.ssh_gateway_auth,
                        "key".to_string(),
                        "Key",
                    );
                    ui.selectable_value(
                        &mut self.cfg.ssh_gateway_auth,
                        "password".to_string(),
                        "Password",
                    );
                });
        });
        if self.cfg.ssh_gateway_auth != "password" {
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(
                    "Gateway public key (paste into remote ~/.ssh/authorized_keys):",
                )
                .italics()
                .small(),
            );
            let pubkey = match crate::ssh::client_public_key_openssh() {
                Ok(s) => s,
                Err(e) => format!("<could not load key: {}>", e),
            };
            let mut key_display = pubkey;
            ui.add(
                egui::TextEdit::multiline(&mut key_display)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY)
                    .interactive(true),
            );
        }
    }

    /// Render the Serial Modem frame's primary field rows (port, baud,
    /// line framing, flow control).  Shared between the main layout and
    /// the Serial popup.
    fn draw_serial_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Port:");
            let selected = if self.cfg.serial_port.is_empty() {
                "(none)".to_string()
            } else {
                self.cfg.serial_port.clone()
            };
            egui::ComboBox::from_id_salt("serial_port")
                .width(120.0)
                .selected_text(&selected)
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.cfg.serial_port,
                        String::new(),
                        "(none)",
                    );
                    for port in &self.serial_ports {
                        ui.selectable_value(
                            &mut self.cfg.serial_port,
                            port.clone(),
                            port,
                        );
                    }
                });
            if ui.small_button("\u{21bb}").on_hover_text("Refresh ports").clicked() {
                self.serial_ports = detect_serial_ports();
            }
            ui.add_space(4.0);
            labeled_field(ui, "Baud:", &mut self.serial_baud_buf, 70.0);
        });
        ui.horizontal(|ui| {
            ui.label("Bits:");
            egui::ComboBox::from_id_salt("databits")
                .width(36.0)
                .selected_text(self.cfg.serial_databits.to_string())
                .show_ui(ui, |ui| {
                    for b in [5u8, 6, 7, 8] {
                        ui.selectable_value(&mut self.cfg.serial_databits, b, b.to_string());
                    }
                });
            ui.label("Par:");
            egui::ComboBox::from_id_salt("parity")
                .width(56.0)
                .selected_text(&self.cfg.serial_parity)
                .show_ui(ui, |ui| {
                    for p in ["none", "odd", "even"] {
                        ui.selectable_value(&mut self.cfg.serial_parity, p.to_string(), p);
                    }
                });
            ui.label("Stop:");
            egui::ComboBox::from_id_salt("stopbits")
                .width(36.0)
                .selected_text(self.cfg.serial_stopbits.to_string())
                .show_ui(ui, |ui| {
                    for s in [1u8, 2] {
                        ui.selectable_value(&mut self.cfg.serial_stopbits, s, s.to_string());
                    }
                });
            ui.label("Flow:");
            egui::ComboBox::from_id_salt("flow")
                .width(72.0)
                .selected_text(&self.cfg.serial_flowcontrol)
                .show_ui(ui, |ui| {
                    for f in ["none", "hardware", "software"] {
                        ui.selectable_value(&mut self.cfg.serial_flowcontrol, f.to_string(), f);
                    }
                });
        });
    }

    /// Render the Serial Modem frame's advanced options — Hayes AT saved
    /// state, S-registers, and stored phone-number slots.  Shown only in
    /// the popup.
    fn draw_serial_advanced(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Hayes AT Saved State").strong().color(AMBER));
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.cfg.serial_echo, "Echo (E1)");
            ui.add_space(8.0);
            ui.checkbox(&mut self.cfg.serial_verbose, "Verbose (V1)");
            ui.add_space(8.0);
            ui.checkbox(&mut self.cfg.serial_quiet, "Quiet (Q1)");
        });
        ui.horizontal(|ui| {
            ui.label("Result level (X):");
            egui::ComboBox::from_id_salt("x_code")
                .width(36.0)
                .selected_text(self.cfg.serial_x_code.to_string())
                .show_ui(ui, |ui| {
                    for x in 0u8..=4 {
                        ui.selectable_value(&mut self.cfg.serial_x_code, x, x.to_string());
                    }
                });
            ui.add_space(8.0);
            ui.label("DTR (&D):");
            egui::ComboBox::from_id_salt("dtr_mode")
                .width(36.0)
                .selected_text(self.cfg.serial_dtr_mode.to_string())
                .show_ui(ui, |ui| {
                    for d in 0u8..=3 {
                        ui.selectable_value(&mut self.cfg.serial_dtr_mode, d, d.to_string());
                    }
                });
            ui.add_space(8.0);
            ui.label("Flow (&K):");
            egui::ComboBox::from_id_salt("flow_mode")
                .width(36.0)
                .selected_text(self.cfg.serial_flow_mode.to_string())
                .show_ui(ui, |ui| {
                    for f in 0u8..=4 {
                        ui.selectable_value(&mut self.cfg.serial_flow_mode, f, f.to_string());
                    }
                });
            ui.add_space(8.0);
            ui.label("DCD (&C):");
            egui::ComboBox::from_id_salt("dcd_mode")
                .width(36.0)
                .selected_text(self.cfg.serial_dcd_mode.to_string())
                .show_ui(ui, |ui| {
                    for c in 0u8..=1 {
                        ui.selectable_value(&mut self.cfg.serial_dcd_mode, c, c.to_string());
                    }
                });
        });

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(2.0);
        ui.label(egui::RichText::new("S-Registers").strong().color(AMBER));
        ui.label(
            egui::RichText::new(
                "Comma-separated decimal values for S0..S26 (ATSn=v sets, ATSn? reads).",
            )
            .italics()
            .small(),
        );
        ui.add(
            egui::TextEdit::multiline(&mut self.cfg.serial_s_regs)
                .desired_rows(2)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new("Stored Phone Numbers (AT&Zn=s / ATDSn)")
                .strong()
                .color(AMBER),
        );
        for (i, slot) in self.cfg.serial_stored_numbers.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.label(format!("&Z{} =", i));
                ui.add(
                    egui::TextEdit::singleline(slot)
                        .desired_width(f32::INFINITY),
                );
            });
        }
    }

    /// Persist the current in-memory config to disk.  Called by popup
    /// Save buttons; leaves the server running (no restart).
    fn save_config_now(&mut self) {
        self.sync_numeric_fields();
        config::save_config(&self.cfg);
        self.last_synced_cfg = self.cfg.clone();
        self.dirty = false;
        logger::log("Configuration saved.".into());
    }

    /// Pull the global config singleton and, if it changed since our last
    /// sync (i.e. a telnet/SSH session persisted a setting), refresh every
    /// GUI field to match.
    fn refresh_from_global(&mut self) {
        if self.dirty {
            return; // Don't overwrite fields the user is actively editing.
        }
        let global = config::get_config();
        if global == self.last_synced_cfg {
            return;
        }
        self.cfg = global.clone();
        self.last_synced_cfg = global;
        // Rebuild the string buffers that back numeric text fields.
        self.telnet_port_buf = self.cfg.telnet_port.to_string();
        self.ssh_port_buf = self.cfg.ssh_port.to_string();
        self.max_sessions_buf = self.cfg.max_sessions.to_string();
        self.idle_timeout_buf = self.cfg.idle_timeout_secs.to_string();
        self.negotiation_timeout_buf = self.cfg.xmodem_negotiation_timeout.to_string();
        self.block_timeout_buf = self.cfg.xmodem_block_timeout.to_string();
        self.max_retries_buf = self.cfg.xmodem_max_retries.to_string();
        self.serial_baud_buf = self.cfg.serial_baud.to_string();
    }
}

/// Helper: labeled text field in a horizontal row.
fn labeled_field(ui: &mut egui::Ui, label: &str, buf: &mut String, width: f32) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(buf).desired_width(width));
}

/// Helper: labeled password field in a horizontal row.
fn labeled_password(ui: &mut egui::Ui, label: &str, buf: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(buf).password(true));
}

const CONSOLE_FONT_SIZE: f32 = 16.0;

impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        BG_DARKEST.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Apply theme on first frame (after renderer is fully initialized)
        if !self.theme_applied {
            apply_theme(ui.ctx());
            self.theme_applied = true;
        }

        // Close the GUI window when the server shuts down
        if self.shutdown.load(Ordering::SeqCst) {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }

        self.poll_logs();
        self.refresh_from_global();

        ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));

        // ── Console panel (bottom) ────────────────────────────
        egui::Panel::bottom("console_panel")
            .resizable(true)
            .min_size(140.0)
            .default_size(240.0)
            .show_inside(ui, |ui| {
                egui::Frame::NONE.fill(CONSOLE_BG).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Console Output").size(16.0).strong().color(AMBER));
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for line in &self.console_lines {
                                ui.label(
                                    egui::RichText::new(line)
                                        .monospace()
                                        .size(CONSOLE_FONT_SIZE)
                                        .color(CONSOLE_TEXT),
                                );
                            }
                        });
                });
            });

        // ── Config editor (remaining space) ───────────────────
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let avail = ui.available_width();
                let half = (avail - 16.0) / 2.0;
                // Row height based on line spacing so frames match
                let line_h = ui.text_style_height(&egui::TextStyle::Body);
                let row_h = line_h * 3.5 + 16.0;

                ui.horizontal(|ui| {
                    ui.heading(
                        egui::RichText::new(format!(
                            "XMODEM Gateway v{}",
                            env!("CARGO_PKG_VERSION")
                        ))
                        .strong()
                        .color(AMBER_BRIGHT),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(&self.local_ip)
                                .color(AMBER)
                                .monospace()
                                .size(16.0),
                        );
                        ui.label(
                            egui::RichText::new("Server IP:")
                                .color(AMBER)
                                .monospace()
                                .size(16.0),
                        );
                    });
                });
                ui.add_space(4.0);

                // ── Row 1: Server + Security ──────────────────
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(half, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(row_h);
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Server").strong().color(AMBER));
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.add_space(4.0);
                                            if ui.small_button("More...").clicked() {
                                                self.server_popup_open = true;
                                            }
                                        },
                                    );
                                });
                                self.draw_server_controls(ui);
                            });
                        },
                    );

                    ui.allocate_ui_with_layout(
                        egui::vec2(half, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(row_h);
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Security").strong().color(AMBER));
                                    ui.add_space(8.0);
                                    ui.checkbox(&mut self.cfg.security_enabled, "Require Login");
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Telnet").color(AMBER_DIM));
                                    labeled_field(ui, "User:", &mut self.cfg.username, 70.0);
                                    labeled_password(ui, "Pass:", &mut self.cfg.password);
                                });
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("SSH").color(AMBER_DIM));
                                    ui.add_space(16.0);
                                    labeled_field(ui, "User:", &mut self.cfg.ssh_username, 70.0);
                                    labeled_password(ui, "Pass:", &mut self.cfg.ssh_password);
                                });
                            });
                        },
                    );
                });
                ui.add_space(4.0);

                // ── Row 2: File Transfer + AI/Browser ─────────
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(half, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(row_h);
                                ui.set_min_width(ui.available_width());
                                ui.label(egui::RichText::new("File Transfer (XMODEM)").strong().color(AMBER));
                                ui.horizontal(|ui| {
                                    ui.label("Dir:");
                                    ui.text_edit_singleline(&mut self.cfg.transfer_dir);
                                });
                                ui.horizontal(|ui| {
                                    labeled_field(ui, "Negotiate:", &mut self.negotiation_timeout_buf, 40.0);
                                    labeled_field(ui, "Block:", &mut self.block_timeout_buf, 40.0);
                                    labeled_field(ui, "Retries:", &mut self.max_retries_buf, 40.0);
                                });
                            });
                        },
                    );

                    ui.allocate_ui_with_layout(
                        egui::vec2(half, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(row_h);
                                ui.set_min_width(ui.available_width());
                                ui.label(egui::RichText::new("AI Chat, Browser, and Weather").strong().color(AMBER));
                                ui.horizontal(|ui| {
                                    ui.label("API Key:");
                                    ui.add(egui::TextEdit::singleline(&mut self.cfg.groq_api_key).password(true));
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Home:");
                                    ui.text_edit_singleline(&mut self.cfg.browser_homepage);
                                    labeled_field(ui, "Zip:", &mut self.cfg.weather_zip, 60.0);
                                });
                            });
                        },
                    );
                });
                ui.add_space(4.0);

                // ── Row 3: Serial Modem + General ─────────────
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(half, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(row_h);
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Serial Modem").strong().color(AMBER));
                                    ui.add_space(8.0);
                                    ui.checkbox(&mut self.cfg.serial_enabled, "Enabled");
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.add_space(4.0);
                                            if ui.small_button("More...").clicked() {
                                                self.serial_popup_open = true;
                                            }
                                        },
                                    );
                                });
                                self.draw_serial_controls(ui);
                            });
                        },
                    );

                    ui.allocate_ui_with_layout(
                        egui::vec2(half, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(row_h);
                                ui.set_min_width(ui.available_width());
                                ui.label(egui::RichText::new("General").strong().color(AMBER));
                                ui.checkbox(&mut self.cfg.verbose, "Verbose XMODEM Logging");
                                ui.checkbox(&mut self.cfg.enable_console, "Show GUI on Startup");
                            });
                        },
                    );
                });
                ui.add_space(6.0);

                // ── Save & Restart button ─────────────────────
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(
                            egui::RichText::new("Save and Restart Server")
                                .strong()
                                .size(16.0)
                                .color(AMBER_BRIGHT),
                        ))
                        .clicked()
                    {
                        self.sync_numeric_fields();
                        config::save_config(&self.cfg);
                        self.last_synced_cfg = self.cfg.clone();
                        self.dirty = false;
                        logger::log("Configuration saved — restarting server...".into());
                        // Set restart BEFORE shutdown so main loop sees the
                        // intent to restart when it checks after join().
                        self.restart.store(true, Ordering::SeqCst);
                        self.shutdown.store(true, Ordering::SeqCst);
                    }
                });
                ui.label(
                    egui::RichText::new("Saves configuration and restarts the server.")
                        .weak()
                        .italics()
                        .small(),
                );
                // ── User Manual button ────────────────────────
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(
                            egui::RichText::new("User Manual")
                                .strong()
                                .size(16.0)
                                .color(AMBER_BRIGHT),
                        ))
                        .clicked()
                    {
                        ui.ctx().open_url(egui::OpenUrl::new_tab(
                            "https://github.com/rickybryce/xmodem-gateway/blob/master/usermanual.pdf",
                        ));
                    }
                });
                ui.add_space(20.0);
                // ── Scripture (left) + Logo (right) ──────────
                // Logo source is 432px tall; scale to 42.35% for the GUI.
                // The 1.6 aspect ratio matches the original image proportions.
                // The +84 / -84 offset on the right column shifts the logo
                // upward without affecting the left column layout.
                let logo_h = 432.0 * 0.4235;
                let logo_w = logo_h * 1.6;
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(half, logo_h),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.label(
                                egui::RichText::new(
                                    "\u{201c}For God so loved the world, that he gave \
                                     his only begotten Son, that whosoever believeth in \
                                     him should not perish, but have everlasting life.\u{201d}"
                                )
                                .italics()
                                .strong()
                                .size(17.0)
                                .color(SCRIPTURE),
                            );
                            ui.label(
                                egui::RichText::new("\u{2014} John 3:16, KJV")
                                    .italics()
                                    .strong()
                                    .size(15.0)
                                    .color(SCRIPTURE),
                            );
                        },
                    );

                    ui.allocate_ui_with_layout(
                        egui::vec2(half, logo_h + 84.0),
                        egui::Layout::top_down(egui::Align::Max),
                        |ui| {
                            ui.add_space(-84.0);
                            ui.add(
                                egui::Image::new(egui::include_image!("../xmodemlogo.png"))
                                    .fit_to_exact_size(egui::vec2(logo_w, logo_h)),
                            );
                        },
                    );
                });
                ui.add_space(20.0);
            });

        // ── Advanced-options popups ──────────────────────────
        // Drawn after the scroll area so they float above the main
        // layout.  Each popup mirrors the primary controls and adds
        // per-frame advanced fields, with its own Save button.
        let ctx = ui.ctx().clone();

        let mut server_open = self.server_popup_open;
        egui::Window::new(egui::RichText::new("Server — More").strong().color(AMBER_BRIGHT))
            .open(&mut server_open)
            .resizable(true)
            .collapsible(false)
            .default_width(440.0)
            .show(&ctx, |ui| {
                self.draw_server_controls(ui);
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);
                self.draw_server_advanced(ui);
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);
                if ui
                    .add(egui::Button::new(
                        egui::RichText::new("Save")
                            .strong()
                            .size(16.0)
                            .color(AMBER_BRIGHT),
                    ))
                    .clicked()
                {
                    self.save_config_now();
                }
            });
        self.server_popup_open = server_open;

        let mut serial_open = self.serial_popup_open;
        egui::Window::new(egui::RichText::new("Serial Modem — More").strong().color(AMBER_BRIGHT))
            .open(&mut serial_open)
            .resizable(true)
            .collapsible(false)
            .default_width(520.0)
            .show(&ctx, |ui| {
                self.draw_serial_controls(ui);
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);
                self.draw_serial_advanced(ui);
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);
                if ui
                    .add(egui::Button::new(
                        egui::RichText::new("Save")
                            .strong()
                            .size(16.0)
                            .color(AMBER_BRIGHT),
                    ))
                    .clicked()
                {
                    self.save_config_now();
                }
            });
        self.serial_popup_open = serial_open;

        // Detect whether the user has unsaved edits.  Compare bound
        // config fields against the last-synced snapshot so that
        // refresh_from_global will not overwrite in-progress changes.
        if !self.dirty {
            self.dirty = self.cfg != self.last_synced_cfg
                || self.telnet_port_buf != self.last_synced_cfg.telnet_port.to_string()
                || self.ssh_port_buf != self.last_synced_cfg.ssh_port.to_string()
                || self.max_sessions_buf != self.last_synced_cfg.max_sessions.to_string()
                || self.idle_timeout_buf != self.last_synced_cfg.idle_timeout_secs.to_string()
                || self.negotiation_timeout_buf != self.last_synced_cfg.xmodem_negotiation_timeout.to_string()
                || self.block_timeout_buf != self.last_synced_cfg.xmodem_block_timeout.to_string()
                || self.max_retries_buf != self.last_synced_cfg.xmodem_max_retries.to_string()
                || self.serial_baud_buf != self.last_synced_cfg.serial_baud.to_string();
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a test App with default config and fresh shutdown/restart flags.
    fn test_app() -> App {
        App::new(
            Config::default(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    // ── App::new initialization ──────────────────────────────

    #[test]
    fn test_app_new_buffers_match_config() {
        let app = test_app();
        assert_eq!(app.telnet_port_buf, app.cfg.telnet_port.to_string());
        assert_eq!(app.ssh_port_buf, app.cfg.ssh_port.to_string());
        assert_eq!(app.max_sessions_buf, app.cfg.max_sessions.to_string());
        assert_eq!(app.idle_timeout_buf, app.cfg.idle_timeout_secs.to_string());
        assert_eq!(app.negotiation_timeout_buf, app.cfg.xmodem_negotiation_timeout.to_string());
        assert_eq!(app.block_timeout_buf, app.cfg.xmodem_block_timeout.to_string());
        assert_eq!(app.max_retries_buf, app.cfg.xmodem_max_retries.to_string());
        assert_eq!(app.serial_baud_buf, app.cfg.serial_baud.to_string());
    }

    #[test]
    fn test_app_new_defaults() {
        let app = test_app();
        assert!(app.console_lines.is_empty());
        assert!(!app.theme_applied);
        assert!(!app.shutdown.load(Ordering::SeqCst));
        assert!(!app.restart.load(Ordering::SeqCst));
        assert!(!app.local_ip.is_empty());
    }

    // ── sync_numeric_fields ──────────────────────────────────

    #[test]
    fn test_sync_valid_values() {
        let mut app = test_app();
        app.telnet_port_buf = "8080".into();
        app.ssh_port_buf = "3333".into();
        app.max_sessions_buf = "100".into();
        app.idle_timeout_buf = "1800".into();
        app.negotiation_timeout_buf = "60".into();
        app.block_timeout_buf = "30".into();
        app.max_retries_buf = "5".into();
        app.serial_baud_buf = "115200".into();
        app.sync_numeric_fields();
        assert_eq!(app.cfg.telnet_port, 8080);
        assert_eq!(app.cfg.ssh_port, 3333);
        assert_eq!(app.cfg.max_sessions, 100);
        assert_eq!(app.cfg.idle_timeout_secs, 1800);
        assert_eq!(app.cfg.xmodem_negotiation_timeout, 60);
        assert_eq!(app.cfg.xmodem_block_timeout, 30);
        assert_eq!(app.cfg.xmodem_max_retries, 5);
        assert_eq!(app.cfg.serial_baud, 115200);
    }

    #[test]
    fn test_sync_invalid_leaves_original() {
        let mut app = test_app();
        let orig_port = app.cfg.telnet_port;
        let orig_baud = app.cfg.serial_baud;
        app.telnet_port_buf = "not_a_number".into();
        app.serial_baud_buf = "".into();
        app.sync_numeric_fields();
        assert_eq!(app.cfg.telnet_port, orig_port);
        assert_eq!(app.cfg.serial_baud, orig_baud);
    }

    #[test]
    fn test_sync_boundary_values() {
        let mut app = test_app();
        let orig_ssh = app.cfg.ssh_port;
        // u16 max for ports
        app.telnet_port_buf = "65535".into();
        app.ssh_port_buf = "0".into(); // port 0 is rejected (minimum is 1)
        app.sync_numeric_fields();
        assert_eq!(app.cfg.telnet_port, 65535);
        assert_eq!(app.cfg.ssh_port, orig_ssh);
    }

    #[test]
    fn test_sync_overflow_leaves_original() {
        let mut app = test_app();
        let orig = app.cfg.telnet_port;
        // u16 overflow
        app.telnet_port_buf = "70000".into();
        app.sync_numeric_fields();
        assert_eq!(app.cfg.telnet_port, orig);
    }

    #[test]
    fn test_sync_negative_leaves_unsigned() {
        let mut app = test_app();
        let orig_port = app.cfg.telnet_port;
        let orig_sessions = app.cfg.max_sessions;
        app.telnet_port_buf = "-1".into();
        app.max_sessions_buf = "-5".into();
        app.sync_numeric_fields();
        assert_eq!(app.cfg.telnet_port, orig_port);
        assert_eq!(app.cfg.max_sessions, orig_sessions);
    }

    #[test]
    fn test_sync_partial_invalid() {
        let mut app = test_app();
        // Valid port, invalid baud — only port should update
        app.telnet_port_buf = "9999".into();
        app.serial_baud_buf = "abc".into();
        let orig_baud = app.cfg.serial_baud;
        app.sync_numeric_fields();
        assert_eq!(app.cfg.telnet_port, 9999);
        assert_eq!(app.cfg.serial_baud, orig_baud);
    }

    // ── poll_logs buffer cap ─────────────────────────────────

    #[test]
    fn test_poll_logs_caps_at_2000() {
        logger::init();
        let mut app = test_app();
        // Pre-fill with 1990 lines
        for i in 0..1990 {
            app.console_lines.push(format!("line {}", i));
        }
        // Push 20 more through the logger
        for i in 0..20 {
            logger::log(format!("new {}", i));
        }
        app.poll_logs();
        assert!(app.console_lines.len() <= 2000);
    }

    #[test]
    fn test_poll_logs_trims_oldest() {
        logger::init();
        let mut app = test_app();
        // Fill to exactly 2000
        for i in 0..2000 {
            app.console_lines.push(format!("old {}", i));
        }
        // Add one more through logger
        logger::log("newest".into());
        app.poll_logs();
        assert!(app.console_lines.len() <= 2000);
        assert_eq!(app.console_lines.last().expect("should contain newest"), "newest");
    }

    // ── local_ip ─────────────────────────────────────────────

    #[test]
    fn test_local_ip_returns_string() {
        let ip = local_ip();
        // Must return either a valid IPv4 address or "unknown"
        assert!(
            ip == "unknown" || ip.parse::<std::net::Ipv4Addr>().is_ok(),
            "local_ip() returned unexpected value: {}",
            ip
        );
    }

    // ── detect_serial_ports ──────────────────────────────────

    #[test]
    fn test_detect_serial_ports_returns_vec() {
        // Should not panic regardless of hardware present
        let ports = detect_serial_ports();
        // Each entry should be a non-empty path
        for port in &ports {
            assert!(!port.is_empty());
        }
    }

    // ── Color palette constants ──────────────────────────────

    #[test]
    fn test_palette_colors_are_opaque() {
        // All theme colors should be fully opaque (alpha = 255)
        let colors = [
            BG_DARKEST, BG_DARK, BG_MID, BG_LIGHT, BORDER,
            AMBER, AMBER_BRIGHT, AMBER_DIM,
            TEXT_PRIMARY, TEXT_INPUT,
            GREEN, CONSOLE_TEXT, SCRIPTURE, CONSOLE_BG, SELECTION,
        ];
        for (i, color) in colors.iter().enumerate() {
            assert_eq!(color.a(), 255, "Color index {} is not fully opaque", i);
        }
    }

    #[test]
    fn test_palette_bg_gradient_ordering() {
        // Background colors should get progressively lighter
        fn luminance(c: Color32) -> u16 {
            c.r() as u16 + c.g() as u16 + c.b() as u16
        }
        assert!(luminance(BG_DARKEST) < luminance(BG_DARK));
        assert!(luminance(BG_DARK) < luminance(BG_MID));
        assert!(luminance(BG_MID) < luminance(BG_LIGHT));
    }

    #[test]
    fn test_amber_brightness_ordering() {
        fn luminance(c: Color32) -> u16 {
            c.r() as u16 + c.g() as u16 + c.b() as u16
        }
        assert!(luminance(AMBER_DIM) < luminance(AMBER));
        assert!(luminance(AMBER) < luminance(AMBER_BRIGHT));
    }

    // ── Restart / shutdown coordination ────────────────────────

    #[test]
    fn test_restart_sets_both_flags() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let restart = Arc::new(AtomicBool::new(false));
        // Simulate what the restart button does
        restart.store(true, Ordering::SeqCst);
        shutdown.store(true, Ordering::SeqCst);
        assert!(restart.load(Ordering::SeqCst));
        assert!(shutdown.load(Ordering::SeqCst));
    }

    #[test]
    fn test_restart_flag_reset_cycle() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let restart = Arc::new(AtomicBool::new(false));
        // Trigger restart
        restart.store(true, Ordering::SeqCst);
        shutdown.store(true, Ordering::SeqCst);
        // Simulate main loop reset after restart
        restart.store(false, Ordering::SeqCst);
        shutdown.store(false, Ordering::SeqCst);
        assert!(!restart.load(Ordering::SeqCst));
        assert!(!shutdown.load(Ordering::SeqCst));
    }

    // ── Logo sizing constants ────────────────────────────────

    #[test]
    fn test_logo_dimensions_are_reasonable() {
        let logo_h = 432.0_f32 * 0.4235;
        let logo_w = logo_h * 1.6;
        // Logo should fit within a reasonable GUI panel
        assert!(logo_h > 50.0 && logo_h < 400.0);
        assert!(logo_w > 80.0 && logo_w < 600.0);
        // Landscape orientation
        assert!(logo_w > logo_h);
    }
}
