//! GUI console and configuration editor using egui/eframe.
//!
//! When `enable_console = true` in the config, this window is shown on startup.
//! Closing the window does NOT stop the server — it continues running headless.

use eframe::egui;
use egui::{Color32, Stroke};

use crate::config::{self, Config};
use crate::logger;

// ── Retro amber-on-dark color palette (telnetbible.com inspired) ──

const BG_DARKEST: Color32 = Color32::from_rgb(0x0a, 0x14, 0x2e); // deep navy
const BG_DARK: Color32 = Color32::from_rgb(0x10, 0x1c, 0x3a);   // panel/frame bg
const BG_MID: Color32 = Color32::from_rgb(0x18, 0x28, 0x48);    // input fields
const BG_LIGHT: Color32 = Color32::from_rgb(0x22, 0x36, 0x5a);  // hover
const BORDER: Color32 = Color32::from_rgb(0x30, 0x45, 0x70);    // blue-gold border
const AMBER: Color32 = Color32::from_rgb(0xe6, 0xb4, 0x22);
const AMBER_BRIGHT: Color32 = Color32::from_rgb(0xff, 0xd7, 0x00);
const AMBER_DIM: Color32 = Color32::from_rgb(0x8b, 0x7a, 0x3a);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(0xd4, 0xc5, 0x90);
const TEXT_INPUT: Color32 = Color32::from_rgb(0xe8, 0xdc, 0xb0);
const GREEN: Color32 = Color32::from_rgb(0x33, 0xff, 0x33);
const CONSOLE_TEXT: Color32 = Color32::from_rgb(0x33, 0xcc, 0x33);
const SELECTION: Color32 = Color32::from_rgb(0x26, 0x4f, 0x78);

/// Launch the GUI window.  Blocks the calling thread until the window is closed.
/// If the GUI fails to start (e.g. missing graphics drivers), logs the error and
/// returns so the server continues running headless.
pub fn run(cfg: Config) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title(format!("XMODEM Gateway v{}", env!("CARGO_PKG_VERSION")))
                .with_inner_size([900.0, 780.0])
                .with_min_inner_size([640.0, 480.0]),
            ..Default::default()
        };

        eframe::run_native(
            "XMODEM Gateway",
            options,
            Box::new(|cc| {
                egui_extras::install_image_loaders(&cc.egui_ctx);
                Ok(Box::new(App::new(cfg)))
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
    // Increase base font sizes
    let mut style = (*ctx.global_style()).clone();
    for (_text_style, font_id) in style.text_styles.iter_mut() {
        font_id.size *= 1.2;
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
    vis.faint_bg_color = BG_DARK;
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

struct App {
    cfg: Config,
    console_lines: Vec<String>,
    status_msg: String,
    status_timer: f64,
    theme_applied: bool,
    // String buffers for numeric fields so the user can type freely
    telnet_port_buf: String,
    ssh_port_buf: String,
    max_sessions_buf: String,
    idle_timeout_buf: String,
    negotiation_timeout_buf: String,
    block_timeout_buf: String,
    max_retries_buf: String,
    serial_baud_buf: String,
}

impl App {
    fn new(cfg: Config) -> Self {
        let telnet_port_buf = cfg.telnet_port.to_string();
        let ssh_port_buf = cfg.ssh_port.to_string();
        let max_sessions_buf = cfg.max_sessions.to_string();
        let idle_timeout_buf = cfg.idle_timeout_secs.to_string();
        let negotiation_timeout_buf = cfg.xmodem_negotiation_timeout.to_string();
        let block_timeout_buf = cfg.xmodem_block_timeout.to_string();
        let max_retries_buf = cfg.xmodem_max_retries.to_string();
        let serial_baud_buf = cfg.serial_baud.to_string();
        Self {
            cfg,
            console_lines: Vec::new(),
            status_msg: String::new(),
            status_timer: 0.0,
            theme_applied: false,
            telnet_port_buf,
            ssh_port_buf,
            max_sessions_buf,
            idle_timeout_buf,
            negotiation_timeout_buf,
            block_timeout_buf,
            max_retries_buf,
            serial_baud_buf,
        }
    }

    fn sync_numeric_fields(&mut self) {
        if let Ok(v) = self.telnet_port_buf.parse() { self.cfg.telnet_port = v; }
        if let Ok(v) = self.ssh_port_buf.parse() { self.cfg.ssh_port = v; }
        if let Ok(v) = self.max_sessions_buf.parse() { self.cfg.max_sessions = v; }
        if let Ok(v) = self.idle_timeout_buf.parse() { self.cfg.idle_timeout_secs = v; }
        if let Ok(v) = self.negotiation_timeout_buf.parse() { self.cfg.xmodem_negotiation_timeout = v; }
        if let Ok(v) = self.block_timeout_buf.parse() { self.cfg.xmodem_block_timeout = v; }
        if let Ok(v) = self.max_retries_buf.parse() { self.cfg.xmodem_max_retries = v; }
        if let Ok(v) = self.serial_baud_buf.parse() { self.cfg.serial_baud = v; }
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
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Apply theme on first frame (after renderer is fully initialized)
        if !self.theme_applied {
            apply_theme(ui.ctx());
            self.theme_applied = true;
        }

        self.poll_logs();

        // Fade status message
        if !self.status_msg.is_empty() {
            self.status_timer -= ui.ctx().input(|i| i.unstable_dt) as f64;
            if self.status_timer <= 0.0 {
                self.status_msg.clear();
            }
        }

        ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));

        // ── Console panel (bottom) ────────────────────────────
        egui::Panel::bottom("console_panel")
            .resizable(true)
            .min_size(140.0)
            .default_size(240.0)
            .show_inside(ui, |ui| {
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

        // ── Config editor (remaining space) ───────────────────
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let avail = ui.available_width();
                let half = (avail - 16.0) / 2.0;
                // Row height based on line spacing so frames match
                let line_h = ui.text_style_height(&egui::TextStyle::Body);
                let row_h = line_h * 3.5 + 16.0;

                ui.heading(
                    egui::RichText::new(format!(
                        "XMODEM Gateway v{}",
                        env!("CARGO_PKG_VERSION")
                    ))
                    .strong()
                    .color(AMBER_BRIGHT),
                );
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
                                ui.label(egui::RichText::new("Server").strong().color(AMBER));
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
                                ui.label(egui::RichText::new("AI Chat & Browser").strong().color(AMBER));
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
                                });
                                ui.horizontal(|ui| {
                                    labeled_field(ui, "Port:", &mut self.cfg.serial_port, 120.0);
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
                                ui.checkbox(&mut self.cfg.verbose, "Verbose Logging");
                                ui.checkbox(&mut self.cfg.enable_console, "Show Console on Startup");
                            });
                        },
                    );
                });
                ui.add_space(6.0);

                // ── Save button ───────────────────────────────
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(
                            egui::RichText::new("Save Configuration")
                                .strong()
                                .size(16.0)
                                .color(AMBER_BRIGHT),
                        ))
                        .clicked()
                    {
                        self.sync_numeric_fields();
                        config::save_config(&self.cfg);
                        self.status_msg = "Saved!".into();
                        self.status_timer = 3.0;
                        logger::log("Configuration saved to xmodem.conf".into());
                    }
                    if !self.status_msg.is_empty() {
                        ui.add_space(12.0);
                        ui.colored_label(GREEN, egui::RichText::new(&self.status_msg).size(15.0));
                    }
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new("Server/port changes take effect on restart.")
                            .weak()
                            .italics()
                            .small(),
                    );
                });
                ui.add_space(8.0);

                // ── Logo (right-aligned with frames) ──────────
                let logo_h = 432.0 * 0.4;
                let logo_w = logo_h * 1.6;
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    ui.add(
                        egui::Image::new(egui::include_image!("../xmodemlogo.png"))
                            .fit_to_exact_size(egui::vec2(logo_w, logo_h)),
                    );
                });
                ui.add_space(4.0);
            });
    }
}
