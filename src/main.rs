#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame,
    Layout, Margin, RichText, Shadow, Stroke, Theme, ThemePreference, Vec2, Visuals, WidgetInfo,
    WidgetType,
};
use hasher::{
    Algorithm, FileInspection, HashResult, VerifyOutcome, VerifyReport, build_report,
    detect_expected_algorithm, format_results, hash_bytes, hash_ewf_media, hash_file,
    inspect_file, is_ewf_path, normalise_expected_hash, read_hash_list,
};
use std::{
    cmp::Ordering,
    fs,
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    time::Duration,
};

const APP_ICON_PNG: &[u8] = include_bytes!("../assets/hasher-icon.png");
const UPDATE_ENDPOINT: &str = "https://api.github.com/repos/fruitmac/Hasher/releases/latest";

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Text,
    File,
    Verify,
    Settings,
}

#[derive(Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
enum ThemeChoice {
    System,
    Dark,
    Light,
}

/// Settings restored from disk between runs via eframe's storage.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSettings {
    theme: ThemeChoice,
    accent: [u8; 4],
    order: Vec<Algorithm>,
    reorder_locked: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum FileHashMode {
    EvidenceStream,
    ContainerFile,
}

#[derive(Clone, Copy, PartialEq)]
enum ResultSource {
    Text,
    File,
}

enum WorkResult {
    Hashed(
        PathBuf,
        FileHashMode,
        Box<anyhow::Result<(Vec<HashResult>, FileInspection)>>,
    ),
    Verified(anyhow::Result<Vec<HashResult>>),
}

#[derive(Clone)]
struct UpdateInfo {
    latest_version: String,
    release_url: String,
    is_newer: bool,
}

enum UpdateState {
    Idle,
    Checking,
    Current(UpdateInfo),
    Available(UpdateInfo),
    Failed(String),
}

#[derive(serde::Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
}

#[derive(Clone, Copy, PartialEq)]
enum VerifyInput {
    Text,
    File,
}

fn verify_status_line(report: &VerifyReport) -> String {
    match report.outcome {
        VerifyOutcome::Match => "Verified: MATCH".into(),
        VerifyOutcome::Mismatch => "Verified: MISMATCH".into(),
        VerifyOutcome::Invalid if !report.note.is_empty() => report.note.clone(),
        VerifyOutcome::Invalid => "Verification incomplete".into(),
    }
}

fn clean_version(value: &str) -> String {
    value
        .trim()
        .trim_start_matches(['v', 'V'])
        .trim()
        .to_owned()
}

fn version_component(value: &str) -> u64 {
    value
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let left = clean_version(left);
    let right = clean_version(right);
    let mut left_parts = left.split(['.', '-', '+']);
    let mut right_parts = right.split(['.', '-', '+']);
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return Ordering::Equal,
            (left, right) => {
                let left = left.map(version_component).unwrap_or(0);
                let right = right.map(version_component).unwrap_or(0);
                match left.cmp(&right) {
                    Ordering::Equal => {}
                    ordering => return ordering,
                }
            }
        }
    }
}

fn check_latest_release() -> anyhow::Result<UpdateInfo> {
    let release: GitHubRelease = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get(UPDATE_ENDPOINT)
        .header(
            reqwest::header::USER_AGENT,
            format!("Hasher/{}", env!("CARGO_PKG_VERSION")),
        )
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()?
        .error_for_status()?
        .json()?;
    let latest_version = clean_version(&release.tag_name);
    let is_newer =
        compare_versions(&latest_version, env!("CARGO_PKG_VERSION")) == Ordering::Greater;
    Ok(UpdateInfo {
        latest_version,
        release_url: release.html_url,
        is_newer,
    })
}

/// A resolved set of colours for the current theme. Cheap to copy so it can be
/// stashed on the app each frame and handed to the free-standing draw helpers.
#[derive(Clone, Copy)]
struct Palette {
    base: Color32,
    surface: Color32,
    surface_alt: Color32,
    border: Color32,
    text: Color32,
    text_muted: Color32,
    accent: Color32,
    danger: Color32,
    success: Color32,
    warn: Color32,
    dark: bool,
}

fn palette(dark: bool, accent: Color32) -> Palette {
    if dark {
        Palette {
            base: Color32::from_rgb(13, 17, 23),
            surface: Color32::from_rgb(22, 27, 34),
            surface_alt: Color32::from_rgb(30, 36, 44),
            border: Color32::from_rgb(48, 54, 61),
            text: Color32::from_rgb(230, 237, 243),
            text_muted: Color32::from_rgb(139, 148, 158),
            accent,
            danger: Color32::from_rgb(248, 81, 73),
            success: Color32::from_rgb(63, 185, 80),
            warn: Color32::from_rgb(210, 153, 34),
            dark: true,
        }
    } else {
        Palette {
            base: Color32::from_rgb(246, 248, 250),
            surface: Color32::from_rgb(255, 255, 255),
            surface_alt: Color32::from_rgb(238, 241, 245),
            border: Color32::from_rgb(208, 215, 222),
            text: Color32::from_rgb(31, 35, 40),
            text_muted: Color32::from_rgb(101, 109, 118),
            accent,
            danger: Color32::from_rgb(207, 34, 46),
            success: Color32::from_rgb(26, 127, 55),
            warn: Color32::from_rgb(154, 103, 0),
            dark: false,
        }
    }
}

/// sRGB channel to linear, per WCAG relative-luminance.
fn linear_channel(value: u8) -> f32 {
    let c = value as f32 / 255.0;
    if c <= 0.03928 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn relative_luminance(color: Color32) -> f32 {
    0.2126 * linear_channel(color.r())
        + 0.7152 * linear_channel(color.g())
        + 0.0722 * linear_channel(color.b())
}

/// WCAG contrast ratio between two colours (1.0 = identical, 21.0 = max).
fn contrast_ratio(a: Color32, b: Color32) -> f32 {
    let (l1, l2) = (relative_luminance(a), relative_luminance(b));
    let (hi, lo) = if l1 >= l2 { (l1, l2) } else { (l2, l1) };
    (hi + 0.05) / (lo + 0.05)
}

/// One file's result inside a multi-file batch.
struct BatchEntry {
    path: PathBuf,
    result: anyhow::Result<Vec<HashResult>>,
}

type BatchMessage = (PathBuf, Box<anyhow::Result<Vec<HashResult>>>);

struct HasherApp {
    custom_chrome: bool,
    page: Page,
    theme: ThemeChoice,
    accent: Color32,
    pal: Palette,
    text: String,
    file_path: String,
    /// Cached EWF detection for the current `file_path`, so the File page does
    /// not re-open the file from disk on every frame.
    file_is_ewf: bool,
    results: Vec<HashResult>,
    results_source: Option<ResultSource>,
    inspection: Option<FileInspection>,
    file_hash_mode: FileHashMode,
    /// Per-file results when several files are hashed at once.
    batch: Vec<BatchEntry>,
    batch_pending: usize,
    verify_expected: String,
    verify_input: VerifyInput,
    verify_text: String,
    verify_file: String,
    verify_report: Option<VerifyReport>,
    verifying: bool,
    status: String,
    working: bool,
    file_receiver: Option<Receiver<WorkResult>>,
    verify_receiver: Option<Receiver<WorkResult>>,
    batch_receiver: Option<Receiver<BatchMessage>>,
    update_state: UpdateState,
    update_receiver: Option<Receiver<anyhow::Result<UpdateInfo>>>,
    icon_texture: Option<egui::TextureHandle>,
    supported_formats_open: bool,
    /// User-chosen display order for the hash rows, keyed by algorithm so it
    /// survives re-hashing when the text or file changes.
    order: Vec<Algorithm>,
    reorder_locked: bool,
    /// Cache of the last appearance we applied, so we only rebuild the egui
    /// style when the theme or accent actually changes (cheap frames in a VM).
    style_key: Option<(bool, [u8; 4])>,
}

impl Default for HasherApp {
    fn default() -> Self {
        let accent = Color32::from_rgb(88, 166, 255);
        Self {
            custom_chrome: false,
            page: Page::Text,
            theme: ThemeChoice::System,
            accent,
            pal: palette(true, accent),
            text: String::new(),
            file_path: String::new(),
            file_is_ewf: false,
            results: Vec::new(),
            results_source: None,
            inspection: None,
            file_hash_mode: FileHashMode::ContainerFile,
            batch: Vec::new(),
            batch_pending: 0,
            verify_expected: String::new(),
            verify_input: VerifyInput::Text,
            verify_text: String::new(),
            verify_file: String::new(),
            verify_report: None,
            verifying: false,
            status: "Ready".into(),
            working: false,
            file_receiver: None,
            verify_receiver: None,
            batch_receiver: None,
            update_state: UpdateState::Idle,
            update_receiver: None,
            icon_texture: None,
            supported_formats_open: false,
            order: Algorithm::ALL.to_vec(),
            reorder_locked: false,
            style_key: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Free-standing draw helpers (take a Palette by value so callers can still
// mutate `self` inside the closures).
// ---------------------------------------------------------------------------

/// An elevated surface card.
fn card<R>(pal: Palette, ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    Frame::new()
        .fill(pal.surface)
        .stroke(Stroke::new(1.0, pal.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .show(ui, add)
        .inner
}

/// A small rounded label, e.g. an algorithm name.
fn chip(pal: Palette, ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(if pal.dark { 0.20 } else { 0.16 }))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).strong().color(color));
        });
}

fn section_header(pal: Palette, ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(18.0).strong().color(pal.text));
    ui.add_space(2.0);
    ui.label(RichText::new(subtitle).size(12.0).color(pal.text_muted));
    ui.add_space(8.0);
}

/// A full-width, left-aligned sidebar navigation entry with a selected pill.
/// Returns true when clicked.
fn nav_button(pal: Palette, ui: &mut egui::Ui, selected: bool, label: &str) -> bool {
    let desired = Vec2::new(ui.available_width(), 32.0);
    let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());
    let radius = CornerRadius::same(7);
    let painter = ui.painter().clone();

    let bg = if selected {
        pal.accent.gamma_multiply(0.20)
    } else if response.hovered() {
        pal.surface_alt
    } else {
        Color32::TRANSPARENT
    };
    painter.rect_filled(rect, radius, bg);
    if selected {
        painter.rect_stroke(
            rect,
            radius,
            Stroke::new(1.0, pal.accent.gamma_multiply(0.85)),
            egui::StrokeKind::Inside,
        );
    }

    let text_color = if selected { pal.text } else { pal.text_muted };
    painter.text(
        egui::pos2(rect.left() + 12.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::new(13.0, FontFamily::Proportional),
        text_color,
    );

    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response.widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, label));
    ui.add_space(2.0);
    response.clicked()
}

/// Draw invisible drag zones around the window edges and corners. Because the
/// window is created with `decorations(false)`, the OS no longer provides resize
/// borders, so we re-create them by sending `BeginResize` from each zone.
fn window_resize_handles(ctx: &egui::Context) {
    use egui::{CursorIcon, ResizeDirection as Dir};

    // No edge resizing while maximized.
    if ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
        return;
    }

    let screen = ctx.viewport_rect();
    let b = 6.0; // border thickness
    let (l, t, r, btm) = (screen.left(), screen.top(), screen.right(), screen.bottom());
    let w = screen.width();
    let h = screen.height();

    let zones: [(egui::Rect, Dir, CursorIcon); 8] = [
        // Edges
        (
            egui::Rect::from_min_size(egui::pos2(l, t + b), Vec2::new(b, h - 2.0 * b)),
            Dir::West,
            CursorIcon::ResizeWest,
        ),
        (
            egui::Rect::from_min_size(egui::pos2(r - b, t + b), Vec2::new(b, h - 2.0 * b)),
            Dir::East,
            CursorIcon::ResizeEast,
        ),
        (
            egui::Rect::from_min_size(egui::pos2(l + b, t), Vec2::new(w - 2.0 * b, b)),
            Dir::North,
            CursorIcon::ResizeNorth,
        ),
        (
            egui::Rect::from_min_size(egui::pos2(l + b, btm - b), Vec2::new(w - 2.0 * b, b)),
            Dir::South,
            CursorIcon::ResizeSouth,
        ),
        // Corners
        (
            egui::Rect::from_min_size(egui::pos2(l, t), Vec2::splat(b)),
            Dir::NorthWest,
            CursorIcon::ResizeNwSe,
        ),
        (
            egui::Rect::from_min_size(egui::pos2(r - b, t), Vec2::splat(b)),
            Dir::NorthEast,
            CursorIcon::ResizeNeSw,
        ),
        (
            egui::Rect::from_min_size(egui::pos2(l, btm - b), Vec2::splat(b)),
            Dir::SouthWest,
            CursorIcon::ResizeNeSw,
        ),
        (
            egui::Rect::from_min_size(egui::pos2(r - b, btm - b), Vec2::splat(b)),
            Dir::SouthEast,
            CursorIcon::ResizeNwSe,
        ),
    ];

    for (i, (zone, dir, cursor)) in zones.into_iter().enumerate() {
        let response = egui::Area::new(egui::Id::new(("resize_handle", i)))
            .order(egui::Order::Foreground)
            .fixed_pos(zone.min)
            .interactable(true)
            .show(ctx, |ui| {
                ui.allocate_response(zone.size(), egui::Sense::click_and_drag())
            })
            .inner;

        if response.hovered() || response.dragged() {
            ctx.set_cursor_icon(cursor);
        }
        if response.drag_started() {
            ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
        }
    }
}

const ACCENT_PRESETS: [Color32; 6] = [
    Color32::from_rgb(88, 166, 255),  // blue
    Color32::from_rgb(63, 185, 80),   // green
    Color32::from_rgb(188, 140, 255), // purple
    Color32::from_rgb(255, 160, 87),  // amber
    Color32::from_rgb(248, 81, 73),   // red
    Color32::from_rgb(57, 197, 187),  // teal
];

/// One segment of the theme selector.
fn theme_choice(
    pal: Palette,
    ui: &mut egui::Ui,
    current: &mut ThemeChoice,
    value: ThemeChoice,
    label: &str,
) {
    let selected = *current == value;
    let color = if selected { pal.text } else { pal.text_muted };
    let mut button = egui::Button::new(RichText::new(label).color(color));
    if selected {
        button = button
            .fill(pal.accent.gamma_multiply(0.20))
            .stroke(Stroke::new(1.0, pal.accent.gamma_multiply(0.85)));
    }
    if ui.add(button).clicked() {
        *current = value;
    }
    ui.add_space(6.0);
}

/// A clickable accent-colour swatch. Returns true when clicked.
fn accent_swatch(ui: &mut egui::Ui, color: Color32, selected: bool) -> bool {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(22.0), egui::Sense::click());
    let painter = ui.painter().clone();
    painter.rect_filled(rect, CornerRadius::same(6), color);
    if selected {
        painter.rect_stroke(
            rect.expand(2.0),
            CornerRadius::same(8),
            Stroke::new(2.0, color),
            egui::StrokeKind::Outside,
        );
    } else if response.hovered() {
        painter.rect_stroke(
            rect,
            CornerRadius::same(6),
            Stroke::new(1.0, Color32::from_white_alpha(120)),
            egui::StrokeKind::Inside,
        );
    }
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response.widget_info(|| WidgetInfo::selected(WidgetType::Button, true, selected, "Accent colour"));
    response.clicked()
}

fn grip_handle(pal: Palette, ui: &mut egui::Ui) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(16.0, 22.0), egui::Sense::hover());
    let color = if response.hovered() {
        pal.accent
    } else {
        pal.text_muted
    };
    let painter = ui.painter();
    for row in 0..3 {
        for col in 0..2 {
            let pos = egui::pos2(
                rect.center().x - 3.0 + col as f32 * 6.0,
                rect.center().y - 6.0 + row as f32 * 6.0,
            );
            painter.circle_filled(pos, 1.4, color);
        }
    }
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Other, true, "Drag to reorder hash"));
    response.on_hover_text("Drag to reorder")
}

impl HasherApp {
    fn with_custom_chrome(custom_chrome: bool) -> Self {
        Self {
            custom_chrome,
            ..Default::default()
        }
    }

    /// Decode the embedded PNG once and upload it as a texture. This uses the
    /// PNG decoder eframe already bundles (the same one `main` uses for the
    /// window icon), so the app needs no image-loader plugin to show its logo.
    fn ensure_icon(&mut self, ctx: &egui::Context) {
        if self.icon_texture.is_some() {
            return;
        }
        if let Ok(icon) = eframe::icon_data::from_png_bytes(APP_ICON_PNG) {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            self.icon_texture =
                Some(ctx.load_texture("hasher-icon", image, egui::TextureOptions::LINEAR));
        }
    }

    fn install_font(ctx: &egui::Context) {
        let mut fonts = FontDefinitions::default();
        fonts.font_data.insert(
            "JetBrains Mono".into(),
            FontData::from_static(include_bytes!("../assets/JetBrainsMono-Regular.ttf")).into(),
        );
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .insert(0, "JetBrains Mono".into());
        }
        ctx.set_fonts(fonts);
    }

    fn apply_appearance(&mut self, ctx: &egui::Context) {
        let dark = match self.theme {
            ThemeChoice::Dark => true,
            ThemeChoice::Light => false,
            ThemeChoice::System => ctx
                .input(|input| input.raw.system_theme)
                .map(|theme| matches!(theme, Theme::Dark))
                .unwrap_or(true),
        };

        let pal = palette(dark, self.accent);
        self.pal = pal;

        // Rebuilding the whole egui Style every frame is wasteful and shows up
        // as lag on a software-rendered VM. Only do it when something visual
        // actually changed.
        let accent = self.accent;
        let key = (dark, [accent.r(), accent.g(), accent.b(), accent.a()]);
        if self.style_key == Some(key) {
            return;
        }
        self.style_key = Some(key);

        ctx.set_theme(match self.theme {
            ThemeChoice::System => ThemePreference::System,
            ThemeChoice::Dark => ThemePreference::Dark,
            ThemeChoice::Light => ThemePreference::Light,
        });

        ctx.all_styles_mut(move |style| {
            let mut visuals = if dark {
                Visuals::dark()
            } else {
                Visuals::light()
            };
            let radius = CornerRadius::same(8);

            visuals.dark_mode = dark;
            visuals.override_text_color = Some(pal.text);
            visuals.window_fill = pal.base;
            visuals.panel_fill = pal.base;
            visuals.faint_bg_color = pal.surface;
            visuals.extreme_bg_color = if dark {
                Color32::from_rgb(9, 12, 17)
            } else {
                Color32::from_rgb(255, 255, 255)
            };
            visuals.code_bg_color = pal.surface_alt;
            visuals.hyperlink_color = pal.accent;
            visuals.window_stroke = Stroke::new(1.0, pal.border);
            visuals.window_corner_radius = CornerRadius::same(12);

            visuals.selection.bg_fill = pal.accent.gamma_multiply(0.40);
            visuals.selection.stroke = Stroke::new(1.0, pal.text);

            visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, pal.border);
            visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, pal.text_muted);
            visuals.widgets.noninteractive.corner_radius = radius;

            visuals.widgets.inactive.weak_bg_fill = pal.surface_alt;
            visuals.widgets.inactive.bg_fill = pal.surface_alt;
            visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, pal.border);
            visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, pal.text);
            visuals.widgets.inactive.corner_radius = radius;

            let hover_fill = if dark {
                pal.surface_alt.gamma_multiply(1.35)
            } else {
                pal.surface_alt.gamma_multiply(0.92)
            };
            visuals.widgets.hovered.weak_bg_fill = hover_fill;
            visuals.widgets.hovered.bg_fill = hover_fill;
            visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, pal.accent);
            visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, pal.text);
            visuals.widgets.hovered.corner_radius = radius;

            visuals.widgets.active.weak_bg_fill = pal.accent.gamma_multiply(0.30);
            visuals.widgets.active.bg_fill = pal.accent.gamma_multiply(0.30);
            visuals.widgets.active.bg_stroke = Stroke::new(1.0, pal.accent);
            visuals.widgets.active.fg_stroke = Stroke::new(1.0, pal.text);
            visuals.widgets.active.corner_radius = radius;

            visuals.widgets.open.weak_bg_fill = pal.surface_alt;
            visuals.widgets.open.bg_fill = pal.surface_alt;
            visuals.widgets.open.bg_stroke = Stroke::new(1.0, pal.border);
            visuals.widgets.open.fg_stroke = Stroke::new(1.0, pal.text);
            visuals.widgets.open.corner_radius = radius;

            visuals.window_shadow = Shadow::NONE;
            visuals.popup_shadow = Shadow {
                offset: [0, 3],
                blur: 6,
                spread: 0,
                color: Color32::from_black_alpha(if dark { 95 } else { 35 }),
            };

            style.visuals = visuals;

            style.spacing.item_spacing = Vec2::new(7.0, 6.0);
            style.spacing.button_padding = Vec2::new(10.0, 5.0);
            style.spacing.menu_margin = Margin::same(6);
            style.spacing.interact_size.y = 26.0;

            style.text_styles = [
                (
                    egui::TextStyle::Heading,
                    FontId::new(22.0, FontFamily::Proportional),
                ),
                (
                    egui::TextStyle::Body,
                    FontId::new(14.0, FontFamily::Proportional),
                ),
                (
                    egui::TextStyle::Monospace,
                    FontId::new(13.0, FontFamily::Monospace),
                ),
                (
                    egui::TextStyle::Button,
                    FontId::new(14.0, FontFamily::Proportional),
                ),
                (
                    egui::TextStyle::Small,
                    FontId::new(11.5, FontFamily::Proportional),
                ),
            ]
            .into();
        });
    }

    /// Route chosen or dropped paths: a single file uses the rich single-file
    /// view, several files are hashed as a batch.
    fn dispatch_paths(&mut self, mut paths: Vec<PathBuf>, ctx: egui::Context) {
        if paths.is_empty() {
            return;
        }
        if paths.len() == 1 {
            let path = paths.remove(0);
            let mode = if is_ewf_path(&path) {
                FileHashMode::EvidenceStream
            } else {
                FileHashMode::ContainerFile
            };
            self.begin_file_hash(path, mode, ctx);
        } else {
            self.begin_batch_hash(paths, ctx);
        }
    }

    fn begin_file_hash(&mut self, path: PathBuf, mode: FileHashMode, ctx: egui::Context) {
        self.batch.clear();
        self.batch_pending = 0;
        self.batch_receiver = None;
        self.file_path = path.display().to_string();
        self.file_is_ewf = is_ewf_path(&path);
        self.file_hash_mode = mode;
        self.results.clear();
        self.results_source = None;
        self.inspection = None;
        self.working = true;
        self.status = match mode {
            FileHashMode::EvidenceStream => {
                format!(
                    "Reconstructing and hashing EWF evidence stream {}…",
                    path.display()
                )
            }
            FileHashMode::ContainerFile => format!("Hashing container file {}…", path.display()),
        };
        let (sender, receiver) = mpsc::channel();
        self.file_receiver = Some(receiver);
        std::thread::spawn(move || {
            let result = match mode {
                FileHashMode::EvidenceStream => {
                    hash_ewf_media(&path).map(|analysis| (analysis.results, analysis.inspection))
                }
                FileHashMode::ContainerFile => hash_file(&path)
                    .and_then(|hashes| inspect_file(&path).map(|info| (hashes, info))),
            };
            let _ = sender.send(WorkResult::Hashed(path, mode, Box::new(result)));
            ctx.request_repaint();
        });
    }

    fn begin_batch_hash(&mut self, paths: Vec<PathBuf>, ctx: egui::Context) {
        self.file_path.clear();
        self.file_is_ewf = false;
        self.results.clear();
        self.results_source = None;
        self.inspection = None;
        self.batch.clear();
        self.batch_pending = paths.len();
        self.working = true;
        self.status = format!("Hashing {} files…", paths.len());
        let (sender, receiver) = mpsc::channel();
        self.batch_receiver = Some(receiver);
        std::thread::spawn(move || {
            for path in paths {
                let result = if is_ewf_path(&path) {
                    hash_ewf_media(&path).map(|analysis| analysis.results)
                } else {
                    hash_file(&path)
                };
                let _ = sender.send((path, Box::new(result)));
                ctx.request_repaint();
            }
        });
    }

    fn begin_verify_file(&mut self, path: PathBuf, ctx: egui::Context) {
        self.verify_file = path.display().to_string();
        self.verifying = true;
        self.verify_report = None;
        self.status = format!("Hashing {} for verification…", path.display());
        let (sender, receiver) = mpsc::channel();
        self.verify_receiver = Some(receiver);
        std::thread::spawn(move || {
            let result = if is_ewf_path(&path) {
                hash_ewf_media(&path).map(|analysis| analysis.results)
            } else {
                hash_file(&path)
            };
            let _ = sender.send(WorkResult::Verified(result));
            ctx.request_repaint();
        });
    }

    fn run_text_verify(&mut self) {
        let results = hash_bytes(self.verify_text.as_bytes());
        let report = build_report(&self.verify_expected, &results);
        self.status = verify_status_line(&report);
        self.verify_report = Some(report);
    }

    fn poll_work(&mut self) {
        // Single-file hashing.
        if let Some(WorkResult::Hashed(path, mode, result)) = self
            .file_receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok())
        {
            self.file_receiver = None;
            self.working = false;
            match *result {
                Ok((hashes, info)) => {
                    self.results = hashes;
                    self.results_source = Some(ResultSource::File);
                    self.inspection = Some(info);
                    self.status = match mode {
                        FileHashMode::EvidenceStream => {
                            format!("Hashed reconstructed evidence stream from {}", path.display())
                        }
                        FileHashMode::ContainerFile => {
                            format!("Hashed container file {}", path.display())
                        }
                    };
                }
                Err(error) => {
                    self.results.clear();
                    self.results_source = None;
                    self.inspection = None;
                    self.status = format!("Error: {error:#}");
                }
            }
        }

        // Verification hashing.
        if let Some(WorkResult::Verified(result)) = self
            .verify_receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok())
        {
            self.verify_receiver = None;
            self.verifying = false;
            match result {
                Ok(hashes) => {
                    let report = build_report(&self.verify_expected, &hashes);
                    self.status = verify_status_line(&report);
                    self.verify_report = Some(report);
                }
                Err(error) => self.status = format!("Verify failed: {error:#}"),
            }
        }

        self.poll_batch();
    }

    fn poll_batch(&mut self) {
        if self.batch_receiver.is_none() {
            return;
        }
        while let Some((path, result)) = self
            .batch_receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok())
        {
            self.batch.push(BatchEntry {
                path,
                result: *result,
            });
            self.batch_pending = self.batch_pending.saturating_sub(1);
        }
        if self.batch_pending == 0 {
            self.batch_receiver = None;
            self.working = false;
            let failed = self.batch.iter().filter(|e| e.result.is_err()).count();
            self.status = if failed == 0 {
                format!("Hashed {} files", self.batch.len())
            } else {
                format!("Hashed {} files · {failed} failed", self.batch.len())
            };
        }
    }

    fn export_batch(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("hashes.txt")
            .add_filter("Text or log", &["txt", "log"])
            .save_file()
        else {
            return;
        };
        let mut out = String::new();
        for entry in &self.batch {
            match &entry.result {
                Ok(hashes) => {
                    out.push_str(&format!("# {}\n{}\n\n", entry.path.display(), format_results(hashes)));
                }
                Err(error) => {
                    out.push_str(&format!("# {}\n(error: {error:#})\n\n", entry.path.display()));
                }
            }
        }
        match fs::write(&path, out) {
            Ok(()) => self.status = format!("Exported {}", path.display()),
            Err(error) => self.status = format!("Export failed: {error}"),
        }
    }

    fn begin_update_check(&mut self, ctx: egui::Context) {
        if matches!(self.update_state, UpdateState::Checking) {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.update_state = UpdateState::Checking;
        self.update_receiver = Some(receiver);
        self.status = "Checking for updates…".into();
        std::thread::spawn(move || {
            let _ = sender.send(check_latest_release());
            ctx.request_repaint();
        });
    }

    fn poll_update_check(&mut self) {
        let message = self
            .update_receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());
        let Some(message) = message else {
            return;
        };
        self.update_receiver = None;
        match message {
            Ok(info) if info.is_newer => {
                self.status = format!("Hasher {} is available", info.latest_version);
                self.update_state = UpdateState::Available(info);
            }
            Ok(info) => {
                self.status = "Hasher is up to date".into();
                self.update_state = UpdateState::Current(info);
            }
            Err(error) => {
                let message = format!("{error:#}");
                self.status = format!("Update check failed: {message}");
                self.update_state = UpdateState::Failed(message);
            }
        }
    }

    fn export_results(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("hashes.txt")
            .add_filter("Text or log", &["txt", "log"])
            .save_file()
        else {
            return;
        };
        let ordered = self.ordered_results();
        match fs::write(&path, format!("{}\n", format_results(&ordered))) {
            Ok(()) => self.status = format!("Exported {}", path.display()),
            Err(error) => self.status = format!("Export failed: {error}"),
        }
    }

    /// Keep `order` in sync with the algorithms actually present in `results`:
    /// drop any that vanished, append any new ones at the end.
    fn reconcile_order(&mut self) {
        let present: Vec<Algorithm> = self.results.iter().map(|r| r.algorithm).collect();
        if present.is_empty() {
            return;
        }
        self.order.retain(|a| present.contains(a));
        for algorithm in present {
            if !self.order.contains(&algorithm) {
                self.order.push(algorithm);
            }
        }
    }

    /// Results cloned into the user's chosen display order.
    fn ordered_results(&self) -> Vec<HashResult> {
        let mut out: Vec<HashResult> = Vec::new();
        for algorithm in &self.order {
            if let Some(result) = self.results.iter().find(|r| r.algorithm == *algorithm) {
                out.push(result.clone());
            }
        }
        for result in &self.results {
            if !out.iter().any(|r| r.algorithm == result.algorithm) {
                out.push(result.clone());
            }
        }
        out
    }

    fn result_table(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        self.reconcile_order();
        let ordered = self.ordered_results();
        if ordered.is_empty() {
            ui.label(RichText::new("No results yet.").color(pal.text_muted));
            return;
        }

        let mut drag_from: Option<usize> = None;
        let mut drop_to: Option<usize> = None;

        for (idx, result) in ordered.iter().enumerate() {
            let algorithm = result.algorithm.to_string();
            let value = result.value.clone();
            let row_id = egui::Id::new(("hash-row", algorithm.as_str()));

            let mut draw_row = |ui: &mut egui::Ui, show_handle: bool| {
                card(pal, ui, |ui| {
                    ui.horizontal(|ui| {
                        if show_handle {
                            grip_handle(pal, ui);
                            ui.add_space(6.0);
                        }
                        chip(pal, ui, &algorithm, pal.accent);
                        ui.add_space(6.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("Copy").clicked() {
                                ui.ctx().copy_text(value.clone());
                                self.status = format!("Copied {algorithm}");
                            }
                            ui.add_space(6.0);
                            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&value).monospace().color(pal.text),
                                    )
                                    .selectable(true)
                                    .wrap(),
                                );
                            });
                        });
                    });
                });
            };

            let response = if self.reorder_locked || ordered.len() <= 1 {
                draw_row(ui, false);
                None
            } else {
                Some(
                    ui.dnd_drag_source(row_id, idx, |ui| draw_row(ui, true))
                        .response,
                )
            };

            // Draw an insertion line and capture a drop while something is hovering.
            if let Some(response) = response
                && let (Some(pointer), Some(_payload)) = (
                    ui.input(|i| i.pointer.interact_pos()),
                    response.dnd_hover_payload::<usize>(),
                )
            {
                let rect = response.rect;
                let stroke = Stroke::new(2.0, pal.accent);
                let insert = if pointer.y < rect.center().y {
                    ui.painter().hline(rect.x_range(), rect.top(), stroke);
                    idx
                } else {
                    ui.painter().hline(rect.x_range(), rect.bottom(), stroke);
                    idx + 1
                };
                if let Some(dragged) = response.dnd_release_payload::<usize>() {
                    drag_from = Some(*dragged);
                    drop_to = Some(insert);
                }
            }

            ui.add_space(5.0);
        }

        if let (Some(from), Some(mut to)) = (drag_from, drop_to) {
            if from < to {
                to -= 1;
            }
            if from < self.order.len() {
                let item = self.order.remove(from);
                let to = to.min(self.order.len());
                self.order.insert(to, item);
                self.status = "Reordered hashes".into();
            }
        }

        ui.add_space(1.0);
        ui.horizontal(|ui| {
            if ui.button("Copy all").clicked() {
                ui.ctx().copy_text(format_results(&ordered));
                self.status = "Copied all hashes".into();
            }
            if ui.button("Export").clicked() {
                self.export_results();
            }
        });
    }

    fn title_button(
        ui: &mut egui::Ui,
        label: &str,
        tooltip: &str,
        color: Color32,
    ) -> egui::Response {
        // Fixed, identical box for every window control so the glyphs sit in
        // consistently sized, centred pills like the sidebar nav buttons.
        let (rect, response) = ui.allocate_exact_size(Vec2::new(34.0, 28.0), egui::Sense::click());
        let painter = ui.painter().clone();

        if response.hovered() {
            painter.rect_filled(rect, CornerRadius::same(6), color.gamma_multiply(0.20));
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            FontId::new(15.0, FontFamily::Proportional),
            color,
        );

        response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, true, tooltip));
        response.on_hover_text(tooltip)
    }

    fn title_bar(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            if let Some(texture) = &self.icon_texture {
                let sized = egui::load::SizedTexture::new(texture.id(), texture.size_vec2());
                ui.add(egui::Image::from_texture(sized).fit_to_exact_size(Vec2::splat(30.0)));
            } else {
                ui.add_space(30.0);
            }
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.add_space(1.0);
                ui.label(
                    RichText::new("Hasher")
                        .size(19.0)
                        .strong()
                        .color(pal.accent),
                );
                ui.label(
                    RichText::new("hashing without the mystery meat")
                        .size(11.0)
                        .color(pal.text_muted),
                );
            });

            let drag_width = (ui.available_width() - 120.0).max(12.0);
            let (_, drag_response) =
                ui.allocate_exact_size(Vec2::new(drag_width, 36.0), egui::Sense::click_and_drag());
            if drag_response.double_clicked() {
                let maximized = ui
                    .ctx()
                    .input(|input| input.viewport().maximized.unwrap_or(false));
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
            } else if drag_response.drag_started() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }

            ui.add_space(4.0);

            if Self::title_button(ui, "−", "Minimize", pal.text_muted).clicked() {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }

            let maximized = ui
                .ctx()
                .input(|input| input.viewport().maximized.unwrap_or(false));
            if Self::title_button(
                ui,
                if maximized { "❐" } else { "□" },
                "Maximize",
                pal.text_muted,
            )
            .clicked()
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
            }

            if Self::title_button(ui, "×", "Close", pal.danger).clicked() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ui.add_space(2.0);
        });

        ui.add_space(8.0);
    }

    fn inspection_panel(&self, ui: &mut egui::Ui, info: &FileInspection) {
        let pal = self.pal;
        card(pal, ui, |ui| {
            ui.horizontal(|ui| {
                chip(pal, ui, &info.kind.to_string(), pal.accent);
                ui.label(
                    RichText::new(format!(
                        "{} bytes · {} segment(s) detected",
                        info.size, info.segment_count
                    ))
                    .color(pal.text_muted)
                    .size(12.0),
                );
            });
            ui.add_space(6.0);
            ui.label(RichText::new(&info.note).color(pal.text_muted).size(12.0));

            if let Some(ewf) = &info.ewf {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "Logical media: {} bytes · {} chunks of {} bytes",
                        ewf.media_size, ewf.chunk_count, ewf.chunk_size
                    ))
                    .color(pal.text),
                );

                ui.add_space(8.0);
                if ewf.stored_hashes.is_empty() {
                    ui.label(
                        RichText::new("No acquisition digest is stored in this image.")
                            .color(pal.text_muted),
                    );
                } else {
                    ui.label(
                        RichText::new("Stored acquisition digests")
                            .strong()
                            .color(pal.text),
                    );
                    ui.add_space(4.0);
                    for stored in &ewf.stored_hashes {
                        let computed = self
                            .results
                            .iter()
                            .find(|result| result.algorithm == stored.algorithm);
                        let (label, color) = if self.file_hash_mode == FileHashMode::EvidenceStream
                        {
                            match computed {
                                Some(result) if result.value == stored.value => {
                                    ("✓ MATCH", pal.success)
                                }
                                Some(_) => ("✗ MISMATCH", pal.danger),
                                None => ("not computed", pal.text_muted),
                            }
                        } else {
                            ("compare using evidence-stream mode", pal.text_muted)
                        };
                        Frame::new()
                            .fill(pal.surface_alt)
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::symmetric(10, 7))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    chip(pal, ui, &stored.algorithm.to_string(), pal.text_muted);
                                    ui.add_space(4.0);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&stored.value)
                                                .monospace()
                                                .size(12.0)
                                                .color(pal.text),
                                        )
                                        .selectable(true)
                                        .wrap(),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        ui.label(RichText::new(label).strong().color(color));
                                    });
                                });
                            });
                        ui.add_space(5.0);
                    }
                }

                egui::CollapsingHeader::new(RichText::new("Acquisition metadata").color(pal.text))
                    .default_open(true)
                    .show(ui, |ui| {
                        if ewf.metadata.is_empty() {
                            ui.label(
                                RichText::new("No populated case fields.").color(pal.text_muted),
                            );
                        }
                        for (name, value) in &ewf.metadata {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("{name}:")).strong().color(pal.text),
                                );
                                ui.label(RichText::new(value).color(pal.text_muted));
                            });
                        }
                    });

                if !ewf.acquisition_errors.is_empty() {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "⚠ {} acquisition read-error range(s) recorded",
                            ewf.acquisition_errors.len()
                        ))
                        .color(pal.warn),
                    );
                }
            } else if !info.embedded_hashes.is_empty() {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "{} sidecar hash value(s) discovered",
                        info.embedded_hashes.len()
                    ))
                    .color(pal.text),
                );
            }
        });
    }
}

impl eframe::App for HasherApp {
    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();
        self.poll_work();
        self.poll_update_check();
        self.apply_appearance(&ctx);
        if self.custom_chrome {
            self.ensure_icon(&ctx);
        }
        let pal = self.pal;

        if self.custom_chrome {
            window_resize_handles(&ctx);
        }

        let dropped: Vec<PathBuf> = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if !dropped.is_empty() {
            self.page = Page::File;
            self.dispatch_paths(dropped, ctx.clone());
        }

        if self.custom_chrome {
            egui::Panel::top("header").show(root_ui, |ui| {
                self.title_bar(ui);
            });
        }

        egui::Panel::bottom("status").show(root_ui, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                let problem = self.status.starts_with("Error")
                    || self.status.contains("failed")
                    || self.status.contains("MISMATCH");
                let (dot, state) = if self.working {
                    (pal.warn, "Working")
                } else if problem {
                    (pal.danger, "Attention")
                } else {
                    (pal.success, "Ready")
                };
                let (rect, response) =
                    ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 3.5, dot);
                response.on_hover_text(format!(
                    "{state}\n\nGreen — idle and ready\nAmber — a hash is being computed\nRed — the last action reported a problem"
                ));
                ui.add_space(3.0);
                ui.label(RichText::new(&self.status).size(11.5).color(pal.text_muted));
            });
            ui.add_space(3.0);
        });

        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(148.0)
            .show(root_ui, |ui| {
                ui.add_space(8.0);

                if nav_button(pal, ui, self.page == Page::Text, "Text & Numbers") {
                    self.page = Page::Text;
                }
                if nav_button(pal, ui, self.page == Page::File, "Files & Images") {
                    self.page = Page::File;
                }
                if nav_button(pal, ui, self.page == Page::Verify, "Verify") {
                    self.page = Page::Verify;
                }

                // Settings pinned to the bottom.
                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.add_space(4.0);
                    if nav_button(pal, ui, self.page == Page::Settings, "Settings") {
                        self.page = Page::Settings;
                        if matches!(self.update_state, UpdateState::Idle) {
                            self.begin_update_check(ctx.clone());
                        }
                    }
                });
            });

        egui::CentralPanel::default().show(root_ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                .show(ui, |ui| {
                    Frame::new()
                        .inner_margin(Margin {
                            left: 14,
                            right: 14,
                            top: 10,
                            bottom: 14,
                        })
                        .show(ui, |ui| match self.page {
                            Page::Text => self.page_text(ui),
                            Page::File => self.page_file(ui, &ctx),
                            Page::Verify => self.page_verify(ui, &ctx),
                            Page::Settings => self.page_settings(ui),
                        });
                });
        });

        self.supported_formats_window(&ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        let settings = PersistedSettings {
            theme: self.theme,
            accent: [
                self.accent.r(),
                self.accent.g(),
                self.accent.b(),
                self.accent.a(),
            ],
            order: self.order.clone(),
            reorder_locked: self.reorder_locked,
        };
        eframe::set_value(storage, eframe::APP_KEY, &settings);
    }
}

impl HasherApp {
    fn page_text(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        section_header(
            pal,
            ui,
            "Hash text or a number string",
            "The exact UTF-8 bytes are hashed. No newline is added.",
        );
        let response = ui.add_sized(
            [ui.available_width(), 86.0],
            egui::TextEdit::multiline(&mut self.text)
                .hint_text("Type or paste here…")
                .font(egui::TextStyle::Monospace),
        );
        if response.changed() {
            if self.text.is_empty() {
                self.results.clear();
                self.results_source = None;
                self.status = "Ready".into();
            } else {
                self.results = hash_bytes(self.text.as_bytes());
                self.results_source = Some(ResultSource::Text);
                self.status = format!("{} bytes", self.text.len());
            }
        }
        ui.add_space(10.0);
        if self.results_source == Some(ResultSource::Text) {
            self.result_table(ui);
        } else {
            ui.label(RichText::new("No results yet.").color(pal.text_muted));
        }
    }

    fn page_file(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let pal = self.pal;
        section_header(
            pal,
            ui,
            "Hash a file or forensic container",
            "Choose one or more files, or drag and drop them anywhere on the window.",
        );

        card(pal, ui, |ui| {
            ui.horizontal(|ui| {
                let mut shown = if self.batch.is_empty() {
                    self.file_path.clone()
                } else {
                    format!("{} files", self.batch_pending.max(self.batch.len()))
                };
                ui.add_enabled(
                    false,
                    egui::TextEdit::singleline(&mut shown)
                        .hint_text("No file selected")
                        .desired_width(ui.available_width() - 110.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.working, egui::Button::new("Choose"))
                        .clicked()
                        && let Some(paths) = rfd::FileDialog::new().pick_files()
                    {
                        self.dispatch_paths(paths, ctx.clone());
                    }
                });
            });
        });

        if self.batch.is_empty() && self.file_is_ewf {
            ui.add_space(8.0);
            card(pal, ui, |ui| {
                ui.label(RichText::new("Hash target").strong().color(pal.text));
                ui.add_space(4.0);
                ui.radio_value(
                    &mut self.file_hash_mode,
                    FileHashMode::EvidenceStream,
                    "Reconstructed evidence stream",
                );
                ui.radio_value(
                    &mut self.file_hash_mode,
                    FileHashMode::ContainerFile,
                    "Selected container segment",
                );
                ui.add_space(6.0);
                if ui
                    .add_enabled(!self.working, egui::Button::new("Hash again"))
                    .clicked()
                {
                    self.begin_file_hash(
                        PathBuf::from(&self.file_path),
                        self.file_hash_mode,
                        ctx.clone(),
                    );
                }
            });
        }

        if self.working {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().color(pal.accent));
                ui.label(RichText::new("Working…").color(pal.text_muted));
            });
        }

        if !self.batch.is_empty() {
            ui.add_space(10.0);
            self.batch_table(ui);
            return;
        }

        if let Some(info) = self.inspection.clone() {
            ui.add_space(10.0);
            self.inspection_panel(ui, &info);
        }

        ui.add_space(10.0);
        if self.results_source == Some(ResultSource::File) {
            self.result_table(ui);
        } else {
            ui.label(RichText::new("No results yet.").color(pal.text_muted));
        }
    }

    fn batch_table(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{} files", self.batch.len()))
                    .strong()
                    .color(pal.text),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(!self.working, egui::Button::new("Export all"))
                    .clicked()
                {
                    self.export_batch();
                }
            });
        });
        ui.add_space(6.0);

        // Take the batch out so the per-row closures can still touch `self`.
        let batch = std::mem::take(&mut self.batch);
        for entry in &batch {
            card(pal, ui, |ui| {
                let name = entry
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| entry.path.display().to_string());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(name).strong().color(pal.text));
                    if let Ok(hashes) = &entry.result {
                        let hashes = hashes.clone();
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("Copy").clicked() {
                                ui.ctx().copy_text(format_results(&hashes));
                                self.status = "Copied hashes".into();
                            }
                        });
                    }
                });
                ui.add_space(4.0);
                match &entry.result {
                    Ok(hashes) => {
                        for hash in hashes {
                            ui.horizontal(|ui| {
                                chip(pal, ui, &hash.algorithm.to_string(), pal.accent);
                                ui.add_space(4.0);
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&hash.value)
                                            .monospace()
                                            .size(12.0)
                                            .color(pal.text),
                                    )
                                    .selectable(true)
                                    .wrap(),
                                );
                            });
                        }
                    }
                    Err(error) => {
                        ui.label(
                            RichText::new(format!("Error: {error:#}")).color(pal.danger),
                        );
                    }
                }
            });
            ui.add_space(6.0);
        }
        self.batch = batch;
    }

    fn page_verify(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let pal = self.pal;
        section_header(
            pal,
            ui,
            "Verify a hash",
            "Compute a hash from text or a file and compare it against a value you trust.",
        );

        // 1 — the expected hash, typed or imported.
        card(pal, ui, |ui| {
            ui.label(RichText::new("Expected hash").strong().color(pal.text));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.verify_expected)
                        .hint_text("Paste the hash to check against")
                        .font(egui::TextStyle::Monospace)
                        .desired_width(ui.available_width() - 100.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Import").clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .add_filter("Hash list", &["txt", "log"])
                            .pick_file()
                    {
                        match read_hash_list(&path) {
                            Ok(values) if !values.is_empty() => {
                                self.verify_expected = values[0].value.clone();
                                self.status = if values.len() > 1 {
                                    format!("Imported the first of {} hash values", values.len())
                                } else {
                                    "Imported hash value".into()
                                };
                            }
                            Ok(_) => self.status = "No hash values found in that file".into(),
                            Err(error) => self.status = format!("Import failed: {error:#}"),
                        }
                    }
                });
            });

            ui.add_space(4.0);
            let cleaned = normalise_expected_hash(&self.verify_expected);
            if !cleaned.is_empty() {
                let detected = detect_expected_algorithm(&self.verify_expected);
                if let Some(algorithm) = detected {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Detected").size(11.0).color(pal.text_muted));
                        ui.add_space(2.0);
                        chip(pal, ui, &algorithm.to_string(), pal.accent);
                    });
                    if algorithm == Algorithm::Adler32 {
                        ui.label(
                            RichText::new(
                                "8-hex values are ambiguous — confirm this is an ADLER32 checksum.",
                            )
                            .size(11.0)
                            .color(pal.text_muted),
                        );
                    }
                } else {
                    ui.label(
                        RichText::new(
                            "Unrecognised hash — expected 8, 32, 40 or 64 hex characters.",
                        )
                        .size(11.0)
                        .color(pal.warn),
                    );
                }
            }
        });

        ui.add_space(8.0);

        // 2 — the input to hash: text or a file.
        card(pal, ui, |ui| {
            ui.label(RichText::new("Input to hash").strong().color(pal.text));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.verify_input, VerifyInput::Text, "Text / Number");
                ui.radio_value(&mut self.verify_input, VerifyInput::File, "File");
            });
            ui.add_space(6.0);
            match self.verify_input {
                VerifyInput::Text => {
                    ui.add_sized(
                        [ui.available_width(), 66.0],
                        egui::TextEdit::multiline(&mut self.verify_text)
                            .hint_text("Type or paste the text to hash…")
                            .font(egui::TextStyle::Monospace),
                    );
                }
                VerifyInput::File => {
                    ui.horizontal(|ui| {
                        ui.add_enabled(
                            false,
                            egui::TextEdit::singleline(&mut self.verify_file)
                                .hint_text("No file selected")
                                .desired_width(ui.available_width() - 100.0),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add_enabled(!self.verifying, egui::Button::new("Choose"))
                                .clicked()
                                && let Some(path) = rfd::FileDialog::new().pick_file()
                            {
                                self.verify_file = path.display().to_string();
                            }
                        });
                    });
                }
            }
        });

        ui.add_space(10.0);

        // 3 — run it.
        ui.horizontal(|ui| {
            let verify = ui
                .add_enabled(
                    !self.verifying,
                    egui::Button::new(RichText::new("Verify").strong().color(pal.text))
                        .min_size(Vec2::new(100.0, 30.0))
                        .fill(pal.accent.gamma_multiply(0.30))
                        .stroke(Stroke::new(1.0, pal.accent)),
                )
                .clicked();
            if verify {
                match self.verify_input {
                    VerifyInput::Text => self.run_text_verify(),
                    VerifyInput::File => {
                        if self.verify_file.is_empty() {
                            self.status = "Choose a file to verify first".into();
                        } else {
                            self.begin_verify_file(PathBuf::from(&self.verify_file), ctx.clone());
                        }
                    }
                }
            }
            if self.verifying {
                ui.add_space(8.0);
                ui.add(egui::Spinner::new().color(pal.accent));
                ui.label(RichText::new("Hashing…").color(pal.text_muted));
            }
        });

        // 4 — the verdict.
        if let Some(report) = self.verify_report.clone() {
            ui.add_space(10.0);
            self.verify_banner(ui, &report);
        }
    }

    fn verify_banner(&self, ui: &mut egui::Ui, report: &VerifyReport) {
        let pal = self.pal;
        let (color, headline) = match report.outcome {
            VerifyOutcome::Match => (pal.success, "✓  MATCH"),
            VerifyOutcome::Mismatch => (pal.danger, "✗  MISMATCH"),
            VerifyOutcome::Invalid => (pal.warn, "Cannot verify"),
        };
        Frame::new()
            .fill(color.gamma_multiply(if pal.dark { 0.18 } else { 0.12 }))
            .stroke(Stroke::new(1.0, color))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(12))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(headline).size(16.0).strong().color(color));
                    if let Some(algorithm) = report.algorithm {
                        ui.add_space(6.0);
                        chip(pal, ui, &algorithm.to_string(), color);
                    }
                });
                if !report.note.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(&report.note).size(12.5).color(pal.text_muted));
                }
                if report.outcome != VerifyOutcome::Invalid {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Expected").size(11.0).color(pal.text_muted));
                    ui.add(
                        egui::Label::new(
                            RichText::new(&report.expected).monospace().color(pal.text),
                        )
                        .selectable(true)
                        .wrap(),
                    );
                    if let Some(computed) = &report.computed {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Computed").size(11.0).color(pal.text_muted));
                        ui.add(
                            egui::Label::new(RichText::new(computed).monospace().color(pal.text))
                                .selectable(true)
                                .wrap(),
                        );
                    }
                }
            });
    }

    fn page_settings(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        section_header(pal, ui, "Settings", "Appearance and behaviour for Hasher.");

        card(pal, ui, |ui| {
            ui.label(
                RichText::new("Appearance")
                    .size(15.0)
                    .strong()
                    .color(pal.text),
            );
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Theme").color(pal.text_muted));
                ui.add_space(8.0);
                theme_choice(pal, ui, &mut self.theme, ThemeChoice::System, "System");
                theme_choice(pal, ui, &mut self.theme, ThemeChoice::Dark, "Dark");
                theme_choice(pal, ui, &mut self.theme, ThemeChoice::Light, "Light");
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Accent").color(pal.text_muted));
                ui.add_space(8.0);
                ui.color_edit_button_srgba(&mut self.accent)
                    .on_hover_text("Pick any colour");
                ui.add_space(10.0);
                for preset in ACCENT_PRESETS {
                    if accent_swatch(ui, preset, self.accent == preset) {
                        self.accent = preset;
                    }
                    ui.add_space(4.0);
                }
            });

            if contrast_ratio(self.accent, pal.base) < 3.0 {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "⚠ This accent has low contrast with the background and may be hard to see.",
                    )
                    .size(11.0)
                    .color(pal.warn),
                );
            }
        });

        ui.add_space(8.0);

        card(pal, ui, |ui| {
            ui.label(
                RichText::new("Hash list")
                    .size(15.0)
                    .strong()
                    .color(pal.text),
            );
            ui.add_space(4.0);
            ui.checkbox(&mut self.reorder_locked, "Lock reorder");
            ui.add_space(6.0);
            if ui.button("Reset to default order").clicked() {
                self.order = Algorithm::ALL.to_vec();
                self.status = "Hash order reset".into();
            }
        });

        ui.add_space(8.0);

        card(pal, ui, |ui| {
            ui.label(RichText::new("Updates").size(15.0).strong().color(pal.text));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Installed").color(pal.text_muted));
                ui.label(
                    RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                        .monospace()
                        .color(pal.text),
                );
            });
            ui.add_space(4.0);
            match &self.update_state {
                UpdateState::Idle => {
                    ui.label(RichText::new("No update check has run yet.").color(pal.text_muted));
                }
                UpdateState::Checking => {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().color(pal.accent));
                        ui.label(RichText::new("Checking GitHub Releases…").color(pal.text_muted));
                    });
                }
                UpdateState::Current(info) => {
                    ui.label(
                        RichText::new(format!(
                            "Up to date. Latest release is v{}.",
                            info.latest_version
                        ))
                        .color(pal.success),
                    );
                    ui.hyperlink_to("View latest release", &info.release_url);
                }
                UpdateState::Available(info) => {
                    ui.label(
                        RichText::new(format!("Update available: v{}", info.latest_version))
                            .strong()
                            .color(pal.warn),
                    );
                    ui.hyperlink_to("Download release", &info.release_url);
                }
                UpdateState::Failed(message) => {
                    ui.label(RichText::new("Could not check for updates.").color(pal.danger));
                    ui.add(
                        egui::Label::new(RichText::new(message).size(12.0).color(pal.text_muted))
                            .wrap(),
                    );
                }
            }
            ui.add_space(8.0);
            let checking = matches!(self.update_state, UpdateState::Checking);
            if ui
                .add_enabled(!checking, egui::Button::new("Check now"))
                .clicked()
            {
                self.begin_update_check(ui.ctx().clone());
            }
        });

        ui.add_space(8.0);

        card(pal, ui, |ui| {
            ui.label(RichText::new("About").size(15.0).strong().color(pal.text));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Hasher").strong().color(pal.accent));
                ui.label(
                    RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).color(pal.text_muted),
                );
            });
            ui.add_space(3.0);
            ui.label(
                RichText::new("A friendly, fully offline hashing calculator.")
                    .size(12.5)
                    .color(pal.text_muted),
            );
            ui.add_space(1.0);
            ui.label(
                RichText::new("Algorithms: ADLER32 · MD5 · SHA-1 · SHA-256")
                    .size(12.0)
                    .color(pal.text_muted),
            );
            ui.add_space(8.0);
            if ui.button("Supported hashes & containers").clicked() {
                self.supported_formats_open = true;
            }
        });
    }

    fn supported_formats_window(&mut self, ctx: &egui::Context) {
        if !self.supported_formats_open {
            return;
        }

        let pal = self.pal;
        egui::Window::new("Supported hashes & containers")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut self.supported_formats_open)
            .show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.label(
                    RichText::new("Hash algorithms")
                        .size(15.0)
                        .strong()
                        .color(pal.text),
                );
                ui.add_space(6.0);
                for (name, detail) in [
                    ("ADLER32", "8 hex characters"),
                    ("MD5", "32 hex characters"),
                    ("SHA-1", "40 hex characters"),
                    ("SHA-256", "64 hex characters"),
                ] {
                    ui.horizontal(|ui| {
                        chip(pal, ui, name, pal.accent);
                        ui.label(RichText::new(detail).color(pal.text_muted));
                    });
                    ui.add_space(3.0);
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                ui.label(
                    RichText::new("Forensic containers and images")
                        .size(15.0)
                        .strong()
                        .color(pal.text),
                );
                ui.add_space(6.0);
                supported_format_row(
                    pal,
                    ui,
                    "EWF / Expert Witness",
                    ".E01, .Ex01, .L01, .Lx01 segment families",
                    "Detects EVF, EVF2 and LEF2 signatures, decodes metadata, stored MD5/SHA-1 values and acquisition errors, and can hash the reconstructed evidence stream.",
                );
                supported_format_row(
                    pal,
                    ui,
                    "Raw images",
                    ".dd, .img, .raw",
                    "Hashes the selected image byte-for-byte.",
                );
                supported_format_row(
                    pal,
                    ui,
                    "Segmented raw images",
                    ".001, .002, .003 and matching numbered segments",
                    "Detects sibling segments and warns that hashing one path covers only the selected segment.",
                );
                supported_format_row(
                    pal,
                    ui,
                    "Sidecar hash lists",
                    ".txt, .log",
                    "Extracts supported hash values from sidecar files next to the selected image.",
                );
            });
    }
}

fn supported_format_row(
    pal: Palette,
    ui: &mut egui::Ui,
    title: &str,
    extensions: &str,
    detail: &str,
) {
    ui.label(RichText::new(title).strong().color(pal.text));
    ui.label(
        RichText::new(extensions)
            .monospace()
            .size(12.0)
            .color(pal.accent),
    );
    ui.add(egui::Label::new(RichText::new(detail).color(pal.text_muted)).wrap());
    ui.add_space(8.0);
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn renderer_from_env() -> eframe::Renderer {
    let renderer = if env_flag("HASHER_SOFTWARE_RENDERER") {
        Some("glow".to_owned())
    } else {
        std::env::var("HASHER_RENDERER").ok()
    };

    renderer
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

fn main() -> eframe::Result {
    let custom_chrome = env_flag("HASHER_CUSTOM_CHROME");
    let icon = eframe::icon_data::from_png_bytes(APP_ICON_PNG).ok();
    let options = eframe::NativeOptions {
        viewport: {
            let viewport = egui::ViewportBuilder::default()
                .with_title("Hasher")
                .with_inner_size(Vec2::new(760.0, 520.0))
                .with_min_inner_size(Vec2::new(620.0, 420.0))
                .with_decorations(!custom_chrome);
            if let Some(icon) = icon {
                viewport.with_icon(icon)
            } else {
                viewport
            }
        },
        renderer: renderer_from_env(),
        ..Default::default()
    };
    eframe::run_native(
        "Hasher",
        options,
        Box::new(move |creation| {
            HasherApp::install_font(&creation.egui_ctx);
            creation.egui_ctx.set_theme(Theme::Dark);
            let mut app = HasherApp::with_custom_chrome(custom_chrome);
            if let Some(storage) = creation.storage
                && let Some(saved) =
                    eframe::get_value::<PersistedSettings>(storage, eframe::APP_KEY)
            {
                let [r, g, b, a] = saved.accent;
                app.theme = saved.theme;
                app.accent = Color32::from_rgba_premultiplied(r, g, b, a);
                if !saved.order.is_empty() {
                    app.order = saved.order;
                }
                app.reorder_locked = saved.reorder_locked;
                app.style_key = None;
            }
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_plain_and_prefixed_versions() {
        assert_eq!(compare_versions("v1.2.3", "1.2.2"), Ordering::Greater);
        assert_eq!(compare_versions("1.2.3", "v1.2.3"), Ordering::Equal);
        assert_eq!(compare_versions("1.2.3", "1.3.0"), Ordering::Less);
    }

    #[test]
    fn compares_missing_patch_as_zero() {
        assert_eq!(compare_versions("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.2.1", "1.2"), Ordering::Greater);
    }
}
