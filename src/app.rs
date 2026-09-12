#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId,
    Frame, Layout, Margin, RichText, ScrollArea, Sense, Stroke, TextStyle, Vec2, Visuals,
};
use hasher::{
    Algorithm, FileInspection, HashResult, VerifyOutcome, build_report, collect_files_recursively,
    hash_ewf_media_with_progress, hash_file_with_progress, hash_raw_media_with_progress,
    inspect_file, is_ewf_path, is_raw_segment_path, read_manifest,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, SystemTime},
};

const ICON: &[u8] = include_bytes!("../assets/hasher-icon.png");
const ALGORITHMS: [Algorithm; 5] = [
    Algorithm::Md5,
    Algorithm::Sha1,
    Algorithm::Sha256,
    Algorithm::Sha512,
    Algorithm::Blake3,
];
const BLUE: Color32 = Color32::from_rgb(35, 111, 255);
const CYAN: Color32 = Color32::from_rgb(0, 190, 225);
const GREEN: Color32 = Color32::from_rgb(27, 198, 125);
const RED: Color32 = Color32::from_rgb(239, 92, 92);
const SIDEBAR_WIDTH: f32 = 190.0;
const SELECT_COLUMN_WIDTH: f32 = 34.0;
const RESIZE_HANDLE_WIDTH: f32 = 8.0;
const MIN_COLUMN_RATIOS: [f32; 5] = [0.16, 0.08, 0.09, 0.10, 0.14];

fn default_column_ratios() -> [f32; 5] {
    [0.34, 0.12, 0.14, 0.16, 0.24]
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Files,
    Verify,
    History,
}

#[derive(Clone)]
enum Status {
    Hashing,
    Complete,
    Failed(String),
}

struct FileEntry {
    id: u64,
    path: PathBuf,
    size: u64,
    algorithm: Algorithm,
    status: Status,
    progress: f32,
    hashes: Vec<HashResult>,
    inspection: Option<FileInspection>,
    selected: bool,
}

impl FileEntry {
    fn hash(&self) -> Option<&str> {
        self.hashes
            .iter()
            .find(|hash| hash.algorithm == self.algorithm)
            .map(|hash| hash.value.as_str())
    }
}

enum WorkerMessage {
    Progress(u64, u64, u64),
    Finished(u64, anyhow::Result<(Vec<HashResult>, FileInspection)>),
    Manifest(PathBuf, Vec<ManifestResult>),
}

struct ManifestResult {
    path: PathBuf,
    algorithm: Algorithm,
    expected: String,
    computed: Option<String>,
    error: Option<String>,
}

impl ManifestResult {
    fn matches(&self) -> bool {
        self.computed.as_deref() == Some(self.expected.as_str())
    }
}

enum HistoryItem {
    Hash(PathBuf, Algorithm, String),
    Verification(String, bool),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    dark: bool,
    algorithm: Algorithm,
    #[serde(default = "default_column_ratios")]
    column_ratios: [f32; 5],
}

struct App {
    page: Page,
    dark: bool,
    algorithm: Algorithm,
    files: Vec<FileEntry>,
    inspected: Option<u64>,
    next_id: u64,
    tx: Sender<WorkerMessage>,
    rx: Receiver<WorkerMessage>,
    checksum: String,
    verification: Option<bool>,
    manifest: Option<PathBuf>,
    manifest_results: Vec<ManifestResult>,
    manifest_working: bool,
    history: Vec<HistoryItem>,
    notice: Option<String>,
    logo: Option<egui::TextureHandle>,
    column_ratios: [f32; 5],
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let saved = cc
            .storage
            .and_then(|storage| eframe::get_value::<Saved>(storage, eframe::APP_KEY));
        let (dark, algorithm, column_ratios) = saved
            .map(|saved| (saved.dark, saved.algorithm, saved.column_ratios))
            .unwrap_or((true, Algorithm::Sha256, default_column_ratios()));
        install_font(&cc.egui_ctx);
        apply_theme(&cc.egui_ctx, dark);
        Self {
            page: Page::Files,
            dark,
            algorithm,
            files: Vec::new(),
            inspected: None,
            next_id: 1,
            tx,
            rx,
            checksum: String::new(),
            verification: None,
            manifest: None,
            manifest_results: Vec::new(),
            manifest_working: false,
            history: Vec::new(),
            notice: None,
            logo: None,
            column_ratios,
        }
    }

    fn ensure_logo(&mut self, ctx: &egui::Context) {
        if self.logo.is_none()
            && let Ok(icon) = eframe::icon_data::from_png_bytes(ICON)
        {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            self.logo = Some(ctx.load_texture("hasher-logo", image, egui::TextureOptions::LINEAR));
        }
    }

    fn add_paths(&mut self, paths: impl IntoIterator<Item = PathBuf>, ctx: &egui::Context) {
        let mut files = Vec::new();
        for path in paths {
            if path.is_dir() {
                match collect_files_recursively(&path) {
                    Ok(mut found) => files.append(&mut found),
                    Err(error) => self.notice = Some(format!("Could not read folder: {error}")),
                }
            } else {
                files.push(path);
            }
        }
        for path in files {
            if !path.is_file() || self.files.iter().any(|entry| entry.path == path) {
                continue;
            }
            let select_initial = self.files.is_empty();
            let id = self.next_id;
            self.next_id += 1;
            let size = path.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            self.files.push(FileEntry {
                id,
                path: path.clone(),
                size,
                algorithm: self.algorithm,
                status: Status::Hashing,
                progress: 0.0,
                hashes: Vec::new(),
                inspection: None,
                selected: select_initial,
            });
            self.inspected.get_or_insert(id);
            spawn_hash(id, path, size, self.tx.clone(), ctx.clone());
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(message) = self.rx.try_recv() {
            match message {
                WorkerMessage::Progress(id, done, total) => {
                    if let Some(entry) = self.files.iter_mut().find(|entry| entry.id == id) {
                        entry.progress = if total == 0 {
                            1.0
                        } else {
                            (done as f32 / total as f32).clamp(0.0, 1.0)
                        };
                    }
                }
                WorkerMessage::Finished(id, result) => {
                    if let Some(entry) = self.files.iter_mut().find(|entry| entry.id == id) {
                        entry.progress = 1.0;
                        match result {
                            Ok((hashes, inspection)) => {
                                entry.hashes = hashes;
                                entry.inspection = Some(inspection);
                                entry.status = Status::Complete;
                                if let Some(value) = entry.hash().map(str::to_owned) {
                                    self.history.push(HistoryItem::Hash(
                                        entry.path.clone(),
                                        entry.algorithm,
                                        value,
                                    ));
                                }
                            }
                            Err(error) => entry.status = Status::Failed(error.to_string()),
                        }
                    }
                }
                WorkerMessage::Manifest(path, results) => {
                    let matched =
                        !results.is_empty() && results.iter().all(ManifestResult::matches);
                    self.history.push(HistoryItem::Verification(
                        format!("Manifest: {}", file_name(&path)),
                        matched,
                    ));
                    self.manifest = Some(path);
                    self.manifest_results = results;
                    self.manifest_working = false;
                }
            }
            ctx.request_repaint();
        }
    }

    fn remove_selected(&mut self) {
        let inspected_removed = self.inspected.is_some_and(|id| {
            self.files
                .iter()
                .any(|entry| entry.id == id && entry.selected)
        });
        self.files.retain(|entry| !entry.selected);
        if inspected_removed {
            self.inspected = self.files.first().map(|entry| entry.id);
        }
    }

    fn rehash_selected(&mut self, ctx: &egui::Context) {
        for entry in self
            .files
            .iter_mut()
            .filter(|entry| entry.selected && !matches!(entry.status, Status::Hashing))
        {
            entry.algorithm = self.algorithm;
            entry.status = Status::Hashing;
            entry.progress = 0.0;
            entry.hashes.clear();
            entry.inspection = None;
            spawn_hash(
                entry.id,
                entry.path.clone(),
                entry.size,
                self.tx.clone(),
                ctx.clone(),
            );
        }
    }

    fn inspected(&self) -> Option<&FileEntry> {
        self.inspected
            .and_then(|id| self.files.iter().find(|entry| entry.id == id))
    }

    fn copy(ctx: &egui::Context, text: String) {
        ctx.output_mut(|output| output.commands.push(egui::OutputCommand::CopyText(text)));
    }

    fn export(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export hash report")
            .set_file_name("hasher-report.txt")
            .add_filter("Text report", &["txt"])
            .save_file()
        else {
            return;
        };
        let mut report = String::from("HASHER REPORT\n\n");
        for entry in &self.files {
            report.push_str(&format!(
                "File: {}\nSize: {}\n",
                entry.path.display(),
                format_bytes(entry.size)
            ));
            for hash in &entry.hashes {
                report.push_str(&format!("{}: {}\n", hash.algorithm, hash.value));
            }
            report.push('\n');
        }
        self.notice = Some(match fs::write(&path, report) {
            Ok(()) => format!("Report saved to {}", path.display()),
            Err(error) => format!("Could not save report: {error}"),
        });
    }

    fn open_manifest(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.manifest_working = true;
        self.manifest_results.clear();
        self.manifest = Some(path.clone());
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let mut results = Vec::new();
            match read_manifest(&path) {
                Ok(entries) => {
                    let base = path.parent().unwrap_or_else(|| Path::new("."));
                    for item in entries {
                        let target = if item.path.is_absolute() {
                            item.path.clone()
                        } else {
                            base.join(&item.path)
                        };
                        let (computed, error) = match hash_file_with_progress(&target, |_| true) {
                            Ok(hashes) => (
                                hashes
                                    .into_iter()
                                    .find(|hash| hash.algorithm == item.hash.algorithm)
                                    .map(|hash| hash.value),
                                None,
                            ),
                            Err(error) => (None, Some(error.to_string())),
                        };
                        results.push(ManifestResult {
                            path: item.path,
                            algorithm: item.hash.algorithm,
                            expected: item.hash.value,
                            computed,
                            error,
                        });
                    }
                }
                Err(error) => results.push(ManifestResult {
                    path: path.clone(),
                    algorithm: Algorithm::Sha256,
                    expected: String::new(),
                    computed: None,
                    error: Some(error.to_string()),
                }),
            }
            let _ = tx.send(WorkerMessage::Manifest(path, results));
            repaint.request_repaint();
        });
    }

    fn sidebar(&mut self, root: &mut egui::Ui, ctx: &egui::Context) {
        egui::Panel::left("navigation")
            .resizable(false)
            .exact_size(SIDEBAR_WIDTH)
            .frame(panel_frame(self.dark, 8))
            .show(root, |ui| {
                ui.add_space(2.0);
                nav(ui, &mut self.page, Page::Files, "Hash files");
                nav(ui, &mut self.page, Page::Verify, "Verify");
                nav(ui, &mut self.page, Page::History, "History");
                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Theme").small().weak());
                        if ui.selectable_label(!self.dark, "Light").clicked() {
                            self.dark = false;
                            apply_theme(ctx, false);
                        }
                        if ui.selectable_label(self.dark, "Dark").clicked() {
                            self.dark = true;
                            apply_theme(ctx, true);
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Integrity for a safer tomorrow.")
                            .small()
                            .weak(),
                    );
                    ui.separator();
                });
            });
    }

    fn header(&mut self, root: &mut egui::Ui) {
        egui::Panel::top("header")
            .exact_size(48.0)
            .frame(panel_frame(self.dark, 12))
            .show(root, |ui| {
                ui.horizontal_centered(|ui| {
                    if let Some(logo) = &self.logo {
                        ui.image((logo.id(), Vec2::splat(22.0)));
                    }
                    ui.label(RichText::new("H A S H  D E S K").size(16.0).strong());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new("Small files. Greater trust.").small().weak());
                    });
                });
            });
    }

    fn inspector(&mut self, root: &mut egui::Ui, ctx: &egui::Context) {
        if self.page != Page::Files {
            return;
        }
        egui::Panel::right("inspector")
            .resizable(false)
            .exact_size(360.0)
            .frame(panel_frame(self.dark, 18))
            .show(root, |ui| {
                let Some(entry) = self.inspected() else {
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new("Select a file to inspect").weak());
                    });
                    return;
                };
                let path = entry.path.clone();
                let size = entry.size;
                let algorithm = entry.algorithm;
                let hash = entry.hash().map(str::to_owned);
                let hashes = entry.hashes.clone();
                let inspection = entry.inspection.clone();
                let metadata = path.metadata().ok();
                let modified = metadata
                    .as_ref()
                    .and_then(|metadata| metadata.modified().ok())
                    .map(relative_time)
                    .unwrap_or_else(|| "Unavailable".into());
                let access = if metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.permissions().readonly())
                {
                    "Read-only"
                } else {
                    "Read and write"
                };
                ui.horizontal(|ui| {
                    Frame::new()
                        .fill(ui.visuals().faint_bg_color)
                        .stroke(border(self.dark))
                        .corner_radius(CornerRadius::same(5))
                        .inner_margin(Margin::symmetric(6, 5))
                        .show(ui, |ui| {
                            ui.label(RichText::new("FILE").monospace().size(9.0).strong());
                        });
                    ui.vertical(|ui| {
                        ui.label(RichText::new(file_name(&path)).size(14.0).strong());
                        ui.label(RichText::new(format_bytes(size)).size(12.0).weak());
                        ui.label(RichText::new(algorithm.to_string()).size(12.0).weak());
                    });
                });
                ui.add_space(10.0);
                Frame::new()
                    .fill(ui.visuals().extreme_bg_color)
                    .stroke(border(self.dark))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.set_min_height(92.0);
                        ui.label(
                            RichText::new(hash.as_deref().unwrap_or("Hashing…"))
                                .monospace()
                                .small(),
                        );
                    });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            hash.is_some(),
                            egui::Button::new(RichText::new("Copy hash").color(Color32::WHITE))
                                .fill(BLUE)
                                .min_size(Vec2::new(146.0, 36.0)),
                        )
                        .clicked()
                    {
                        Self::copy(ctx, hash.clone().unwrap_or_default());
                        self.notice = Some("Hash copied to clipboard".into());
                    }
                    if ui
                        .add_sized([146.0, 36.0], egui::Button::new("Export report"))
                        .clicked()
                    {
                        self.export();
                    }
                });
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);
                detail(ui, "Path", &path.display().to_string());
                detail(ui, "Modified", &modified);
                if let Some(info) = inspection.as_ref() {
                    detail(ui, "Type", &info.kind.to_string());
                }
                detail(ui, "Access", access);
                detail(ui, "Size", &format_bytes(size));
                detail(ui, "Algorithm", &algorithm.to_string());
                if let Some(info) = inspection.as_ref() {
                    detail(ui, "Segments", &info.segment_count.to_string());
                    if !info.note.is_empty() {
                        ui.label(RichText::new(&info.note).small().weak());
                    }
                }
                if !hashes.is_empty() {
                    ui.add_space(8.0);
                    egui::CollapsingHeader::new("All computed hashes")
                        .default_open(false)
                        .show(ui, |ui| {
                            ScrollArea::vertical().max_height(210.0).show(ui, |ui| {
                                for result in hashes {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(result.algorithm.to_string())
                                                .small()
                                                .strong(),
                                        );
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                if ui.small_button("Copy").clicked() {
                                                    Self::copy(ctx, result.value.clone());
                                                }
                                            },
                                        );
                                    });
                                    ui.label(
                                        RichText::new(result.value).monospace().small().weak(),
                                    );
                                    ui.add_space(5.0);
                                }
                            });
                        });
                }
            });
    }

    fn files_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let compact = ui.available_width() < 790.0;
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("+  Add files").color(Color32::WHITE))
                        .fill(BLUE)
                        .min_size(Vec2::new(92.0, 36.0)),
                )
                .clicked()
                && let Some(paths) = rfd::FileDialog::new().set_title("Add files").pick_files()
            {
                self.add_paths(paths, ctx);
            }
            if ui.button("Add folder").clicked()
                && let Some(folder) = rfd::FileDialog::new().set_title("Add folder").pick_folder()
            {
                self.add_paths([folder], ctx);
            }
            if ui.button("Remove").clicked() {
                self.remove_selected();
            }
            if !compact {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Rehash selected").clicked() {
                        self.rehash_selected(ctx);
                    }
                    for algorithm in ALGORITHMS.into_iter().rev() {
                        if ui
                            .selectable_label(self.algorithm == algorithm, algorithm.to_string())
                            .clicked()
                        {
                            self.algorithm = algorithm;
                        }
                    }
                    ui.label("Algorithm");
                });
            }
        });
        if compact {
            ui.horizontal(|ui| {
                ui.label("Algorithm");
                for algorithm in ALGORITHMS {
                    if ui
                        .selectable_label(self.algorithm == algorithm, algorithm.to_string())
                        .clicked()
                    {
                        self.algorithm = algorithm;
                    }
                }
                if ui.button("Rehash selected").clicked() {
                    self.rehash_selected(ctx);
                }
            });
        }
        ui.add_space(12.0);
        Frame::new()
            .fill(card_fill(self.dark))
            .stroke(border(self.dark))
            .corner_radius(CornerRadius::same(8))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                table_header(ui, &mut self.files, &mut self.column_ratios);
                ui.separator();
                let column_ratios = self.column_ratios;
                ScrollArea::vertical().max_height(520.0).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.set_min_height(260.0);
                    if self.files.is_empty() {
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), 220.0),
                            Layout::centered_and_justified(egui::Direction::TopDown),
                            |ui| {
                                ui.label(
                                    RichText::new(
                                        "Add files, choose a folder, or drag items into this window",
                                    )
                                    .weak(),
                                );
                            },
                        );
                    } else {
                        let mut inspect = None;
                        for entry in &mut self.files {
                            if file_row(
                                ui,
                                entry,
                                self.inspected == Some(entry.id),
                                column_ratios,
                            ) {
                                inspect = Some(entry.id);
                            }
                        }
                        if let Some(id) = inspect {
                            self.inspected = Some(id);
                        }
                    }
                });
            });
        ui.horizontal(|ui| {
            let selected = self.files.iter().filter(|entry| entry.selected).count();
            ui.label(
                RichText::new(format!("{selected} of {} files selected", self.files.len())).weak(),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let active = self
                    .files
                    .iter()
                    .filter(|entry| matches!(entry.status, Status::Hashing))
                    .count();
                if active == 0 {
                    status_cell(ui, 150.0, "All tasks complete", GREEN);
                } else {
                    status_cell(ui, 150.0, &format!("Hashing {active} file(s)"), CYAN);
                }
            });
        });
    }

    fn verify_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.set_min_width(ui.available_width());
        ui.heading("Verify checksums");
        ui.label(
            RichText::new("Compare one file directly or validate an entire checksum manifest.")
                .weak(),
        );
        ui.add_space(14.0);

        let selected = self.inspected().map(|entry| {
            (
                file_name(&entry.path),
                entry.path.display().to_string(),
                entry.size,
                entry.algorithm,
                entry.hashes.clone(),
            )
        });

        Frame::new()
            .fill(card_fill(self.dark))
            .stroke(border(self.dark))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("DIRECT COMPARISON").small().weak().strong());
                        ui.label(RichText::new("Selected queue item").strong().size(16.0));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("View file queue").clicked() {
                            self.page = Page::Files;
                        }
                    });
                });
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                let available = ui.available_width();
                let left_width = (available * 0.34).clamp(260.0, 430.0);
                let right_width = (available - left_width - 26.0).max(320.0);
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        Vec2::new(left_width, 168.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.set_min_width(left_width);
                            if let Some((name, path, size, algorithm, _)) = &selected {
                                ui.horizontal(|ui| {
                                    file_badge(ui, 38.0);
                                    ui.vertical(|ui| {
                                        ui.label(RichText::new(name).strong().size(16.0));
                                        ui.label(RichText::new(format_bytes(*size)).small().weak());
                                    });
                                });
                                ui.add_space(12.0);
                                detail(ui, "Algorithm", &algorithm.to_string());
                                ui.add_space(2.0);
                                ui.label(RichText::new("Path").small().weak());
                                ui.add(
                                    egui::Label::new(RichText::new(path).small())
                                        .truncate()
                                        .sense(Sense::hover()),
                                )
                                .on_hover_text(path);
                            } else {
                                ui.allocate_ui_with_layout(
                                    Vec2::new(left_width, 132.0),
                                    Layout::centered_and_justified(egui::Direction::TopDown),
                                    |ui| {
                                        ui.label(
                                            RichText::new(
                                                "Select a completed file from the queue first",
                                            )
                                            .weak(),
                                        );
                                    },
                                );
                            }
                        },
                    );
                    ui.add_space(6.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(right_width, 168.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.set_min_width(right_width);
                            ui.label(RichText::new("Expected checksum").strong());
                            ui.label(
                                RichText::new(
                                    "Paste an MD5, SHA-1, SHA-256, SHA-512, or BLAKE3 value.",
                                )
                                .small()
                                .weak(),
                            );
                            ui.add_space(8.0);
                            let can_verify = selected
                                .as_ref()
                                .is_some_and(|(_, _, _, _, hashes)| !hashes.is_empty());
                            let verify_clicked = ui
                                .horizontal(|ui| {
                                    let input_width = (ui.available_width() - 158.0).max(160.0);
                                    ui.add_sized(
                                        [input_width, 38.0],
                                        egui::TextEdit::singleline(&mut self.checksum)
                                            .font(TextStyle::Monospace)
                                            .hint_text("Paste checksum here"),
                                    );
                                    ui.add_enabled(
                                        can_verify,
                                        egui::Button::new(
                                            RichText::new("Verify checksum").color(Color32::WHITE),
                                        )
                                        .fill(BLUE)
                                        .min_size(Vec2::new(148.0, 38.0)),
                                    )
                                    .clicked()
                                })
                                .inner;
                            if verify_clicked {
                                self.verification = None;
                                if let Some((name, _, _, _, hashes)) = &selected {
                                    let report = build_report(&self.checksum, hashes);
                                    self.verification = match report.outcome {
                                        VerifyOutcome::Match => Some(true),
                                        VerifyOutcome::Mismatch => Some(false),
                                        VerifyOutcome::Invalid => None,
                                    };
                                    if let Some(matched) = self.verification {
                                        self.history.push(HistoryItem::Verification(
                                            format!("Checksum: {name}"),
                                            matched,
                                        ));
                                    } else {
                                        self.notice = Some(report.note);
                                    }
                                }
                            }
                            ui.add_space(10.0);
                            verification_banner(ui, self.verification, can_verify, self.dark);
                        },
                    );
                });
            });

        ui.add_space(14.0);
        Frame::new()
            .fill(card_fill(self.dark))
            .stroke(border(self.dark))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("MANIFEST VERIFICATION")
                                .small()
                                .weak()
                                .strong(),
                        );
                        ui.label(RichText::new("Check a list of files").strong().size(16.0));
                        ui.label(
                            RichText::new("GNU, BSD, SHA256SUMS, and SFV formats are supported.")
                                .small()
                                .weak(),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                !self.manifest_working,
                                egui::Button::new(
                                    RichText::new("Open manifest…").color(Color32::WHITE),
                                )
                                .fill(BLUE)
                                .min_size(Vec2::new(140.0, 36.0)),
                            )
                            .clicked()
                            && let Some(path) = rfd::FileDialog::new()
                                .set_title("Open checksum manifest")
                                .pick_file()
                        {
                            self.open_manifest(path, ctx);
                        }
                    });
                });
                ui.add_space(10.0);
                ui.separator();

                if let Some(path) = &self.manifest {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Manifest").small().weak());
                        ui.add(
                            egui::Label::new(RichText::new(path.display().to_string()).small())
                                .truncate(),
                        )
                        .on_hover_text(path.display().to_string());
                    });
                }

                if self.manifest_working {
                    ui.allocate_ui_with_layout(
                        Vec2::new(ui.available_width(), 160.0),
                        Layout::centered_and_justified(egui::Direction::TopDown),
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("Checking files in the background…");
                            });
                        },
                    );
                } else if self.manifest_results.is_empty() {
                    ui.allocate_ui_with_layout(
                        Vec2::new(ui.available_width(), 160.0),
                        Layout::centered_and_justified(egui::Direction::TopDown),
                        |ui| {
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new("No manifest open").strong());
                                ui.label(
                                    RichText::new(
                                        "Open a checksum manifest to verify every listed file.",
                                    )
                                    .weak(),
                                );
                            });
                        },
                    );
                } else {
                    ui.add_space(6.0);
                    manifest_header(ui);
                    ui.separator();
                    ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        for result in &self.manifest_results {
                            manifest_row(ui, result);
                            ui.separator();
                        }
                    });
                    ui.add_space(6.0);
                    let matches = self
                        .manifest_results
                        .iter()
                        .filter(|result| result.matches())
                        .count();
                    let failures = self.manifest_results.len() - matches;
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} file(s) checked",
                                self.manifest_results.len()
                            ))
                            .small()
                            .weak(),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            status_cell(
                                ui,
                                150.0,
                                if failures == 0 {
                                    "All files match"
                                } else {
                                    "Attention required"
                                },
                                if failures == 0 { GREEN } else { RED },
                            );
                        });
                    });
                }
            });
    }

    fn history_page(&self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.set_min_width(ui.available_width());
        ui.heading("Completed work");
        ui.label(RichText::new("History is kept for this session only.").weak());
        ui.add_space(14.0);
        Frame::new()
            .fill(card_fill(self.dark))
            .stroke(border(self.dark))
            .corner_radius(CornerRadius::same(8))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                history_header(ui);
                ui.separator();
                if self.history.is_empty() {
                    ui.allocate_ui_with_layout(
                        Vec2::new(ui.available_width(), 220.0),
                        Layout::centered_and_justified(egui::Direction::TopDown),
                        |ui| {
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new("No completed work yet").strong());
                                ui.label(
                                    RichText::new(
                                        "Finished hashes and checksum comparisons appear here.",
                                    )
                                    .weak(),
                                );
                            });
                        },
                    );
                } else {
                    ScrollArea::vertical().show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        for (index, item) in self.history.iter().rev().enumerate() {
                            if let Some(value) = history_row(ui, item, index, self.dark) {
                                Self::copy(ctx, value);
                            }
                            ui.separator();
                        }
                    });
                }
            });
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!("{} history item(s)", self.history.len()))
                .small()
                .weak(),
        );
    }
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        self.ensure_logo(&ctx);
        self.poll(&ctx);
        let dropped = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path().to_path_buf())
                .collect::<Vec<_>>()
        });
        if !dropped.is_empty() {
            self.page = Page::Files;
            self.add_paths(dropped, &ctx);
        }
        self.header(root);
        self.sidebar(root, &ctx);
        self.inspector(root, &ctx);
        if let Some(notice) = self.notice.clone() {
            egui::Panel::bottom("notice")
                .show_separator_line(false)
                .show(root, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(notice);
                        if ui.small_button("Dismiss").clicked() {
                            self.notice = None;
                        }
                    });
                });
        }
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(base_fill(self.dark))
                    .inner_margin(Margin::same(16)),
            )
            .show(root, |ui| match self.page {
                Page::Files => self.files_page(ui, &ctx),
                Page::Verify => self.verify_page(ui, &ctx),
                Page::History => self.history_page(ui, &ctx),
            });
        if self
            .files
            .iter()
            .any(|entry| matches!(entry.status, Status::Hashing))
            || self.manifest_working
        {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(
            storage,
            eframe::APP_KEY,
            &Saved {
                dark: self.dark,
                algorithm: self.algorithm,
                column_ratios: self.column_ratios,
            },
        );
    }
}

fn spawn_hash(id: u64, path: PathBuf, total: u64, tx: Sender<WorkerMessage>, ctx: egui::Context) {
    std::thread::spawn(move || {
        let progress = |done| {
            let connected = tx.send(WorkerMessage::Progress(id, done, total)).is_ok();
            ctx.request_repaint();
            connected
        };
        let result = if is_ewf_path(&path) {
            hash_ewf_media_with_progress(&path, progress)
                .map(|analysis| (analysis.results, analysis.inspection))
        } else if is_raw_segment_path(&path) {
            hash_raw_media_with_progress(&path, progress)
                .map(|analysis| (analysis.results, analysis.inspection))
        } else {
            hash_file_with_progress(&path, progress)
                .and_then(|hashes| inspect_file(&path).map(|info| (hashes, info)))
        };
        let _ = tx.send(WorkerMessage::Finished(id, result));
        ctx.request_repaint();
    });
}

fn nav(ui: &mut egui::Ui, page: &mut Page, target: Page, label: &str) {
    let selected = *page == target;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 44.0), Sense::click());
    let visuals = ui.visuals();
    let fill = if selected {
        BLUE
    } else if response.hovered() {
        visuals.widgets.hovered.bg_fill
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, CornerRadius::same(6), fill);
    let color = if selected {
        Color32::WHITE
    } else {
        visuals.text_color()
    };
    let icon_center = egui::pos2(rect.left() + 18.0, rect.center().y);
    match target {
        Page::Files => {
            let icon = egui::Rect::from_center_size(icon_center, Vec2::new(11.0, 15.0));
            ui.painter().rect_filled(icon, CornerRadius::same(2), color);
        }
        Page::Verify => {
            ui.painter()
                .circle_stroke(icon_center, 7.0, Stroke::new(1.5, color));
            ui.painter().line_segment(
                [
                    icon_center + egui::vec2(-3.0, 0.0),
                    icon_center + egui::vec2(-0.5, 3.0),
                ],
                Stroke::new(1.5, color),
            );
            ui.painter().line_segment(
                [
                    icon_center + egui::vec2(-0.5, 3.0),
                    icon_center + egui::vec2(4.0, -3.0),
                ],
                Stroke::new(1.5, color),
            );
        }
        Page::History => {
            ui.painter()
                .circle_stroke(icon_center, 7.0, Stroke::new(1.5, color));
            ui.painter().line_segment(
                [icon_center, icon_center + egui::vec2(0.0, -4.0)],
                Stroke::new(1.5, color),
            );
            ui.painter().line_segment(
                [icon_center, icon_center + egui::vec2(3.5, 2.0)],
                Stroke::new(1.5, color),
            );
        }
    }
    ui.painter().text(
        egui::pos2(rect.left() + 36.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        FontId::new(14.0, FontFamily::Proportional),
        color,
    );
    if response.clicked() {
        *page = target;
    }
}

fn table_header(ui: &mut egui::Ui, files: &mut [FileEntry], column_ratios: &mut [f32; 5]) {
    let available = ui.available_width();
    let usable = table_usable_width(available);
    let widths = table_widths(available, *column_ratios);
    let auto_widths = content_widths(ui, files);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let mut all_selected = !files.is_empty() && files.iter().all(|entry| entry.selected);
        if ui
            .add_sized(
                [SELECT_COLUMN_WIDTH, 36.0],
                egui::Checkbox::without_text(&mut all_selected),
            )
            .changed()
        {
            for entry in files {
                entry.selected = all_selected;
            }
        }
        for (index, (width, title)) in widths
            .into_iter()
            .zip(["Files", "Size", "Algorithm", "Status", "Progress"])
            .enumerate()
        {
            label_cell(ui, width, RichText::new(title).strong());
            if index < 4 {
                column_resize_handle(ui, index, column_ratios, usable, auto_widths[index]);
            }
        }
    });
}

fn file_row(
    ui: &mut egui::Ui,
    entry: &mut FileEntry,
    inspected: bool,
    column_ratios: [f32; 5],
) -> bool {
    let mut clicked = false;
    let widths = table_widths(ui.available_width(), column_ratios);
    Frame::new()
        .fill(if entry.selected {
            BLUE.linear_multiply(0.12)
        } else if inspected {
            ui.visuals().faint_bg_color.linear_multiply(0.55)
        } else {
            Color32::TRANSPARENT
        })
        .show(ui, |ui| {
            let row = ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.add_sized(
                    [SELECT_COLUMN_WIDTH, 36.0],
                    egui::Checkbox::without_text(&mut entry.selected),
                );
                for index in 0..5 {
                    match index {
                        0 => {
                            let name = file_cell(ui, widths[index], &file_name(&entry.path));
                            clicked |= name.clicked();
                        }
                        1 => {
                            label_cell(ui, widths[index], format_bytes(entry.size));
                        }
                        2 => {
                            label_cell(ui, widths[index], entry.algorithm.to_string());
                        }
                        3 => match &entry.status {
                            Status::Hashing => {
                                label_cell(ui, widths[index], "Hashing");
                            }
                            Status::Complete => {
                                status_cell(ui, widths[index], "Complete", GREEN);
                            }
                            Status::Failed(error) => {
                                status_cell(ui, widths[index], "Failed", RED).on_hover_text(error);
                            }
                        },
                        4 => progress_cell(ui, widths[index], entry.progress),
                        _ => unreachable!(),
                    }
                    if index < 4 {
                        ui.allocate_space(Vec2::new(RESIZE_HANDLE_WIDTH, 36.0));
                    }
                }
            });
            clicked |= row.response.clicked();
        });
    ui.separator();
    clicked
}

fn label_cell(ui: &mut egui::Ui, width: f32, text: impl Into<egui::WidgetText>) -> egui::Response {
    ui.add_sized([width, 36.0], egui::Label::new(text).halign(Align::Min))
}

fn file_cell(ui: &mut egui::Ui, width: f32, name: &str) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 36.0), Sense::click());
    let color = ui.visuals().weak_text_color();
    let icon = egui::Rect::from_min_size(
        egui::pos2(rect.left(), rect.center().y - 8.5),
        Vec2::new(14.0, 17.0),
    );
    ui.painter().rect_filled(icon, CornerRadius::same(2), color);
    ui.painter().rect_filled(
        icon.shrink(1.5),
        CornerRadius::same(1),
        ui.visuals().panel_fill,
    );
    for offset in [6.0, 9.0, 12.0] {
        ui.painter().line_segment(
            [
                egui::pos2(icon.left() + 3.5, icon.top() + offset),
                egui::pos2(icon.right() - 3.5, icon.top() + offset),
            ],
            Stroke::new(1.0, color),
        );
    }
    ui.painter().text(
        egui::pos2(rect.left() + 24.0, rect.center().y),
        Align2::LEFT_CENTER,
        name,
        FontId::new(14.0, FontFamily::Proportional),
        ui.visuals().text_color(),
    );
    response
}

fn status_cell(ui: &mut egui::Ui, width: f32, label: &str, color: Color32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 36.0), Sense::hover());
    let center = egui::pos2(rect.left() + 6.0, rect.center().y);
    ui.painter().circle_filled(center, 6.0, color);
    ui.painter().text(
        egui::pos2(rect.left() + 18.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        FontId::new(14.0, FontFamily::Proportional),
        ui.visuals().text_color(),
    );
    response
}

fn progress_cell(ui: &mut egui::Ui, width: f32, progress: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 36.0), Sense::hover());
    let bar = egui::Rect::from_min_max(
        egui::pos2(rect.left(), rect.center().y - 7.0),
        egui::pos2(rect.right() - 46.0, rect.center().y + 7.0),
    );
    ui.painter()
        .rect_filled(bar, CornerRadius::same(4), ui.visuals().extreme_bg_color);
    if progress > 0.0 {
        let filled = egui::Rect::from_min_max(
            bar.min,
            egui::pos2(
                bar.left() + bar.width() * progress.clamp(0.0, 1.0),
                bar.bottom(),
            ),
        );
        ui.painter()
            .rect_filled(filled, CornerRadius::same(4), CYAN);
    }
    ui.painter().text(
        egui::pos2(bar.right() + 10.0, rect.center().y),
        Align2::LEFT_CENTER,
        format!("{:.0}%", progress * 100.0),
        FontId::new(13.0, FontFamily::Proportional),
        ui.visuals().text_color(),
    );
}

fn table_usable_width(available: f32) -> f32 {
    (available - SELECT_COLUMN_WIDTH - RESIZE_HANDLE_WIDTH * 4.0).max(320.0)
}

fn table_widths(available: f32, ratios: [f32; 5]) -> [f32; 5] {
    let usable = table_usable_width(available);
    ratios.map(|ratio| usable * ratio)
}

fn content_widths(ui: &egui::Ui, files: &[FileEntry]) -> [f32; 5] {
    let font = FontId::new(14.0, FontFamily::Proportional);
    let color = ui.visuals().text_color();
    let measure = |text: &str| {
        ui.painter()
            .layout_no_wrap(text.to_owned(), font.clone(), color)
            .size()
            .x
    };
    let mut widths = [
        measure("Files") + 38.0,
        measure("Size") + 24.0,
        measure("Algorithm") + 24.0,
        measure("Status") + 30.0,
        170.0,
    ];
    for entry in files {
        widths[0] = widths[0].max(measure(&file_name(&entry.path)) + 38.0);
        widths[1] = widths[1].max(measure(&format_bytes(entry.size)) + 24.0);
        widths[2] = widths[2].max(measure(&entry.algorithm.to_string()) + 24.0);
        let status = match &entry.status {
            Status::Hashing => "Hashing",
            Status::Complete => "Complete",
            Status::Failed(_) => "Failed",
        };
        widths[3] = widths[3].max(measure(status) + 38.0);
    }
    widths
}

fn column_resize_handle(
    ui: &mut egui::Ui,
    index: usize,
    ratios: &mut [f32; 5],
    usable: f32,
    auto_width: f32,
) {
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(RESIZE_HANDLE_WIDTH, 36.0),
        Sense::click_and_drag(),
    );
    let response = response.on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
    let color = if response.hovered() || response.dragged() {
        BLUE
    } else {
        ui.visuals().widgets.noninteractive.bg_stroke.color
    };
    ui.painter().line_segment(
        [
            egui::pos2(rect.center().x, rect.top() + 7.0),
            egui::pos2(rect.center().x, rect.bottom() - 7.0),
        ],
        Stroke::new(if response.hovered() { 2.0 } else { 1.0 }, color),
    );

    let requested_delta = if response.double_clicked() {
        auto_width / usable - ratios[index]
    } else if response.dragged() {
        ui.input(|input| input.pointer.delta().x) / usable
    } else {
        0.0
    };
    if requested_delta != 0.0 {
        let delta = requested_delta.clamp(
            MIN_COLUMN_RATIOS[index] - ratios[index],
            ratios[index + 1] - MIN_COLUMN_RATIOS[index + 1],
        );
        ratios[index] += delta;
        ratios[index + 1] -= delta;
    }
}

fn history_widths(available: f32) -> [f32; 5] {
    let usable = available.max(620.0);
    [
        usable * 0.30,
        usable * 0.12,
        usable * 0.38,
        usable * 0.12,
        usable * 0.08,
    ]
}

fn history_header(ui: &mut egui::Ui) {
    let widths = history_widths(ui.available_width());
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (width, title) in
            widths
                .into_iter()
                .zip(["Item", "Type", "Hash or activity", "Result", "Action"])
        {
            label_cell(ui, width, RichText::new(title).strong());
        }
    });
}

fn history_row(ui: &mut egui::Ui, item: &HistoryItem, index: usize, dark: bool) -> Option<String> {
    let widths = history_widths(ui.available_width());
    let (name, kind, activity, result, color, copy_value) = match item {
        HistoryItem::Hash(path, algorithm, value) => (
            file_name(path),
            algorithm.to_string(),
            value.clone(),
            "Complete",
            GREEN,
            Some(value.clone()),
        ),
        HistoryItem::Verification(label, matched) => (
            label.strip_prefix("Checksum: ").unwrap_or(label).to_owned(),
            "Verification".to_owned(),
            "Compared with expected checksum".to_owned(),
            if *matched { "Match" } else { "Mismatch" },
            if *matched { GREEN } else { RED },
            None,
        ),
    };
    let mut copy = false;
    Frame::new()
        .fill(if index % 2 == 0 {
            ui.visuals()
                .faint_bg_color
                .linear_multiply(if dark { 0.35 } else { 0.55 })
        } else {
            Color32::TRANSPARENT
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.add_sized(
                    [widths[0], 42.0],
                    egui::Label::new(RichText::new(&name).strong())
                        .truncate()
                        .halign(Align::Min),
                )
                .on_hover_text(&name);
                label_cell(ui, widths[1], kind);
                ui.add_sized(
                    [widths[2], 42.0],
                    egui::Label::new(RichText::new(&activity).monospace().small())
                        .truncate()
                        .halign(Align::Min),
                )
                .on_hover_text(&activity);
                status_cell(ui, widths[3], result, color);
                if copy_value.is_some() {
                    copy = ui
                        .add_sized(
                            [widths[4], 42.0],
                            egui::Button::new(RichText::new("Copy").color(BLUE)).frame(false),
                        )
                        .clicked();
                } else {
                    label_cell(ui, widths[4], RichText::new("—").weak());
                }
            });
        });
    if copy { copy_value } else { None }
}

fn file_badge(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    ui.painter().rect(
        rect,
        CornerRadius::same(5),
        Color32::TRANSPARENT,
        border(ui.visuals().dark_mode),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        "FILE",
        FontId::new(9.0, FontFamily::Monospace),
        ui.visuals().text_color(),
    );
}

fn verification_banner(
    ui: &mut egui::Ui,
    verification: Option<bool>,
    can_verify: bool,
    dark: bool,
) {
    let (message, color) = match verification {
        Some(true) => ("Verified — the checksums match", GREEN),
        Some(false) => ("Mismatch — do not trust this file", RED),
        None if can_verify => ("Ready — paste a checksum to compare", CYAN),
        None => (
            "Select a completed file from the queue to begin",
            ui.visuals().weak_text_color(),
        ),
    };
    let fill = if verification.is_some() {
        color.linear_multiply(if dark { 0.13 } else { 0.10 })
    } else {
        ui.visuals().faint_bg_color.linear_multiply(0.75)
    };
    Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, color.linear_multiply(0.55)))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(7))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_centered(|ui| {
                let (indicator, _) = ui.allocate_exact_size(Vec2::new(12.0, 28.0), Sense::hover());
                ui.painter().circle_filled(indicator.center(), 5.0, color);
                ui.label(RichText::new(message).strong());
            });
        });
}

fn manifest_widths(available: f32) -> [f32; 4] {
    let usable = available.max(480.0);
    [usable * 0.34, usable * 0.12, usable * 0.38, usable * 0.16]
}

fn manifest_header(ui: &mut egui::Ui) {
    let widths = manifest_widths(ui.available_width());
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (width, title) in
            widths
                .into_iter()
                .zip(["File", "Algorithm", "Expected checksum", "Result"])
        {
            label_cell(ui, width, RichText::new(title).strong());
        }
    });
}

fn manifest_row(ui: &mut egui::Ui, result: &ManifestResult) {
    let widths = manifest_widths(ui.available_width());
    let matches = result.matches();
    let failed = !matches;
    Frame::new()
        .fill(if failed {
            RED.linear_multiply(0.07)
        } else {
            Color32::TRANSPARENT
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.add_sized(
                    [widths[0], 40.0],
                    egui::Label::new(file_name(&result.path))
                        .truncate()
                        .halign(Align::Min),
                )
                .on_hover_text(result.path.display().to_string());
                label_cell(ui, widths[1], result.algorithm.to_string());
                ui.add_sized(
                    [widths[2], 40.0],
                    egui::Label::new(RichText::new(&result.expected).monospace().small())
                        .truncate()
                        .halign(Align::Min),
                )
                .on_hover_text(&result.expected);
                let (label, color) = if result.error.is_some() {
                    ("Error", RED)
                } else if matches {
                    ("Match", GREEN)
                } else {
                    ("Mismatch", RED)
                };
                let response = status_cell(ui, widths[3], label, color);
                if let Some(error) = &result.error {
                    response.on_hover_text(error);
                } else if let Some(computed) = &result.computed
                    && !matches
                {
                    response.on_hover_text(format!("Computed: {computed}"));
                }
            });
        });
}

fn detail(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.add_sized([76.0, 20.0], egui::Label::new(RichText::new(label).weak()));
        ui.label(value);
    });
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn relative_time(value: SystemTime) -> String {
    let Ok(elapsed) = SystemTime::now().duration_since(value) else {
        return "In the future".into();
    };
    if elapsed.as_secs() < 60 {
        "Just now".into()
    } else if elapsed.as_secs() < 60 * 60 {
        format!("{} minutes ago", elapsed.as_secs() / 60)
    } else if elapsed.as_secs() < 24 * 60 * 60 {
        format!("{} hours ago", elapsed.as_secs() / (60 * 60))
    } else {
        format!("{} days ago", elapsed.as_secs() / (24 * 60 * 60))
    }
}

fn install_font(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "JetBrains Mono".into(),
        FontData::from_static(include_bytes!("../assets/JetBrainsMono-Regular.ttf")).into(),
    );
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "JetBrains Mono".into());
    ctx.set_fonts(fonts);
}

fn apply_theme(ctx: &egui::Context, dark: bool) {
    let mut visuals = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    visuals.selection.bg_fill = BLUE;
    visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(4);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(4);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(4);
    visuals.widgets.active.corner_radius = CornerRadius::same(4);
    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.panel_fill = if dark {
        Color32::from_rgb(12, 25, 39)
    } else {
        Color32::from_rgb(248, 250, 253)
    };
    visuals.extreme_bg_color = if dark {
        Color32::from_rgb(8, 18, 29)
    } else {
        Color32::WHITE
    };
    visuals.faint_bg_color = if dark {
        Color32::from_rgb(18, 35, 52)
    } else {
        Color32::from_rgb(237, 244, 253)
    };
    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.text_styles.insert(
            TextStyle::Heading,
            FontId::new(20.0, FontFamily::Proportional),
        );
        style
            .text_styles
            .insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
        style.text_styles.insert(
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        );
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 8.0);
        style.spacing.interact_size.y = 36.0;
    });
}

fn card_fill(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(16, 31, 47)
    } else {
        Color32::WHITE
    }
}

fn base_fill(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(11, 25, 38)
    } else {
        Color32::from_rgb(250, 252, 255)
    }
}

fn border(dark: bool) -> Stroke {
    Stroke::new(
        1.0,
        if dark {
            Color32::from_rgb(49, 68, 88)
        } else {
            Color32::from_rgb(217, 225, 236)
        },
    )
}

fn panel_frame(dark: bool, margin: i8) -> Frame {
    Frame::new()
        .fill(card_fill(dark))
        .stroke(border(dark))
        .inner_margin(Margin::same(margin))
}

fn main() -> eframe::Result {
    let icon = eframe::icon_data::from_png_bytes(ICON).ok();
    let options = eframe::NativeOptions {
        viewport: {
            let viewport = egui::ViewportBuilder::default()
                .with_title("Hasher")
                .with_inner_size([1280.0, 760.0])
                .with_min_inner_size([980.0, 620.0])
                .with_drag_and_drop(true);
            if let Some(icon) = icon {
                viewport.with_icon(icon)
            } else {
                viewport
            }
        },
        ..Default::default()
    };
    eframe::run_native("Hasher", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
