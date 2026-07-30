//! Shared hashing and forensic-file inspection used by both front ends.

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("Hasher supports only macOS and Windows.");

use adler2::Adler32;
use anyhow::{Context, Result, bail};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    fmt::{self, Display},
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Algorithm {
    Adler32,
    Md5,
    Sha1,
    Sha256,
    Crc32,
}

impl Algorithm {
    pub const ALL: [Self; 5] = [
        Self::Adler32,
        Self::Md5,
        Self::Sha1,
        Self::Sha256,
        Self::Crc32,
    ];

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().replace('-', "").as_str() {
            "adler32" => Ok(Self::Adler32),
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "crc32" => Ok(Self::Crc32),
            _ => bail!("unsupported algorithm: {value}"),
        }
    }

    pub fn hex_len(self) -> usize {
        match self {
            Self::Adler32 | Self::Crc32 => 8,
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Adler32 => "ADLER32",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Crc32 => "CRC32",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashResult {
    pub algorithm: Algorithm,
    pub value: String,
}

struct MultiHasher {
    adler: Adler32,
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
    crc32: u32,
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < table.len() {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = crc32_table();

impl MultiHasher {
    fn new() -> Self {
        Self {
            adler: Adler32::new(),
            md5: Md5::new(),
            sha1: Sha1::new(),
            sha256: Sha256::new(),
            crc32: u32::MAX,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.adler.write_slice(bytes);
        self.md5.update(bytes);
        self.sha1.update(bytes);
        self.sha256.update(bytes);
        for byte in bytes {
            let index = ((self.crc32 ^ u32::from(*byte)) & 0xff) as usize;
            self.crc32 = CRC32_TABLE[index] ^ (self.crc32 >> 8);
        }
    }

    fn finish(self) -> Vec<HashResult> {
        vec![
            HashResult {
                algorithm: Algorithm::Adler32,
                value: format!("{:08x}", self.adler.checksum()),
            },
            HashResult {
                algorithm: Algorithm::Md5,
                value: hex::encode(self.md5.finalize()),
            },
            HashResult {
                algorithm: Algorithm::Sha1,
                value: hex::encode(self.sha1.finalize()),
            },
            HashResult {
                algorithm: Algorithm::Sha256,
                value: hex::encode(self.sha256.finalize()),
            },
            HashResult {
                algorithm: Algorithm::Crc32,
                value: format!("{:08x}", !self.crc32),
            },
        ]
    }
}

pub fn hash_bytes(bytes: &[u8]) -> Vec<HashResult> {
    let mut hasher = MultiHasher::new();
    hasher.update(bytes);
    hasher.finish()
}

pub fn hash_reader(mut reader: impl Read) -> io::Result<Vec<HashResult>> {
    hash_reader_with_progress(&mut reader, |_| true)
}

/// Hashes a stream while reporting the number of bytes consumed.
///
/// Returning `false` from `progress` cooperatively cancels the operation. The
/// callback runs after each read (currently every MiB), so callers can update a
/// UI and stop large hashes without waiting for the whole stream.
pub fn hash_reader_with_progress(
    mut reader: impl Read,
    mut progress: impl FnMut(u64) -> bool,
) -> io::Result<Vec<HashResult>> {
    let mut hasher = MultiHasher::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut processed = 0_u64;
    loop {
        if !progress(processed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "hashing cancelled",
            ));
        }
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        processed = processed.saturating_add(count as u64);
    }
    if !progress(processed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "hashing cancelled",
        ));
    }
    Ok(hasher.finish())
}

pub fn hash_file(path: impl AsRef<Path>) -> Result<Vec<HashResult>> {
    hash_file_with_progress(path, |_| true)
}

pub fn hash_file_with_progress(
    path: impl AsRef<Path>,
    progress: impl FnMut(u64) -> bool,
) -> Result<Vec<HashResult>> {
    let path = path.as_ref();
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    hash_reader_with_progress(BufReader::with_capacity(1024 * 1024, file), progress)
        .with_context(|| format!("could not read {}", path.display()))
}

/// Returns `true` for conventional numbered raw segment suffixes (`.001`-`.999`).
pub fn is_raw_segment_path(path: impl AsRef<Path>) -> bool {
    path.as_ref()
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.len() == 3
                && extension.chars().all(|c| c.is_ascii_digit())
                && extension != "000"
        })
}

pub fn format_results(results: &[HashResult]) -> String {
    results
        .iter()
        .map(|r| format!("{}  {}", r.algorithm, r.value))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestFormat {
    Gnu,
    Bsd,
    Sfv,
}

impl ManifestFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "gnu" | "coreutils" | "sha256sums" => Ok(Self::Gnu),
            "bsd" => Ok(Self::Bsd),
            "sfv" => Ok(Self::Sfv),
            _ => bail!("unsupported manifest format: {value} (expected gnu, bsd, or sfv)"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    pub path: PathBuf,
    pub hash: HashResult,
}

/// Recursively collects regular files below `root` in stable path order.
/// Directory symlinks are not followed.
pub fn collect_files_recursively(root: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        let metadata = path
            .symlink_metadata()
            .with_context(|| format!("could not inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Ok(());
        }
        if metadata.is_file() {
            files.push(path.to_path_buf());
            return Ok(());
        }
        if !metadata.is_dir() {
            return Ok(());
        }

        let mut children = fs::read_dir(path)
            .with_context(|| format!("could not read directory {}", path.display()))?
            .collect::<io::Result<Vec<_>>>()
            .with_context(|| format!("could not enumerate directory {}", path.display()))?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            visit(&child.path(), files)?;
        }
        Ok(())
    }

    let root = root.as_ref();
    let mut files = Vec::new();
    visit(root, &mut files)?;
    Ok(files)
}

fn algorithm_from_digest(value: &str) -> Option<Algorithm> {
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match value.len() {
        8 => Some(Algorithm::Adler32),
        32 => Some(Algorithm::Md5),
        40 => Some(Algorithm::Sha1),
        64 => Some(Algorithm::Sha256),
        _ => None,
    }
}

fn unescape_gnu_path(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => output.push('\n'),
                Some('\\') => output.push('\\'),
                Some(other) => {
                    output.push('\\');
                    output.push(other);
                }
                None => output.push('\\'),
            }
        } else {
            output.push(ch);
        }
    }
    output
}

/// Parses GNU/coreutils, BSD checksum, and SFV-style manifest lines.
pub fn parse_manifest(text: &str) -> Result<Vec<ManifestEntry>> {
    let mut entries = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        let parsed = if let Some((left, digest)) = line.rsplit_once(") = ") {
            let (algorithm, path) = left.split_once(" (").context("invalid BSD checksum line")?;
            let algorithm = Algorithm::parse(algorithm)?;
            let digest = digest.trim();
            if digest.len() != algorithm.hex_len() || !digest.chars().all(|c| c.is_ascii_hexdigit())
            {
                bail!("digest does not match {algorithm}");
            }
            Some(ManifestEntry {
                path: PathBuf::from(path),
                hash: HashResult {
                    algorithm,
                    value: digest.to_ascii_lowercase(),
                },
            })
        } else {
            let escaped = line.starts_with('\\');
            let candidate = if escaped { &line[1..] } else { line };
            let digest_end = candidate
                .find(char::is_whitespace)
                .unwrap_or(candidate.len());
            let first = &candidate[..digest_end];
            if let Some(algorithm) = algorithm_from_digest(first) {
                let mut path = candidate[digest_end..].trim_start();
                if let Some(binary_path) = path.strip_prefix('*') {
                    path = binary_path;
                }
                if path.is_empty() {
                    bail!("missing filename");
                }
                let path = if escaped {
                    unescape_gnu_path(path)
                } else {
                    path.to_owned()
                };
                Some(ManifestEntry {
                    path: PathBuf::from(path),
                    hash: HashResult {
                        algorithm,
                        value: first.to_ascii_lowercase(),
                    },
                })
            } else if let Some((path, digest)) = candidate.rsplit_once(char::is_whitespace) {
                let digest = digest.trim();
                if digest.len() != Algorithm::Crc32.hex_len()
                    || !digest.chars().all(|c| c.is_ascii_hexdigit())
                {
                    bail!("SFV-style entries require an 8-hex digest");
                }
                Some(ManifestEntry {
                    path: PathBuf::from(path.trim_end()),
                    hash: HashResult {
                        algorithm: Algorithm::Crc32,
                        value: digest.to_ascii_lowercase(),
                    },
                })
            } else {
                None
            }
        };

        match parsed {
            Some(entry) if entry.path.as_os_str().is_empty() => {
                bail!("manifest line {} has an empty filename", index + 1)
            }
            Some(entry) => entries.push(entry),
            None => bail!("could not parse manifest line {}", index + 1),
        }
    }
    if entries.is_empty() {
        bail!("manifest contains no checksum entries");
    }
    Ok(entries)
}

pub fn read_manifest(path: impl AsRef<Path>) -> Result<Vec<ManifestEntry>> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .with_context(|| format!("could not read manifest {}", path.display()))?;
    parse_manifest(&text)
}

pub fn format_manifest(entries: &[ManifestEntry], format: ManifestFormat) -> Result<String> {
    let mut output = String::new();
    for entry in entries {
        let path = entry.path.to_string_lossy();
        #[cfg(target_os = "windows")]
        let path = path.replace('\\', "/");
        #[cfg(not(target_os = "windows"))]
        let path = path.into_owned();
        match format {
            ManifestFormat::Gnu => {
                if path.contains('\\') || path.contains('\n') {
                    let escaped = path.replace('\\', "\\\\").replace('\n', "\\n");
                    output.push_str(&format!("\\{}  {escaped}\n", entry.hash.value));
                } else {
                    output.push_str(&format!("{}  {path}\n", entry.hash.value));
                }
            }
            ManifestFormat::Bsd => {
                output.push_str(&format!(
                    "{} ({path}) = {}\n",
                    entry.hash.algorithm, entry.hash.value
                ));
            }
            ManifestFormat::Sfv => {
                if entry.hash.algorithm != Algorithm::Crc32 {
                    bail!("SFV output requires CRC32 results");
                }
                output.push_str(&format!("{path} {}\n", entry.hash.value));
            }
        }
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyOutcome {
    Match,
    Mismatch,
    Invalid,
}

#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub outcome: VerifyOutcome,
    pub algorithm: Option<Algorithm>,
    pub expected: String,
    pub computed: Option<String>,
    pub note: String,
}

/// Normalise an expected-hash string, pick the algorithm by length, and compare
/// against the computed set.
pub fn normalise_expected_hash(expected_raw: &str) -> String {
    let expected_raw = strip_algorithm_label(expected_raw);
    let compact: String = expected_raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();

    if compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return compact;
    }

    let extracted = extract_hashes(expected_raw);
    if extracted.len() == 1 {
        extracted[0].value.clone()
    } else {
        compact
    }
}

pub fn detect_expected_algorithm(expected_raw: &str) -> Option<Algorithm> {
    let expected = normalise_expected_hash(expected_raw);
    if let Some(algorithm) = explicit_algorithm_label(expected_raw)
        && expected.len() == algorithm.hex_len()
        && expected.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Some(algorithm);
    }
    expected
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| {
            Algorithm::ALL
                .into_iter()
                .find(|a| a.hex_len() == expected.len())
        })
        .flatten()
}

fn explicit_algorithm_label(value: &str) -> Option<Algorithm> {
    let trimmed = value.trim_start();
    for (label, algorithm) in [
        ("adler32", Algorithm::Adler32),
        ("adler-32", Algorithm::Adler32),
        ("crc32", Algorithm::Crc32),
        ("crc-32", Algorithm::Crc32),
        ("md5", Algorithm::Md5),
        ("sha1", Algorithm::Sha1),
        ("sha-1", Algorithm::Sha1),
        ("sha256", Algorithm::Sha256),
        ("sha-256", Algorithm::Sha256),
    ] {
        let Some(prefix) = trimmed.get(..label.len()) else {
            continue;
        };
        let boundary = trimmed[label.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        if prefix.eq_ignore_ascii_case(label) && boundary {
            return Some(algorithm);
        }
    }
    None
}

fn strip_algorithm_label(value: &str) -> &str {
    let trimmed = value.trim_start();
    for label in [
        "adler32", "adler-32", "crc32", "crc-32", "md5", "sha1", "sha-1", "sha256", "sha-256",
    ] {
        let Some(prefix) = trimmed.get(..label.len()) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case(label) {
            continue;
        }

        let rest = &trimmed[label.len()..];
        let has_boundary = rest
            .chars()
            .next()
            .map(|c| !c.is_ascii_alphanumeric())
            .unwrap_or(true);
        if has_boundary {
            return rest
                .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, ':' | '=' | '-'));
        }
    }
    trimmed
}

pub fn build_report(expected_raw: &str, computed_set: &[HashResult]) -> VerifyReport {
    let expected = normalise_expected_hash(expected_raw);

    let mut report = VerifyReport {
        outcome: VerifyOutcome::Invalid,
        algorithm: None,
        expected: expected.clone(),
        computed: None,
        note: String::new(),
    };

    if expected.is_empty() {
        report.note = "Enter or import a hash value to verify against.".into();
        return report;
    }
    if !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        report.note = "The expected value contains non-hexadecimal characters.".into();
        return report;
    }

    let Some(algorithm) = detect_expected_algorithm(expected_raw) else {
        report.note = format!(
            "{} hex characters doesn't match ADLER32/CRC32 (8), MD5 (32), SHA-1 (40) or SHA-256 (64).",
            expected.len()
        );
        return report;
    };
    report.algorithm = Some(algorithm);

    let computed = computed_set
        .iter()
        .find(|r| r.algorithm == algorithm)
        .map(|r| r.value.clone());
    match &computed {
        Some(value) if *value == expected => report.outcome = VerifyOutcome::Match,
        Some(_) => report.outcome = VerifyOutcome::Mismatch,
        None => report.note = "Could not compute this algorithm for the given input.".into(),
    }
    report.computed = computed;
    report
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKind {
    RawImage,
    RawSegment,
    ExpertWitness,
    OrdinaryFile,
}

impl Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RawImage => "raw forensic image",
            Self::RawSegment => "segmented raw image",
            Self::ExpertWitness => "Expert Witness/E01 container",
            Self::OrdinaryFile => "ordinary file",
        })
    }
}

#[derive(Clone, Debug)]
pub struct FileInspection {
    pub path: PathBuf,
    pub kind: EvidenceKind,
    pub size: u64,
    pub segment_count: usize,
    /// Digests stored inside the inspected evidence container.
    pub embedded_hashes: Vec<HashResult>,
    /// Digests parsed from adjacent `.txt` or `.log` files.
    pub sidecar_hashes: Vec<HashResult>,
    pub ewf: Option<EwfDetails>,
    pub note: String,
}

#[derive(Clone, Debug)]
pub struct EwfDetails {
    /// Logical, decompressed evidence-stream size.
    pub media_size: u64,
    pub chunk_size: u64,
    pub chunk_count: usize,
    pub metadata: Vec<(String, String)>,
    pub acquisition_errors: Vec<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct EwfAnalysis {
    pub results: Vec<HashResult>,
    pub inspection: FileInspection,
}

#[derive(Clone, Debug)]
pub struct RawAnalysis {
    pub results: Vec<HashResult>,
    pub inspection: FileInspection,
    pub media_size: u64,
}

pub fn is_ewf_path(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let chars: Vec<char> = ext.chars().collect();
    let plausible_extension = match chars.as_slice() {
        [kind @ ('e' | 'l'), a, b] => {
            let _ = kind;
            (a.is_ascii_digit() && b.is_ascii_digit())
                || (a.is_ascii_alphabetic() && b.is_ascii_alphabetic())
        }
        [kind @ ('e' | 'l'), series @ ('x'..='z'), a, b] => {
            let _ = (kind, series);
            (a.is_ascii_digit() && b.is_ascii_digit())
                || (a.is_ascii_alphabetic() && b.is_ascii_alphabetic())
        }
        _ => false,
    };
    if !plausible_extension {
        return false;
    }
    let mut signature = [0_u8; 8];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut signature))
        .is_ok()
        && matches!(
            signature,
            [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]
                | [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00]
                | [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00]
        )
}

fn open_ewf_details(path: &Path) -> Result<(ewf::EwfReader, EwfDetails, Vec<HashResult>)> {
    let reader = ewf::EwfReader::open(path)
        .with_context(|| format!("could not open EWF evidence set at {}", path.display()))?;
    let stored = reader.stored_hashes();
    let mut embedded_hashes = Vec::new();
    if let Some(md5) = stored.md5 {
        embedded_hashes.push(HashResult {
            algorithm: Algorithm::Md5,
            value: hex::encode(md5),
        });
    }
    if let Some(sha1) = stored.sha1 {
        embedded_hashes.push(HashResult {
            algorithm: Algorithm::Sha1,
            value: hex::encode(sha1),
        });
    }

    let meta = reader.metadata();
    let metadata = [
        ("Case number", &meta.case_number),
        ("Evidence number", &meta.evidence_number),
        ("Description", &meta.description),
        ("Examiner", &meta.examiner),
        ("Notes", &meta.notes),
        ("Acquisition software", &meta.acquiry_software),
        ("Operating system", &meta.os_version),
        ("Acquisition date", &meta.acquiry_date),
        ("System date", &meta.system_date),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.clone().map(|value| (name.to_owned(), value)))
    .collect();
    let acquisition_errors = reader
        .acquisition_errors()
        .iter()
        .map(|error| (error.first_sector, error.sector_count))
        .collect();
    let details = EwfDetails {
        media_size: reader.total_size(),
        chunk_size: reader.chunk_size(),
        chunk_count: reader.chunk_count(),
        metadata,
        acquisition_errors,
    };
    Ok((reader, details, embedded_hashes))
}

/// Hashes the logical evidence stream reconstructed from every EWF segment.
/// The returned MD5/SHA-1 can be compared with acquisition digests stored in the image.
pub fn hash_ewf_media(path: impl AsRef<Path>) -> Result<EwfAnalysis> {
    hash_ewf_media_with_progress(path, |_| true)
}

pub fn hash_ewf_media_with_progress(
    path: impl AsRef<Path>,
    progress: impl FnMut(u64) -> bool,
) -> Result<EwfAnalysis> {
    let path = path.as_ref();
    let (reader, details, embedded_hashes) = open_ewf_details(path)?;
    let results = hash_reader_with_progress(reader, progress)
        .context("could not decode the EWF evidence stream")?;
    let inspection = ewf_inspection(path, details, embedded_hashes)?;
    Ok(EwfAnalysis {
        results,
        inspection,
    })
}

/// Discovers the complete contiguous numbered raw set containing `path`.
pub fn raw_segment_paths(path: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    let path = path.as_ref();
    if !is_raw_segment_path(path) {
        bail!("{} is not a numbered raw segment", path.display());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let wanted_stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    let mut numbered = Vec::new();
    for entry in fs::read_dir(parent)
        .with_context(|| format!("could not inspect raw segment set at {}", parent.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let candidate = entry.path();
        let stem = candidate
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("");
        let extension = candidate
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("");
        if stem.eq_ignore_ascii_case(wanted_stem)
            && extension.len() == 3
            && extension.chars().all(|c| c.is_ascii_digit())
        {
            let number: u16 = extension.parse().expect("three ASCII digits");
            if number > 0 {
                numbered.push((number, candidate));
            }
        }
    }
    numbered.sort_by_key(|(number, _)| *number);
    if numbered.first().map(|(number, _)| *number) != Some(1) {
        bail!(
            "raw segment set for {} is incomplete: .001 is missing",
            path.display()
        );
    }
    for pair in numbered.windows(2) {
        let expected = pair[0].0 + 1;
        if pair[1].0 == pair[0].0 {
            bail!(
                "raw segment set for {} contains duplicate .{:03} segments",
                path.display(),
                pair[0].0
            );
        }
        if pair[1].0 != expected {
            bail!(
                "raw segment set for {} is incomplete: .{:03} is missing",
                path.display(),
                expected
            );
        }
    }
    Ok(numbered.into_iter().map(|(_, path)| path).collect())
}

struct RawSegmentReader {
    paths: std::vec::IntoIter<PathBuf>,
    current: Option<BufReader<File>>,
}

impl RawSegmentReader {
    fn open(paths: Vec<PathBuf>) -> io::Result<Self> {
        let mut paths = paths.into_iter();
        let current = paths
            .next()
            .map(File::open)
            .transpose()?
            .map(BufReader::new);
        Ok(Self { paths, current })
    }
}

impl Read for RawSegmentReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let Some(current) = &mut self.current else {
                return Ok(0);
            };
            let read = current.read(buffer)?;
            if read != 0 {
                return Ok(read);
            }
            self.current = self
                .paths
                .next()
                .map(File::open)
                .transpose()?
                .map(BufReader::new);
        }
    }
}

/// Hashes all numbered raw segments in numeric order as one logical stream.
pub fn hash_raw_media(path: impl AsRef<Path>) -> Result<RawAnalysis> {
    hash_raw_media_with_progress(path, |_| true)
}

pub fn hash_raw_media_with_progress(
    path: impl AsRef<Path>,
    progress: impl FnMut(u64) -> bool,
) -> Result<RawAnalysis> {
    let path = path.as_ref();
    let paths = raw_segment_paths(path)?;
    let media_size = paths.iter().try_fold(0_u64, |total, segment| {
        segment
            .metadata()
            .map(|metadata| total.saturating_add(metadata.len()))
    })?;
    let reader = RawSegmentReader::open(paths)
        .with_context(|| format!("could not open raw segment set at {}", path.display()))?;
    let results = hash_reader_with_progress(reader, progress)
        .context("could not read the reconstructed raw evidence stream")?;
    let inspection = inspect_file(path)?;
    Ok(RawAnalysis {
        results,
        inspection,
        media_size,
    })
}

fn ewf_inspection(
    path: &Path,
    details: EwfDetails,
    embedded_hashes: Vec<HashResult>,
) -> Result<FileInspection> {
    let sidecar_hashes = read_sidecar_hashes(path)?;
    let metadata = path
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    Ok(FileInspection {
        path: path.to_owned(),
        kind: EvidenceKind::ExpertWitness,
        size: metadata.len(),
        segment_count: count_segments(path, EvidenceKind::ExpertWitness),
        embedded_hashes,
        sidecar_hashes,
        note: "EWF metadata and stored acquisition digests were decoded. Evidence-stream hashing reconstructs and hashes the logical media across the complete segment set.".into(),
        ewf: Some(details),
    })
}

/// Performs safe, non-mutating identification. E01 is a compressed container:
/// hashing the container and hashing its reconstructed media are distinct operations.
pub fn inspect_file(path: impl AsRef<Path>) -> Result<FileInspection> {
    let path = path.as_ref();
    let metadata = path
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let kind = if is_ewf_path(path) {
        EvidenceKind::ExpertWitness
    } else if is_raw_segment_path(path) {
        EvidenceKind::RawSegment
    } else if matches!(ext.as_str(), "dd" | "img" | "raw") {
        EvidenceKind::RawImage
    } else {
        EvidenceKind::OrdinaryFile
    };
    let segment_count = if matches!(kind, EvidenceKind::RawSegment | EvidenceKind::ExpertWitness) {
        count_segments(path, kind)
    } else {
        1
    };
    if kind == EvidenceKind::ExpertWitness {
        let (_reader, details, embedded_hashes) = open_ewf_details(path)?;
        return ewf_inspection(path, details, embedded_hashes);
    }
    let sidecar_hashes = read_sidecar_hashes(path)?;
    let note = match kind {
        EvidenceKind::ExpertWitness => unreachable!(),
        EvidenceKind::RawSegment => match raw_segment_paths(path) {
            Ok(_) => "A complete segmented raw image was detected. Evidence-stream hashing reconstructs the logical media in numeric order; selected-file hashing covers only this segment.".into(),
            Err(error) => format!("A numbered raw image segment was detected, but its set cannot be reconstructed: {error:#}. Selected-file hashing still covers only this segment."),
        },
        EvidenceKind::RawImage => "Raw images have no standard embedded digest field; any discovered values came from a sidecar TXT/LOG file.".into(),
        EvidenceKind::OrdinaryFile => "The complete file can be hashed byte-for-byte.".into(),
    };
    Ok(FileInspection {
        path: path.to_owned(),
        kind,
        size: metadata.len(),
        segment_count,
        embedded_hashes: Vec::new(),
        sidecar_hashes,
        ewf: None,
        note,
    })
}

fn count_segments(path: &Path, kind: EvidenceKind) -> usize {
    if kind == EvidenceKind::RawSegment {
        return raw_segment_paths(path)
            .map(|segments| segments.len())
            .unwrap_or_else(|_| {
                let Some(parent) = path.parent() else {
                    return 1;
                };
                let wanted_stem = path.file_stem();
                fs::read_dir(parent)
                    .ok()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter(|entry| {
                        let candidate = entry.path();
                        candidate.file_stem() == wanted_stem && is_raw_segment_path(&candidate)
                    })
                    .count()
                    .max(1)
            });
    }
    let Some(parent) = path.parent() else {
        return 1;
    };
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let prefix = stem.to_ascii_lowercase();
    std::fs::read_dir(parent)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            let candidate = Path::new(&name);
            let ext = candidate.extension().and_then(|s| s.to_str()).unwrap_or("");
            let stem = candidate.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if kind == EvidenceKind::ExpertWitness {
                // Match siblings of the exact same base name, e.g. `disk.E01`,
                // `disk.E02`, not unrelated files that merely share a prefix.
                stem == prefix
                    && matches!(ext.chars().next(), Some('e' | 'l'))
                    && ext.len() >= 3
                    && ext.chars().all(|c| c.is_ascii_alphanumeric())
            } else {
                unreachable!()
            }
        })
        .count()
        .max(1)
}

pub fn extract_hashes(text: &str) -> Vec<HashResult> {
    let mut found = Vec::new();
    for token in text.split(|c: char| !c.is_ascii_hexdigit()) {
        let algorithm = match token.len() {
            8 => Some(Algorithm::Adler32),
            32 => Some(Algorithm::Md5),
            40 => Some(Algorithm::Sha1),
            64 => Some(Algorithm::Sha256),
            _ => None,
        };
        if let Some(algorithm) = algorithm {
            found.push(HashResult {
                algorithm,
                value: token.to_ascii_lowercase(),
            });
        }
    }
    found
}

pub fn read_hash_list(path: impl AsRef<Path>) -> Result<Vec<HashResult>> {
    let path = path.as_ref();
    let text =
        fs::read_to_string(path).with_context(|| format!("could not open {}", path.display()))?;
    if let Ok(entries) = parse_manifest(&text) {
        return Ok(entries.into_iter().map(|entry| entry.hash).collect());
    }
    let mut found = Vec::new();
    for line in text.lines() {
        found.extend(extract_hashes(line));
    }
    Ok(found)
}

fn read_sidecar_hashes(path: &Path) -> Result<Vec<HashResult>> {
    let mut found = Vec::new();
    for ext in ["txt", "log"] {
        let candidate = path.with_extension(ext);
        if candidate.exists() {
            found.extend(read_hash_list(candidate)?);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn raw_test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hasher-{name}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn known_abc_vectors() {
        let got = hash_bytes(b"abc");
        assert_eq!(got[0].value, "024d0127");
        assert_eq!(got[1].value, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(got[2].value, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            got[3].value,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(got[4].value, "352441c2");
    }

    #[test]
    fn progress_callback_can_cancel_hashing() {
        let input = vec![0_u8; 2 * 1024 * 1024];
        let mut reports = Vec::new();
        let error = hash_reader_with_progress(input.as_slice(), |processed| {
            reports.push(processed);
            processed < 1024 * 1024
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(reports, vec![0, 1024 * 1024]);
    }

    #[test]
    fn hashes_numbered_raw_segments_as_one_stream() {
        let directory = raw_test_dir("raw-stream");
        fs::create_dir(&directory).unwrap();
        let first = directory.join("evidence.001");
        fs::write(&first, b"ab").unwrap();
        fs::write(directory.join("evidence.002"), b"c").unwrap();
        fs::write(
            directory.join("evidence.txt"),
            "MD5: 900150983cd24fb0d6963f7d28e17f72",
        )
        .unwrap();

        let analysis = hash_raw_media(&first).unwrap();
        assert_eq!(analysis.results, hash_bytes(b"abc"));
        assert_eq!(analysis.media_size, 3);
        assert_eq!(analysis.inspection.segment_count, 2);
        assert!(analysis.inspection.embedded_hashes.is_empty());
        assert_eq!(
            analysis.inspection.sidecar_hashes,
            vec![HashResult {
                algorithm: Algorithm::Md5,
                value: "900150983cd24fb0d6963f7d28e17f72".into(),
            }]
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_incomplete_numbered_raw_sets() {
        let directory = raw_test_dir("raw-gap");
        fs::create_dir(&directory).unwrap();
        let first = directory.join("evidence.001");
        fs::write(&first, b"a").unwrap();
        fs::write(directory.join("evidence.003"), b"c").unwrap();

        let error = hash_raw_media(&first).unwrap_err();
        assert!(error.to_string().contains(".002 is missing"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn parses_standard_manifest_formats() {
        let sha256 = "a".repeat(64);
        let text = format!(
            "{sha256}  folder/file.bin\nSHA256 (other.bin) = {sha256}\nlegacy.bin deadbeef\n"
        );
        let entries = parse_manifest(&text).unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, PathBuf::from("folder/file.bin"));
        assert_eq!(entries[0].hash.algorithm, Algorithm::Sha256);
        assert_eq!(entries[1].path, PathBuf::from("other.bin"));
        assert_eq!(entries[1].hash.algorithm, Algorithm::Sha256);
        assert_eq!(entries[2].path, PathBuf::from("legacy.bin"));
        assert_eq!(entries[2].hash.algorithm, Algorithm::Crc32);
    }

    #[test]
    fn formats_gnu_bsd_and_sfv_manifests() {
        let sha = ManifestEntry {
            path: PathBuf::from("folder/file.bin"),
            hash: HashResult {
                algorithm: Algorithm::Sha256,
                value: "a".repeat(64),
            },
        };
        assert_eq!(
            format_manifest(std::slice::from_ref(&sha), ManifestFormat::Gnu).unwrap(),
            format!("{}  folder/file.bin\n", "a".repeat(64))
        );
        assert_eq!(
            format_manifest(std::slice::from_ref(&sha), ManifestFormat::Bsd).unwrap(),
            format!("SHA-256 (folder/file.bin) = {}\n", "a".repeat(64))
        );

        let sfv = ManifestEntry {
            path: PathBuf::from("legacy.bin"),
            hash: HashResult {
                algorithm: Algorithm::Crc32,
                value: "deadbeef".into(),
            },
        };
        assert_eq!(
            format_manifest(&[sfv], ManifestFormat::Sfv).unwrap(),
            "legacy.bin deadbeef\n"
        );
    }

    #[test]
    fn extracts_supported_hash_lengths() {
        let hashes = extract_hashes("MD5: 900150983CD24FB0D6963F7D28E17F72");
        assert_eq!(hashes[0].algorithm, Algorithm::Md5);
        assert_eq!(hashes[0].value, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn eight_hex_tokens_are_read_as_adler32() {
        // Any 8-character hex word is ambiguous and parses as ADLER32.
        let hashes = extract_hashes("deadbeef and cafef00d");
        assert_eq!(hashes.len(), 2);
        assert!(hashes.iter().all(|h| h.algorithm == Algorithm::Adler32));
    }

    #[test]
    fn unrecognised_lengths_are_ignored() {
        // 16 hex chars matches no supported algorithm.
        assert!(extract_hashes("0123456789abcdef").is_empty());
    }

    #[test]
    fn build_report_matches_and_mismatches() {
        let computed = hash_bytes(b"abc");
        let md5 = "900150983cd24fb0d6963f7d28e17f72";

        let good = build_report(md5, &computed);
        assert_eq!(good.outcome, VerifyOutcome::Match);
        assert_eq!(good.algorithm, Some(Algorithm::Md5));

        // Labels, whitespace and `:` separators are tolerated, case-insensitively.
        let spaced = build_report("MD5: 90015098 3CD24FB0 D6963F7D 28E17F72", &computed);
        assert_eq!(spaced.outcome, VerifyOutcome::Match);

        let mismatch = build_report(&"0".repeat(32), &computed);
        assert_eq!(mismatch.outcome, VerifyOutcome::Mismatch);
    }

    #[test]
    fn normalises_labelled_expected_hashes() {
        assert_eq!(
            normalise_expected_hash(
                "SHA-256 = BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD"
            ),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn detects_expected_hash_algorithm_after_normalising() {
        assert_eq!(
            detect_expected_algorithm("MD5: 900150983cd24fb0d6963f7d28e17f72"),
            Some(Algorithm::Md5)
        );
        assert_eq!(detect_expected_algorithm("not a hash"), None);
        assert_eq!(
            detect_expected_algorithm("CRC32: 352441c2"),
            Some(Algorithm::Crc32)
        );
    }

    #[test]
    fn build_report_accepts_common_expected_hash_formats() {
        let computed = hash_bytes(b"abc");
        let cases = [
            ("MD5: 900150983cd24fb0d6963f7d28e17f72", Algorithm::Md5),
            (
                "sha1 = A9993E364706816ABA3E25717850C26C9CD0D89D",
                Algorithm::Sha1,
            ),
            (
                "SHA-256 (ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad)",
                Algorithm::Sha256,
            ),
            (
                "90:01:50:98:3c:d2:4f:b0:d6:96:3f:7d:28:e1:7f:72",
                Algorithm::Md5,
            ),
        ];

        for (expected, algorithm) in cases {
            let report = build_report(expected, &computed);
            assert_eq!(report.outcome, VerifyOutcome::Match, "{expected}");
            assert_eq!(report.algorithm, Some(algorithm), "{expected}");
        }
    }

    #[test]
    fn build_report_rejects_bad_input() {
        let computed = hash_bytes(b"abc");
        assert_eq!(build_report("", &computed).outcome, VerifyOutcome::Invalid);
        assert_eq!(
            build_report("xyz123", &computed).outcome,
            VerifyOutcome::Invalid
        );
        // Right characters, wrong length.
        assert_eq!(
            build_report("abcd", &computed).outcome,
            VerifyOutcome::Invalid
        );
    }
}
