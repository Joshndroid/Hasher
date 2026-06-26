//! Shared hashing and forensic-file inspection used by both front ends.

use adler2::Adler32;
use anyhow::{Context, Result, bail};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    fmt::{self, Display},
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Adler32,
    Md5,
    Sha1,
    Sha256,
}

impl Algorithm {
    pub const ALL: [Self; 4] = [Self::Adler32, Self::Md5, Self::Sha1, Self::Sha256];

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().replace('-', "").as_str() {
            "adler32" => Ok(Self::Adler32),
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => bail!("unsupported algorithm: {value}"),
        }
    }

    pub fn hex_len(self) -> usize {
        match self {
            Self::Adler32 => 8,
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
}

impl MultiHasher {
    fn new() -> Self {
        Self {
            adler: Adler32::new(),
            md5: Md5::new(),
            sha1: Sha1::new(),
            sha256: Sha256::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.adler.write_slice(bytes);
        self.md5.update(bytes);
        self.sha1.update(bytes);
        self.sha256.update(bytes);
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
        ]
    }
}

pub fn hash_bytes(bytes: &[u8]) -> Vec<HashResult> {
    let mut hasher = MultiHasher::new();
    hasher.update(bytes);
    hasher.finish()
}

pub fn hash_reader(mut reader: impl Read) -> io::Result<Vec<HashResult>> {
    let mut hasher = MultiHasher::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finish())
}

pub fn hash_file(path: impl AsRef<Path>) -> Result<Vec<HashResult>> {
    let path = path.as_ref();
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    hash_reader(BufReader::with_capacity(1024 * 1024, file))
        .with_context(|| format!("could not read {}", path.display()))
}

pub fn format_results(results: &[HashResult]) -> String {
    results
        .iter()
        .map(|r| format!("{}  {}", r.algorithm, r.value))
        .collect::<Vec<_>>()
        .join("\n")
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
    pub embedded_hashes: Vec<HashResult>,
    pub ewf: Option<EwfDetails>,
    pub note: String,
}

#[derive(Clone, Debug)]
pub struct EwfDetails {
    /// Logical, decompressed evidence-stream size.
    pub media_size: u64,
    pub chunk_size: u64,
    pub chunk_count: usize,
    pub stored_hashes: Vec<HashResult>,
    pub metadata: Vec<(String, String)>,
    pub acquisition_errors: Vec<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct EwfAnalysis {
    pub results: Vec<HashResult>,
    pub inspection: FileInspection,
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
        stored_hashes: embedded_hashes.clone(),
        metadata,
        acquisition_errors,
    };
    Ok((reader, details, embedded_hashes))
}

/// Hashes the logical evidence stream reconstructed from every EWF segment.
/// The returned MD5/SHA-1 can be compared with acquisition digests stored in the image.
pub fn hash_ewf_media(path: impl AsRef<Path>) -> Result<EwfAnalysis> {
    let path = path.as_ref();
    let (reader, details, embedded_hashes) = open_ewf_details(path)?;
    let results = hash_reader(reader).context("could not decode the EWF evidence stream")?;
    let inspection = ewf_inspection(path, details, embedded_hashes)?;
    Ok(EwfAnalysis {
        results,
        inspection,
    })
}

fn ewf_inspection(
    path: &Path,
    details: EwfDetails,
    mut embedded_hashes: Vec<HashResult>,
) -> Result<FileInspection> {
    let sidecar = read_sidecar_hashes(path)?;
    for hash in sidecar {
        if !embedded_hashes.contains(&hash) {
            embedded_hashes.push(hash);
        }
    }
    let metadata = path
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    Ok(FileInspection {
        path: path.to_owned(),
        kind: EvidenceKind::ExpertWitness,
        size: metadata.len(),
        segment_count: count_segments(path, EvidenceKind::ExpertWitness),
        embedded_hashes,
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
    } else if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
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
    let sidecar = read_sidecar_hashes(path)?;
    let note = match kind {
        EvidenceKind::ExpertWitness => unreachable!(),
        EvidenceKind::RawSegment => "A segmented raw image was detected. Hashing only this path covers this segment, not the complete image set.".into(),
        EvidenceKind::RawImage => "Raw images have no standard embedded digest field; any discovered values came from a sidecar TXT/LOG file.".into(),
        EvidenceKind::OrdinaryFile => "The complete file can be hashed byte-for-byte.".into(),
    };
    Ok(FileInspection {
        path: path.to_owned(),
        kind,
        size: metadata.len(),
        segment_count,
        embedded_hashes: sidecar,
        ewf: None,
        note,
    })
}

fn count_segments(path: &Path, kind: EvidenceKind) -> usize {
    let Some(parent) = path.parent() else {
        return 1;
    };
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let prefix = if kind == EvidenceKind::ExpertWitness {
        stem.to_ascii_lowercase()
    } else {
        stem.trim_end_matches(|c: char| c.is_ascii_digit())
            .to_ascii_lowercase()
    };
    std::fs::read_dir(parent)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if kind == EvidenceKind::ExpertWitness {
                name.starts_with(&prefix)
                    && name.rsplit('.').next().is_some_and(|e| {
                        matches!(e.chars().next(), Some('e' | 'l'))
                            && e.len() >= 3
                            && e[1..].chars().all(|c| c.is_ascii_alphanumeric())
                    })
            } else {
                name.starts_with(&prefix)
                    && name
                        .rsplit('.')
                        .next()
                        .is_some_and(|e| e.len() == 3 && e.chars().all(|c| c.is_ascii_digit()))
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
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut found = Vec::new();
    for line in BufReader::new(file).lines() {
        found.extend(extract_hashes(&line?));
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
    }

    #[test]
    fn extracts_supported_hash_lengths() {
        let hashes = extract_hashes("MD5: 900150983CD24FB0D6963F7D28E17F72");
        assert_eq!(hashes[0].algorithm, Algorithm::Md5);
        assert_eq!(hashes[0].value, "900150983cd24fb0d6963f7d28e17f72");
    }
}
