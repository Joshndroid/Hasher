use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hasher::{
    Algorithm, ManifestEntry, ManifestFormat, VerifyOutcome, build_report,
    collect_files_recursively, format_manifest, format_results, hash_bytes, hash_ewf_media,
    hash_file, inspect_file, is_ewf_path, read_hash_list, read_manifest,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "hasher-cli",
    version,
    about = "Hash text, files, and forensic image containers"
)]
struct Cli {
    /// Verify every entry in a GNU, BSD, SHA256SUMS, or SFV manifest.
    #[arg(short = 'c', long, value_name = "MANIFEST")]
    check: Option<PathBuf>,
    /// Resolve relative --check entries from this directory instead of the manifest directory.
    #[arg(long, requires = "check")]
    base: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Hash an exact UTF-8 string (numbers remain strings; no newline is added).
    Text {
        value: String,
        #[arg(short, long, default_value = "all")]
        algorithm: String,
    },
    /// Hash one file byte-for-byte.
    File {
        path: PathBuf,
        #[arg(short, long, default_value = "all")]
        algorithm: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Reconstruct and hash the logical media stream across a complete EWF/E01 set.
    Ewf {
        path: PathBuf,
        #[arg(short, long, default_value = "all")]
        algorithm: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Recursively hash every regular file below a folder.
    Folder {
        path: PathBuf,
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
        #[arg(short, long, default_value = "gnu")]
        format: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Extract supported hash values from a .txt or .log file.
    Read { path: PathBuf },
    /// Identify a forensic image/container and discover sidecar hashes.
    Inspect { path: PathBuf },
    /// Compare an expected hash against a file or text. Exits 1 on mismatch,
    /// 2 when the expected value or input is unusable.
    Verify {
        /// The trusted hash to check against (ADLER32, CRC32, MD5, SHA-1 or SHA-256).
        expected: String,
        /// Hash this file (raw or EWF/E01) and compare.
        #[arg(short, long, conflicts_with = "text")]
        file: Option<PathBuf>,
        /// Hash this exact UTF-8 text and compare.
        #[arg(short, long)]
        text: Option<String>,
    },
}

fn selected(results: Vec<hasher::HashResult>, algorithm: &str) -> Result<Vec<hasher::HashResult>> {
    if algorithm.eq_ignore_ascii_case("all") {
        return Ok(results);
    }
    let wanted = Algorithm::parse(algorithm)?;
    Ok(results
        .into_iter()
        .filter(|r| r.algorithm == wanted)
        .collect())
}

fn emit(rendered: &str, output: Option<PathBuf>) -> Result<()> {
    if let Some(output) = output {
        let ext = output.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !matches!(ext.to_ascii_lowercase().as_str(), "txt" | "log") {
            bail!("output must use .txt or .log");
        }
        fs::write(&output, format!("{rendered}\n"))
            .with_context(|| format!("could not write {}", output.display()))?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

fn run_verify(expected: &str, file: Option<PathBuf>, text: Option<String>) -> Result<ExitCode> {
    let computed = match (file, text) {
        (Some(path), _) => {
            if is_ewf_path(&path) {
                hash_ewf_media(&path)?.results
            } else {
                hash_file(&path)?
            }
        }
        (None, Some(text)) => hash_bytes(text.as_bytes()),
        (None, None) => bail!("provide --file <PATH> or --text <STRING> to hash"),
    };
    let report = build_report(expected, &computed);
    let algorithm = report.algorithm.map(|a| a.to_string()).unwrap_or_default();
    match report.outcome {
        VerifyOutcome::Match => {
            println!("MATCH {algorithm} {}", report.expected);
            Ok(ExitCode::SUCCESS)
        }
        VerifyOutcome::Mismatch => {
            println!("MISMATCH {algorithm}");
            println!("expected {}", report.expected);
            if let Some(computed) = report.computed {
                println!("computed {computed}");
            }
            Ok(ExitCode::from(1))
        }
        VerifyOutcome::Invalid => {
            let note = if report.note.is_empty() {
                "could not verify the supplied value"
            } else {
                &report.note
            };
            eprintln!("{note}");
            Ok(ExitCode::from(2))
        }
    }
}

fn manifest_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map(PathBuf::from)
        .unwrap_or_else(|_| path.to_path_buf())
}

fn run_folder(
    root: PathBuf,
    algorithm: &str,
    format: &str,
    output: Option<PathBuf>,
) -> Result<ExitCode> {
    let algorithm = Algorithm::parse(algorithm)?;
    let format = ManifestFormat::parse(format)?;
    if format == ManifestFormat::Sfv && algorithm != Algorithm::Crc32 {
        bail!("SFV output requires --algorithm crc32");
    }

    let output_canonical = output.as_ref().and_then(|path| fs::canonicalize(path).ok());
    let paths = collect_files_recursively(&root)?;
    if paths.is_empty() {
        bail!("no files found in {}", root.display());
    }
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        if output_canonical
            .as_ref()
            .is_some_and(|output| fs::canonicalize(&path).is_ok_and(|file| file == *output))
        {
            continue;
        }
        let results = hash_file(&path)?;
        let hash = results
            .into_iter()
            .find(|result| result.algorithm == algorithm)
            .context("selected algorithm was not computed")?;
        entries.push(ManifestEntry {
            path: manifest_path(&root, &path),
            hash,
        });
    }
    let rendered = format_manifest(&entries, format)?;
    if let Some(output) = output {
        fs::write(&output, rendered)
            .with_context(|| format!("could not write {}", output.display()))?;
    } else {
        print!("{rendered}");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_check(manifest: PathBuf, base: Option<PathBuf>) -> Result<ExitCode> {
    let entries = read_manifest(&manifest)?;
    let base = base.unwrap_or_else(|| {
        manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    let mut failed = 0_usize;
    for entry in entries {
        let path = if entry.path.is_absolute() {
            entry.path.clone()
        } else {
            base.join(&entry.path)
        };
        let result = hash_file(&path)
            .ok()
            .and_then(|hashes| {
                hashes
                    .into_iter()
                    .find(|hash| hash.algorithm == entry.hash.algorithm)
            })
            .is_some_and(|computed| computed.value == entry.hash.value);
        if result {
            println!("{}: OK", entry.path.display());
        } else {
            println!("{}: FAILED", entry.path.display());
            failed += 1;
        }
    }
    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    if let Some(manifest) = cli.check {
        if cli.command.is_some() {
            bail!("--check cannot be combined with a subcommand");
        }
        return run_check(manifest, cli.base);
    }
    let command = cli.command.context("a subcommand or --check is required")?;
    let code = match command {
        Command::Text { value, algorithm } => {
            println!(
                "{}",
                format_results(&selected(hash_bytes(value.as_bytes()), &algorithm)?)
            );
            ExitCode::SUCCESS
        }
        Command::File {
            path,
            algorithm,
            output,
        } => {
            let rendered = format_results(&selected(hash_file(&path)?, &algorithm)?);
            emit(&rendered, output)?;
            ExitCode::SUCCESS
        }
        Command::Ewf {
            path,
            algorithm,
            output,
        } => {
            let analysis = hash_ewf_media(path)?;
            if let Some(ewf) = &analysis.inspection.ewf {
                for stored in &ewf.stored_hashes {
                    let status = analysis
                        .results
                        .iter()
                        .find(|computed| computed.algorithm == stored.algorithm)
                        .map_or("NOT COMPUTED", |computed| {
                            if computed.value == stored.value {
                                "MATCH"
                            } else {
                                "MISMATCH"
                            }
                        });
                    eprintln!("Stored {} {}: {status}", stored.algorithm, stored.value);
                }
            }
            let rendered = format_results(&selected(analysis.results, &algorithm)?);
            emit(&rendered, output)?;
            ExitCode::SUCCESS
        }
        Command::Folder {
            path,
            algorithm,
            format,
            output,
        } => run_folder(path, &algorithm, &format, output)?,
        Command::Read { path } => {
            println!("{}", format_results(&read_hash_list(path)?));
            ExitCode::SUCCESS
        }
        Command::Inspect { path } => {
            let info = inspect_file(path)?;
            println!(
                "Type: {}\nSize: {} bytes\nSegments: {}\n{}",
                info.kind, info.size, info.segment_count, info.note
            );
            if !info.embedded_hashes.is_empty() {
                println!(
                    "Stored/sidecar hashes:\n{}",
                    format_results(&info.embedded_hashes)
                );
            }
            if let Some(ewf) = info.ewf {
                println!(
                    "Logical media size: {} bytes\nChunk size: {} bytes\nChunks: {}\nAcquisition error ranges: {}",
                    ewf.media_size,
                    ewf.chunk_size,
                    ewf.chunk_count,
                    ewf.acquisition_errors.len()
                );
                for (name, value) in ewf.metadata {
                    println!("{name}: {value}");
                }
            }
            ExitCode::SUCCESS
        }
        Command::Verify {
            expected,
            file,
            text,
        } => run_verify(&expected, file, text)?,
    };
    Ok(code)
}
