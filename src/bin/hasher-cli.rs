use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hasher::{
    Algorithm, format_results, hash_bytes, hash_ewf_media, hash_file, inspect_file, read_hash_list,
};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "hasher-cli",
    version,
    about = "Hash text, files, and forensic image containers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    /// Extract supported hash values from a .txt or .log file.
    Read { path: PathBuf },
    /// Identify a forensic image/container and discover sidecar hashes.
    Inspect { path: PathBuf },
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Text { value, algorithm } => println!(
            "{}",
            format_results(&selected(hash_bytes(value.as_bytes()), &algorithm)?)
        ),
        Command::File {
            path,
            algorithm,
            output,
        } => {
            let rendered = format_results(&selected(hash_file(&path)?, &algorithm)?);
            emit(&rendered, output)?;
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
        }
        Command::Read { path } => println!("{}", format_results(&read_hash_list(path)?)),
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
        }
    }
    Ok(())
}
