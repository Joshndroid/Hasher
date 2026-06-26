# Hasher

<p align="center">
  <img src="assets/hasher-icon.png" alt="Hasher icon" width="128" height="128">
</p>

Hasher is a native Rust/egui hashing calculator for macOS and Windows. It has a
desktop interface and a script-friendly CLI, and works without a network
connection after installation.

## Features

- ADLER32, MD5, SHA-1, and SHA-256 in a single pass
- Exact UTF-8 text and number-string hashing
- Buffered, background file hashing with drag and drop
- `.txt` and `.log` hash-value import and export
- `.dd`, `.img`, `.raw`, numbered raw segments (`.001`, etc.), and EWF
  (`.E01`, `.Ex01`, `.L01`, `.Lx01`) identification
- Pure-Rust EWF reconstruction across complete multi-segment sets
- Embedded EWF MD5/SHA-1 acquisition-digest and case-metadata extraction
- Explicit MATCH/MISMATCH comparison of stored and reconstructed-media hashes
- Acquisition read-error reporting and optional compressed container-segment hashing
- System, dark, and light themes with an editable accent colour
- JetBrains Mono embedded in the executable
- Separate `hasher-cli` executable

## Run from source

```sh
cargo run --bin hasher
cargo run --bin hasher-cli -- text "123456"
cargo run --bin hasher-cli -- file evidence.img --algorithm sha256
cargo run --bin hasher-cli -- file evidence.img --output evidence.log
cargo run --bin hasher-cli -- ewf evidence.E01 --algorithm sha256
cargo run --bin hasher-cli -- read acquisition.log
cargo run --bin hasher-cli -- inspect evidence.E01
```

For laggy virtual machines, the GUI now uses native OS window chrome by default
because it is much cheaper to move and resize than the custom frameless window.
Set `HASHER_CUSTOM_CHROME=1` to restore the old custom title bar. If the virtual
GPU is still unhappy, try `HASHER_RENDERER=glow cargo run --bin hasher` or
`HASHER_RENDERER=wgpu cargo run --bin hasher`; `HASHER_SOFTWARE_RENDERER=1` is
also available for the OpenGL backend on platforms that support it.

Algorithm names accepted by `--algorithm` are `all`, `adler32`, `md5`, `sha1`,
and `sha256`. CLI output is written to stdout and errors to stderr.

## Build and package

On macOS:

```sh
chmod +x packaging/macos/build.sh
packaging/macos/build.sh
```

This creates an ad-hoc-signed `.app`, DMG, app ZIP, and portable GUI/CLI ZIP in
`dist/macos`. Distribution outside your own machines should add a Developer ID
signature and Apple notarisation.

On Windows PowerShell:

```powershell
.\packaging\windows\build.ps1
```

This creates portable and offline-portable ZIPs in `dist/windows`. If Inno Setup
6 is installed and `ISCC.exe` is on `PATH`, it also creates the Windows installer.
The embedded font and statically linked CRT make the offline package independent
of a Rust toolchain, VC++ redistributable, or network connection.

The GitHub Actions workflow builds native Apple Silicon macOS and Windows x64
artifacts. A `vX.Y.Z` tag publishes only after locked tests, Clippy, RustSec,
Developer ID signing/notarization, Microsoft Defender scanning, and GitHub provenance
attestations succeed. Manual dispatch runs the same pipeline as a
dry run without publishing a release. See
[GitHub release security setup](docs/github-release-security.md) for required repository
settings and signing secrets.

## Forensic-image semantics

A raw `.dd`, `.img`, or `.001` file contains evidence bytes directly. An EWF image
is a segmented, compressed Expert Witness container. Hasher keeps these concepts separate:

- **Container hash:** hashes only the selected compressed EWF segment byte-for-byte.
- **Acquisition digest:** a value stored by the acquisition tool inside the EWF
  hash/digest section. Hasher extracts stored MD5 and SHA-1 values when present.
- **Evidence-stream hash:** hashes the decompressed/reconstructed media across the
  complete discovered EWF segment set. Hasher computes ADLER32, MD5, SHA-1 and
  SHA-256 over that logical stream in one pass.

EWF files default to evidence-stream mode. The GUI shows stored acquisition digests,
MATCH/MISMATCH results, logical media geometry, populated case fields and recorded
acquisition read-error ranges. Container-segment mode remains available when that
specific provenance value is needed.

MD5 and SHA-1 remain useful for interoperability and evidence verification but
are collision-broken for security decisions. Prefer SHA-256 for new integrity records.
