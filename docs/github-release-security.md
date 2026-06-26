# GitHub release security setup

The workflows enforce the controls that can live in the repository. The settings below
must also be enabled in the GitHub repository UI because workflow files cannot grant
their own branch protection, environments, or security products.

## Required repository settings

1. Set Actions **Workflow permissions** to read-only. Do not enable “Allow GitHub
   Actions to create and approve pull requests.” Individual jobs elevate only the
   permissions they require.
2. Create a `release-signing` environment. Require a maintainer reviewer, prevent
   self-review, restrict deployment to protected release tags/approved dry-run branches,
   and store signing secrets in that environment rather than as ordinary repository
   secrets.
3. Protect `main`: require pull requests, at least one approval, dismissal of stale
   approvals, conversation resolution, linear history, and the CI `Test` and `RustSec`
   checks. Block force pushes/deletion and do not allow bypasses.
4. Add a tag ruleset for `v*.*.*` that limits tag creation/deletion to release
   maintainers. Releases are created only by an exact semantic-version tag whose value
   matches `Cargo.toml`.
5. Enable Dependabot alerts and security updates, secret scanning, push protection,
   private vulnerability reporting, and immutable releases if available for the plan.
6. Restrict allowed Actions to GitHub-authored and explicitly approved actions. Every
   action used here is pinned to a full commit SHA; Dependabot proposes pin updates.

## `release-signing` secrets

macOS signing and notarization are mandatory in both releases and full dry runs:

- `MACOS_CERTIFICATE_P12_BASE64`
- `MACOS_CERTIFICATE_PASSWORD`
- `MACOS_KEYCHAIN_PASSWORD`
- `MACOS_CODESIGN_IDENTITY` (`Developer ID Application: ...`)
- `APPLE_ID`
- `APPLE_TEAM_ID`
- `APPLE_APP_PASSWORD` (app-specific password)

Windows Authenticode signing is supported when `HASHER_SIGNTOOL_COMMAND` is present. It
must contain a literal `{file}` placeholder, for example a command invoking `signtool`
with SHA-256 file/timestamp digests and a certificate supplied by the protected runner.
The build fails if the command fails or the resulting Authenticode signature is invalid.
If this secret is omitted, Windows artifacts remain unsigned but are still Defender
scanned, checksummed, and attested.

## Release and dry-run operation

- Push `vX.Y.Z` to run the gated build and publish only after tests, RustSec, signing,
  notarization, Defender scanning, checksums, and provenance attestations succeed.
- Run **Release or full dry run** manually with an intended `vX.Y.Z` tag to execute the
  same pipeline—including signing, notarization, Defender, and attestations—without
  creating a GitHub Release.
- The workflow emits a tag-to-tag commit changelog with a GitHub full-diff link.
- `SHA256SUMS.txt` contains a SHA-256 digest for every published payload and scan report.
- Verify provenance with:

  ```sh
  gh attestation verify <artifact> --repo OWNER/Hasher
  ```

Microsoft Defender scanning fails closed if Defender is disabled, not in Normal mode,
already reports a detection on the fresh runner, cannot update signatures, or detects
anything in the installer, archives, or expanded portable contents.

