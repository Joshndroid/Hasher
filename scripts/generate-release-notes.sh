#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${1:-release-notes.md}"
CURRENT_TAG="${2:-${GITHUB_REF_NAME:-}}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-fruitmac/Hasher}"

if [[ -z "$CURRENT_TAG" ]]; then
  CURRENT_TAG="$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null || true)"
fi
if [[ -z "$CURRENT_TAG" ]]; then
  echo "A release tag is required." >&2
  exit 1
fi
if ! git -C "$ROOT_DIR" rev-parse --verify --quiet "$CURRENT_TAG^{commit}" >/dev/null; then
  echo "Release tag '$CURRENT_TAG' does not exist in this checkout." >&2
  exit 1
fi

current_commit="$(git -C "$ROOT_DIR" rev-list -n 1 "$CURRENT_TAG")"
previous_tag="$(git -C "$ROOT_DIR" describe --tags --match 'v[0-9]*.[0-9]*.[0-9]*' --abbrev=0 "${current_commit}^" 2>/dev/null || true)"

{
  echo "## Changes"
  echo
  if [[ -n "$previous_tag" ]]; then
    echo "Changes since [$previous_tag](https://github.com/${GITHUB_REPOSITORY}/releases/tag/${previous_tag}):"
    echo
    echo "[Full diff](https://github.com/${GITHUB_REPOSITORY}/compare/${previous_tag}...${CURRENT_TAG})"
    echo
    git -C "$ROOT_DIR" log --pretty=format:'- [`%h`](https://github.com/'"${GITHUB_REPOSITORY}"'/commit/%H) %s' "${previous_tag}..${CURRENT_TAG}"
  else
    echo "Initial release commit list:"
    echo
    git -C "$ROOT_DIR" log --pretty=format:'- [`%h`](https://github.com/'"${GITHUB_REPOSITORY}"'/commit/%H) %s' "$CURRENT_TAG"
  fi
  echo
  echo
  echo "## Verification"
  echo
  echo "Every downloadable artifact is listed in \`SHA256SUMS.txt\` and receives a GitHub build-provenance attestation."
  echo
  echo '```sh'
  echo "sha256sum --check SHA256SUMS.txt"
  echo "gh attestation verify <artifact> --repo ${GITHUB_REPOSITORY}"
  echo '```'
} >"$OUTPUT_PATH"

echo "Wrote $OUTPUT_PATH"

