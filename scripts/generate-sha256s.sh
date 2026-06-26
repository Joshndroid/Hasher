#!/usr/bin/env bash
set -euo pipefail

ASSET_DIR="${1:-release-assets}"
OUTPUT_PATH="${2:-$ASSET_DIR/SHA256SUMS.txt}"

if [[ ! -d "$ASSET_DIR" ]]; then
  echo "Asset directory does not exist: $ASSET_DIR" >&2
  exit 1
fi

output_name="$(basename "$OUTPUT_PATH")"
files="$(find "$ASSET_DIR" -maxdepth 1 -type f ! -name "$output_name" -print | LC_ALL=C sort)"
if [[ -z "$files" ]]; then
  echo "No release artifacts found in $ASSET_DIR" >&2
  exit 1
fi

: >"$OUTPUT_PATH"
while IFS= read -r file; do
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$file" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$file" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$(basename "$file")" >>"$OUTPUT_PATH"
done <<<"$files"

echo "Wrote $OUTPUT_PATH"
