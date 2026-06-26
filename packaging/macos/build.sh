#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
TARGET="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$TARGET" in
  aarch64-apple-darwin) ARCH="arm64" ;;
  x86_64-apple-darwin) ARCH="x64" ;;
  *) echo "Unsupported macOS target: $TARGET" >&2; exit 1 ;;
esac
DIST="$ROOT/dist/macos"
APP="$DIST/Hasher.app"
BINDIR="$ROOT/target/$TARGET/release"

cd "$ROOT"
cargo build --release --bins --locked --target "$TARGET"
rm -rf "$DIST"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$DIST/Hasher-portable"
cp "$BINDIR/hasher" "$APP/Contents/MacOS/hasher"
cp packaging/macos/Info.plist "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP/Contents/Info.plist"
cp assets/hasher-icon.icns "$APP/Contents/Resources/hasher-icon.icns"
cp assets/OFL.txt "$APP/Contents/Resources/JetBrainsMono-OFL.txt"
cp "$BINDIR/hasher" "$BINDIR/hasher-cli" "$DIST/Hasher-portable/"
cp README.md LICENSE assets/OFL.txt assets/hasher-icon.png "$DIST/Hasher-portable/"

CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
if [[ "$CODESIGN_IDENTITY" == "-" ]]; then
  codesign --force --sign - "$APP/Contents/MacOS/hasher"
  codesign --force --sign - "$DIST/Hasher-portable/hasher"
  codesign --force --sign - "$DIST/Hasher-portable/hasher-cli"
  codesign --force --deep --sign - "$APP"
else
  for binary in "$APP/Contents/MacOS/hasher" "$DIST/Hasher-portable/hasher" "$DIST/Hasher-portable/hasher-cli"; do
    codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$binary"
  done
  codesign --force --deep --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP"

if [[ "${NOTARIZE:-0}" == "1" ]]; then
  : "${APPLE_ID:?APPLE_ID is required for notarization}"
  : "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required for notarization}"
  : "${APPLE_APP_PASSWORD:?APPLE_APP_PASSWORD is required for notarization}"
  NOTARY_ZIP="$DIST/Hasher-notarization.zip"
  ditto -c -k --sequesterRsrc --keepParent "$APP" "$NOTARY_ZIP"
  xcrun notarytool submit "$NOTARY_ZIP" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --wait
  xcrun stapler staple "$APP"
  rm -f "$NOTARY_ZIP"
fi

ditto -c -k --sequesterRsrc --keepParent "$APP" "$DIST/Hasher-${VERSION}-macOS-${ARCH}.zip"
ditto -c -k "$DIST/Hasher-portable" "$DIST/Hasher-${VERSION}-macOS-${ARCH}-portable.zip"
if [[ "${NOTARIZE:-0}" == "1" ]]; then
  xcrun notarytool submit "$DIST/Hasher-${VERSION}-macOS-${ARCH}-portable.zip" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --wait
fi

if command -v hdiutil >/dev/null; then
  DMG="$DIST/Hasher-${VERSION}-macOS-${ARCH}.dmg"
  hdiutil create -volname Hasher -srcfolder "$APP" -ov -format UDZO "$DMG"
  if [[ "$CODESIGN_IDENTITY" != "-" ]]; then
    codesign --force --timestamp --sign "$CODESIGN_IDENTITY" "$DMG"
  fi
  if [[ "${NOTARIZE:-0}" == "1" ]]; then
    xcrun notarytool submit "$DMG" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --wait
    xcrun stapler staple "$DMG"
    xcrun stapler validate "$APP"
    xcrun stapler validate "$DMG"
    spctl --assess --type execute --verbose=4 "$APP"
  fi
fi

printf 'Artifacts written to %s\n' "$DIST"
