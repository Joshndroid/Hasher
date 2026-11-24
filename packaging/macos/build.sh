#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
TARGET="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
export COPYFILE_DISABLE=1
case "$TARGET" in
  aarch64-apple-darwin) ARCH="arm64" ;;
  *) echo "Unsupported macOS target: $TARGET; only Apple Silicon is packaged." >&2; exit 1 ;;
esac
DIST="$ROOT/dist/macos"
APP="$DIST/Hasher.app"
BINDIR="$ROOT/target/$TARGET/release"

cd "$ROOT"
cargo build --release --bins --locked --target "$TARGET"
rm -rf "$DIST"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINDIR/hasher" "$APP/Contents/MacOS/hasher"
cp packaging/macos/Info.plist "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP/Contents/Info.plist"
cp assets/hasher-icon.icns "$APP/Contents/Resources/hasher-icon.icns"
cp assets/OFL.txt "$APP/Contents/Resources/JetBrainsMono-OFL.txt"
if command -v xattr >/dev/null; then
  xattr -cr "$APP"
fi

CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
if [[ "$CODESIGN_IDENTITY" == "-" ]]; then
  codesign --force --sign - "$APP/Contents/MacOS/hasher"
  codesign --force --sign - "$BINDIR/hasher-cli"
  codesign --force --deep --sign - "$APP"
else
  codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$APP/Contents/MacOS/hasher"
  codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$BINDIR/hasher-cli"
  codesign --force --deep --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP"
codesign --verify --strict --verbose=2 "$BINDIR/hasher-cli"
if command -v xattr >/dev/null; then
  xattr -cr "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP"
fi

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

APP_ZIP="$DIST/Hasher-${VERSION}-macOS-${ARCH}.zip"
PORTABLE_DIR="$DIST/Hasher-${VERSION}-macOS-${ARCH}-portable"
PORTABLE_ZIP="$DIST/Hasher-${VERSION}-macOS-${ARCH}-portable.zip"
rm -f "$APP_ZIP" "$PORTABLE_ZIP"
rm -rf "$PORTABLE_DIR"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$APP_ZIP"
mkdir -p "$PORTABLE_DIR"
ditto "$APP" "$PORTABLE_DIR/Hasher.app"
cp "$BINDIR/hasher-cli" README.md LICENSE assets/OFL.txt "$PORTABLE_DIR/"
mv "$PORTABLE_DIR/OFL.txt" "$PORTABLE_DIR/JetBrainsMono-OFL.txt"
ditto -c -k --sequesterRsrc --keepParent "$PORTABLE_DIR" "$PORTABLE_ZIP"
rm -rf "$PORTABLE_DIR"

if command -v pkgbuild >/dev/null; then
  PKG="$DIST/Hasher-${VERSION}-macOS-${ARCH}.pkg"
  PKG_SIGN_IDENTITY="${PKG_SIGN_IDENTITY:-}"
  if [[ -n "$PKG_SIGN_IDENTITY" ]]; then
    pkgbuild --component "$APP" --install-location /Applications --sign "$PKG_SIGN_IDENTITY" "$PKG"
  else
    pkgbuild --component "$APP" --install-location /Applications "$PKG"
  fi
  if [[ "${NOTARIZE:-0}" == "1" && -n "$PKG_SIGN_IDENTITY" ]]; then
    xcrun notarytool submit "$PKG" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --wait
    xcrun stapler staple "$PKG"
  elif [[ "${NOTARIZE:-0}" == "1" ]]; then
    echo "Skipping PKG notarization because PKG_SIGN_IDENTITY is not set."
  fi
fi

create_dmg_background() {
  local output="$1"
  local icon="$2"

  if ! command -v swift >/dev/null; then
    return 1
  fi

  swift - "$output" "$icon" <<'SWIFT'
import AppKit
import Foundation

let output = URL(fileURLWithPath: CommandLine.arguments[1])
let size = NSSize(width: 640, height: 420)
let image = NSImage(size: size)

image.lockFocus()

NSColor(calibratedRed: 0.95, green: 0.96, blue: 0.94, alpha: 1).setFill()
NSBezierPath(rect: NSRect(origin: .zero, size: size)).fill()

NSColor(calibratedRed: 0.87, green: 0.91, blue: 0.89, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(x: 28, y: 28, width: 584, height: 364), xRadius: 24, yRadius: 24).fill()

let titleStyle = NSMutableParagraphStyle()
titleStyle.alignment = .center
let titleAttributes: [NSAttributedString.Key: Any] = [
    .font: NSFont.systemFont(ofSize: 28, weight: .semibold),
    .foregroundColor: NSColor(calibratedRed: 0.11, green: 0.13, blue: 0.14, alpha: 1),
    .paragraphStyle: titleStyle
]
"Install Hasher".draw(
    in: NSRect(x: 0, y: 318, width: size.width, height: 44),
    withAttributes: titleAttributes
)

let captionAttributes: [NSAttributedString.Key: Any] = [
    .font: NSFont.systemFont(ofSize: 16, weight: .medium),
    .foregroundColor: NSColor(calibratedRed: 0.29, green: 0.32, blue: 0.32, alpha: 1),
    .paragraphStyle: titleStyle
]
"Drag Hasher to Applications".draw(
    in: NSRect(x: 0, y: 74, width: size.width, height: 28),
    withAttributes: captionAttributes
)

let arrow = NSBezierPath()
arrow.move(to: NSPoint(x: 260, y: 202))
arrow.line(to: NSPoint(x: 380, y: 202))
arrow.move(to: NSPoint(x: 360, y: 222))
arrow.line(to: NSPoint(x: 382, y: 202))
arrow.line(to: NSPoint(x: 360, y: 182))
arrow.lineWidth = 8
arrow.lineCapStyle = .round
arrow.lineJoinStyle = .round
NSColor(calibratedRed: 0.13, green: 0.43, blue: 0.53, alpha: 0.74).setStroke()
arrow.stroke()

image.unlockFocus()

guard
    let tiff = image.tiffRepresentation,
    let bitmap = NSBitmapImageRep(data: tiff),
    let png = bitmap.representation(using: .png, properties: [:])
else {
    exit(1)
}

try png.write(to: output)
SWIFT
}

if command -v hdiutil >/dev/null; then
  DMG="$DIST/Hasher-${VERSION}-macOS-${ARCH}.dmg"
  RW_DMG="$DIST/Hasher-${VERSION}-macOS-${ARCH}-rw.dmg"
  MOUNT_DIR=""

  cleanup_dmg() {
    if [[ -n "$MOUNT_DIR" && -d "$MOUNT_DIR" ]]; then
      hdiutil detach "$MOUNT_DIR" >/dev/null 2>&1 || true
    fi
    rm -f "$RW_DMG"
  }
  trap cleanup_dmg EXIT

  rm -f "$DMG" "$RW_DMG"
  hdiutil create -size 64m -volname Hasher -fs HFS+ "$RW_DMG"
  MOUNT_DIR="$(hdiutil attach -readwrite -noverify -noautoopen "$RW_DMG" | sed -n 's#^.*\(/Volumes/.*\)$#\1#p' | tail -1)"
  if [[ -z "$MOUNT_DIR" || ! -d "$MOUNT_DIR" ]]; then
    echo "Could not mount temporary DMG." >&2
    exit 1
  fi

  mkdir -p "$MOUNT_DIR/.background"
  ditto "$APP" "$MOUNT_DIR/Hasher.app"
  ln -s /Applications "$MOUNT_DIR/Applications"
  if ! create_dmg_background "$MOUNT_DIR/.background/installer.png" "$ROOT/assets/hasher-icon.png"; then
    cp "$ROOT/assets/hasher-icon.png" "$MOUNT_DIR/.background/installer.png"
  fi
  chflags hidden "$MOUNT_DIR/.background" || true

  if command -v osascript >/dev/null; then
    osascript <<OSA || echo "Warning: Finder DMG layout could not be written." >&2
tell application "Finder"
  tell disk "Hasher"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set bounds of container window to {100, 100, 740, 520}
    set theOptions to icon view options of container window
    set arrangement of theOptions to not arranged
    set icon size of theOptions to 128
    set text size of theOptions to 13
    set background picture of theOptions to file ".background:installer.png"
    set position of item "Hasher.app" of container window to {170, 215}
    set position of item "Applications" of container window to {470, 215}
    close
    open
    update without registering applications
    delay 1
    close
  end tell
end tell
OSA
  fi

  sync
  hdiutil detach "$MOUNT_DIR"
  MOUNT_DIR=""
  hdiutil convert "$RW_DMG" -format UDZO -imagekey zlib-level=9 -o "$DMG"
  rm -f "$RW_DMG"
  trap - EXIT
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
