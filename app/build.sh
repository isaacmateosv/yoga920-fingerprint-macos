#!/bin/bash
# Builds YogaFP.app (universal, ad-hoc signed) into app/build/.
set -euo pipefail
cd "$(dirname "$0")"
OUT=build/YogaFP.app
rm -rf build; mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources"
for arch in x86_64 arm64; do
  swiftc -O -parse-as-library -target "$arch-apple-macos14.0" -o "build/YogaFP-$arch" YogaFP.swift
done
lipo -create -output "$OUT/Contents/MacOS/YogaFP" build/YogaFP-x86_64 build/YogaFP-arm64
rm -f build/YogaFP-x86_64 build/YogaFP-arm64
# App icon: an original fingerprint drawing (Apple's license does not allow SF Symbols in app icons)
swift make_icon.swift build/AppIcon.iconset >/dev/null
iconutil -c icns build/AppIcon.iconset -o "$OUT/Contents/Resources/AppIcon.icns"
rm -rf build/AppIcon.iconset
cat > "$OUT/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.yogafp.menubar</string>
  <key>CFBundleName</key><string>YogaFP</string>
  <key>CFBundleExecutable</key><string>YogaFP</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.2.0</string>
  <key>CFBundleVersion</key><string>2</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSAppleEventsUsageDescription</key><string>YogaFP asks for administrator approval to enroll a fingerprint.</string>
</dict></plist>
EOF
codesign --force --deep -s - "$OUT"
echo "built $OUT"
