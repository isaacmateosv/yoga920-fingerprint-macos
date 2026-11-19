#!/bin/bash
# Builds an offline macOS installer for yoga-fp: dist/YogaFP-<version>[-personal].pkg and a .dmg around it.
#
#   packaging/make-pkg.sh                      # public build: no Lenovo firmware inside
#   packaging/make-pkg.sh --fwext FILE         # personal recovery build: includes the firmware file.
#                                              #   DO NOT redistribute that one (Lenovo's file).
#
# Everything is prebuilt (PAM module, authorization plugin, self-check, menu bar app) and a private Python runtime
# with all dependencies is bundled, so the target Mac needs no Xcode, no Python and no internet. Intel (x86_64)
# Macs only, because the bundled Python packages are x86_64 wheels.
# Needs on the build Mac: Xcode command line tools, a python.org Python 3.11+ (framework build), internet once.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
FWEXT=""
while [[ $# -gt 0 ]]; do case "$1" in --fwext) FWEXT="$2"; shift 2 ;; *) echo "unknown option $1"; exit 1 ;; esac; done
VERSION="$(sed -n "s/^__version__ = '\(.*\)'/\1/p" "$ROOT/yogafp/__init__.py")"
NAME="YogaFP-$VERSION"; if [[ -n "$FWEXT" ]]; then NAME="$NAME-personal"; fi
DIST="$ROOT/dist"; WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/root/usr/local/share/yoga-fp-installer"; PB="$STAGE/prebuilt"
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
mkdir -p "$PB" "$DIST"

say "Staging sources ($VERSION)"
cp -R "$ROOT/yogafp" "$ROOT/vendor" "$ROOT/launchd" "$ROOT/pam" "$ROOT/authplugin" "$ROOT/app" "$STAGE/"
cp "$ROOT/install.sh" "$ROOT/requirements.txt" "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/THIRD_PARTY_NOTICES.md" "$STAGE/"
find "$STAGE" \( -name '__pycache__' -o -name build -o -name '*.so' -o -name pamcheck -o -name authtest -o -name '*.bundle' \) -prune -exec rm -rf {} +

say "Building native components (universal)"
B="$WORK/b"; mkdir -p "$B"
cp "$ROOT/pam/"*.c "$ROOT/pam/Makefile" "$B/" && make -s -C "$B" >/dev/null
cp "$B/pam_yogafp.so" "$B/pamcheck" "$PB/"; rm -rf "$B"; mkdir -p "$B"
cp "$ROOT/authplugin/"* "$B/" && make -s -C "$B" >/dev/null
ditto "$B/YogaFPAuth.bundle" "$PB/YogaFPAuth.bundle"; cp "$B/authtest" "$PB/authtest"; rm -rf "$B"; mkdir -p "$B"
cp "$ROOT/app/YogaFP.swift" "$ROOT/app/build.sh" "$ROOT/app/make_icon.swift" "$B/" && bash "$B/build.sh" >/dev/null
ditto "$B/build/YogaFP.app" "$PB/YogaFP.app"; rm -rf "$B"

say "Building the private Python runtime with dependencies"
PY="${PYTHON:-/Library/Frameworks/Python.framework/Versions/Current/bin/python3}"
# reuse the installer's runtime builder (relocation, re-signing, isolation check)
( say() { :; }; warn() { echo "warning: $*" >&2; }; PREFIX="$WORK/none"
  eval "$(sed -n '/^make_runtime() {/,/^}/p' "$ROOT/install.sh")"
  make_runtime "$PY" "$PB/runtime" ) || { echo "error: $PY is not a python.org framework build"; exit 1; }
"$PB/runtime/bin/python3" -I -m pip install -q --no-cache-dir --disable-pip-version-check --only-binary=:all: -r "$ROOT/requirements.txt"
"$PB/runtime/bin/python3" -I -c 'import numpy, cv2, cryptography, usb, libusb_package; print("    runtime ok: numpy", numpy.__version__, "| opencv", cv2.__version__)'
find "$PB/runtime" -name '__pycache__' -prune -exec rm -rf {} +
rm -rf "$PB/runtime/bin/pip"* 2>/dev/null || true

if [[ -n "$FWEXT" ]]; then
  [[ "$(shasum -a 256 "$FWEXT" | cut -d' ' -f1)" == 45f6e553ca59b0b3a17b4b93f6353ba43d71a7aa7d26205f732ca819365aa339 ]] \
    || { echo "error: firmware checksum mismatch"; exit 1; }
  cp "$FWEXT" "$PB/6_07f_Lenovo.xpfwext"; say "Including the Lenovo firmware (PERSONAL build: do not redistribute)"
fi

say "Package scripts and pages"
mkdir -p "$WORK/scripts" "$WORK/res"
cat > "$WORK/scripts/postinstall" <<'EOF'
#!/bin/bash
# Runs the yoga-fp installer from the staged files; full log in /var/log/yoga-fp-install.log
LOG=/var/log/yoga-fp-install.log
echo "=== $(date) yoga-fp package install" >> "$LOG"
/bin/bash /usr/local/share/yoga-fp-installer/install.sh install >> "$LOG" 2>&1
rc=$?
echo "=== exit $rc" >> "$LOG"
exit $rc
EOF
chmod 755 "$WORK/scripts/postinstall"
cp "$ROOT/LICENSE" "$WORK/res/LICENSE.txt"; printf '\n\n' >> "$WORK/res/LICENSE.txt"; cat "$ROOT/THIRD_PARTY_NOTICES.md" >> "$WORK/res/LICENSE.txt"
cat > "$WORK/res/welcome.html" <<EOF
<html><body style="font-family:-apple-system,sans-serif">
<h2>YogaFP $VERSION</h2>
<p>Fingerprint sign-in for <b>sudo</b> and <b>admin dialogs</b> on the Lenovo Yoga 920 (Synaptics/Validity 06cb:0081) under macOS.
Created by <b>isaacmateosv</b>.</p>
<ul>
<li>Your fingerprint never leaves this Mac: it is stored encrypted, as feature points, in a root-only folder.</li>
<li>A root service makes every match decision. Your password always keeps working.</li>
<li>Everything is included: no Xcode, Python or internet needed. Intel Macs only.</li>
</ul>
<p>After installation, the <b>YogaFP Setup Assistant</b> opens in the menu bar to enroll your finger and turn on sudo and admin dialogs.</p>
<p style="color:#888">Not affiliated with Lenovo, Synaptics or Apple.</p>
</body></html>
EOF
cat > "$WORK/res/conclusion.html" <<'EOF'
<html><body style="font-family:-apple-system,sans-serif">
<h2>YogaFP is installed</h2>
<p>Look for the fingerprint icon in the menu bar. The <b>Setup Assistant</b> guides you through enrollment and turning on sudo and admin dialogs.</p>
<p>Install log: <code>/var/log/yoga-fp-install.log</code><br>
Uninstall: double-click <i>Uninstall YogaFP.command</i> on the disk image, or run<br>
<code>sudo /usr/local/libexec/yoga-fp/yogafp-admin.sh uninstall --purge</code></p>
</body></html>
EOF
cat > "$WORK/distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>YogaFP $VERSION</title>
  <organization>com.yogafp</organization>
  <welcome file="welcome.html" mime-type="text/html"/>
  <license file="LICENSE.txt" mime-type="text/plain"/>
  <conclusion file="conclusion.html" mime-type="text/html"/>
  <options customize="never" require-scripts="true" hostArchitectures="x86_64"/>
  <volume-check><allowed-os-versions><os-version min="14.0"/></allowed-os-versions></volume-check>
  <domains enable_localSystem="true"/>
  <choices-outline><line choice="default"><line choice="com.yogafp.pkg"/></line></choices-outline>
  <choice id="default"/>
  <choice id="com.yogafp.pkg" visible="false"><pkg-ref id="com.yogafp.pkg"/></choice>
  <pkg-ref id="com.yogafp.pkg" version="$VERSION" onConclusion="none">yogafp-component.pkg</pkg-ref>
</installer-gui-script>
EOF

say "Building the package"
pkgbuild --quiet --root "$WORK/root" --scripts "$WORK/scripts" --identifier com.yogafp.pkg --version "$VERSION" \
  --install-location / "$WORK/yogafp-component.pkg"
productbuild --quiet --distribution "$WORK/distribution.xml" --resources "$WORK/res" --package-path "$WORK" "$DIST/$NAME.pkg"

say "Building the disk image"
DMGSRC="$WORK/dmg"; mkdir -p "$DMGSRC"
cp "$DIST/$NAME.pkg" "$DMGSRC/Install YogaFP.pkg"
cat > "$DMGSRC/Uninstall YogaFP.command" <<'EOF'
#!/bin/bash
echo "This removes YogaFP: sudo and admin-dialog integration are restored first, then the service, app and files."
read -r -p "Also delete your enrolled fingerprints and their encryption key? [y/N] " a
P=""; [[ "$a" == [yY] ]] && P="--purge"
sudo /usr/local/libexec/yoga-fp/yogafp-admin.sh uninstall $P
read -r -p "Done. Press Return to close."
EOF
chmod 755 "$DMGSRC/Uninstall YogaFP.command"
cp "$ROOT/README.md" "$DMGSRC/README.md"; cp "$ROOT/LICENSE" "$DMGSRC/LICENSE.txt"
hdiutil create -quiet -volname "YogaFP $VERSION" -srcfolder "$DMGSRC" -ov -format UDZO "$DIST/$NAME.dmg"

say "Done:"
ls -lh "$DIST/$NAME.pkg" "$DIST/$NAME.dmg" | awk '{print "    " $5 "  " $NF}'
shasum -a 256 "$DIST/$NAME.pkg" "$DIST/$NAME.dmg" | sed 's/^/    /'
if [[ -n "$FWEXT" ]]; then echo "    PERSONAL build (contains Lenovo firmware): keep it private, e.g. on your rescue USB."; fi
exit 0
