#!/bin/bash
# yoga-fp installer for the Synaptics 06cb:0081 fingerprint sensor (Lenovo Yoga 920) on macOS.
#
#   sudo ./install.sh install --fwext /path/to/6_07f_Lenovo.xpfwext
#   sudo ./install.sh install --lenovo-exe /path/to/n1cgn08w.exe      (needs `innoextract`)
#   sudo ./install.sh enable-sudo        # after enrolling: use the fingerprint for sudo
#   sudo ./install.sh disable-sudo
#   sudo ./install.sh admin-test         # try fingerprint for admin dialogs on a private test right (safe)
#   sudo ./install.sh enable-admin       # use it for real admin dialogs (backup + automatic rollback)
#   sudo ./install.sh disable-admin      # restore the original admin-dialog definitions
#   sudo ./install.sh update             # upgrade dependencies (security fixes) and restart
#   sudo ./install.sh uninstall [--purge]   # --purge also deletes fingerprint data and the key
#   ./install.sh status
#
# The Lenovo firmware file is not redistributed; get n1cgn08w.exe from Lenovo support (DS120491).
set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:/opt/local/bin:$PATH"

PREFIX=/usr/local/libexec/yoga-fp
DATA="/Library/Application Support/yoga-fp"
PAMDIR=/usr/local/lib/pam
PAMMOD="$PAMDIR/pam_yogafp.so"
BIN=/usr/local/bin/yogafp
LABEL=com.yogafp.yogafpd
PLIST=/Library/LaunchDaemons/$LABEL.plist
SOCK=/var/run/yogafpd.sock
SUDO_LOCAL=/etc/pam.d/sudo_local
APP=/Applications/YogaFP.app
AUTHPLUGIN=/Library/Security/SecurityAgentPlugins/YogaFPAuth.bundle
AUTHDB_BACKUP="$DATA/authdb-backup"
# Admin prompts handled by the plugin. System Settings uses one right per pane, not just system.preferences.
# Excluded on purpose: panes that extract the administrator's PASSWORD from the authorization afterwards
# (Users & Groups creates/edits accounts with it; Privacy & Security for FileVault etc.). A fingerprint approval
# carries no password, so those panes must keep the standard password dialog.
# Not system.preferences: loginwindow evaluates it non-interactively during login (FileVault auto-login).
ADMIN_RIGHTS=(system.privilege.admin system.install.software
              system.preferences.network system.preferences.sharing system.preferences.datetime
              system.preferences.energysaver system.preferences.printing system.preferences.startupdisk
              system.preferences.timemachine)
NEEDS_PASSWORD_RIGHTS=(system.preferences.accounts system.preferences.security)
# Rights an older version switched that must go back to Apple's definition (restored by enable/disable-admin).
RETIRED_RIGHTS=(system.preferences)
TEST_RIGHT=com.yogafp.test
CHECK_SVC=/etc/pam.d/yogafp-check
PAM_LINE="auth       sufficient     $PAMMOD"

FWEXT_SHA256=45f6e553ca59b0b3a17b4b93f6353ba43d71a7aa7d26205f732ca819365aa339
LENOVO_SHA512=d839fa65adf4c952ecb4a5c4b2fc5b5bdedd8e02a421564bdc7fae1d281be4ea26fcde2333f2ab78d56cef0fdccce0a3cf429300b89544cdc9cfee6d0fe0db55

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "run with sudo"; }

sensor_present() {   # 06cb:0081 = idVendor 1739, idProduct 129, in the same IOUSB device node
  ioreg -p IOUSB -l -w0 | awk '/\+-o /{if(v&&p)f=1; v=p=0} /"idVendor" = 1739$/{v=1} /"idProduct" = 129$/{p=1} END{if(v&&p)f=1; exit !f}'
}

find_python() {
  for p in "${PYTHON:-}" /Library/Frameworks/Python.framework/Versions/Current/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    [[ -n "$p" && -x "$p" ]] || continue
    if "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then echo "$p"; return; fi
  done
  die "Python 3.11+ not found (install from python.org or Homebrew, or set PYTHON=/path/to/python3)"
}

get_fwext() {   # $1 = output path
  local out="$1" tmp
  if [[ -n "${FWEXT:-}" ]]; then
    [[ -f "$FWEXT" ]] || die "no such file: $FWEXT"
    cp "$FWEXT" "$out"
  elif [[ -n "${LENOVO_EXE:-}" ]]; then
    [[ -f "$LENOVO_EXE" ]] || die "no such file: $LENOVO_EXE"
    [[ "$(shasum -a 512 "$LENOVO_EXE" | cut -d' ' -f1)" == "$LENOVO_SHA512" ]] || die "n1cgn08w.exe checksum mismatch"
    command -v innoextract >/dev/null || die "innoextract not found (e.g. sudo port install innoextract / brew install innoextract)"
    tmp="$(mktemp -d)"
    innoextract -q -d "$tmp" "$LENOVO_EXE" >/dev/null
    local f; f="$(find "$tmp" -name '6_07f_Lenovo.xpfwext' -print -quit)"
    [[ -n "$f" ]] || { rm -rf "$tmp"; die "6_07f_Lenovo.xpfwext not found inside the Lenovo package"; }
    cp "$f" "$out"; rm -rf "$tmp"
  else
    die "pass --fwext <6_07f_Lenovo.xpfwext> or --lenovo-exe <n1cgn08w.exe>"
  fi
  [[ "$(shasum -a 256 "$out" | cut -d' ' -f1)" == "$FWEXT_SHA256" ]] || { rm -f "$out"; die "firmware file checksum mismatch"; }
}

# Private, root-owned copy of the Python runtime (python.org framework builds): the daemon must not run on a
# runtime that admin-group code can modify. Trimmed (no tests/Tk/docs), every absolute library link rewritten to
# @loader_path, re-signed ad hoc. Dependencies are installed into it directly (no venv). Falls back to a venv on
# non-framework Pythons (e.g. Homebrew) with a warning.
make_runtime() {   # $1 = source python, $2 = destination dir
  local py="$1" dest="$2" base
  base="$("$py" -I -c 'import sys; print(sys.base_prefix)')"
  if [[ ! -f "$base/Python" ]]; then return 1; fi
  local stamp; stamp="$base $(shasum -a 256 "$base/Python" | cut -d' ' -f1)"
  if [[ -f "$PREFIX/runtime/.yogafp-runtime" && "$(cat "$PREFIX/runtime/.yogafp-runtime")" == "$stamp" ]]; then
    mv "$PREFIX/runtime" "$dest"; say "Python runtime: reusing the private copy"; return 0
  fi
  say "Python runtime: building a private root-owned copy (one time, ~140 MB)"
  local v; v="$(basename "$base")"
  rsync -a --exclude "lib/python$v/test" --exclude "lib/python$v/idlelib" --exclude "lib/python$v/tkinter" \
    --exclude "lib/python$v/turtledemo" --exclude "lib/python$v/site-packages/*" --exclude share --exclude Frameworks \
    --exclude include --exclude __pycache__ --exclude _CodeSignature --exclude "lib/python$v/lib-dynload/_tkinter*" \
    "$base/" "$dest/"
  local f d dep rel idl
  while IFS= read -r f; do
    [[ -L "$f" ]] && continue
    file "$f" | grep -q Mach-O || continue
    d="$(dirname "$f")"
    for dep in $(otool -L "$f" | tail -n +2 | awk '{print $1}' | grep "^$base/" || true); do
      rel="$("$py" -I -c 'import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' "$dest${dep#$base}" "$d")"
      install_name_tool -change "$dep" "@loader_path/$rel" "$f" 2>/dev/null || true
    done
    idl="$(otool -D "$f" 2>/dev/null | tail -n +2)"
    [[ "$idl" == "$base/"* ]] && install_name_tool -id "@rpath/$(basename "$idl")" "$f" 2>/dev/null
    codesign --force -s - "$f" 2>/dev/null || true
  done < <(find "$dest" -type f \( -perm -u+x -o -name '*.so' -o -name '*.dylib' -o -name Python \))
  if DYLD_PRINT_LIBRARIES=1 "$dest/bin/python3" -I -c 'import ssl, sqlite3, ctypes' 2>&1 | grep -q "$base/"; then
    rm -rf "$dest"; warn "relocated runtime still references $base; falling back"; return 1
  fi
  "$dest/bin/python3" -I -m ensurepip >/dev/null 2>&1 || { rm -rf "$dest"; return 1; }
  echo "$stamp" > "$dest/.yogafp-runtime"
}

wait_socket() {   # until the daemon actually answers (a stale socket file is not enough)
  for _ in $(seq 1 90); do "$BIN" status >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1
}

cmd_install() {
  need_root
  [[ "$(uname)" == Darwin ]] || die "macOS only"
  sensor_present || die "Synaptics 06cb:0081 not found on USB"
  local py; py="$(find_python)"
  say "Python: $py ($("$py" -V 2>&1))"

  say "Installing to $PREFIX"
  launchctl bootout system/$LABEL 2>/dev/null || true
  rm -f "$SOCK"
  rm -rf "$PREFIX.new"; mkdir -p "$PREFIX.new"
  cp -R "$HERE/yogafp" "$HERE/vendor" "$HERE/requirements.txt" "$PREFIX.new/"
  find "$PREFIX.new" -name '__pycache__' -prune -exec rm -rf {} +
  if ! make_runtime "$py" "$PREFIX.new/runtime"; then
    warn "$py is not a python.org framework build: using a venv. Its base runtime stays admin-writable (see README)."
    "$py" -m venv "$PREFIX.new/runtime"
  fi
  "$PREFIX.new/runtime/bin/python3" -I -m pip install -q --no-cache-dir --disable-pip-version-check --root-user-action=ignore --upgrade \
      --only-binary=:all: pip -r "$HERE/requirements.txt"
  command -v cc >/dev/null || die "a C compiler is required (xcode-select --install)"
  local build; build="$(mktemp -d)"; cp "$HERE/pam/"*.c "$HERE/pam/Makefile" "$build/"
  make -s -C "$build" >/dev/null || die "building the PAM module failed"
  cp "$build/pamcheck" "$PREFIX.new/pamcheck"; cp "$build/pam_yogafp.so" "$PREFIX.new/pam_yogafp.so"; rm -rf "$build"
  chown -R root:wheel "$PREFIX.new"; chmod -R go-w "$PREFIX.new"
  rm -rf "$PREFIX"; mv "$PREFIX.new" "$PREFIX"

  say "Data directory (root-only): $DATA"
  mkdir -p "$DATA/validity"; chmod 700 "$DATA" "$DATA/validity"; chown -R root:wheel "$DATA"
  if [[ ! -f "$DATA/validity/6_07f_Lenovo.xpfwext" ]]; then
    get_fwext "$DATA/validity/6_07f_Lenovo.xpfwext"; chmod 600 "$DATA/validity/6_07f_Lenovo.xpfwext"
  fi

  if [[ -f "$SUDO_LOCAL" ]] && grep -qF "$PAMMOD" "$SUDO_LOCAL"; then
    say "PAM module: $PAMMOD (sudo fingerprint stays enabled)"
  else
    say "PAM module: $PAMMOD (not enabled for sudo yet)"
  fi
  mkdir -p "$PAMDIR"; install -m 444 -o root -g wheel "$PREFIX/pam_yogafp.so" "$PAMMOD"

  cat > "$BIN" <<EOF
#!/bin/sh
exec "$PREFIX/runtime/bin/python3" -I "$PREFIX/yogafp/cli.py" "\$@"
EOF
  chmod 755 "$BIN"; chown root:wheel "$BIN"

  if [[ -d "$AUTHPLUGIN" ]]; then          # admin-dialog plugin already in use: refresh it with this version
    say "Authorization plugin: updating $AUTHPLUGIN"
    install_authplugin
  fi

  if command -v swiftc >/dev/null; then
    say "Menu bar app: $APP"
    local abuild; abuild="$(mktemp -d)"; cp "$HERE/app/YogaFP.swift" "$HERE/app/build.sh" "$abuild/"
    if bash "$abuild/build.sh" >/dev/null 2>&1; then
      pkill -x YogaFP 2>/dev/null || true
      rm -rf "$APP"; cp -R "$abuild/build/YogaFP.app" "$APP"; chown -R root:admin "$APP"; chmod -R go-w "$APP"
    else
      warn "menu bar app build failed (the service and sudo still work)"
    fi
    rm -rf "$abuild"
  else
    warn "swiftc not found: skipping the menu bar app (install Xcode or the Command Line Tools)"
  fi

  sed -e "s#@PREFIX@#$PREFIX#g" -e "s#@DATA@#$DATA#g" -e "s#@LABEL@#$LABEL#g" "$HERE/launchd/yogafpd.plist.in" > "$PLIST"
  chown root:wheel "$PLIST"; chmod 644 "$PLIST"
  launchctl bootstrap system "$PLIST"
  wait_socket || die "daemon did not start; see /var/log/yogafpd.log"
  say "Daemon running. Pairing/firmware/calibration happen on first start (the sensor may reboot a few times)."
  "$BIN" setup || warn "sensor setup reported a problem; see /var/log/yogafpd.log"
  echo
  local who="${SUDO_USER:-root}"
  if sudo -u "$who" "$BIN" status 2>/dev/null | grep -q '"enrolled": true'; then
    say "Your fingerprint enrollment was kept."
  else
    say "Next: enroll your finger (a guided 25-touch process) from the YogaFP menu, or:"
    echo "      sudo yogafp grant-enroll && yogafp enroll"
  fi
  if ! { [[ -f "$SUDO_LOCAL" ]] && grep -qF "$PAMMOD" "$SUDO_LOCAL"; }; then
    say "Then optionally:  sudo $0 enable-sudo"
  fi
  if [[ -d "$APP" && -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
    sudo -u "$SUDO_USER" open "$APP" 2>/dev/null || true
  fi
  [[ -d "$APP" ]] && say "Menu bar app: $APP (add it under System Settings > General > Login Items to start at login)"
}

cmd_enable_sudo() {
  need_root
  [[ -S "$SOCK" ]] || die "yoga-fp is not installed/running"
  local user="${SUDO_USER:-}"; [[ -n "$user" && "$user" != root ]] || die "run as: sudo $0 enable-sudo (from your user account)"
  sudo -u "$user" "$BIN" status | grep -q '"enrolled": true' || die "$user has no enrolled fingerprint; run: sudo yogafp grant-enroll && yogafp enroll"
  [[ -f "$PAMMOD" ]] || die "PAM module missing"

  say "Step 1/3: test the module in an isolated PAM service (touch the sensor when asked)"
  printf '%s\nauth       required       pam_deny.so\n' "$PAM_LINE" > "$CHECK_SVC"
  if ! "$PREFIX/pamcheck" yogafp-check "$user"; then
    rm -f "$CHECK_SVC"; die "fingerprint check did not succeed; sudo was NOT changed"
  fi
  rm -f "$CHECK_SVC"

  say "Step 2/3: add the module to $SUDO_LOCAL (backup kept)"
  local bak=""
  if [[ -f "$SUDO_LOCAL" ]]; then
    grep -qF "$PAMMOD" "$SUDO_LOCAL" && { say "already enabled"; return 0; }
    bak="$SUDO_LOCAL.yogafp-backup.$(date +%Y%m%d%H%M%S)"; cp -p "$SUDO_LOCAL" "$bak"
    { echo "$PAM_LINE"; cat "$bak"; } > "$SUDO_LOCAL.tmp"
  else
    printf '# sudo_local: local config file which survives system update and is included for sudo\n%s\n' "$PAM_LINE" > "$SUDO_LOCAL.tmp"
  fi
  chown root:wheel "$SUDO_LOCAL.tmp"; chmod 444 "$SUDO_LOCAL.tmp"; mv "$SUDO_LOCAL.tmp" "$SUDO_LOCAL"

  say "Step 3/3: verify the sudo PAM stack still loads (touch the sensor once more)"
  local rc=0; "$PREFIX/pamcheck" sudo "$user" >/tmp/yogafp-pamcheck.$$ 2>&1 || rc=$?
  if grep -qiE 'pam_start|system error|Unable to load|module is unknown' /tmp/yogafp-pamcheck.$$; then
    warn "sudo PAM stack failed to load; rolling back"
    if [[ -n "$bak" ]]; then mv "$bak" "$SUDO_LOCAL"; else rm -f "$SUDO_LOCAL"; fi
    rm -f /tmp/yogafp-pamcheck.$$; die "rolled back; sudo unchanged"
  fi
  rm -f /tmp/yogafp-pamcheck.$$
  say "Enabled. sudo now asks for your fingerprint first (3 tries), then your password. SSH sessions always use the password."
}

cmd_disable_sudo() {
  need_root
  if [[ -f "$SUDO_LOCAL" ]] && grep -qF "$PAMMOD" "$SUDO_LOCAL"; then
    grep -vF "$PAMMOD" "$SUDO_LOCAL" > "$SUDO_LOCAL.tmp" || true
    chown root:wheel "$SUDO_LOCAL.tmp"; chmod 444 "$SUDO_LOCAL.tmp"; mv "$SUDO_LOCAL.tmp" "$SUDO_LOCAL"
    say "fingerprint removed from sudo"
  else
    say "sudo was not using the fingerprint"
  fi
}

cmd_uninstall() {
  need_root
  cmd_disable_sudo                       # always first: never leave sudo pointing at a missing module
  cmd_disable_admin                      # and never leave admin dialogs pointing at a missing plugin
  launchctl bootout system/$LABEL 2>/dev/null || true
  pkill -x YogaFP 2>/dev/null || true
  rm -f "$PLIST" "$BIN" "$PAMMOD" "$CHECK_SVC" "$SOCK"; rm -rf "$APP" "$AUTHPLUGIN"
  rm -rf "$PREFIX"
  if [[ "${1:-}" == --purge ]]; then
    rm -rf "$DATA"
    security delete-generic-password -a root -s yoga-fp-template-key /Library/Keychains/System.keychain >/dev/null 2>&1 || true
    say "removed yoga-fp, fingerprint data and the encryption key"
  else
    say "removed yoga-fp (fingerprint data kept in $DATA; use --purge to delete it)"
  fi
}

cmd_update() {   # upgrade Python dependencies to the newest stable releases in range, then restart
  need_root
  [[ -x "$PREFIX/runtime/bin/python3" ]] || die "yoga-fp is not installed"
  say "Upgrading dependencies"
  "$PREFIX/runtime/bin/python3" -I -m pip install -q --no-cache-dir --disable-pip-version-check --root-user-action=ignore --upgrade \
      --only-binary=:all: pip -r "$PREFIX/requirements.txt"
  chown -R root:wheel "$PREFIX"; chmod -R go-w "$PREFIX"
  "$PREFIX/runtime/bin/python3" -I -m pip list --format=freeze 2>/dev/null | grep -iE '^(numpy|opencv|cryptography|pyusb|libusb)'
  launchctl kickstart -k system/$LABEL
  wait_socket && say "updated and restarted" || die "daemon did not restart; see /var/log/yogafpd.log"
}

# ---------------------------------------------------------------- admin dialogs (authorization plugin)
right_def() {   # $1 = shared (true/false), $2 = timeout seconds -> evaluate-mechanisms right using YogaFP
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>class</key><string>evaluate-mechanisms</string>
  <key>comment</key><string>yoga-fp: one dialog, fingerprint or password; root step decides. Restore: sudo ./install.sh disable-admin</string>
  <key>mechanisms</key><array>
    <string>YogaFPAuth:ui</string>
    <string>YogaFPAuth:grant,privileged</string>
  </array>
  <key>shared</key><$1/>
  <key>timeout</key><integer>$2</integer>
  <key>tries</key><integer>3</integer>
  <key>version</key><integer>1</integer>
</dict></plist>
EOF
}

install_authplugin() {
  command -v cc >/dev/null || die "a C compiler is required (xcode-select --install)"
  local b; b="$(mktemp -d)"; cp "$HERE/authplugin/"* "$b/"
  make -s -C "$b" >/dev/null || { rm -rf "$b"; die "building the authorization plugin failed"; }
  rm -rf "$AUTHPLUGIN"; cp -R "$b/YogaFPAuth.bundle" "$AUTHPLUGIN"
  chown -R root:wheel "$AUTHPLUGIN"; chmod -R go-w "$AUTHPLUGIN"
  install -m 755 -o root -g wheel "$b/authtest" "$PREFIX/authtest"
  rm -rf "$b"
}

AUTHLOG=/var/log/yogafp-auth.log

authlog_since() {   # $1 = byte offset -> new lines of the root step's log
  [[ -f "$AUTHLOG" ]] && tail -c +$(( $1 + 1 )) "$AUTHLOG" || true
}

cmd_admin_test() {
  need_root
  [[ -S "$SOCK" ]] || die "yoga-fp is not installed/running"
  local user="${SUDO_USER:-}"; [[ -n "$user" && "$user" != root ]] || die "run as: sudo $0 admin-test (from your user account)"
  sudo -u "$user" "$BIN" status | grep -q '"enrolled": true' || die "$user has no enrolled fingerprint"
  say "Installing the authorization plugin: $AUTHPLUGIN"
  install_authplugin
  right_def false 0 | security authorizationdb write "$TEST_RIGHT" >/dev/null 2>&1 || die "could not create the test right"
  local def; def="$(security authorizationdb read "$TEST_RIGHT" 2>/dev/null | grep -c 'YogaFPAuth:' || true)"
  [[ "$def" == 2 ]] || { security authorizationdb remove "$TEST_RIGHT" >/dev/null 2>&1; die "test right was not stored as expected"; }
  say "Test right $TEST_RIGHT created and verified."
  touch "$AUTHLOG"; chmod 600 "$AUTHLOG"

  local o1 r1 l1 o2 r2 l2
  o1=$(stat -f %z "$AUTHLOG")
  say "Test 1/2: one dialog appears. TOUCH THE SENSOR (do not type anything)."
  r1="$(sudo -u "$user" "$PREFIX/authtest" "$TEST_RIGHT" 2>&1 || true)"
  l1="$(authlog_since "$o1")"; echo "    result: $r1"; sed 's/^/    root step: /' <<<"$l1" | tail -3
  o2=$(stat -f %z "$AUTHLOG")
  say "Test 2/2: the dialog appears again. TYPE YOUR PASSWORD and press OK (do not touch the sensor)."
  r2="$(sudo -u "$user" "$PREFIX/authtest" "$TEST_RIGHT" 2>&1 || true)"
  l2="$(authlog_since "$o2")"; echo "    result: $r2"; sed 's/^/    root step: /' <<<"$l2" | tail -3
  security authorizationdb remove "$TEST_RIGHT" >/dev/null 2>&1 || true

  local ok1=no ok2=no
  [[ "$r1" == granted ]] && grep -q "grant: fingerprint for .* accepted" <<<"$l1" && ok1=yes
  [[ "$r2" == granted ]] && grep -q "grant: password for .* accepted" <<<"$l2" && ok2=yes
  if [[ $ok1 == yes && $ok2 == yes ]]; then
    date > "$DATA/admin-test-passed"; chmod 600 "$DATA/admin-test-passed"
    say "PASS: the root step approved test 1 by fingerprint and test 2 by password."
    say "Real admin dialogs are unchanged; enable them with: sudo $0 enable-admin"
  else
    rm -f "$DATA/admin-test-passed"
    warn "not passed (fingerprint: $ok1, password: $ok2). Nothing system-wide was changed."
    [[ -n "$l1$l2" ]] || warn "the root step never ran (see ~/Library/Logs/yogafp-auth.log for the dialog side)"
    warn "a 'granted' without a root-step line means macOS answered from a cached authorization; wait 5 minutes and retry"
    exit 1
  fi
}

cmd_admin_test_define() {   # keep the private test right defined for manual/diagnostic requests
  need_root
  install_authplugin
  right_def false 0 | security authorizationdb write "$TEST_RIGHT" >/dev/null 2>&1 || die "could not create the test right"
  say "Test right $TEST_RIGHT is defined. Request it as your normal user (no sudo):"
  echo "      $PREFIX/authtest $TEST_RIGHT"
  say "Remove it with: sudo $0 admin-test-remove"
}

cmd_admin_test_remove() {
  need_root
  security authorizationdb remove "$TEST_RIGHT" >/dev/null 2>&1 || true
  say "test right removed"
}

cmd_enable_admin() {
  need_root
  [[ -f "$DATA/admin-test-passed" ]] || die "run 'sudo $0 admin-test' first (it must pass)"
  [[ -d "$AUTHPLUGIN" ]] || die "plugin missing; run admin-test again"
  local user="${SUDO_USER:-}"; [[ -n "$user" && "$user" != root ]] || die "run as: sudo $0 enable-admin (from your user account)"
  mkdir -p "$AUTHDB_BACKUP"; chmod 700 "$AUTHDB_BACKUP"
  local r shared timeout
  for r in "${ADMIN_RIGHTS[@]}"; do
    if [[ ! -f "$AUTHDB_BACKUP/$r.plist" ]]; then           # first enable: keep the pristine definition
      security authorizationdb read "$r" > "$AUTHDB_BACKUP/$r.plist" 2>/dev/null || die "could not back up $r"
    fi
  done
  local x
  for x in "${NEEDS_PASSWORD_RIGHTS[@]}" "${RETIRED_RIGHTS[@]}"; do   # undo an older version that switched these
    [[ -f "$AUTHDB_BACKUP/$x.plist" ]] && security authorizationdb write "$x" < "$AUTHDB_BACKUP/$x.plist" >/dev/null 2>&1 \
      && say "restored $x (keeps Apple's standard definition)"
  done
  local eligible=()
  for r in "${ADMIN_RIGHTS[@]}"; do                         # only plain "authenticate an admin" rules
    local cls grp
    cls=$(/usr/libexec/PlistBuddy -c "Print :class" "$AUTHDB_BACKUP/$r.plist" 2>/dev/null || true)
    grp=$(/usr/libexec/PlistBuddy -c "Print :group" "$AUTHDB_BACKUP/$r.plist" 2>/dev/null || true)
    if [[ "$cls" == user && "$grp" == admin ]]; then eligible+=("$r"); else warn "skipping $r (class '$cls', group '$grp')"; fi
  done
  say "Original definitions backed up to $AUTHDB_BACKUP"
  for r in "${eligible[@]}"; do
    shared=$(/usr/libexec/PlistBuddy -c "Print :shared" "$AUTHDB_BACKUP/$r.plist" 2>/dev/null || true)
    timeout=$(/usr/libexec/PlistBuddy -c "Print :timeout" "$AUTHDB_BACKUP/$r.plist" 2>/dev/null || true)
    [[ "$shared" == true ]] || shared=false
    [[ "$timeout" =~ ^[0-9]+$ ]] || timeout=0
    right_def "$shared" "$timeout" | security authorizationdb write "$r" >/dev/null 2>&1 || { cmd_disable_admin; die "writing $r failed; restored"; }
  done
  say "Self-check: an admin request appears now - touch the sensor (or use your password)."
  touch "$AUTHLOG"; local off; off=$(stat -f %z "$AUTHLOG")
  local res; res="$(sudo -u "$user" "$PREFIX/authtest" system.privilege.admin 2>&1 || true)"; echo "    -> $res"
  if [[ "$res" != granted ]] || ! authlog_since "$off" | grep -q "grant: .* accepted"; then
    warn "self-check failed ($res); restoring the original definitions"
    cmd_disable_admin
    exit 1
  fi
  say "Enabled for ${#eligible[@]} admin prompts: ${eligible[*]}"
  say "Your password always works in the dialog."
  say "Undo anytime with: sudo $0 disable-admin   (sudo with your password always works)"
}

cmd_disable_admin() {
  need_root
  local r n=0
  for r in "${ADMIN_RIGHTS[@]}" "${NEEDS_PASSWORD_RIGHTS[@]}" "${RETIRED_RIGHTS[@]}"; do
    if [[ -f "$AUTHDB_BACKUP/$r.plist" ]]; then
      security authorizationdb write "$r" < "$AUTHDB_BACKUP/$r.plist" >/dev/null 2>&1 && n=$((n+1)) || warn "could not restore $r"
    fi
  done
  security authorizationdb remove "$TEST_RIGHT" >/dev/null 2>&1 || true
  say "restored $n admin-dialog definition(s)"
}

cmd_status() {
  echo "sensor on USB:    $(sensor_present && echo yes || echo no)"
  echo "daemon:           $([[ -S "$SOCK" ]] && echo running || echo 'not running')"
  echo "sudo fingerprint: $([[ -f "$SUDO_LOCAL" ]] && grep -qF "$PAMMOD" "$SUDO_LOCAL" && echo enabled || echo disabled)"
  [[ -S "$SOCK" ]] && "$BIN" status || true
}

cmd="${1:-}"; shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fwext) FWEXT="$2"; shift 2 ;;
    --lenovo-exe) LENOVO_EXE="$2"; shift 2 ;;
    --purge) PURGE=--purge; shift ;;
    *) die "unknown option $1" ;;
  esac
done
case "$cmd" in
  install) cmd_install ;;
  enable-sudo) cmd_enable_sudo ;;
  disable-sudo) cmd_disable_sudo ;;
  uninstall) cmd_uninstall "${PURGE:-}" ;;
  update) cmd_update ;;
  admin-test) cmd_admin_test ;;
  admin-test-define) cmd_admin_test_define ;;
  admin-test-remove) cmd_admin_test_remove ;;
  enable-admin) cmd_enable_admin ;;
  disable-admin) cmd_disable_admin ;;
  status) cmd_status ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
