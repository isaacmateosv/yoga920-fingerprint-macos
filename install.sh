#!/bin/bash
# yoga-fp installer for the Synaptics 06cb:0081 fingerprint sensor (Lenovo Yoga 920) on macOS.
#
#   sudo ./install.sh install --fwext /path/to/6_07f_Lenovo.xpfwext
#   sudo ./install.sh install --lenovo-exe /path/to/n1cgn08w.exe      (needs `innoextract`)
#   sudo ./install.sh enable-sudo        # after enrolling: use the fingerprint for sudo
#   sudo ./install.sh disable-sudo
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

wait_socket() {   # until the daemon actually answers (a stale socket file is not enough)
  for _ in $(seq 1 90); do "$BIN" status >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1
}

cmd_install() {
  need_root
  [[ "$(uname)" == Darwin ]] || die "macOS only"
  sensor_present || die "Synaptics 06cb:0081 not found on USB"
  local py; py="$(find_python)"
  say "Python: $py ($("$py" -V 2>&1))"
  if [[ -n "$(find "$(dirname "$(dirname "$("$py" -c 'import sys;print(sys.executable)')")")" -maxdepth 0 -perm -g+w 2>/dev/null)" ]]; then
    warn "your Python runtime is group-writable (normal for python.org/Homebrew). yoga-fp's own code is root-owned,"
    warn "but code running as an admin user could still alter the runtime. See README > Security."
  fi

  say "Installing to $PREFIX"
  launchctl bootout system/$LABEL 2>/dev/null || true
  rm -f "$SOCK"
  rm -rf "$PREFIX.new"; mkdir -p "$PREFIX.new"
  cp -R "$HERE/yogafp" "$HERE/vendor" "$HERE/requirements.txt" "$PREFIX.new/"
  find "$PREFIX.new" -name '__pycache__' -prune -exec rm -rf {} +
  if [[ -x "$PREFIX/venv/bin/python" ]]; then
    mv "$PREFIX/venv" "$PREFIX.new/venv"          # reuse; pip below still upgrades anything outdated
  else
    "$py" -m venv "$PREFIX.new/venv"
  fi
  "$PREFIX.new/venv/bin/python" -m pip install -q --no-cache-dir --disable-pip-version-check --upgrade --only-binary=:all: pip -r "$HERE/requirements.txt"
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
exec "$PREFIX/venv/bin/python" -I "$PREFIX/yogafp/cli.py" "\$@"
EOF
  chmod 755 "$BIN"; chown root:wheel "$BIN"

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
  launchctl bootout system/$LABEL 2>/dev/null || true
  pkill -x YogaFP 2>/dev/null || true
  rm -f "$PLIST" "$BIN" "$PAMMOD" "$CHECK_SVC" "$SOCK"; rm -rf "$APP"
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
  [[ -x "$PREFIX/venv/bin/python" ]] || die "yoga-fp is not installed"
  say "Upgrading dependencies"
  "$PREFIX/venv/bin/python" -m pip install -q --no-cache-dir --disable-pip-version-check --upgrade \
      --only-binary=:all: pip -r "$PREFIX/requirements.txt"
  chown -R root:wheel "$PREFIX"; chmod -R go-w "$PREFIX"
  "$PREFIX/venv/bin/python" -m pip list --format=freeze 2>/dev/null | grep -iE '^(numpy|opencv|cryptography|pyusb|libusb)'
  launchctl kickstart -k system/$LABEL
  wait_socket && say "updated and restarted" || die "daemon did not restart; see /var/log/yogafpd.log"
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
  status) cmd_status ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
