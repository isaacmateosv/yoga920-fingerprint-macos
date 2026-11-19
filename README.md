# Lenovo Yoga 920 fingerprint on macOS — Synaptics/Validity 06cb:0081

**yoga-fp**: fingerprint authentication for `sudo` on macOS (Hackintosh) with the Synaptics/Validity **06cb:0081**
sensor (`57K0 FM-3297-004`, ROM 6.7 build 164) built into the **Lenovo Yoga 920 (80Y7)**.

Includes a root daemon, a PAM module for `sudo` (with a "touch the sensor / use password" panel), a menu bar app
with guided enrollment, and a one-command installer. Built on a patched
[python-validity](https://github.com/uunicorn/python-validity) plus a host-side matcher, because this sensor's 2016
firmware cannot match fingerprints on-chip.

> Status: working on the author's Lenovo Yoga 920 Hackintosh (macOS 26.7.3, OpenCore). Treat it as beta.
> Your password always remains a fallback. Not affiliated with Lenovo, Synaptics or Apple.

## How it works

```
 sensor (USB, TLS-paired to this Mac)
   │  raw frames, in memory only
 yogafpd  (root LaunchDaemon)  ── encrypted templates  /Library/Application Support/yoga-fp  (root, 0700)
   │  UNIX socket, caller identified by the kernel        key: System keychain
   ├── pam_yogafp.so  → sudo (via /etc/pam.d/sudo_local)
   ├── YogaFPAuth.bundle → admin dialogs (authorization plugin, optional)
   ├── yogafp CLI
   └── YogaFP menu bar app (status, enrollment, sudo prompt panel)
```

* **Pairing / firmware:** the sensor is formatted with the 0090 partition layout (ROM 6.7 b164 has no signed
  partition tables, python-validity PR #294), paired over TLS with a key bound to this Mac's model and serial,
  and loaded with Lenovo's `6_07f_Lenovo.xpfwext`.
* **Matching:** SIFT keypoints on the 112×112 image, RANSAC-consistent match count against 31 guided partial
  touches (7 regions + 2 rotations), plus up to 40 areas learned automatically from certain matches.
  Default threshold 10.

### Matcher evaluation

Chosen on a labeled, encrypted local dataset (31 enrollment / 30 own-finger / 30 other-finger captures, collected
with `devtools/collect.py`, scored with `devtools/evaluate.py`, deleted afterwards):

| Method | AUC | Own finger per touch (no other finger accepted) |
|---|---|---|
| **SIFT + RANSAC (used)** | **0.94** | **70% at threshold 10 → 97% per sudo (3 tries)** |
| SIFT on Gabor-enhanced ridges | 0.67 | 10% |
| Band-limited phase-only correlation | 0.76 | 53% |
| BLPOC on enhanced ridges | 0.82 | 37% |
| Fusions, top-k sums, assembled template | 0.91–0.94 | ≤ 87% (no gain) |

Across 120 other-finger touches the highest score was 9. The remaining ~13% of own-finger touches overlap almost
nothing that was enrolled (sensor area limit); adaptive learning fills those areas in with use.

## How we got here

The sensor had no macOS driver and no Linux support for this exact model, so this was built step by step,
mostly read-only investigation before anything was written to the sensor.

1. **Identify the hardware.** USB `06cb:0081`; the sensor reports ROM **6.7 build 164** and identifies as
   `57K0 FM-3297-004` (sensor type `0xb5`). The closest supported relative in
   [python-validity](https://github.com/uunicorn/python-validity) is `138a:0090` (ThinkPad), with the same ROM.
2. **Study the Windows driver** (copied from the laptop's own Windows partition, plus two Microsoft Update Catalog
   releases, 5.5.2740 and 5.5.2811). The TLS pairing with the sensor (`DoPairing`, ECDH/ECDSA) runs in ordinary
   driver code. The sensor command programs live in an Intel SGX enclave image, `synaTEE.signed.dll`, which at
   first looked encrypted. It is not: two of its programs are **byte-identical** to python-validity's published
   `0090` blobs, so the high-entropy data is compressed sensor programs stored in the clear.
3. **Get the firmware extension.** `6_07f_Lenovo.xpfwext` (6.07.0164, product 0x30) from Lenovo's official
   driver `n1cgn08w.exe` (SHA-512 verified, extracted with innoextract). It is the same file the 0090 uses.
4. **Fix the partition table.** Formatting failed with `0x04af` and an 11-entry table: ROM 6.7 b164 predates
   signed partition tables (CVE-2019-18618) and stores the signature as extra partitions. python-validity
   **PR #294** (unmerged) describes exactly this ROM; using the 0090 layout *without* a signature, plus not
   re-selecting an already active USB configuration, fixed pairing.
5. **Pick the right command blobs.** Candidates taken from the newer 5.5.2811 driver rebooted or crashed the
   sensor (wrong ROM/firmware generation). Upstream's tested 0090 blob set works unchanged, because the ROM and
   firmware are identical. **Nothing from the Windows driver ships in this project.**
6. **Calibrate.** Iterative per-pixel calibration crashes the 2016 firmware; like the 0090's sensor (type
   `0xdb`), type `0xb5` uses a single blank reference frame.
7. **Pair to this Mac.** The TLS pairing key is derived from the Mac's model and serial (read via `ioreg`),
   so the sensor stays paired to this machine across reinstalls.
8. **Match on the Mac.** On-chip enrollment is not supported by this firmware (`0x69` → `0x0401`), but raw
   112×112 frames can be streamed. Matching is done on the host: SIFT keypoints + RANSAC-consistent inliers,
   chosen over Gabor-enhanced SIFT, band-limited phase-only correlation and fusions on a labeled, encrypted,
   local dataset (see *Matcher evaluation*). Then: a steadier capture (finger must settle), adaptive enrollment,
   Touch ID-style password rules and up to 3 fingers.
9. **Make it a product.** Root daemon with kernel-verified callers, PAM module for `sudo`, authorization plugin
   for admin dialogs (root step verifies a one-time match proof), menu bar app, installer with automatic
   rollback, private root-owned Python runtime, and CI.

### What was (not) used

* **No SGX bypass, decryption or enclave attack** was done or needed. Step 2 showed the relevant data is not
  protected by the enclave, and the final project does not use the enclave image at all.
* **[rea](https://github.com/morluto/rea)** (Reverse Engineer Anything) was available, and its documentation was
  read, but it was **not used**: the analysis was done with `llvm-objdump`, small Python scripts (PE section
  mapper, blob catalog parser, entropy measurement) and python-validity's own code.
* Development was done with the help of [Claude Code](https://claude.com/claude-code) (Anthropic). Biometric
  data was never sent to it: images stayed in memory or encrypted on the Mac, and quality checks were numbers only.

## Requirements

* Lenovo Yoga 920 (or another machine with a 06cb:0081, ROM 6.7 build 164 — the installer checks the USB ID)
* macOS 14+ (uses `/etc/pam.d/sudo_local`), Python 3.11+, Xcode Command Line Tools
* Lenovo's fingerprint driver package **n1cgn08w.exe** (Lenovo support DS120491) and `innoextract`,
  or the extracted `6_07f_Lenovo.xpfwext`. It is Lenovo's file and is not redistributed here.

## Install

### Installer package (easiest, offline)

`packaging/make-pkg.sh` builds `dist/YogaFP-<version>.pkg` (and a `.dmg` with the package, an uninstaller and this
README). Everything is prebuilt and a private Python runtime with all dependencies is bundled, so the target Mac
needs **no Xcode, Python or internet** (Intel Macs, macOS 14+). The package is unsigned: right-click → Open.

**Updates:** the menu bar's *Check for Updates…* asks GitHub's public releases API (only when you click; one
anonymous request) and opens the download page if a newer version exists. Nothing installs automatically.

After installing, the **YogaFP Setup Assistant** opens from the menu bar icon: enroll your finger, turn on sudo,
turn on admin dialogs (private test first), start at login. Each step uses the standard admin prompt.

The Lenovo firmware is not in the public package; the sensor keeps its firmware and pairing across macOS
reinstalls on the same Mac, so it is only needed for a sensor that was never set up. For personal disaster
recovery, `packaging/make-pkg.sh --fwext 6_07f_Lenovo.xpfwext` builds a `-personal` package that includes it
(do not redistribute it). Note: a full wipe also deletes your encrypted enrollment and its key, so you enroll again.

### From source

```bash
sudo ./install.sh install --lenovo-exe ~/Downloads/n1cgn08w.exe
sudo yogafp grant-enroll && yogafp enroll        # guided: 25 touches over 7 regions of the fingertip
yogafp test 20                                     # optional: see scores for your finger vs others
sudo ./install.sh enable-sudo                      # optional: fingerprint for sudo
```

`enable-sudo` first proves the module works in an isolated PAM service with a real touch, then edits only
`sudo_local` (backup kept), re-checks that sudo's PAM stack loads, and rolls back automatically on failure.

**More fingers:** up to 3 named fingers per account, like Touch ID (each extra finger slightly raises the chance
of a false accept). Adding or removing one needs a touch from an already-enrolled finger:
`yogafp add-finger "Left index"`, `yogafp fingers`, `yogafp remove-finger "Left index"`, or the YogaFP menu.

Tuning: `sudo yogafp set-threshold N` (default 10). Other commands: `sudo ./install.sh update`, `yogafp verify`, `yogafp add 5` (more touches for an area that fails), `yogafp delete`,
`./install.sh status`, `sudo ./install.sh disable-sudo`, `sudo ./install.sh uninstall [--purge]`.
After installing, the same commands are available as `sudo /usr/local/libexec/yoga-fp/yogafp-admin.sh ...`.

## Admin dialogs (optional)

`sudo ./install.sh enable-admin` adds fingerprint to macOS admin prompts — apps asking for administrator rights
(`system.privilege.admin`), package installers (`system.install.software`) and System Settings unlocks
(`system.preferences`) — via an authorization plugin (`authplugin/`, installed in
`/Library/Security/SecurityAgentPlugins`). One dialog offers both: touch the sensor **or** type your password.

* **The dialog decides nothing.** It runs in SecurityAgent (as you) and starts a fingerprint verify tagged with a
  random one-time nonce. The **root** step then asks the daemon to consume that nonce: accepted only if the daemon
  itself recorded a real match for that user within 60 s, once. Passwords are checked by the root step with
  OpenDirectory. Both paths require admin group membership.
* **Safe rollout:** `sudo ./install.sh admin-test` first proves both paths on a private test right (it passes only
  on the root step's own log line); `enable-admin` backs up the original definitions, self-checks and rolls back
  automatically; `sudo ./install.sh disable-admin` restores the originals. `sudo` never depends on the plugin.
* Logs without secrets: `/var/log/yogafp-auth.log` (root step), `~/Library/Logs/yogafp-auth.log` (dialog).
* **Password-only panes:** Users & Groups and Privacy & Security extract the administrator's *password* from the
  approval (e.g. to create accounts or manage FileVault). A fingerprint approval carries no password, so these keep
  the standard macOS dialog (`NEEDS_PASSWORD_RIGHTS` in `install.sh`). Storing your password to hand out on a match
  would work around it, but is deliberately not done.
* **Not possible:** the Passwords app, Keychain prompts, Apple Pay and the App Store use LocalAuthentication, which
  only accepts Apple's Touch ID hardware.

## Security model

* **Biometric data never leaves the machine and is never written as an image.** Frames live in memory; only
  SIFT keypoints are stored, AES-256-GCM encrypted, bound to the user ID (a file copied to another account
  fails authentication). The 256-bit key is random and kept in the System keychain, passed to `security`
  on stdin, never on a command line.
* **The match decision is made by root.** `yogafpd` runs as root and its code is root-owned. The PAM module
  only trusts a socket peer with uid 0 (`getpeereid`), so a user process cannot impersonate the daemon.
* **Caller identity comes from the kernel** (`LOCAL_PEERCRED`), never from the request. Users can only act on
  their own data; only root may name another user.
* **Enrolling requires an administrator** (`sudo yogafp grant-enroll`, single-use, 5 minutes) or, to change an
  existing enrollment, a matching enrolled finger. Someone at your unlocked Mac cannot add their finger.
* **No remote approval:** the PAM module ignores SSH sessions, so a remote login can't trigger a prompt that a
  person at the machine approves.
* **Password rules, as Touch ID:** the fingerprint only works if you used your password in the last 48 hours
  (your login after a restart counts, as do password `sudo` and password approvals in admin dialogs), and
  5 failed fingerprint attempts require the password once. `yogafp status` shows when a password is needed.
* **Fallback:** 3 tries, then your password. A missing daemon or sensor falls through to the password.

### Known limitations (read before enabling sudo)

* **No Secure Enclave.** Unlike Touch ID, the templates and key are protected by root permissions, the System
  keychain and FileVault — not by dedicated hardware. Use FileVault.
* **Private Python runtime.** python.org installs are admin-group writable, so the installer builds a private,
  root-owned copy (trimmed, library links rewritten to relative paths, re-signed) in `/usr/local/libexec/yoga-fp/
  runtime` and runs the daemon on it; nothing is loaded from the original install. Non-framework Pythons (e.g.
  Homebrew) fall back to a venv, whose base runtime stays admin-writable (the installer warns).
* **Small sensor.** 112×112 px partial prints; accuracy depends on good enrollment coverage. Measure with
  `yogafp test` before relying on it. The threshold favours rejecting over accepting.
* **Lock screen / login are not supported.** macOS offers no supported way for third-party readers there.
* **Admin dialogs** use an authorization plugin; a broken plugin can affect admin prompts. Keep `disable-admin`
  handy (Terminal `sudo` with your password is independent of it) and a bootable rescue USB.

## Updates & dependencies

`requirements.txt` uses version ranges rather than exact pins: each install takes the newest stable release
in range, so security fixes arrive without editing the file. Upper bounds sit only at the next major version.
Only prebuilt wheels are accepted (no compiling from source as root). To update an existing install:

```bash
sudo ./install.sh update        # newest in-range releases, then restarts the daemon
```

The repository has Dependabot enabled for pip, so security advisories show up as pull requests.

## Development

```bash
python3 -m venv venv && venv/bin/pip install --only-binary=:all: -r requirements.txt
venv/bin/python -I tests/test_daemon.py          # fake sensor + synthetic patterns, no hardware needed
make -C pam && bash app/build.sh                   # PAM module and menu bar app
```

`devtools/collect.py` and `devtools/evaluate.py` build an **encrypted, local, labeled dataset** (login-keychain key,
owner-only folder) to compare matchers; they print numbers only, and `collect.py --delete` removes the data and key.
They need the service stopped (it owns the sensor) and the firmware file in `run-data/` (git-ignored).

## Uninstall

`sudo ./install.sh uninstall` removes sudo integration first (so sudo never points at a missing module), then
the daemon and files. `--purge` also deletes all fingerprint data and the encryption key.

## Credits & licenses

* **yoga-fp was created by [isaacmateosv](https://github.com/isaacmateosv)** — MIT License (`LICENSE`).

* python-validity © uunicorn, MIT (`vendor/LICENSE.python-validity`); 0081 support follows PR #294 (gocarlos).
* Synaptics/Lenovo firmware is not included; the installer verifies the SHA-512 of the official package.
