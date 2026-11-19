"""yoga-fp core: sensor access, capture, quality gates, matching and encrypted template storage.

Privacy invariants (enforced here, relied on everywhere else):
  * Raw frames and images exist only in memory. Nothing here writes or logs pixel data.
  * Only SIFT keypoints/descriptors are persisted, AES-256-GCM encrypted with a random key held in a
    Keychain (System keychain when running as root). The key is handed to `security` on stdin.
"""
import io, os, sys, time, getpass, secrets, subprocess, logging

import numpy as np
import cv2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger('yogafp')

# ---------------------------------------------------------------- tunables
THRESHOLD = 10          # RANSAC inliers to accept (default; override in <data>/config.json).
                        # Evaluated 2026-11-18 on a labeled local dataset (31 enroll / 30 own / 30 other):
                        # own finger 70% per touch (97% per sudo with 3 tries), other fingers 0/30 (max 4);
                        # 120 other-finger touches overall, max 9. SIFT+RANSAC beat Gabor-enhanced SIFT,
                        # BLPOC (raw/enhanced) and all fusions (AUC 0.94 vs 0.67-0.94).
THRESHOLD_MIN = {'best': 10, 'mosaic': 7}   # floors per method (scales differ). Labeled data 2026-11-18:
                        # other fingers best<=9 (70 touches), mosaic<=4 (40 touches); own finger mosaic 1-48.
FINGER_ON = 25.0        # ridge contrast vs blank (no finger ~2.5, finger ~40)
FINGER_OFF = 8.0
MIN_COVERAGE = 0.60     # fraction of 8x8 blocks with ridge texture
MIN_KEYPOINTS = 60

REGIONS = [
    ('center', 'Center of your fingertip, pressed flat', 4),
    ('tip', 'Tip: slide down so the top of the fingertip is on the sensor', 4),
    ('upper_right', 'Upper right: roll so the upper-right part of the fingertip touches', 5),
    ('upper_left', 'Upper left: roll so the upper-left part touches', 3),
    ('right', 'Right side of the pad', 3),
    ('left', 'Left side of the pad', 3),
    ('lower', 'Lower part of the pad (slide the finger up)', 3),
    ('rot_cw', 'Rotate: turn your finger about 20 degrees clockwise', 3),
    ('rot_ccw', 'Rotate: turn your finger about 20 degrees counter-clockwise', 3),
]

# Adaptive enrollment: learn new areas of the finger from certain matches (as phone sensors do).
ADAPT_FACTOR = 2.0      # only matches scoring >= 2x the threshold teach the template
ADAPT_NOVEL_MAX = 0.6   # ...and only if they are not a near-duplicate (best score < 60% of their own keypoints)
ADAPT_MAX_LEARNED = 40  # cap on learned samples; oldest learned are dropped first, guided ones never

AAD = b'yoga-fp-templates-v1'
KC_SERVICE = 'yoga-fp-template-key'
SYSTEM_KEYCHAIN = '/Library/Keychains/System.keychain'


class FPError(Exception):
    pass


# ---------------------------------------------------------------- key + encrypted store
class Store:
    """Per-user encrypted template files in `root` (one file per uid), key in a Keychain."""

    def __init__(self, root, system_keychain=None):
        self.root = root
        self.system = (os.geteuid() == 0) if system_keychain is None else system_keychain

    def path(self, uid):
        return os.path.join(self.root, 'templates', '%d.enc' % int(uid))

    def _kc_args(self):
        return ([SYSTEM_KEYCHAIN] if self.system else [])

    def _account(self):
        return 'root' if self.system else getpass.getuser()

    def key(self, create=False):
        r = subprocess.run(['/usr/bin/security', 'find-generic-password', '-a', self._account(),
                            '-s', KC_SERVICE, '-w'] + self._kc_args(), capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return bytes.fromhex(r.stdout.strip())
        if not create:
            raise FPError('template key not found in Keychain')
        k = secrets.token_bytes(32)
        cmd = 'add-generic-password -U -a %s -s %s -l "yoga-fp template key" -w %s %s\n' % (
            self._account(), KC_SERVICE, k.hex(), ' '.join(self._kc_args()))
        r = subprocess.run(['/usr/bin/security', '-i'], input=cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise FPError('could not store key in Keychain: %s' % r.stderr.strip())
        return k

    def delete_key(self):
        subprocess.run(['/usr/bin/security', 'delete-generic-password', '-a', self._account(),
                        '-s', KC_SERVICE] + self._kc_args(), capture_output=True)

    def enrolled(self, uid):
        return os.path.exists(self.path(uid))

    def save(self, uid, samples, n_enrolled=None):
        """samples[:n_enrolled] come from guided enrollment; the rest were learned from strong matches."""
        buf = io.BytesIO()
        arrays = {'n_enrolled': np.array([len(samples) if n_enrolled is None else int(n_enrolled)], np.int32)}
        for i, (kp, de) in enumerate(samples):
            arrays['kp%d' % i] = kp
            arrays['de%d' % i] = de
        np.savez(buf, **arrays)
        k = self.key(create=True)
        nonce = secrets.token_bytes(12)
        aad = AAD + b':%d' % int(uid)                       # a template file can't be swapped to another uid
        blob = nonce + AESGCM(k).encrypt(nonce, buf.getvalue(), aad)
        d = os.path.dirname(self.path(uid))
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700); os.chmod(d, 0o700)
        tmp = self.path(uid) + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(blob)
        os.replace(tmp, self.path(uid))

    def load(self, uid):
        return self.load_full(uid)[0]

    def load_full(self, uid):
        """-> (samples, n_enrolled)"""
        p = self.path(uid)
        if not os.path.exists(p):
            raise FPError('no fingerprint enrolled for uid %d' % uid)
        blob = open(p, 'rb').read()
        try:
            data = AESGCM(self.key()).decrypt(blob[:12], blob[12:], AAD + b':%d' % int(uid))
        except Exception:
            raise FPError('template file failed authentication (tampered or wrong key)')
        z = np.load(io.BytesIO(data), allow_pickle=False)
        n = len([k for k in z.files if k.startswith('kp')])
        ne = int(z['n_enrolled'][0]) if 'n_enrolled' in z.files else n
        return [(z['kp%d' % i], z['de%d' % i]) for i in range(n)], ne

    def delete(self, uid):
        if os.path.exists(self.path(uid)):
            os.remove(self.path(uid))


# ---------------------------------------------------------------- features + matching
_sift = cv2.SIFT_create(nfeatures=300, contrastThreshold=0.04, edgeThreshold=12)
_clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 4))
_bf = cv2.BFMatcher(cv2.NORM_L2)


def coverage(diff, blk=8, thr=10.0):
    h, w = diff.shape
    h, w = h - h % blk, w - w % blk
    b = diff[:h, :w].reshape(h // blk, blk, w // blk, blk).std(axis=(1, 3))
    return float((b > thr).mean())


def features(diff):
    lo, hi = np.percentile(diff, 1), np.percentile(diff, 99)
    img = np.clip((diff - lo) * 255.0 / max(1e-6, hi - lo), 0, 255).astype(np.uint8)
    img = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    img = cv2.GaussianBlur(img, (0, 0), 1.2)
    img = _clahe.apply(img)
    kps, desc = _sift.detectAndCompute(img, None)
    if desc is None or len(kps) < 8:
        return None
    kp = np.array([[k.pt[0], k.pt[1], k.size, k.angle] for k in kps], dtype=np.float32)
    return kp, desc.astype(np.float32)


def align(a, b):
    """Match features a against b. Returns (inlier count, 2x3 similarity transform a->b or None)."""
    (kpa, da), (kpb, db) = a, b
    if len(da) < 2 or len(db) < 2:
        return 0, None
    good = [m for m, n in (p for p in _bf.knnMatch(da, db, k=2) if len(p) == 2)
            if m.distance < 0.75 * n.distance]
    if len(good) < 4:
        return len(good) // 2, None
    src = np.float32([kpa[m.queryIdx][:2] for m in good])
    dst = np.float32([kpb[m.trainIdx][:2] for m in good])
    M, mask = cv2.estimateAffinePartial2D(src, dst, method=cv2.RANSAC, ransacReprojThreshold=6.0)
    if M is None:
        return 0, None
    s = float(np.hypot(M[0, 0], M[1, 0]))
    if not (0.8 < s < 1.25):            # same sensor, same scale: reject implausible transforms
        return 0, None
    return int(mask.sum()), M


def inliers(a, b):
    return align(a, b)[0]


# ---------------------------------------------------------------- mosaic ("assembled") template
MERGE_MIN_INLIERS = 15      # strict: a wrong merge would corrupt the map
DEDUP_PX = 3.0              # keypoints closer than this (in map coords) are the same point


def _transform(kp, M):
    out = kp.copy()
    pts = np.c_[kp[:, :2], np.ones(len(kp), np.float32)]
    out[:, :2] = pts @ M.T
    out[:, 3] = (kp[:, 3] + np.degrees(np.arctan2(M[1, 0], M[0, 0]))) % 360
    return out


def _merge_into(cluster, feat, M):
    kp, de = feat
    tk = _transform(kp, M)
    ck, cd = cluster['kp'], cluster['de']
    d2 = ((tk[:, None, :2] - ck[None, :, :2]) ** 2).sum(-1)
    new = d2.min(axis=1) > DEDUP_PX ** 2
    cluster['kp'] = np.vstack([ck, tk[new]])
    cluster['de'] = np.vstack([cd, de[new]])
    cluster['n'] += 1


def build_mosaic(samples):
    """Assemble enrolled touches into as few consistent maps ("pieces") as possible.
    Each touch is aligned to an existing piece when enough ridges agree, else it starts a new piece;
    pieces are then joined when one bridges another."""
    clusters = []
    for feat in samples:
        best = (0, None, None)
        for c in clusters:
            n, M = align(feat, (c['kp'], c['de']))
            if n > best[0]:
                best = (n, M, c)
        if best[0] >= MERGE_MIN_INLIERS:
            _merge_into(best[2], feat, best[1])
        else:
            clusters.append({'kp': feat[0].copy(), 'de': feat[1].copy(), 'n': 1})
    merged = True
    while merged and len(clusters) > 1:          # join pieces that overlap
        merged = False
        clusters.sort(key=lambda c: -c['n'])
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                a, b = clusters[i], clusters[j]
                n, M = align((b['kp'], b['de']), (a['kp'], a['de']))
                if n >= MERGE_MIN_INLIERS:
                    _merge_into(a, (b['kp'], b['de']), M)
                    a['n'] += b['n'] - 1
                    del clusters[j]
                    merged = True
                    break
            if merged:
                break
    return clusters


def mosaic_stats(clusters):
    sizes = sorted((c['n'] for c in clusters), reverse=True)
    return {'pieces': len(clusters), 'largest': sizes[0] if sizes else 0, 'sizes': sizes}


def score_mosaic(probe, clusters):
    """Best inlier count of the probe against any assembled piece."""
    return max((align(probe, (c['kp'], c['de']))[0] for c in clusters), default=0)


def score(probe, samples):
    sc = sorted((inliers(probe, s) for s in samples), reverse=True)
    return (sc[0] if sc else 0), sc[:3]


# ---------------------------------------------------------------- sensor
class Sensor:
    """Owns the 06cb:0081 through python-validity. Reopens after sleep/replug."""

    VID, PID = 0x06cb, 0x0081

    def __init__(self):
        import usb.core as ucore
        import usb.backend.libusb1 as lb
        import libusb_package
        be = lb.get_backend(find_library=lambda x: libusb_package.get_library_path())
        of = ucore.find
        if not getattr(ucore.find, '_yogafp', False):
            def find(**kw):
                return of(**({'backend': be, **kw}))
            find._yogafp = True
            ucore.find = find
        self.ucore = ucore
        from validitysensor.usb import usb as vusb
        from validitysensor.tls import tls
        vusb.trace_enabled = False
        tls.trace_enabled = False
        self.vusb, self.tls = vusb, tls
        self.ready = False

    def present(self):
        return self.ucore.find(idVendor=self.VID, idProduct=self.PID) is not None

    def open(self):
        from validitysensor.sensor import RebootException
        from validitysensor import init as INIT
        for attempt in range(4):
            try:
                for _ in range(60):
                    if self.present():
                        break
                    time.sleep(0.5)
                self.vusb.dev = None
                self.tls.reset()
                self.vusb.open(self.VID, self.PID)
                try:
                    self.vusb.dev.reset()
                except Exception:
                    pass
                time.sleep(0.4)
                self.vusb.dev = None
                self.vusb.open(self.VID, self.PID)
                INIT.open_common()
                self.ready = True
                return
            except (RebootException, self.ucore.USBError) as e:
                log.info('sensor reconnect (%s)', type(e).__name__)
                t0 = time.time()
                while time.time() - t0 < 8 and self.present():
                    time.sleep(0.25)
                time.sleep(1.5)
        self.ready = False
        raise FPError('could not open the sensor')

    def ensure(self):
        if not self.ready:
            self.open()

    def grab(self):
        """One raw frame -> float32 HxW (in memory only)."""
        from validitysensor.sensor import sensor, CaptureMode
        from validitysensor.util import assert_status
        assert_status(self.tls.cmd(sensor.build_cmd_02(CaptureMode.CALIBRATE)))
        raw = self.vusb.read_82()
        if raw is None:
            raise FPError('no image data from sensor')
        bpl, lpf = sensor.bytes_per_line, sensor.lines_per_frame
        W, rep = sensor.type_info.line_width, sensor.type_info.repeat_multiplier
        fs = bpl * lpf
        nf = len(raw) // fs
        frames = np.frombuffer(raw[:nf * fs], dtype=np.uint8).reshape(nf, lpf, bpl)[:, :, 8:8 + W]
        frames = frames[1:] if nf > 1 else frames      # first frame of a burst is unsettled (as in calibration)
        fr = frames.astype(np.float32).mean(axis=0)    # averaging the burst lowers sensor noise
        return fr.reshape(lpf // rep, rep, W).mean(axis=1)

    def safe(self, fn, *a):
        """Run a capture step; on USB failure (sleep/wake re-enumeration) reopen once and retry."""
        try:
            self.ensure()
            return fn(*a)
        except (self.ucore.USBError, FPError):
            self.ready = False
            self.open()
            return fn(*a)


# ---------------------------------------------------------------- capture flows (emit events, no pixels)
def contrast(img, blank):
    return float(np.std(img - blank))


class Capture:
    """ref_path: stored no-finger reference frame (not biometric). Used to detect a finger already
    resting on the sensor when an operation starts, which would otherwise be taken as the blank."""

    def __init__(self, sensor, emit, cancelled=lambda: False, ref_path=None):
        self.s, self.emit, self.cancelled = sensor, emit, cancelled
        self.blank = None
        self.ref_path = ref_path

    def grab(self):
        if self.cancelled():
            raise FPError('cancelled')
        return self.s.safe(self.s.grab)

    def _ref(self):
        if self.ref_path and os.path.exists(self.ref_path):
            try:
                r = np.load(self.ref_path, allow_pickle=False)
                return r.astype(np.float32)
            except Exception:
                return None
        return None

    def take_blank(self, trusted=False):
        """trusted=True (enrollment start, user was told to lift) may (re)write the stored reference."""
        self.emit({'event': 'lift', 'msg': 'Keep your finger off the sensor'})
        ref = self._ref()
        warned = False
        for _ in range(80):
            fr = [self.grab() for _ in range(3)]
            stable = max(contrast(f, fr[0]) for f in fr) < FINGER_OFF
            b = np.mean(fr, axis=0)
            touched = ref is not None and ref.shape == b.shape and contrast(b, ref) > FINGER_ON
            if stable and not touched:
                self.blank = b
                if self.ref_path and (trusted or ref is None):
                    tmp = self.ref_path + '.tmp.npy'
                    np.save(tmp, b.astype(np.float32))
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, self.ref_path)
                return
            if touched and not warned:
                log.info('finger already on the sensor at start; waiting for it to lift')
                self.emit({'event': 'lift', 'msg': 'Lift your finger off the sensor first'})
                warned = True
            time.sleep(0.25)
        raise FPError('sensor is being touched; lift your finger')

    def wait_finger(self, timeout):
        """Wait for a finger that has fully landed: three consecutive frames above FINGER_ON whose
        contrast has stopped rising and that look alike. A finger still pressing down produces
        rising contrast and a smeared image; matching that is the usual cause of a missed first touch."""
        t0 = time.time()
        hist = []                                   # recent (frame, contrast) while touched
        while time.time() - t0 < timeout:
            f = self.grab()
            c = contrast(f, self.blank)
            if c > FINGER_ON:
                hist.append((f, c))
                hist = hist[-3:]
                if len(hist) == 3:
                    (f0, c0), (f1, c1), (f2, c2) = hist
                    settled = (abs(c2 - c1) < 0.08 * c2 and abs(c1 - c0) < 0.12 * c2
                               and contrast(f2, f1) < 0.25 * c2)
                    if settled:
                        avg = np.mean([f1, f2] + [self.grab() for _ in range(2)], axis=0)
                        return avg - self.blank
            else:
                hist = []
            time.sleep(0.03)
        return None

    def wait_lift(self, timeout=15):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if contrast(self.grab(), self.blank) < FINGER_OFF:
                return
            time.sleep(0.05)

    def probe(self, timeout):
        """Wait for a good-quality touch; returns features or None on timeout."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            diff = self.wait_finger(timeout - (time.time() - t0))
            if diff is None:
                log.info('no finger detected within %.0fs', timeout)
                return None
            cov = coverage(diff)
            if cov >= MIN_COVERAGE:
                ft = features(diff)
                if ft is not None:
                    return ft
                log.info('touch skipped: too few features (coverage %.2f)', cov)    # numbers only
            else:
                log.info('touch skipped: partial, coverage %.2f < %.2f', cov, MIN_COVERAGE)
            self.emit({'event': 'partial', 'coverage': round(cov, 2), 'msg': 'Partial touch - press flatter'})
            self.wait_lift()
        log.info('no usable touch within %.0fs', timeout)
        return None

    def enroll(self, samples=None, regions=REGIONS):
        samples = list(samples or [])
        if self.blank is None:
            self.take_blank(trusted=True)
        total = sum(r[2] for r in regions)
        done = 0
        for rid, label, count in regions:
            got = 0
            while got < count:
                self.emit({'event': 'place', 'region': rid, 'msg': label, 'step': got + 1, 'of': count,
                           'progress': done / total})
                diff = self.wait_finger(30)
                if diff is None:
                    raise FPError('timed out waiting for a finger')
                cov = coverage(diff)
                ft = features(diff) if cov >= MIN_COVERAGE else None
                if cov < MIN_COVERAGE:
                    self.emit({'event': 'partial', 'coverage': round(cov, 2), 'msg': 'Partial touch - press flatter'})
                elif ft is None or len(ft[0]) < MIN_KEYPOINTS:
                    self.emit({'event': 'rejected', 'msg': 'Not enough detail - press again'})
                else:
                    samples.append(ft)
                    got += 1
                    done += 1
                    ms = mosaic_stats(build_mosaic(samples))
                    self.emit({'event': 'accepted', 'region': rid, 'coverage': round(cov, 2),
                               'progress': done / total, 'pieces': ms['pieces'], 'largest': ms['largest']})
                self.emit({'event': 'lift', 'msg': 'Lift your finger'})
                self.wait_lift()
        return samples
