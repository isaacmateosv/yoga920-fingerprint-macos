"""Offline tests for yogafpd: protocol, authorization, rate limiting, crypto binding.
Uses a fake sensor that renders synthetic ridge patterns (no hardware, no biometric data) and a
throwaway Keychain service name.  Run:  python -I tests/test_daemon.py
"""
import os, sys, json, time, socket, tempfile, threading
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import numpy as np, cv2
from yogafp import core, daemon, cli

core.KC_SERVICE = 'yoga-fp-selftest-delete-me'
core.FINGER_ON, core.FINGER_OFF = 25.0, 8.0
core.MIN_KEYPOINTS = 15        # synthetic patterns yield ~20-47 keypoints; real fingers 166-300
core.THRESHOLD = 10            # synthetic genuine 10-16 vs impostor 6-8 (real-finger threshold is 15)


def pattern(seed, N=400):
    r = np.random.default_rng(seed)
    y, x = np.mgrid[0:N, 0:N].astype(np.float32)
    cx, cy = r.uniform(150, 250, 2)
    th = np.arctan2(y - cy, x - cx); rad = np.hypot(x - cx, y - cy)
    img = np.sin(rad / r.uniform(4.5, 6) + 3 * np.sin(th * r.integers(1, 3)) + 0.8 * np.sin(x / 37 + seed) * np.cos(y / 41))
    for _ in range(40):
        px, py = r.integers(0, N, 2); img[py:py + 4, px:px + 4] = r.uniform(-1, 1)
    return img * 40


class FakeSensor:
    """Each touch = N frames of a crop of `finger` pattern, separated by blank frames."""
    def __init__(self):
        self.ready = True
        self.rng = np.random.default_rng(3)
        self.base = self.rng.normal(130, 30, (112, 112)).astype(np.float32)
        self.queue = []                 # list of (pattern, dx, dy, angle)
        self.cur = None; self.frames_left = 0; self.gap = 3

    def present(self): return True
    def open(self): self.ready = True
    def ensure(self): pass
    def safe(self, fn, *a): return fn(*a)

    def touch(self, pat, dx=0, dy=0, ang=0):
        if not self.queue and self.frames_left == 0:
            self.gap = max(self.gap, 6)          # a person touches after the prompt, not mid-blank
        self.queue.append((pat, dx, dy, ang))

    def grab(self):
        noise = self.rng.normal(0, 2.0, (112, 112)).astype(np.float32)
        if self.frames_left > 0:
            self.frames_left -= 1
            return self.base + self.cur + noise
        if self.gap > 0 or not self.queue:
            self.gap -= 1
            return self.base + noise
        pat, dx, dy, ang = self.queue.pop(0)
        M = cv2.getRotationMatrix2D((200, 200), ang, 1.0); M[:, 2] += [dx, dy]
        self.cur = cv2.warpAffine(pat.astype(np.float32), M, (400, 400))[144:256, 144:256]
        self.frames_left = 8; self.gap = 3
        return self.base + self.cur + noise


def other_texture(seed, N=400):
    """Impostor: a smooth random ridge-like texture unrelated to pattern() (a different 'finger')."""
    r = np.random.default_rng(seed)
    f = cv2.GaussianBlur(r.normal(0, 1, (N, N)).astype(np.float32), (0, 0), 3.0)
    return 28.0 * f / (f.std() + 1e-6)          # same contrast as pattern() (std ~28)


A, B = pattern(7), other_texture(99)
ENROLL_POSES = [(0, 0, 0), (15, 0, 5), (-15, 5, -5), (0, 15, 8), (5, -15, -8), (20, 20, 0),
                (-20, -10, 3), (10, -5, -3), (8, 8, 2), (-8, 8, -2)]
SMALL_REGIONS = [('center', 'c', 5), ('upper_right', 'ur', 5)]

results = []
def check(name, cond):
    results.append((name, bool(cond))); print('  %-60s %s' % (name, 'PASS' if cond else 'FAIL'))


def run():
    tmp = tempfile.mkdtemp(prefix='yogafp-test-')
    store = core.Store(tmp, system_keychain=False)
    fs = FakeSensor()
    d = daemon.Daemon(store=store, sensor=fs)
    core.REGIONS[:] = SMALL_REGIONS
    me = os.getuid()
    events = []
    emit = events.append
    never = lambda: False

    def call(req, caller):
        try:
            return {'ok': True, **(d.handle(req, caller, emit, never) or {})}
        except core.FPError as e:
            return {'ok': False, 'error': str(e)}

    r = call({'op': 'status'}, me)
    check('status works for a user, not enrolled', r['ok'] and r['enrolled'] is False)
    r = call({'op': 'enroll'}, me)
    check('user cannot do first enrollment without a grant', not r['ok'] and 'administrator' in r['error'])
    r = call({'op': 'grant_enroll'}, me)
    check('user cannot grant themselves', not r['ok'])
    r = call({'op': 'status', 'uid': 0}, me)
    check('user cannot query another uid', not r['ok'])

    r = call({'op': 'grant_enroll', 'uid': me}, 0)
    check('root can grant enrollment', r['ok'])
    for p in ENROLL_POSES + ENROLL_POSES: fs.touch(A, *p)      # spares, like a user retrying partial touches
    r = call({'op': 'enroll'}, me)
    check('granted user enrolls (%s)' % (r.get('samples') or r.get('error')), r['ok'] and r['samples'] == 10)
    fs.queue.clear()
    check('template file is 0600', oct(os.stat(store.path(me)).st_mode & 0o777) == '0o600')
    check('enroll emitted region prompts', any(e.get('region') == 'upper_right' for e in events))
    check('no event carries pixel data', all(len(json.dumps(e)) < 400 for e in events))

    r = call({'op': 'enroll', }, me)          # no grant left, no finger -> must not succeed
    check('grant is single-use (re-enroll needs finger confirm)', not r['ok'])
    d.locked_until.clear(); d.fails.clear()

    fs.touch(A, 7, 3, 2)
    r = call({'op': 'verify'}, me)
    check('genuine verify matches (%s)' % r, r['ok'] and r['match'])
    fs.touch(B, 0, 0, 0); fs.grab(); fs.frames_left = 200       # finger resting when verify starts
    fs.touch(A, -6, 4, 3)
    import threading as _t
    tm = _t.Timer(1.0, lambda: setattr(fs, 'frames_left', 0)); tm.start()  # user lifts after 1 s
    r = call({'op': 'verify'}, me)
    check('resting finger at start is not taken as blank (%s)' % r, r['ok'] and r['match'])
    tm.cancel(); tm.join(); fs.frames_left = 0; fs.queue.clear(); fs.gap = 0
    fs.touch(B, 0, 0, 0); fs.touch(B, 10, 5, 3); fs.touch(B, -8, 12, -4)
    r = call({'op': 'verify', 'tries': 3}, me)
    check('impostor verify rejected after 3 tries (%s)' % r, r['ok'] and not r['match'] and r['reason'] == 'nomatch')

    r = call({'op': 'verify', 'uid': me}, 0)    # root (PAM) verifying for a uid: needs touches
    fs.queue.clear()
    for _ in range(2): fs.touch(B, 0, 0, 0)
    r = call({'op': 'verify', 'uid': me, 'tries': 2, 'timeout': 2}, 0)
    check('5 failures in window -> locked out', d.rate_limited(me))
    r = call({'op': 'verify', 'uid': me}, 0)
    check('locked-out uid is refused', not r['ok'] and 'too many' in r['error'])
    d.locked_until.clear(); d.fails.clear(); fs.queue.clear()

    # PAM-style verify (root, service=sudo) mirrored to the user's watcher; user may cancel
    import threading as _th
    got, other_got = [], []
    stop = {'v': False}
    def watcher(caller, sink):
        try: d.handle({'op': 'watch'}, caller, sink.append, lambda: stop['v'])
        except core.FPError: pass
    w1 = _th.Thread(target=watcher, args=(me, got)); w1.start()
    w2 = _th.Thread(target=watcher, args=(me + 7, other_got)); w2.start()
    time.sleep(0.3)
    fs.queue.clear(); fs.frames_left = 0; fs.gap = 0; fs.touch(A, 5, 5, 1)
    r = call({'op': 'verify', 'uid': me, 'service': 'sudo'}, 0)
    check('PAM verify for sudo matches (%s)' % r, r['ok'] and r['match'])
    kinds = [e.get('event') for e in got]
    check('watcher saw auth_start..matched..auth_end %s' % kinds, kinds[:2] == ['watching', 'auth_start'] and 'matched' in kinds and kinds[-1] == 'auth_end')
    check('other user\'s watcher saw nothing of it', [e.get('event') for e in other_got] == ['watching'])
    # cancel: start a PAM verify with no finger, cancel from the user after 1 s
    fs.queue.clear()
    res = {}
    t = _th.Thread(target=lambda: res.update(call({'op': 'verify', 'uid': me, 'service': 'sudo', 'timeout': 8}, 0)))
    t.start(); time.sleep(1.0)
    r_other = call({'op': 'cancel_auth'}, me + 7)
    r_me = call({'op': 'cancel_auth'}, me)
    t.join(10)
    check('another user cannot cancel', r_other['ok'] and not r_other['cancelled'])
    check('user cancel ends sudo verify -> password (%s)' % res.get('error'), not res.get('ok') and 'password' in res.get('error', ''))
    stop['v'] = True; w1.join(2); w2.join(2)
    d.locked_until.clear(); d.fails.clear()

    # threshold config: root only, bounded, read live
    r = call({'op': 'set_threshold', 'threshold': 20}, me)
    check('user cannot change the threshold', not r['ok'])
    r = call({'op': 'set_threshold', 'threshold': 5}, 0)
    check('threshold below minimum is rejected', not r['ok'])
    r = call({'op': 'set_threshold', 'threshold': 22}, 0)
    st = call({'op': 'status'}, me)
    check('root sets threshold; status reports it (%s)' % st.get('threshold'), r['ok'] and st['threshold'] == 22)
    check('config.json is 0600', oct(os.stat(d.config_path()).st_mode & 0o777) == '0o600')
    r = call({'op': 'set_threshold', 'method': 'mosaic', 'threshold': 9}, 0)
    check('mosaic method accepts threshold 9 (%s)' % r, r['ok'] and call({'op': 'status'}, me)['threshold'] == 9)
    r = call({'op': 'set_threshold', 'method': 'best'}, 0)
    check('switching back to best raises threshold to its floor', r['ok'] and r['threshold'] == core.THRESHOLD_MIN['best'])
    os.remove(d.config_path())
    check('default threshold when no config', call({'op': 'status'}, me)['threshold'] == core.THRESHOLD)

    # adaptive enrollment (thresholds scaled for synthetic patterns)
    fs.queue.clear(); fs.frames_left = 0; fs.gap = 0; d.locked_until.clear(); d.fails.clear()
    s0, ne0 = store.load_full(me)
    saved = (core.ADAPT_FACTOR, core.ADAPT_NOVEL_MAX, core.ADAPT_MAX_LEARNED)
    core.ADAPT_FACTOR, core.ADAPT_NOVEL_MAX, core.ADAPT_MAX_LEARNED = 1.0, 10.0, 2
    fs.touch(A, 9, -4, 4)
    r = call({'op': 'verify'}, me)
    s1, ne1 = store.load_full(me)
    check('strong match teaches the template (%d -> %d, guided %d)' % (len(s0), len(s1), ne1),
          r['match'] and len(s1) == len(s0) + 1 and ne1 == ne0)
    fs.touch(B, 0, 0, 0); fs.touch(B, 4, 4, 0); fs.touch(B, -4, 3, 0)
    call({'op': 'verify'}, me)
    check('other finger never teaches the template', len(store.load(me)) == len(s1))
    d.locked_until.clear(); d.fails.clear()
    fs.touch(A, -7, 6, -3)
    call({'op': 'test', 'tries': 1}, me)
    check('test runs never teach the template', len(store.load(me)) == len(s1))
    for p in [(3, 9, 2), (-9, -3, 5), (6, 6, -4)]:
        fs.touch(A, *p); call({'op': 'verify'}, me)
    s2, ne2 = store.load_full(me)
    check('learned samples capped, guided preserved (%d total, guided %d)' % (len(s2), ne2),
          ne2 == ne0 and len(s2) <= ne0 + core.ADAPT_MAX_LEARNED and
          all(np.array_equal(a[0], b[0]) for a, b in zip(s2[:ne0], s0[:ne0])))
    core.ADAPT_FACTOR = 100.0
    n_before = len(store.load(me)); fs.touch(A, 2, 2, 1); call({'op': 'verify'}, me)
    check('ordinary (non-certain) match does not teach', len(store.load(me)) == n_before)
    core.ADAPT_FACTOR, core.ADAPT_NOVEL_MAX, core.ADAPT_MAX_LEARNED = saved
    store.save(me, s0[:ne0], n_enrolled=ne0)
    # legacy file without n_enrolled still loads (all samples count as guided)
    import io as _io
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _G
    buf = _io.BytesIO(); np.savez(buf, kp0=s0[0][0], de0=s0[0][1]); n_ = os.urandom(12)
    open(store.path(other := me + 3), 'wb').write(n_ + _G(store.key()).encrypt(n_, buf.getvalue(), core.AAD + b':%d' % other))
    ls, lne = store.load_full(other)
    check('legacy template (no n_enrolled) loads', len(ls) == 1 and lne == 1)
    os.remove(store.path(other))

    # one-time match proofs for the authorization plugin (nonce)
    fs.queue.clear(); fs.frames_left = 0; fs.gap = 0; d.locked_until.clear(); d.fails.clear()
    nonce = os.urandom(16).hex()
    fs.touch(A, 6, -2, 2)
    r = call({'op': 'verify', 'nonce': nonce}, me)
    check('user verify with nonce matches (%s)' % r.get('reason'), r['ok'] and r['match'])
    r = call({'op': 'consume_match', 'nonce': nonce, 'uid': me}, me)
    check('non-root cannot consume a match proof', not r['ok'])
    r = call({'op': 'consume_match', 'nonce': nonce, 'uid': me + 1}, 0)
    check('match proof for the wrong uid is rejected', r['ok'] and not r['valid'])
    fs.queue.clear(); fs.frames_left = 0; fs.gap = 0
    fs.touch(A, 6, -2, 2); n2 = os.urandom(16).hex()
    rv = call({'op': 'verify', 'nonce': n2}, me)
    r = call({'op': 'consume_match', 'nonce': n2, 'uid': me}, 0)
    check('root consumes a real match proof once (verify: %s)' % rv.get('reason'), rv.get('match') and r['ok'] and r['valid'])
    r = call({'op': 'consume_match', 'nonce': n2, 'uid': me}, 0)
    check('a match proof cannot be reused', r['ok'] and not r['valid'])
    n3 = os.urandom(16).hex(); d.record_match(n3, me); d.matches[n3] = (me, time.time() - 120)
    r = call({'op': 'consume_match', 'nonce': n3, 'uid': me}, 0)
    check('an expired match proof is rejected', r['ok'] and not r['valid'])
    r = call({'op': 'verify', 'nonce': 'not-hex!'}, me)
    check('malformed nonce is refused', not r['ok'])
    fs.touch(B, 0, 0, 0); fs.touch(B, 4, 4, 0); fs.touch(B, -4, 3, 0); n4 = os.urandom(16).hex()
    call({'op': 'verify', 'nonce': n4}, me)
    check('no proof is recorded for a failed verify', n4 not in d.matches)
    d.locked_until.clear(); d.fails.clear(); fs.queue.clear()

    # cross-uid template swap must fail authentication
    other = me + 1
    os.makedirs(os.path.dirname(store.path(other)), exist_ok=True)
    open(store.path(other), 'wb').write(open(store.path(me), 'rb').read())
    try:
        store.load(other); swapped = False
    except core.FPError:
        swapped = True
    check('template copied to another uid fails authentication', swapped)
    os.remove(store.path(other))

    # busy lock
    d.lock.acquire()
    r = call({'op': 'verify'}, me)
    check('concurrent sensor op is refused as busy', not r['ok'] and 'busy' in r['error'])
    d.lock.release()

    # delete requires finger confirmation for a user
    fs.touch(B, 0, 0, 0); fs.touch(B, 3, 3, 0); fs.touch(B, -3, 2, 0)
    r = call({'op': 'delete'}, me)
    check('user delete refused without matching finger (%s, enrolled=%s)' % (r, store.enrolled(me)), not r['ok'] and store.enrolled(me))
    d.locked_until.clear(); d.fails.clear(); fs.queue.clear()
    fs.touch(A, 4, -6, 3)
    r = call({'op': 'delete'}, me)
    check('user delete allowed after matching finger (%s)' % r, r['ok'] and not store.enrolled(me))

    # end-to-end over a real UNIX socket with kernel peer credentials
    sock = os.path.join(tmp, 's.sock')
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); srv.bind(sock); srv.listen(2)
    def loop():
        while True:
            try: c, _ = srv.accept()
            except OSError: return
            threading.Thread(target=d.serve_conn, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    cli.SOCK = sock
    res = cli.call({'op': 'status'})
    check('socket round-trip; daemon sees our real uid', res['ok'] and res['uid'] == me)
    res = cli.call({'op': 'status', 'uid': 0})
    check('socket: spoofed uid in request is rejected', not res['ok'])
    srv.close()

    # a finger that lands gradually must be captured only once fully pressed
    class Ramp(FakeSensor):
        def __init__(self):
            super().__init__(); self.seq = [0] * 6 + [0.3, 0.5, 0.7, 0.85, 0.95] + [1.0] * 10 + [0] * 5; self.k = 0
            yy, xx = np.mgrid[0:112, 0:112]; self.fp = (40 * np.sin(xx / 3.0 + yy / 7.0)).astype(np.float32)
        def grab(self):
            a = self.seq[min(self.k, len(self.seq) - 1)]; self.k += 1
            return self.base + a * self.fp + self.rng.normal(0, 2, (112, 112)).astype(np.float32)
    rs = Ramp(); cp = core.Capture(rs, lambda e: None); cp.take_blank()
    dd = cp.wait_finger(5)
    check('landing finger captured only when fully pressed', dd is not None and np.std(dd) / np.std(rs.fp) > 0.95)

    store.delete_key()
    print('\n%d/%d passed' % (sum(ok for _, ok in results), len(results)))
    return all(ok for _, ok in results)


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
