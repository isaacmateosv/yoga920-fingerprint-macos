"""yogafpd - root fingerprint service for the Synaptics 06cb:0081 (Lenovo Yoga 920) on macOS.

Protocol: JSON lines over a UNIX socket. The client sends one request line; the daemon streams
event lines and finishes with {"done": true, "ok": bool, ...}. Closing the socket cancels.

Authorization (caller identity comes from the kernel via LOCAL_PEERCRED, never from the request):
  status                      anyone
  verify                      own uid; root may name any uid (the sudo PAM module runs as root)
  enroll / add / delete       root (for any uid), or a user for their own uid when either
                                - root granted an enrollment window (grant_enroll), or
                                - they first pass a fingerprint verify in the same request
  grant_enroll, setup         root only
  watch                       a user gets live events of PAM authentications for their own uid
                              (the menu bar app shows a "touch the sensor / use password" panel)
  cancel_auth                 the target user (or root) can cancel a running PAM verify -> password
                              (cancel only ever denies; it can never approve)
Failed verifies are rate limited per uid.
"""
import os, re, sys, json, time, socket, struct, threading, logging, signal

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))                                  # yogafp package
sys.path.insert(0, os.environ.get('YOGAFP_VALIDITY_SRC', os.path.join(os.path.dirname(HERE), 'vendor')))

from yogafp import core

SOCK = os.environ.get('YOGAFP_SOCKET', '/var/run/yogafpd.sock')
DATA = os.environ.get('YOGAFP_DATA', '/Library/Application Support/yoga-fp')
VERSION = '0.1.0'

GRANT_SECONDS = 300
FAIL_WINDOW, FAIL_MAX, LOCKOUT = 120, 5, 60

log = logging.getLogger('yogafpd')

SOL_LOCAL, LOCAL_PEERCRED, LOCAL_PEERPID = 0, 1, 2


def peer_uid(conn):
    raw = conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 4 + 4 + 2 + 2 + 16 * 4)
    version, uid = struct.unpack_from('<II', raw)
    return uid


def peer_pid(conn):
    try:
        return struct.unpack('<i', conn.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0]
    except OSError:
        return -1


class Daemon:
    def __init__(self, store=None, sensor=None):
        self.store = store or core.Store(DATA)
        self.sensor = sensor
        self.lock = threading.Lock()
        self.grants = {}           # uid -> expiry
        self.fails = {}            # uid -> [timestamps]
        self.locked_until = {}
        self.watchers = {}         # id -> (uid, emit)
        self.wlock = threading.Lock()
        self.auth = None           # running PAM verify: {'uid', 'service', 'cancel': Event}
        self._mosaics = {}         # uid -> (template mtime, clusters)
        self.matches = {}          # one-time nonce -> (uid, time): proof of a real match for the auth plugin
        self.mlock = threading.Lock()

    MATCH_TTL = 60

    def record_match(self, nonce, uid):
        if not nonce:
            return
        with self.mlock:
            now = time.time()
            for k in [k for k, (_, t) in self.matches.items() if now - t > self.MATCH_TTL]:
                del self.matches[k]
            self.matches[nonce] = (uid, now)

    def broadcast(self, uid, obj):
        with self.wlock:
            targets = [e for (u, e) in self.watchers.values() if u == uid or u == 0]
        for e in targets:
            e(obj)

    # ------------------------------------------------------------ helpers
    def config_path(self):
        return os.path.join(self.store.root, 'config.json')

    def _config(self):
        p = self.config_path()
        try:
            st = os.stat(p)
        except FileNotFoundError:
            return {}
        if st.st_uid != 0 and os.geteuid() == 0:
            log.warning('ignoring %s: not owned by root', p)
            return {}
        try:
            return json.load(open(p))
        except Exception as e:
            log.warning('bad config.json (%s)', e)
            return {}

    def method(self):
        m = self._config().get('method', 'best')
        return m if m in ('best', 'mosaic') else 'best'

    def mosaic(self, uid, samples):
        """Assembled template, cached until the enrollment file changes."""
        key = os.path.getmtime(self.store.path(uid))
        c = self._mosaics.get(uid)
        if c and c[0] == key:
            return c[1]
        m = core.build_mosaic(samples)
        self._mosaics[uid] = (key, m)
        log.info('assembled template uid=%d: %s', uid, core.mosaic_stats(m))
        return m

    def scores(self, uid, ft, samples):
        best, top = core.score(ft, samples)
        mos = core.score_mosaic(ft, self.mosaic(uid, samples))
        return best, top, mos

    def threshold(self):
        """Root-only config (<data>/config.json, {"threshold": N}); read on every verify, no restart needed."""
        try:
            p = self.config_path()
            st = os.stat(p)
            if st.st_uid != 0 and os.geteuid() == 0:
                log.warning('ignoring %s: not owned by root', p)
                return core.THRESHOLD
            t = int(json.load(open(p)).get('threshold', core.THRESHOLD))
            return max(core.THRESHOLD_MIN[self.method()], min(60, t))
        except FileNotFoundError:
            return core.THRESHOLD
        except Exception as e:
            log.warning('bad config.json (%s); using default threshold', e)
            return core.THRESHOLD

    def get_sensor(self):
        if self.sensor is None:
            self.sensor = core.Sensor()
        return self.sensor

    def rate_limited(self, uid):
        return time.time() < self.locked_until.get(uid, 0)

    def note_result(self, uid, ok):
        if ok:
            self.fails.pop(uid, None)
            return
        now = time.time()
        f = [t for t in self.fails.get(uid, []) if now - t < FAIL_WINDOW] + [now]
        self.fails[uid] = f
        if len(f) >= FAIL_MAX:
            self.locked_until[uid] = now + LOCKOUT
            self.fails[uid] = []
            log.warning('uid %d locked out for %ds after %d failed verifies', uid, LOCKOUT, FAIL_MAX)

    def adapt(self, uid, ft, score_):
        """Add a certain match that covers new area to the template (encrypted), within the caps."""
        try:
            samples, ne = self.store.load_full(uid)
            if score_ >= core.ADAPT_NOVEL_MAX * len(ft[0]):
                return                                    # mostly a repeat of something already enrolled
            learned = samples[ne:] + [ft]
            if len(learned) > core.ADAPT_MAX_LEARNED:
                learned = learned[-core.ADAPT_MAX_LEARNED:]
            self.store.save(uid, samples[:ne] + learned, n_enrolled=ne)
            log.info('template learned a new area uid=%d (guided %d + learned %d)', uid, ne, len(learned))
        except Exception as e:
            log.warning('template adaptation skipped: %s', e)

    def do_verify(self, uid, cap, tries, timeout, learn=True):
        if self.rate_limited(uid):
            raise core.FPError('too many failed attempts; try again in a minute')
        samples = self.store.load(uid)
        thr, method = self.threshold(), self.method()
        cap.take_blank()
        for i in range(tries):
            cap.emit({'event': 'place', 'msg': 'Touch the fingerprint sensor', 'try': i + 1, 'of': tries})
            ft = cap.probe(timeout)
            if ft is None:
                return False, 'timeout'
            best, _, mos = self.scores(uid, ft, samples)
            used = mos if method == 'mosaic' else best
            ok = used >= thr
            log.info('verify uid=%d try=%d/%d method=%s best=%d mosaic=%d threshold=%d keypoints=%d %s', uid,
                     i + 1, tries, method, best, mos, thr, len(ft[0]), 'MATCH' if ok else 'no-match')  # numbers only
            self.note_result(uid, ok)
            if ok:
                cap.emit({'event': 'matched'})
                if learn and used >= core.ADAPT_FACTOR * thr:
                    self.adapt(uid, ft, best)
                return True, 'match'
            cap.emit({'event': 'nomatch', 'msg': 'Not recognized - try again'})
            if self.rate_limited(uid):
                return False, 'locked'
            cap.wait_lift()
        return False, 'nomatch'

    # ------------------------------------------------------------ request handling
    def handle(self, req, caller, emit, cancelled):
        op = req.get('op')
        is_root = caller == 0
        uid = int(req.get('uid', caller)) if is_root else caller
        if not is_root and 'uid' in req and int(req['uid']) != caller:
            raise core.FPError('not allowed to act for another user')

        if op == 'status':
            s = self.sensor
            return {'version': VERSION, 'uid': uid, 'enrolled': self.store.enrolled(uid), 'threshold': self.threshold(),
                    'method': self.method(),
                    'sensor_present': (s.present() if s else None), 'sensor_ready': bool(s and s.ready),
                    'grant': self.grants.get(uid, 0) > time.time()}

        if op == 'watch':
            wid = object()
            with self.wlock:
                self.watchers[wid] = (uid, emit)
            try:
                emit({'event': 'watching'})
                while not cancelled():
                    time.sleep(0.5)
            finally:
                with self.wlock:
                    self.watchers.pop(wid, None)
            return {}

        if op == 'cancel_auth':
            a = self.auth
            if a and (is_root or a['uid'] == caller):
                a['cancel'].set()
                return {'cancelled': True}
            return {'cancelled': False}

        if op == 'set_threshold':
            if not is_root:
                raise core.FPError('root only')
            cfg = dict(self._config())
            if 'method' in req:
                if req['method'] not in ('best', 'mosaic'):
                    raise core.FPError('method must be best or mosaic')
                cfg['method'] = req['method']
            m = cfg.get('method', 'best')
            if 'threshold' in req:
                t = int(req['threshold'])
                if not core.THRESHOLD_MIN[m] <= t <= 60:
                    raise core.FPError('threshold for %s must be between %d and 60' % (m, core.THRESHOLD_MIN[m]))
                cfg['threshold'] = t
            elif 'threshold' in cfg and cfg['threshold'] < core.THRESHOLD_MIN[m]:
                cfg['threshold'] = core.THRESHOLD_MIN[m]     # switching method never leaves an unsafe threshold
            tmp = self.config_path() + '.tmp'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(cfg, f)
            os.replace(tmp, self.config_path())
            log.info('config set: %s', cfg)
            return cfg

        if op == 'consume_match':      # the auth plugin's root step: was there a real match for this nonce+uid?
            if not is_root:
                raise core.FPError('root only')
            nonce = str(req.get('nonce', ''))
            with self.mlock:
                entry = self.matches.pop(nonce, None)
            ok = bool(entry and entry[0] == uid and time.time() - entry[1] <= self.MATCH_TTL)
            log.info('consume_match uid=%d %s', uid, 'ok' if ok else 'rejected')
            return {'valid': ok}

        if op == 'grant_enroll':
            if not is_root:
                raise core.FPError('root only')
            self.grants[uid] = time.time() + GRANT_SECONDS
            return {'granted_until': self.grants[uid]}

        if op not in ('verify', 'enroll', 'add', 'delete', 'setup', 'test'):
            raise core.FPError('unknown op')

        if not self.lock.acquire(blocking=False):
            raise core.FPError('busy: another fingerprint operation is in progress')
        try:
            sensor = self.get_sensor()
            cap = core.Capture(sensor, emit, cancelled, ref_path=os.path.join(self.store.root, 'blank-ref.npy'))

            if op == 'setup':
                if not is_root:
                    raise core.FPError('root only')
                if sensor.ready and not req.get('force'):
                    # Already open: re-initializing a live session makes this sensor reboot (and drop off USB).
                    return {'sensor_ready': True, 'note': 'already open'}
                emit({'event': 'status', 'msg': 'Pairing / loading firmware / calibrating (may reboot the sensor)'})
                sensor.open()
                return {'sensor_ready': True}

            if op == 'verify':
                tries, tmo = int(req.get('tries', 3)), float(req.get('timeout', 10))
                service = str(req.get('service', ''))[:32] if is_root else ''
                nonce = str(req.get('nonce', ''))
                if nonce and not re.fullmatch(r'[0-9a-f]{32,64}', nonce):
                    raise core.FPError('bad nonce')
                if not service:
                    ok, why = self.do_verify(uid, cap, tries, tmo)
                    if ok:
                        self.record_match(nonce, uid)
                    return {'match': ok, 'reason': why}
                # PAM authentication (e.g. sudo): mirror progress to the user's menu bar app, allow cancel.
                cancel = threading.Event()
                self.auth = {'uid': uid, 'service': service, 'cancel': cancel}

                def emit2(ev):
                    emit(ev)
                    self.broadcast(uid, {**ev, 'auth': service})
                cap2 = core.Capture(sensor, emit2, lambda: cancelled() or cancel.is_set(),
                                    ref_path=os.path.join(self.store.root, 'blank-ref.npy'))
                self.broadcast(uid, {'event': 'auth_start', 'auth': service})
                result = 'error'
                try:
                    ok, why = self.do_verify(uid, cap2, tries, tmo)
                    result = 'match' if ok else why
                    if ok:
                        self.record_match(nonce, uid)
                    return {'match': ok, 'reason': why}
                except core.FPError as e:
                    result = 'cancelled' if cancel.is_set() else 'error'
                    if cancel.is_set():
                        raise core.FPError('cancelled: use your password')
                    raise
                finally:
                    self.auth = None
                    self.broadcast(uid, {'event': 'auth_end', 'auth': service, 'result': result})

            if op == 'test':           # diagnostic scores for threshold tuning; own uid only for non-root
                samples = self.store.load(uid)
                thr, method = self.threshold(), self.method()
                emit({'event': 'status', 'msg': 'assembled template: %s' % core.mosaic_stats(self.mosaic(uid, samples))})
                cap.take_blank()
                scores = []
                for i in range(int(req.get('tries', 10))):
                    emit({'event': 'place', 'msg': 'Touch the sensor', 'try': i + 1})
                    ft = cap.probe(20)
                    if ft is None:
                        break
                    best, top, mos = self.scores(uid, ft, samples)
                    used = mos if method == 'mosaic' else best
                    scores.append({'best': best, 'mosaic': mos})
                    emit({'event': 'score', 'try': i + 1, 'score': best, 'top': top, 'mosaic': mos,
                          'match': used >= thr})
                    cap.wait_lift()
                return {'scores': scores, 'threshold': thr, 'method': method}

            # enroll / add / delete: authorize
            if not is_root:
                granted = self.grants.get(uid, 0) > time.time()
                if not granted:
                    if not self.store.enrolled(uid):
                        raise core.FPError('first enrollment needs an administrator: run `sudo yogafp grant-enroll`')
                    emit({'event': 'status', 'msg': 'Confirm with an enrolled finger first'})
                    ok, why = self.do_verify(uid, cap, 3, 10, learn=False)
                    if not ok:
                        raise core.FPError('fingerprint not confirmed (%s)' % why)
                    cap.wait_lift()
                self.grants.pop(uid, None)          # a grant is single-use

            if op == 'delete':
                self.store.delete(uid)
                return {'deleted': True}

            cap.take_blank(trusted=(op == 'enroll'))
            base = self.store.load(uid) if op == 'add' else []
            if op == 'add':
                regions = [('extra', req.get('label', 'Touch the area that is often not recognized'),
                            int(req.get('count', 5)))]
            else:
                regions = core.REGIONS
            samples = cap.enroll(base, regions)
            if op == 'add':
                _, ne = self.store.load_full(uid)
                guided = base[:ne] + samples[len(base):]          # 'add' touches count as guided
                self.store.save(uid, guided + base[ne:], n_enrolled=len(guided))
            else:
                self.store.save(uid, samples)                     # fresh enrollment: all guided, nothing learned
            return {'samples': len(samples)}
        finally:
            self.lock.release()

    def serve_conn(self, conn):
        caller = peer_uid(conn)
        pid = peer_pid(conn)
        closed = {'v': False}
        f = conn.makefile('rwb', buffering=0)

        def emit(obj):
            try:
                f.write((json.dumps(obj) + '\n').encode())
            except OSError:
                closed['v'] = True

        def cancelled():
            if closed['v']:
                return True
            try:
                conn.setblocking(False)
                try:
                    d = conn.recv(1, socket.MSG_PEEK)
                    if d == b'':
                        closed['v'] = True
                except BlockingIOError:
                    pass
                finally:
                    conn.setblocking(True)
            except OSError:
                closed['v'] = True
            return closed['v']

        try:
            line = f.readline(4096)
            req = json.loads(line or b'{}')
            quiet = req.get('op') in ('status', 'watch', 'cancel_auth')
            (log.debug if quiet else log.info)('request op=%s caller_uid=%d pid=%d', req.get('op'), caller, pid)
            res = self.handle(req, caller, emit, cancelled)
            emit({'done': True, 'ok': True, **(res or {})})
            (log.debug if quiet else log.info)('done op=%s ok', req.get('op'))
        except core.FPError as e:
            emit({'done': True, 'ok': False, 'error': str(e)})
            log.info('done error: %s', e)
        except Exception as e:
            log.exception('internal error')
            emit({'done': True, 'ok': False, 'error': 'internal error: %s' % type(e).__name__})
        finally:
            try:
                conn.close()
            except OSError:
                pass


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    if os.geteuid() != 0 and not os.environ.get('YOGAFP_DEV'):
        sys.exit('yogafpd must run as root (set YOGAFP_DEV=1 for development)')
    os.makedirs(DATA, mode=0o700, exist_ok=True)
    os.environ.setdefault('YOGAFP_VALIDITY_DIR', os.path.join(DATA, 'validity'))
    d = Daemon()
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o111)
    srv.bind(SOCK)                     # 0666: any local user may connect; identity is checked per request
    os.umask(old)
    srv.listen(8)
    signal.signal(signal.SIGTERM, lambda *a: (srv.close(), sys.exit(0)))
    log.info('yogafpd %s listening on %s', VERSION, SOCK)
    try:
        d.get_sensor().open()
        log.info('sensor ready')
    except Exception as e:
        log.warning('sensor not ready yet: %s', e)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=d.serve_conn, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    main()
