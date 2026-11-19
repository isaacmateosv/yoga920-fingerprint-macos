"""yogafp - command-line client for yogafpd.

  yogafp status
  yogafp verify
  yogafp enroll                 first time: run `sudo yogafp grant-enroll` first (or run enroll with sudo)
  yogafp add [count]            add touches for an area that is often not recognized (--finger NAME)
  yogafp fingers                list your enrolled fingers
  yogafp add-finger NAME        enroll another finger, e.g. "Left index" (max 3; confirm with an enrolled one)
  yogafp remove-finger NAME     remove one finger (confirm with an enrolled finger)
  yogafp test [tries]           print match scores (threshold tuning)
  yogafp delete                 delete your fingerprint data (confirms with your finger first)
  sudo yogafp grant-enroll [--uid N]   allow the invoking user (or uid N) to enroll for 5 minutes
  sudo yogafp setup             pair the sensor, load firmware, calibrate
  sudo yogafp set-threshold N   match threshold (default 12, minimum 10); use `yogafp test` to choose
  sudo yogafp set-method M [N]  best (per-touch) or mosaic (assembled template), optionally with threshold N
Only numbers and prompts are ever printed; no image data leaves the daemon.
"""
import os, sys, json, socket

SOCK = os.environ.get('YOGAFP_SOCKET', '/var/run/yogafpd.sock')


def call(req, on_event=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(SOCK)
    except OSError as e:
        sys.exit('yogafpd is not running (%s). Is yoga-fp installed?' % e.strerror)
    f = s.makefile('rwb', buffering=0)
    f.write((json.dumps(req) + '\n').encode())
    for line in f:
        msg = json.loads(line)
        if msg.get('done'):
            return msg
        if on_event:
            on_event(msg)
    return {'done': True, 'ok': False, 'error': 'connection closed'}


def show(ev):
    e = ev.get('event')
    if e == 'place':
        extra = ''
        if 'step' in ev:
            extra = '  [%d/%d, %d%% total]' % (ev['step'], ev['of'], ev.get('progress', 0) * 100)
        elif 'try' in ev and 'of' in ev:
            extra = '  (try %d/%d)' % (ev['try'], ev['of'])
        print('  > %s%s' % (ev.get('msg', ''), extra), flush=True)
    elif e == 'accepted':
        extra = ''
        if 'pieces' in ev:
            extra = ', assembled into %d piece%s (largest: %d touches)' % (
                ev['pieces'], '' if ev['pieces'] == 1 else 's', ev['largest'])
        print('    ok (coverage %d%%%s)' % (ev.get('coverage', 0) * 100, extra), flush=True)
    elif e == 'score':
        print('    try %2d: per-touch %3d  top %-14s  assembled %3d   %s' % (
            ev['try'], ev['score'], ev['top'], ev.get('mosaic', 0), 'MATCH' if ev['match'] else '-'), flush=True)
    elif e in ('partial', 'rejected', 'nomatch', 'status', 'matched'):
        print('    %s' % (ev.get('msg') or e), flush=True)


def target_uid():
    # Under sudo, act for the invoking user rather than root.
    if os.geteuid() == 0 and os.environ.get('SUDO_UID'):
        return int(os.environ['SUDO_UID'])
    return os.getuid()


def main(argv=None):
    a = list(argv if argv is not None else sys.argv[1:]) or ['status']
    uid_opt = None
    if '--uid' in a:                       # root only: e.g. the menu bar app's admin-prompted grant
        i = a.index('--uid'); uid_opt = int(a[i + 1]); del a[i:i + 2]
    finger = None
    if '--finger' in a:
        i = a.index('--finger'); finger = a[i + 1]; del a[i:i + 2]
    cmd, rest = a[0], a[1:]
    req = {'op': 'status' if cmd == 'fingers' else cmd.replace('-', '_')}
    if cmd in ('add-finger', 'remove-finger'):
        if not rest:
            sys.exit('usage: yogafp %s "Finger name"' % cmd)
        finger = ' '.join(rest)
        if cmd == 'remove-finger' and input('Remove the finger %r? [y/N] ' % finger).strip().lower() != 'y':
            return 1
    if finger:
        req['finger'] = finger
    if os.geteuid() == 0:
        req['uid'] = uid_opt if uid_opt is not None else target_uid()
    elif uid_opt is not None and uid_opt != os.getuid():
        sys.exit('--uid for another user requires root')
    if cmd == 'add' and rest:
        req['count'] = int(rest[0])
    if cmd == 'test' and rest:
        req['tries'] = int(rest[0])
    if cmd == 'set-method':      # usage: sudo yogafp set-method best|mosaic [threshold]
        if not rest:
            sys.exit('usage: sudo yogafp set-method best|mosaic [threshold]')
        req = {'op': 'set_threshold', 'method': rest[0], **({'uid': req['uid']} if 'uid' in req else {})}
        if len(rest) > 1:
            req['threshold'] = int(rest[1])
    if cmd == 'set-threshold':
        if not rest:
            sys.exit('usage: sudo yogafp set-threshold N')
        req['threshold'] = int(rest[0])
    if cmd == 'delete':
        if input('Delete your enrolled fingerprints? [y/N] ').strip().lower() != 'y':
            return 1
    if cmd in ('-h', '--help', 'help'):
        print(__doc__)
        return 0
    res = call(req, show)
    if not res.get('ok'):
        print('error: %s' % res.get('error'), file=sys.stderr)
        return 1
    out = {k: v for k, v in res.items() if k not in ('done', 'ok')}
    if cmd == 'fingers':
        names = res.get('fingers') or []
        print('\n'.join('  %d. %s' % (i + 1, n) for i, n in enumerate(names)) if names else 'no fingers enrolled')
        return 0
    if cmd == 'verify':
        print('MATCH' if res.get('match') else 'NO MATCH (%s)' % res.get('reason'))
        return 0 if res.get('match') else 2
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
