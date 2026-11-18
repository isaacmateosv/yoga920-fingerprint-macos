"""Collect a labeled, encrypted fingerprint dataset for matcher tuning. Developer tool.

The installed service owns the sensor, so stop it first and restart it afterwards:
    sudo launchctl bootout system/com.yogafp.yogafpd
    <dev venv>/bin/python -I devtools/collect.py enroll       # 31 guided touches (same regions as enrollment)
    <dev venv>/bin/python -I devtools/collect.py genuine 30   # your enrolled finger, natural touches
    <dev venv>/bin/python -I devtools/collect.py other 30     # other fingers
    sudo launchctl bootstrap system /Library/LaunchDaemons/com.yogafp.yogafpd.plist
    <dev venv>/bin/python -I devtools/collect.py --summary | --delete

Prints only counts and coverage percentages. Images are encrypted before touching the disk.
"""
import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'vendor'))
os.environ.setdefault('YOGAFP_VALIDITY_DIR', os.path.join(ROOT, 'run-data'))   # git-ignored
import dataset


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__); return 1
    if a[0] == '--summary':
        print(dataset.summary() or 'no dataset'); return 0
    if a[0] == '--delete':
        print('deleted %d dataset files and the dataset key' % dataset.delete_all()); return 0
    label = a[0]
    if label not in ('enroll', 'genuine', 'other'):
        sys.exit('label must be enroll, genuine or other')
    if os.path.exists('/var/run/yogafpd.sock'):
        import socket
        s = socket.socket(socket.AF_UNIX)
        try:
            s.connect('/var/run/yogafpd.sock')
            sys.exit('the yoga-fp service is running and owns the sensor; stop it first:\n'
                     '  sudo launchctl bootout system/com.yogafp.yogafpd')
        except OSError:
            pass
    from yogafp import core
    import logging
    logging.basicConfig(level=logging.WARNING)
    sensor = core.Sensor()
    sensor.open()
    cap = core.Capture(sensor, lambda e: None)
    print('  keep your finger OFF the sensor...', flush=True)
    cap.take_blank()

    if label == 'enroll':
        plan = [(rid, txt, n) for rid, txt, n in core.REGIONS]
    else:
        n = int(a[1]) if len(a) > 1 else 30
        txt = ('your ENROLLED finger, natural touches (some quick, some off-center or rotated)'
               if label == 'genuine' else 'OTHER fingers (mix both hands, thumbs, angles)')
        plan = [(label, txt, n)]

    images, meta = [], []
    for rid, txt, n in plan:
        got = 0
        while got < n:
            print('  > %s  [%d/%d]' % (txt, got + 1, n), flush=True)
            diff = cap.wait_finger(60)
            if diff is None:
                print('    timed out; try again'); continue
            cov = core.coverage(diff)
            images.append(diff.astype('float32'))
            meta.append({'region': rid, 'coverage': round(cov, 3), 't': time.time()})
            got += 1
            print('    captured (coverage %d%%) - lift' % (cov * 100), flush=True)
            cap.wait_lift()
    path = dataset.save(label, images, meta)
    print('  saved %d %s captures, encrypted: %s' % (len(images), label, os.path.basename(path)))
    print('  dataset now:', dataset.summary())
    return 0


if __name__ == '__main__':
    sys.exit(main())
