"""Encrypted local fingerprint dataset for matcher development (never part of the installed product).

Storage: ~/Library/Application Support/yoga-fp-dataset/<label>-<timestamp>.enc  (dir 0700, files 0600)
Each file: AES-256-GCM(npz of float16 blank-subtracted images + per-image metadata).
Key: 32 random bytes in the login Keychain, service "yoga-fp-dataset-key" (passed to `security` on stdin).
Nothing in here prints or returns pixel data to a terminal; callers get numpy arrays in memory only.
"""
import io, os, glob, json, time, getpass, secrets, subprocess
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DIR = os.path.expanduser('~/Library/Application Support/yoga-fp-dataset')
SERVICE = 'yoga-fp-dataset-key'
AAD = b'yoga-fp-dataset-v1'


def _key(create=False):
    r = subprocess.run(['/usr/bin/security', 'find-generic-password', '-a', getpass.getuser(), '-s', SERVICE, '-w'],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return bytes.fromhex(r.stdout.strip())
    if not create:
        raise SystemExit('no dataset key (nothing collected yet)')
    k = secrets.token_bytes(32)
    cmd = 'add-generic-password -U -a %s -s %s -l "yoga-fp dataset key" -w %s\n' % (getpass.getuser(), SERVICE, k.hex())
    r = subprocess.run(['/usr/bin/security', '-i'], input=cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit('could not store dataset key: %s' % r.stderr.strip())
    return k


def save(label, images, meta):
    os.makedirs(DIR, mode=0o700, exist_ok=True); os.chmod(DIR, 0o700)
    buf = io.BytesIO()
    np.savez(buf, images=np.stack(images).astype(np.float16), meta=np.array(json.dumps(meta)))
    nonce = secrets.token_bytes(12)
    name = '%s-%s.enc' % (label, time.strftime('%Y%m%d-%H%M%S'))
    blob = nonce + AESGCM(_key(create=True)).encrypt(nonce, buf.getvalue(), AAD + b':' + name.encode())
    path = os.path.join(DIR, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(blob)
    return path


def load(label):
    """-> (images float32 [N,H,W], meta list) for all files of this label."""
    imgs, meta = [], []
    k = _key()
    for p in sorted(glob.glob(os.path.join(DIR, label + '-*.enc'))):
        blob = open(p, 'rb').read()
        data = AESGCM(k).decrypt(blob[:12], blob[12:], AAD + b':' + os.path.basename(p).encode())
        z = np.load(io.BytesIO(data), allow_pickle=False)
        imgs.extend(z['images'].astype(np.float32))
        meta.extend(json.loads(str(z['meta'])))
    return (np.stack(imgs) if imgs else np.zeros((0, 112, 112), np.float32)), meta


def summary():
    out = {}
    for p in glob.glob(os.path.join(DIR, '*.enc')):
        lab = os.path.basename(p).split('-')[0]
        out[lab] = out.get(lab, 0) + 1
    return out


def delete_all():
    n = 0
    for p in glob.glob(os.path.join(DIR, '*.enc')):
        os.remove(p); n += 1
    if os.path.isdir(DIR):
        os.rmdir(DIR)
    subprocess.run(['/usr/bin/security', 'delete-generic-password', '-a', getpass.getuser(), '-s', SERVICE],
                   capture_output=True)
    return n
