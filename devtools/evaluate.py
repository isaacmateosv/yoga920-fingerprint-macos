"""Compare matchers on the encrypted local dataset. Prints only numbers (scores, error rates).

    <dev venv>/bin/python -I devtools/evaluate.py

For each method: genuine probes (your finger) and impostor probes (other fingers) are scored against the
31 enrollment captures (max over templates). Reports AUC, EER, the highest impostor score, and how many
genuine touches pass at a threshold with a safety margin above the highest impostor.
"""
import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'vendor'))
import numpy as np
import dataset
from yogafp import matchers as MT

ANGLES = list(range(-30, 31, 6))
MARGIN = 1.25       # threshold = highest impostor score x MARGIN


def auc(g, i):
    g, i = np.asarray(g, float), np.asarray(i, float)
    return float(((g[:, None] > i[None, :]).sum() + 0.5 * (g[:, None] == i[None, :]).sum()) / (len(g) * len(i)))


def eer(g, i):
    ts = np.unique(np.r_[g, i])
    best = (1.0, 0)
    for t in ts:
        frr = np.mean(np.asarray(g) < t); far = np.mean(np.asarray(i) >= t)
        best = min(best, (max(frr, far), t))
    return best[0]


def report(name, g, i):
    g, i = np.asarray(g, float), np.asarray(i, float)
    imax = i.max()
    thr = imax * MARGIN if imax > 0 else 1e-9
    p = float(np.mean(g >= thr)); p0 = float(np.mean(g > imax))
    sudo = 1 - (1 - p) ** 3
    print('%-26s AUC %.3f  EER %5.1f%%  impostor max %7.3f | margin x%.2f: touch pass %3.0f%%  sudo(3 tries) %3.0f%% | no-margin pass %3.0f%%'
          % (name, auc(g, i), 100 * eer(g, i), imax, MARGIN, 100 * p, 100 * sudo, 100 * p0))
    return {'auc': auc(g, i), 'pass': p, 'thr': thr}


def zfuse(*pairs):
    """Fuse methods by normalising each with the impostor distribution (mean/std), then summing.
    Note: normalisation uses the same impostor set it is evaluated on, so this is slightly optimistic."""
    G = np.zeros(len(pairs[0][0])); I = np.zeros(len(pairs[0][1]))
    for g, i in pairs:
        g, i = np.asarray(g, float), np.asarray(i, float)
        mu, sd = i.mean(), i.std() + 1e-6
        G += (g - mu) / sd; I += (i - mu) / sd
    return G, I


def main():
    E, em = dataset.load('enroll')
    G, _ = dataset.load('genuine')
    I, _ = dataset.load('other')
    print('dataset: enroll %d, genuine %d, other %d' % (len(E), len(G), len(I)))
    if min(len(E), len(G), len(I)) == 0:
        sys.exit('collect enroll, genuine and other first')
    res = {}
    t0 = time.time()

    # SIFT raw / enhanced
    for enh in (False, True):
        T = [MT.sift_features(e, enh) for e in E]
        T = [t for t in T if t is not None]
        def sc(img):
            f = MT.sift_features(img, enh)
            return max((MT.sift_score(f, t) for t in T), default=0) if f is not None else 0
        name = 'SIFT ' + ('enhanced' if enh else 'raw (current)')
        res[name] = ([sc(x) for x in G], [sc(x) for x in I])

    # BLPOC raw / enhanced, rotation search on the probe
    for enh in (False, True):
        T = [MT.poc_prepare(e, enh) for e in E]
        def sc(img):
            a = MT.poc_prepare(img, enh, ANGLES)
            return max(MT.poc_score(a, t) for t in T)
        name = 'BLPOC ' + ('enhanced' if enh else 'raw')
        res[name] = ([sc(x) for x in G], [sc(x) for x in I])

    print('scored in %.0fs\n' % (time.time() - t0))
    for name, (g, i) in res.items():
        report(name, g, i)
    print()
    names = list(res)
    for a in range(len(names)):
        for b in range(a + 1, len(names)):
            report('fuse %s + %s' % (names[a].split(' (')[0], names[b].split(' (')[0]), *zfuse(res[names[a]], res[names[b]]))
    report('fuse all four', *zfuse(*res.values()))


if __name__ == '__main__':
    main()
