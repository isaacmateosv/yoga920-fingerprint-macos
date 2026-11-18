"""Matching techniques for small-area fingerprint sensors (112x112 partial prints).

  enhance(img)            ridge enhancement: orientation field + oriented Gabor filtering (contextual
                          filtering, Hong/Wan/Jain 1998). Removes pressure/dryness/noise differences.
  poc_prepare / poc_score band-limited phase-only correlation (BLPOC, Ito et al. 2004/2005): compares the whole
                          ridge pattern's phase; robust for partial overlap. Rotation by explicit search.
  sift_score              SIFT keypoints + RANSAC-consistent similarity transform (the original matcher).

All functions are pure and in-memory; nothing here writes or prints image data.
"""
import numpy as np
import cv2

N = 112


def _norm(img):
    lo, hi = np.percentile(img, 1), np.percentile(img, 99)
    x = np.clip((img - lo) / max(1e-6, hi - lo), 0, 1)
    return (x - x.mean()) / (x.std() + 1e-6)


# ------------------------------------------------------------------ ridge enhancement
_ORIENTS = 16


def ridge_period(img):
    """Dominant ridge period (px) from the radial peak of the spectrum, clamped to a plausible range."""
    x = _norm(img) * np.outer(np.hanning(img.shape[0]), np.hanning(img.shape[1]))
    P = np.abs(np.fft.fftshift(np.fft.fft2(x)))
    cy, cx = np.array(P.shape) // 2
    y, xg = np.indices(P.shape)
    r = np.hypot(y - cy, xg - cx).astype(int)
    radial = np.bincount(r.ravel(), P.ravel()) / np.maximum(1, np.bincount(r.ravel()))
    lo, hi = int(img.shape[0] / 14), int(img.shape[0] / 5)          # periods 5..14 px
    k = lo + int(np.argmax(radial[lo:hi + 1]))
    return float(np.clip(img.shape[0] / max(k, 1), 5, 14))


def _gabor_bank(period):
    ks = int(round(period * 2)) | 1
    sigma = 0.5 * period
    return [cv2.getGaborKernel((ks, ks), sigma, np.pi * i / _ORIENTS, period, 0.6, 0, ktype=cv2.CV_32F)
            for i in range(_ORIENTS)]


def enhance(img):
    """-> (enhanced float32 image, coherence mask float32 0..1)"""
    x = _norm(img).astype(np.float32)
    gx = cv2.Sobel(x, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(x, cv2.CV_32F, 0, 1, ksize=3)
    gxx = cv2.GaussianBlur(gx * gx, (0, 0), 5)
    gyy = cv2.GaussianBlur(gy * gy, (0, 0), 5)
    gxy = cv2.GaussianBlur(gx * gy, (0, 0), 5)
    theta = 0.5 * np.arctan2(2 * gxy, gxx - gyy)                     # gradient direction
    coh = np.sqrt((gxx - gyy) ** 2 + 4 * gxy ** 2) / (gxx + gyy + 1e-6)
    # Gabor kernel angle is the direction of the sinusoid, i.e. the gradient direction (across ridges)
    idx = np.round(((theta % np.pi) / np.pi) * _ORIENTS).astype(int) % _ORIENTS
    bank = _gabor_bank(ridge_period(img))
    out = np.zeros_like(x)
    for i, k in enumerate(bank):
        m = idx == i
        if m.any():
            out[m] = cv2.filter2D(x, cv2.CV_32F, k)[m]
    mask = np.clip((coh - 0.2) / 0.4, 0, 1).astype(np.float32)
    out = out * mask
    return (out / (np.abs(out).max() + 1e-6)).astype(np.float32), mask


# ------------------------------------------------------------------ band-limited phase-only correlation
_WIN = np.outer(np.hanning(N), np.hanning(N)).astype(np.float32)


def _band(period):
    # keep spatial frequencies up to ~1.6x the ridge frequency; drop the rest (noise)
    return int(np.clip(round(1.6 * N / period), 8, N // 2 - 1))


def poc_prepare(img, enhanced=False, angles=None):
    """Precompute FFTs of an image (and optionally rotated copies) for fast POC matching."""
    x = enhance(img)[0] if enhanced else _norm(img).astype(np.float32)
    rots = []
    for a in (angles if angles is not None else [0.0]):
        if a:
            M = cv2.getRotationMatrix2D((N / 2, N / 2), a, 1.0)
            xr = cv2.warpAffine(x, M, (N, N), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT)
        else:
            xr = x
        rots.append(np.fft.fft2(xr * _WIN))
    return {'F': rots, 'period': ridge_period(img)}


def poc_score(a, b):
    """Max BLPOC peak between prepared probe a (any rotations) and prepared template b (first entry)."""
    K = _band(0.5 * (a['period'] + b['period']))
    Fb = b['F'][0]
    best = 0.0
    for Fa in a['F']:
        R = Fa * np.conj(Fb)
        R /= np.abs(R) + 1e-9
        Rs = np.fft.fftshift(R)
        c = N // 2
        Rb = Rs[c - K:c + K + 1, c - K:c + K + 1]
        r = np.real(np.fft.ifft2(np.fft.ifftshift(Rb)))
        # peak energy: top peak plus its immediate neighbours (sub-pixel shifts spread the peak)
        p = np.unravel_index(np.argmax(r), r.shape)
        nb = r[np.ix_([(p[0] + d) % r.shape[0] for d in (-1, 0, 1)], [(p[1] + d) % r.shape[1] for d in (-1, 0, 1)])]
        best = max(best, float(np.sort(nb.ravel())[-2:].sum()))
    return best


# ------------------------------------------------------------------ SIFT (original matcher), optionally enhanced
def sift_features(img, enhanced=False):
    from . import core
    if not enhanced:
        return core.features(img)
    e, _ = enhance(img)
    return core.features(e * 100.0)


def sift_score(probe, template):
    from . import core
    if probe is None or template is None:
        return 0
    return core.inliers(probe, template)
