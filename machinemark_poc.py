#!/usr/bin/env python3
"""machinemark PoC: invisible signed watermark that marks an image as machine-generated.

Light version: single 8x8-DCT layer on the blue channel, Ed25519-signed payload,
PNG tEXt + sidecar.
"""
import argparse, base64, hashlib, json, os, struct, time
import numpy as np
from PIL import Image, PngImagePlugin
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

MAGIC = b"MM1\x00"
CHIP_SEED = 0x4D4D3130
ALPHA = 8.0   # embedding strength in DCT coeff units
K = 8         # chip length per payload bit (spread-spectrum gain)
BAND = (6, 20)  # zigzag index band used per 8x8 block


def dct_matrix(n):
    k = np.arange(n)[:, None]
    x = np.arange(n)[None, :]
    C = np.cos(np.pi * k * (2 * x + 1) / (2 * n))
    C[0] *= np.sqrt(1.0 / n)
    C[1:] *= np.sqrt(2.0 / n)
    return C


def zigzag(n):
    out = []
    for s in range(2 * n - 1):
        diag = [(i, s - i) for i in range(max(0, s - n + 1), min(n - 1, s) + 1)]
        out += diag[::-1] if s % 2 else diag
    return out


ELIG = [p for i, p in enumerate(zigzag(8)) if BAND[0] <= i <= BAND[1]]
C8 = dct_matrix(8)


def to_blocks(Y, n=8):
    h, w = Y.shape
    Y = Y[: h // n * n, : w // n * n]
    H, W = h // n, w // n
    return Y.reshape(H, n, W, n).transpose(0, 2, 1, 3).reshape(-1, n, n)


def from_blocks(B, shape, n=8):
    H, W = shape[0] // n, shape[1] // n
    Y = B.reshape(H, W, n, n).transpose(0, 2, 1, 3).reshape(H * n, W * n)
    out = np.zeros(shape)
    out[: H * n, : W * n] = Y
    if shape[0] % n:
        out[H * n:, :] = out[H * n - 1: H * n, :]
    if shape[1] % n:
        out[:, W * n:] = out[:, W * n - 1: W * n]
    return out


def dct2(b):
    return np.einsum("ku,buv,wv->bkw", C8, b, C8)


def idct2(d):
    return np.einsum("ku,bkw,wv->buv", C8, d, C8)


def chip(length):
    r = np.random.default_rng(CHIP_SEED)
    return np.where(r.random(length) < 0.5, -1.0, 1.0)


def crc32(b):
    import zlib
    return zlib.crc32(b) & 0xFFFFFFFF


def build_payload(key, label, src_hash):
    body = MAGIC + bytes([len(label)]) + label.encode() + os.urandom(8) + src_hash
    sig = key.sign(body).signature
    return body + sig + struct.pack(">I", crc32(body + sig))


def embed(img, out, key, label):
    im = Image.open(img).convert("RGB")
    arr = np.asarray(im).astype(np.float64)
    B = arr[:, :, 2].copy()
    src_hash = hashlib.sha256(open(img, "rb").read()).digest()
    payload = build_payload(key, label, src_hash)
    bits = np.unpackbits(np.frombuffer(payload, np.uint8)).astype(np.float64) * 2 - 1

    blocks = to_blocks(B)
    d = dct2(blocks)
    nblocks = d.shape[0]
    # gather eligible coefficients in fixed order -> (nblocks, len(ELIG))
    vals = np.stack([d[:, u, v] for u, v in ELIG], axis=1)
    flat = vals.reshape(-1)
    need = len(bits) * K
    assert flat.size >= need, f"image too small: {flat.size} < {need}"
    ch = chip(need).reshape(len(bits), K)
    flat[:need] += ALPHA * (bits[:, None] * ch).reshape(-1)
    vals = flat.reshape(nblocks, len(ELIG))
    for i, (u, v) in enumerate(ELIG):
        d[:, u, v] = vals[:, i]
    arr[:, :, 2] = np.clip(from_blocks(idct2(d), B.shape), 0, 255)
    out_im = Image.fromarray(arr.astype(np.uint8), "RGB")

    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text("MachineMark", base64.b64encode(payload).decode())
    pnginfo.add_text("Software", "machinemark-poc/0.1")
    pnginfo.add_text("Comment", f"{label}; signed provenance record in MachineMark")
    out_im.save(out, pnginfo=pnginfo)

    meta = {
        "tool": "machinemark-poc/0.1",
        "label": label,
        "source_sha256": src_hash.hex(),
        "payload_b64": base64.b64encode(payload).decode(),
        "signature_b64": base64.b64encode(payload[4 + 1 + len(label) + 8:][:64]).decode(),
        "embedded_at": int(time.time()),
        "params": {"alpha": ALPHA, "K": K, "band": BAND},
    }
    with open(out + ".mm.json", "w") as f:
        json.dump(meta, f, indent=2)
    return payload


def extract(img):
    im = Image.open(img).convert("RGB")
    B = np.asarray(im).astype(np.float64)[:, :, 2]
    d = dct2(to_blocks(B))
    vals = np.stack([d[:, u, v] for u, v in ELIG], axis=1).reshape(-1)
    return vals


def verify(img, pubkey_path=None):
    vals = extract(img)
    # try to find the payload: we know nbits from payload length, so read enough
    # simplest: recover bits for a generous length, then search for MAGIC+CRC
    maxbytes = 4096
    need = maxbytes * 8 * K
    if vals.size < need:
        maxbytes = vals.size // (8 * K)
        need = maxbytes * 8 * K
    ch = chip(need).reshape(maxbytes * 8, K)
    z = (vals[:need] * ch.reshape(-1)).reshape(maxbytes * 8, K).sum(axis=1)
    bits = (z > 0).astype(np.uint8)
    raw = np.packbits(bits).tobytes()
    idx = raw.find(MAGIC)
    if idx < 0:
        return {"watermark": False, "reason": "marker not found"}
    # length is implicit: try to parse label, then sig+crc
    p = idx
    if raw[p:p + 4] != MAGIC:
        return {"watermark": False}
    llen = raw[p + 4]
    body_len = 4 + 1 + llen + 8 + 32
    total = body_len + 64 + 4
    payload = raw[p:p + total]
    if len(payload) < total or crc32(payload[:-4]) != struct.unpack(">I", payload[-4:])[0]:
        return {"watermark": True, "valid": False, "reason": "CRC mismatch"}
    body = payload[:body_len]
    sig = payload[body_len:body_len + 64]
    label = body[5:5 + llen].decode(errors="replace")
    out = {"watermark": True, "valid": True, "label": label,
           "nonce": body[5 + llen:5 + llen + 8].hex(),
           "source_sha256": body[5 + llen + 8:].hex()}
    if pubkey_path:
        vk = VerifyKey(base64.b64decode(open(pubkey_path).read()))
        try:
            vk.verify(body, sig)
            out["signature"] = "valid"
        except BadSignatureError:
            out["signature"] = "INVALID"
            out["valid"] = False
    return out


def keygen(path):
    sk = SigningKey.generate()
    open(path, "w").write(base64.b64encode(bytes(sk)).decode())
    open(path + ".pub", "w").write(base64.b64encode(bytes(sk.verify_key)).decode())
    return bytes(sk.verify_key).hex()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("out")
    e = sub.add_parser("embed")
    e.add_argument("img"); e.add_argument("out")
    e.add_argument("--key", required=True)
    e.add_argument("--label", default="MACHINE-GENERATED")
    v = sub.add_parser("verify")
    v.add_argument("img")
    v.add_argument("--pub")
    a = ap.parse_args()
    if a.cmd == "keygen":
        print("pubkey", keygen(a.out))
    elif a.cmd == "embed":
        key = SigningKey(base64.b64decode(open(a.key).read()))
        p = embed(a.img, a.out, key, a.label)
        print(f"embedded {len(p)} bytes -> {a.out}")
    else:
        print(json.dumps(verify(a.img, a.pub), indent=2))


if __name__ == "__main__":
    main()
