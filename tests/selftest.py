#!/usr/bin/env python3
"""Smoke test: keygen -> embed -> verify round-trip, plus a negative case.

Generates its own synthetic image and a throwaway key. No network, no fixtures.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image

HERE = Path(__file__).resolve().parent.parent
SCRIPT = HERE / "machinemark_poc.py"
PY = sys.executable


def make_image(path):
    h = w = 512
    y, x = np.mgrid[0:h, 0:w]
    r = x * 255 // w
    g = y * 255 // h
    b = (x + y) * 255 // (w + h)
    Image.fromarray(np.dstack([r, g, b]).astype(np.uint8), "RGB").save(path)


def run(*args):
    return subprocess.run([PY, str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True)


def main():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        src, out, key = td / "src.png", td / "out.png", td / "test.key"

        make_image(src)

        r = run("keygen", key)
        assert r.returncode == 0, r.stderr
        assert (td / "test.key.pub").exists()

        r = run("embed", src, out, "--key", key, "--label", "SELFTEST")
        assert r.returncode == 0, r.stderr
        assert out.exists()

        r = run("verify", out, "--pub", str(key) + ".pub")
        assert r.returncode == 0, r.stderr
        rep = json.loads(r.stdout)
        assert rep["watermark"] and rep["valid"], rep
        assert rep["signature"] == "valid", rep
        assert rep["label"] == "SELFTEST", rep

        # Negative case: the unwatermarked source must not verify.
        r = run("verify", src, "--pub", str(key) + ".pub")
        rep2 = json.loads(r.stdout)
        assert not rep2["watermark"], rep2

    print("selftest: PASS")


if __name__ == "__main__":
    main()
