# machinemark

Invisible, signed watermark that marks an image as **machine-generated**, verifiable
by anyone holding the public key. A small learning/practice project — not production
software.

## Status: what this is (and isn't)

- Works losslessly: embed + verify round-trips, Ed25519 signature checks out.
- **Not robust to JPEG yet.** The marker is lost on JPEG re-encode, even at high
  quality. Treat it as a proof of concept, not a deployable watermark.
- **Not novel.** This idea already exists; see *Prior art* below. It is published here
  as practice, not as a claim of invention.

## What it does

1. `keygen` — make an Ed25519 keypair (base64 seed + verify key).
2. `embed` — build a payload of `MAGIC + label + nonce + source_sha256`, sign it, and
   spread-spectrum-embed the bits into 8x8-DCT coefficients (zigzag band 6–20) of the
   **blue channel** at strength `ALPHA=8`, chip length `K=8`. Also writes the payload
   into a PNG `tEXt` chunk and a `<out>.mm.json` sidecar.
3. `verify` — re-extract the coefficients, correlate with the chip, decode, check the
   MAGIC and CRC, and verify the Ed25519 signature against a public key.

PNG is lossless, so the blue-channel DCT coefficients survive exactly.

## Requirements

Python 3 with `numpy`, `Pillow`, `PyNaCl`:

```sh
python3 -m pip install --user numpy pillow pynacl
```

(Debian/CachyOS: `python-numpy`, `python-pillow`, `python-pynacl`.)

## Quick start

```sh
python3 machinemark_poc.py keygen keys/demo.key
python3 machinemark_poc.py embed input.png out.png --key keys/demo.key --label "MACHINE-GENERATED"
python3 machinemark_poc.py verify out.png --pub keys/demo.key.pub
```

`verify` prints a JSON report: `watermark` (marker found), `valid` (CRC ok),
`signature` (`valid` / `INVALID`), `label`, `nonce`, `source_sha256`.

Smoke test (generates its own key and image, no network):

```sh
python3 tests/selftest.py
```

## Layout

```
machinemark_poc.py   the whole tool (single file, ~210 lines)
tests/selftest.py    keygen -> embed -> verify round-trip + negative case
RESEARCH.md          prior-art survey and PoC status notes
keys/                generated at runtime; gitignored (never commit a private key)
```

## Limitations

- JPEG/crop/resize robustness: **not solved**.
- One layer, no perceptual masking, no key management, no revocation, no format
  support beyond PNG output.
- The signature proves the key holder signed the payload; it does not prove the image
  is unedited or truthful.

## Prior art

- **C2PA / Content Credentials** — signed provenance metadata standard; supports
  invisible watermarks as a "soft binding" (`c2pa.watermarked.bound`). spec.c2pa.org
- **DeepSignature** (arXiv 2604.23016) — Ed25519ph-signed latent encoding embedded as
  an invisible watermark, verified with only the public key. Same core idea.
- **veilmark** (github.com/khoichon/veilmark) — open local-first invisible watermark
  for images/video with Ed25519-signed payloads and public-key verification.
- **Google SynthID**, **Meta Stable Signature**, **Tree-Ring**, **RingID**,
  **MarkDiffusion** — pixel/latent watermarks at scale (mostly proprietary or
  model-bound).
- Classic work: IEEE T-IP "authentication digital watermarks" (signature bit-string
  etched into wavelet coefficients).

## License

MIT — see [LICENSE](LICENSE).
