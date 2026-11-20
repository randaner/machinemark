# MachineMark — landscape survey + PoC status

Goal: mark an image as machine-generated, invisibly and tamper-evidently, in a way
anyone can verify (not just a trusted detector).

## Existing tools

### Family 1 — signed metadata / provenance ("EXIF + PGP" half)
- **C2PA / Content Credentials** (Coalition for Content Provenance and Authenticity).
  Open spec at spec.c2pa.org; reference impls c2pa-rs (Rust) + Python. Backers:
  Adobe, Microsoft, OpenAI, Google, Nikon/Canon/Leica, BBC/Reuters. Ships in
  Microsoft Image Creator, ChatGPT/API images, Google products. IPTC maps metadata.
  - Key spec nuance: **hard binding** = hash of pixels (breaks on any re-encode);
    **soft binding** = perceptual fingerprint *or invisible watermark*. So C2PA
    already anticipates a pixel watermark as the soft-binding layer.
  - Limitation for us: trust is centralized (X.509 certs / CA). It says what a
    signer *asserted*, not what is true.
- IPTC C2PA FAQs, C2PA explainer v2.4/v2.5 (spec.c2pa.org).

### Family 2 — pixel-level invisible watermarks
- **Google SynthID** — deep encoder/decoder pair; image/video/audio/text; deployed
  at ~100B+ assets; SynthID Detector portal (synthid.withgoogle.com-ish). Not
  open; access via partnerships (OpenAI, NVIDIA, Kakao, Apple). Paper: arXiv 2510.09263.
- **Meta Stable Signature** — watermark baked into the latent decoder weights;
  open weights + extractor (github.com/facebookresearch/stable_signature).
  Known weakness: "Stable Signature is Unstable" (fine-tuning scrubs it).
- **Tree-Ring** (USTC, github.com/YuxinWenRick/tree-ring-watermark) — key pattern in
  Fourier domain of the initial noise; training-free; robust. Detection needs model
  inversion.
- **RingID** (showlab/RingID) — multi-key extension of Tree-Ring.
- **MarkDiffusion** (THU-BPM/MarkDiffusion, JMLR) — open toolkit, 11 algorithms
  (Tree-Ring, Ring-ID, ROBIN, WIND, SFW, Gaussian-Shading, PRC, SEAL, GaussMarker,
  VideoShield, VideoMark).
- **invisible-watermark** (ShieldMnt, pip `invisible-watermark`) — closest generic
  open CLI; DWT+DCT / DWT+DCT+SVD / RivaGAN. Blind, CPU-friendly (~300 ms @1080p).
  Explicitly warns: not 100% accurate, poor on screenshots/flat backgrounds.
- Commercial: Imatag, Digimarc, Verance, ScoreDetect PhotoVault.

## The gap (settled)
Direct hit: **DeepSignature** (arXiv 2604.23016) — Ed25519ph-signed latent encoding
embedded as an imperceptible watermark, verifiable client-side with only the public
key. That is exactly our "PGP-ish invisible watermark" idea, published.
Also: **veilmark** (github.com/khoichon/veilmark) — local-first invisible watermark for
images/video, Ed25519-signed payloads, public-key verification, CLI, turbo-coded
two-layer payload. Practically identical to what we sketched.
Older prior art: IEEE T-IP "authentication digital watermarks" (wavelet coeffs carry a
signature bit-string), "Tamper-Proof Image Watermarking based on public key
infrastructure" (DWT + PGP key management).
C2PA v2.4 explicitly supports invisible watermarks as a soft binding, with a
`c2pa.watermarked.bound` action and soft-binding assertion.

Verdict: **not novel.** Both halves and their combination exist, including a current
open-source implementation.

## PoC status (machinemark_poc.py)
- Works losslessly: Ed25519-signed payload (label + nonce + source hash + sig + CRC)
  embedded via 8x8-DCT spread-spectrum (alpha=8, K=8) in the blue channel.
  PSNR 56.8 dB, max diff 16, mean abs 0.12 -> invisible. Signature verifies.
- Known defect: **not yet robust to JPEG** — marker not found even at q95.
  Needs: robustness work (multi-scale / stronger band / better recovery), and the
  marker search should not depend on exact MAGIC recovery.
- Not production; single layer, no CLI polish, no key management.

## Next (if we continue)
1. Fix JPEG robustness (test q50..q95), then crop/resize.
2. Decide: standalone tool vs C2PA soft-binding layer.
3. Only then build the real CLI + docs + GitHub repo.
