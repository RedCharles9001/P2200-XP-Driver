# Quadro P2200 on Windows XP SP3 x86 - Driver 76

Driver 76 adds two monitor-specific DisplayPort timing fixes to the GP106 P2200 port derived from [SupraGSX/Forceware-382.69](https://github.com/SupraGSX/Forceware-382.69/tree/aee0c3a4a5dc7558d30f45e6c3d3e44a5f96eb1b). Download the installer from [Release v76](https://github.com/walshbobbyca/P2200-XP-Driver/releases/tag/v76). Run it on the intended 32-bit XP SP3 P2200 machine and reboot.

| Monitor | Mode | Evidence for Driver 76 |
| --- | --- | --- |
| Samsung Odyssey G95SC (SAME028) | 5120 x 1440 at nominal 120 Hz | Owner confirmed the Samsung's own readout, stable output without panning, and persistence after reboot. |
| ASUS AUSAA34 | 3840 x 2160 at nominal 120 Hz | Existing ASUS rule retained. Driver 76 offline replay reached DP configuration at 1066.56 MHz. |

The current fix is model-specific. The project has not established that other monitors advertising these resolutions work. The release installer SHA-256 is **d99c480ae109b85ee083dcb2715f3e806ae3a0c630e566e6f9c4e9eb44cbdf9a** (220,923,306 bytes).

## Review for SupraGSX

1. Start with [Driver 72's review notes](driver72/SUPRAGSX-REVIEW.txt) and [patch map](driver72/PATCH-MAP.txt). They explain the inherited firmware changes, conditional region acceptance, GP106 constructor/getter and descriptor handling, retained VPR, and restored native FIFO/timer behavior. [Pinned inputs](driver72/inputs-and-layout.json) identify the baseline and both donors.
2. Read the [Driver 76 timing walkthrough](review/TIMING-FIX.md), [guard emitter](guard.py), and [instruction bytes and disassembly](review/guard-disassembly.txt).
3. Compare [every old/new miniport byte from Driver 72 to 76](review/PATCHES.txt) or use the [machine-readable ledger](review/PATCHES.json). File offsets are zero-based. The Driver 72 rebuild generates the corresponding full ledger from the October 19 original, including the donor firmware bytes.
4. [Payload changes](review/PACKAGE-CHANGES.json) list the changed package files and before/after hashes. The [release manifest](review/payload-sha256.json) covers every extracted file. [Replay results](review/replay-results.json) and the [hardware follow-up](review/XP-TEST-STATUS.txt) distinguish offline verification from XP acceptance. The build report records the earlier, pre-hardware state.

## Reproduce the release payload on Windows

Install Python, 7-Zip, and the Python dependencies below. Supply the three hash-pinned installers in an inputs folder as described in [the Driver 72 rebuild instructions](driver72/README.txt). Use fresh output directories. Run from this repository root.

~~~powershell
python -m pip install -r driver72/requirements-verify.txt
python -B driver72/rebuild.py --inputs inputs --out build72
python -B rebuild76.py --clean72 build72 --out build76
~~~

The first stage reconstructs the clean parent. The second assembles the actual x86 hooks, applies them after checking the expected original bytes, calculates the PE checksum, and compares the regenerated ledger and all 635 payload files to the published release. The final nv4_mini.sys SHA-256 is **b180bb3638ec9ea11a4508637d448e298e7a7daf7c1b60750ccffeaba438aac5**. The display DLL stays byte-identical to the parent. The self-extracting installer has its own hash for download verification. The rebuild target is the extracted payload.

Authored scripts and assembly use the [GPL-3.0 license](LICENSE) with the [NVIDIA integration exception](NVIDIA-EXCEPTION.txt). Upstream and vendor material retain their respective terms. See the [attribution and source notice](driver72/NOTICE.txt). Development was AI-assisted with OpenAI Codex; physical test results are owner-reported.
