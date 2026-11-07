P2200 Driver 72 Clean RC1 - rebuild and review kit
November 4, 2026 | XP hardware acceptance pending

PURPOSE
Rebuild the clean nv4_mini.sys from SupraGSX's October 19 installer plus two
official NVIDIA firmware donors. No previous P2200 test build is required.
The rebuilt miniport must match the frozen SHA-256 in inputs-and-layout.json.
The clean nv4_disp.dll is byte-identical to SupraGSX's original and Driver 69.

INPUTS (supply these exact files in a new inputs folder)
Forceware.382.69.10-19-2026.exe
  e3fc9dc564e0d5dcf2967cf4065ec4d21c5818041ac5554ef98032fa61fe3fe2
431.02-quadro-desktop-notebook-win8-win7-64bit-international-whql.exe
  f756b631ab064082fd14a063d9b6594534c83525dfb761a55eb1ad41bd81a292
384.94-desktop-win8-win7-64bit-international-whql.exe
  4a0a63092c8308815e4d8d4a0872f0a51b8f8bcd165e6d87004589142a8fd5f1

Source locations recorded for these inputs:
https://github.com/SupraGSX/Forceware-382.69/releases/tag/382.69-2026-10-19
https://us.download.nvidia.com/Windows/Quadro_Certified/431.02/431.02-quadro-desktop-notebook-win8-win7-64bit-international-whql.exe
https://us.download.nvidia.com/Windows/384.94/384.94-desktop-win8-win7-64bit-international-whql.exe

All installer hashes are checked BEFORE any extraction. Expanded donor module
hashes and every decoded firmware resource hash are checked again. A mismatch
stops the build. Existing output directories are refused. Originals are untouched.

BUILD ON WINDOWS 10/11, NOT ON XP
Requirements: Python 3.9 or newer and 7-Zip. No account or subscription is needed.
The pip command below downloads the listed Python dependency from PyPI. The
rebuild itself is offline, performs no uploads, and never runs NVIDIA installers.
If dependencies are already installed, skip the pip command.

In PowerShell, from the extracted rebuild-kit folder:
  python -m pip install -r requirements-build.txt
  python -B rebuild.py --inputs .\inputs --out .\build-1

If 7-Zip is elsewhere:
  python -B rebuild.py --inputs .\inputs --out .\build-1 --sevenzip "D:\Tools\7z.exe"

Outputs:
  build-1\nv4_mini.sys             frozen, reproducible clean miniport
  build-1\XP-payload\              complete P2200-only install payload
  build-1\PATCHES.txt              EVERY patched/appended byte, old/new and reason
  build-1\PATCHES.json             machine-readable equivalent
  build-1\PACKAGE-CHANGES.json     INF/package changes, including ASUS timing
  build-1\BUILD-REPORT.json        exact input/output hashes; XP remains untested
  build-1\INSTALL-REBUILT-XP.cmd   XP/SP3/P2200-guarded installer launcher

VERIFY
Optional verification dependencies (the pip command downloads from PyPI):
  python -m pip install -r requirements-verify.txt

Extract the ORIGINAL nv4_mini.sys into a separate folder for independent comparison:
  & "C:\Program Files\7-Zip\7z.exe" x .\inputs\Forceware.382.69.10-19-2026.exe -o.\original Display.Driver/nv4_mini.sys
  python -B verify.py --build .\build-1 --baseline .\original\Display.Driver\nv4_mini.sys
  python -B verify_mode.py --build .\build-1

The firmware/adapter checks execute x86 code at three relocated load addresses,
with external memcpy modeled. Region tests include exact 12/15, equality, other
mismatches and failures in the other five comparisons. Mode tests execute the
native EDID/rule producer, cached mode selection and DP bandwidth/depth path.
They stop before real DP programming; the mode cache, OS replies and link state
are fixture inputs. The shared EDID comes from the XP capture with serial fields
removed and the checksum repaired. It is a test fixture, not an EDID override.

To independently reassemble the 1024-byte patch from readable assembly, supply
GNU Binutils with i386pe support (for example the i686 tools in w64devkit):
  python -B assemble.py --binutils "C:\Tools\w64devkit\bin" --out .\assembly-check
It compares the resulting code and symbols against src/clean-code.hex and
src/symbols.json. The normal rebuild needs no assembler: it applies this reviewed,
source-supplied code patch. No NVIDIA firmware is embedded in that hex file.

To check reproducibility from scratch:
  python -B rebuild.py --inputs .\inputs --out .\build-2
  Get-FileHash .\build-1\nv4_mini.sys, .\build-2\nv4_mini.sys -Algorithm SHA256
Both must match inputs-and-layout.json. Installer archive bytes are not the
reproducibility target; nv4_mini.sys is. Do not overwrite a prior build.

WHAT THE CLEAN CANDIDATE KEEPS
* SupraGSX October 19 fixes, including existing DisplayPort support.
* Matched 431.02 ACR resources.
* Matched 384.94 alternate SEC2 resources; existing 56-to-84 adapter with its
  build guard changed to 0x015034F5. All other adapter guards remain.
* Fifth region comparison: original equality OR actual 12 / expected 15.
  All other region comparisons remain strict.
* All seven matched 431.02 GP106 FECS/GPCCS/GR resources. Exact matching signatures
  receive an 84-byte descriptor built from the existing 76 bytes plus two zeros.
  Source length, destination capacity and nonnull destination are checked.
* Driver 71's 431.02 VPR resources, explicitly retained by the operator.
* Driver 71's ASUS AUSAA34 3840x2160/32-bit/120 Hz INF rule at 1066.56 MHz.

WHAT IS RESTORED
The build starts from the original, so our accumulated diagnostic code/data,
logging hooks, forced stops/returns and suppression patches are not carried over.
The native CALL at VA 0x46E7A6 targets 0x4D10F0 again. Native initialization,
timer-start calls, timer callback, GR error handling and mode-validation code
are restored. The upstream driver's own code and normal error handling remain.
This is a behavioral change from Driver 71 and requires real XP acceptance.

SHARING AND LIMITS
Share this source-only kit for technical review. Keep NVIDIA installers, generated
firmware byte dumps, local XP logs and crash dumps out of that archive.
The complete generated PATCHES.txt is available after each user's local rebuild.
The local private USB kit additionally includes the exact Driver 69 rollback;
other users must preserve their own working recovery driver.
P2200 installation is restricted by INF. The binary firmware providers are
GP106-family providers, so this is not a claim about all GP106 boards.
The 4K120 rule matches ASUS AUSAA34 only; it is not a universal monitor override.
Prior Driver 69/71 hardware observations do not validate Driver 72 Clean RC1.
Read XP-TEST.txt, NOTICE.txt, LICENSE and NVIDIA-EXCEPTION.txt before distribution.
