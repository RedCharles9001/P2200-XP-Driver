"""Rebuild P2200 Driver 72 Clean RC1 from three user-supplied installers.
Only extracts and edits files. No installation, networking or firmware flashing.
SPDX-License-Identifier: GPL-3.0-only WITH NVIDIA-integration-exception
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import zlib

try:
    import pefile
except ImportError:
    sys.exit('Missing dependency. Run: python -m pip install pefile==2024.8.26')

HERE = Path(__file__).resolve().parent
BASE = 0x10000
LOCK = json.loads((HERE / 'inputs-and-layout.json').read_text())
sha = lambda b: hashlib.sha256(b).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checked(path, digest):
    require(path.is_file(), 'Required input missing: ' + str(path))
    data = path.read_bytes()
    require(sha(data) == digest, 'SHA-256 mismatch: ' + str(path))
    return data


def extract(seven, package, folder, *members):
    folder.mkdir(parents=True, exist_ok=False)
    result = subprocess.run([str(seven), 'x', '-y', '-o' + str(folder), str(package), *members],
                            capture_output=True, text=True)
    (folder.parent / (folder.name + '-extraction.log')).write_text(result.stdout + result.stderr)
    require(result.returncode == 0, '7-Zip extraction failed: ' + str(package))


def decode_resource(pe, row):
    descriptor = pe.get_data(row['descriptor_va'] - BASE, 24)
    n, pointer, flags = struct.unpack('<I4xQI4x', descriptor)
    require(n == row['size'] and flags in (0, 1, 2, 3), 'Donor descriptor mismatch: ' + row['name'])
    encoded = pe.get_data(pointer - BASE, n + 4096)
    if flags & 1:
        decoder = zlib.decompressobj(-15)
        data = decoder.decompress(encoded, n + 1)
        require(decoder.eof and not decoder.unconsumed_tail, 'Bad compressed resource: ' + row['name'])
    else:
        data = encoded[:n]
    require(len(data) == n and sha(data) == row['sha256'], 'Firmware hash mismatch: ' + row['name'])
    return data


def build_miniport(original, donors, out):
    require(sha(original) == LOCK['inputs']['baseline']['module_sha256'], 'Wrong baseline miniport')
    pe = pefile.PE(data=original)
    require(pe.FILE_HEADER.Machine == 0x14c and pe.OPTIONAL_HEADER.ImageBase == BASE, 'Not expected XP x86 image')
    require(pe.OPTIONAL_HEADER.FileAlignment == pe.OPTIONAL_HEADER.SectionAlignment == 32, 'Unexpected PE alignment')
    require(len(original) == LOCK['baseline_bytes'] == pe.OPTIONAL_HEADER.SizeOfImage, 'Unexpected base extent')
    require(all(s.PointerToRawData == s.VirtualAddress for s in pe.sections), 'Unexpected PE mapping')
    require(pe.sections[-1].Characteristics == 0xe8000060, 'Unexpected final section permissions')
    code = bytes.fromhex((HERE / 'src/clean-code.hex').read_text())
    require(len(code) == LOCK['code_bytes'] and sha(code) == LOCK['code_sha256'], 'Code patch modified')
    symbols = json.loads((HERE / 'src/symbols.json').read_text())
    require(sha((HERE / 'src/symbols.json').read_bytes()) == LOCK['symbols_sha256'], 'Symbol map modified')
    image = bytearray(original)
    changes = []
    relocs = {e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type == 3}

    def record(off, before, after, reason):
        changes.append(dict(offset=off, va=off + BASE, old_hex=before.hex(), new_hex=after.hex(),
                            old_length=len(before), new_length=len(after), reason=reason))

    def patch(va, old, new, reason, pointer=False):
        off = pe.get_offset_from_rva(va - BASE)
        require(len(old) == len(new) and original[off:off+len(old)] == old, 'Patch precondition: ' + hex(va))
        if pointer:
            require(off in relocs, 'Missing existing pointer relocation: ' + hex(va))
        else:
            require(not any(off-3 <= r < off+len(old) for r in relocs), 'Patch overlaps relocation: ' + hex(va))
        image[off:off+len(new)] = new
        record(off, old, new, reason)

    def append(data, reason):
        off = len(image)
        image.extend(data)
        if data:
            record(off, b'', data, reason)

    append(code, 'Position-independent GP106 constructors/getters, exact 12/15 acceptance and bounded GR descriptor adapter; source src/clean.s')
    for row in LOCK['resources']:
        payload = decode_resource(donors[row['donor']], row)
        append(bytes((-len(image)) % 32), 'Zero padding to 32-byte firmware alignment')
        require(len(image) == row['output_offset'], 'Resource layout mismatch: ' + row['name'])
        append(payload, row['reason'] + ': ' + row['name'] + '; donor ' + row['donor'] + ' descriptor ' + hex(row['descriptor_va']))
        if 'target_descriptor_va' in row:
            va = row['target_descriptor_va']
            # Size and flags are scalar fields; the pointer uses the existing PE relocation.
            patch(va, pe.get_data(va-BASE, 4), struct.pack('<I', len(payload)), row['reason'] + ': length')
            patch(va+4, pe.get_data(va+4-BASE, 4), struct.pack('<I', row['output_va']), row['reason'] + ': payload pointer', True)
            require(pe.get_data(va+8-BASE, 4) == bytes(4), 'Expected uncompressed XP resource')
        elif 'target_pointer_va' in row:
            va = row['target_pointer_va']
            patch(va, pe.get_data(va-BASE, 4), struct.pack('<I', row['output_va']), row['reason'] + ': ' + row['name'], True)
    append(bytes((-len(image)) % 32), 'Zero padding to final PE alignment')
    require(len(image) == LOCK['output_bytes'], 'Unexpected final extent')
    patch(0xd06956, struct.pack('<I', 0x014a7c8c), struct.pack('<I', 0x015034f5),
          'SEC2 56-to-84 adapter: accept exact alternate 384.94 build; retain every other guard')
    for va, old, label in [(0xb7b458, 0x4f0630, 'gp106_fecs'), (0xb7b474, 0x4f07a0, 'gp106_gpccs'),
                           (0xb7b484, 0x4f12b0, 'gp106_gr')]:
        patch(va, struct.pack('<I', old), struct.pack('<I', symbols[label]),
              'GP106 family callback: ' + label + '; existing constructor runs before replacing firmware getters', True)
    for va, old, label, reason in [
        (0x7253a9, bytes.fromhex('8b4c24143b0f7543'), 'accept_region', 'Fifth region comparison: equality or exact actual=12/expected=15; sixth remains strict'),
        (0x7271d4, bytes.fromhex('8b8f58010000'), 'gr_descriptor', 'Exact 431.02 FECS/GPCCS signatures: bounded 76-to-84-byte descriptor copy')]:
        new = b'\xe9' + struct.pack('<i', symbols[label] - va - 5) + b'\x90' * (len(old)-5)
        patch(va, old, new, reason)
    last = pe.sections[-1]
    header_values = [(last, 'Misc_VirtualSize', len(image)-last.PointerToRawData),
                     (last, 'SizeOfRawData', len(image)-last.PointerToRawData),
                     (pe.OPTIONAL_HEADER, 'SizeOfImage', len(image))]
    for name in ('SizeOfCode', 'SizeOfInitializedData'):
        header_values.append((pe.OPTIONAL_HEADER, name, getattr(pe.OPTIONAL_HEADER, name)+len(image)-len(original)))
    for obj, name, value in header_values:
        off = obj.get_field_absolute_offset(name)
        new = struct.pack('<I', value)
        record(off, original[off:off+4], new, 'PE header: ' + name + ' includes appended code/data')
        image[off:off+4] = new
    off = pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
    checksum = pefile.PE(data=bytes(image), fast_load=True).generate_checksum()
    new = struct.pack('<I', checksum)
    record(off, original[off:off+4], new, 'Recalculate PE checksum')
    image[off:off+4] = new
    # Independent replay of the entire patch ledger must reproduce every byte.
    replay = bytearray(original)
    for change in changes:
        off = change['offset']; before = bytes.fromhex(change['old_hex']); after = bytes.fromhex(change['new_hex'])
        if before:
            require(replay[off:off+len(before)] == before, 'Overlapping or incorrect audit entry')
            replay[off:off+len(before)] = after
        else:
            require(off == len(replay), 'Noncontiguous append audit')
            replay.extend(after)
    require(replay == image, 'Patch audit does not reconstruct output')
    digest = sha(image)
    require(digest == LOCK['expected_miniport_sha256'], 'Output differs from reviewed clean candidate: ' + digest)
    (out / 'nv4_mini.sys').write_bytes(image)
    (out / 'PATCHES.json').write_text(json.dumps(changes, indent=2)+'\n')
    with (out / 'PATCHES.txt').open('w', encoding='utf-8', newline='\n') as stream:
        stream.write('P2200 Driver 72 Clean RC1 - complete binary patch ledger\nOffsets are FILE offsets; VA is preferred-image address (base 0x10000).\nOLD <EOF> means appended bytes, not bytes overwritten. Unchanged bytes within a patch span are printed too.\nInput SHA256 '+sha(original)+'\nOutput SHA256 '+digest+'\n\n')
        for change in sorted(changes, key=lambda x: x['offset']):
            before = bytes.fromhex(change['old_hex']); after = bytes.fromhex(change['new_hex'])
            stream.write(f"OFFSET 0x{change['offset']:08X}, VA 0x{change['va']:08X}: {change['reason']}\n")
            for n in range(0, len(after), 16):
                stream.write(f"  0x{change['offset']+n:08X} OLD {before[n:n+16].hex(' ') if before else '<EOF>'}\n")
                stream.write(f"             NEW {after[n:n+16].hex(' ')}\n")
            stream.write('\n')
    return bytes(image), changes


def prepare_payload(tree, miniport, out):
    before = {p.relative_to(tree).as_posix(): sha(p.read_bytes()) for p in tree.rglob('*') if p.is_file()}
    require(sha((tree / 'Display.Driver/nv4_disp.dll').read_bytes()) == LOCK['display_dll_sha256'], 'Unexpected display DLL')
    (tree / 'Display.Driver/nv4_mini.sys').write_bytes(miniport)
    edits = []
    for inf in sorted((tree / 'Display.Driver').glob('*.inf')):
        old = inf.read_bytes()
        lines = old.decode('cp1252').splitlines(keepends=True)
        kept = []
        for line in lines:
            if re.match(r'^\s*%[^%]+%\s*=\s*[^,]+,\s*PCI\\VEN_', line, re.I):
                if inf.name.lower() != 'nv4_dispi.inf' or 'PCI\\VEN_10DE&DEV_1C31' not in line:
                    continue
            kept.append(line)
        text = ''.join(kept)
        if inf.name.lower() == 'nv4_dispi.inf':
            text = text.replace('XPP_GPU_38 = "Quadro P2200"', 'XPP_GPU_38 = "Quadro P2200 (Driver 72 Clean RC1)"')
            text, date_count = re.subn(r'(DriverVer\s*=\s*)10/19/2026,', r'\g<1>11/04/2026,', text)
            require(date_count == 1, 'Expected exactly one P2200 INF driver date')
            anchor = next(x for x in text.splitlines() if 'JVC9213,ADD,OEM+' in x)
            addition = 'HKR,,NV_R&T,%REG_SZ_APPEND%,"R&T0000=' + LOCK['rule'] + '"'
            require(text.count(anchor) == 1 and LOCK['rule'] not in text, 'Timing insertion ambiguous')
            text = text.replace(anchor, anchor + '\r\n' + addition)
        new = text.encode('cp1252')
        inf.write_bytes(new)
        edits.append(dict(path=inf.relative_to(tree).as_posix(), old_sha256=sha(old), new_sha256=sha(new)))
    matches = []
    for inf in (tree / 'Display.Driver').glob('*.inf'):
        matches.extend(re.findall(r'^\s*%[^%]+%\s*=\s*[^,]+,\s*(PCI\\[^\r\n]+)', inf.read_text(encoding='cp1252'), re.M|re.I))
    require(matches == ['PCI\\VEN_10DE&DEV_1C31'], 'P2200-only INF restriction failed')
    guide = (HERE / 'XP-TEST.txt').read_text()
    (tree / 'README-INSTALL.txt').write_text(guide)
    (tree / 'ListDevices.txt').write_text('PCI\\VEN_10DE&DEV_1C31 = Quadro P2200 (Driver 72 Clean RC1)\nXP hardware acceptance pending.\n')
    cfg = tree / 'setup.cfg'
    require(b'Forceware 382.69 (10-19-2026)' in cfg.read_bytes(), 'Unexpected setup title')
    cfg.write_bytes(cfg.read_bytes().replace(b'Forceware 382.69 (10-19-2026)', b'P2200 Driver 72 Clean RC1'))
    nvi = tree / 'Display.Driver/DisplayDriver.nvi'
    require(b'timestamp="2026-10-19T12:00:00"' in nvi.read_bytes(), 'Unexpected NVI build date')
    nvi.write_bytes(nvi.read_bytes().replace(b'timestamp="2026-10-19T12:00:00"', b'timestamp="2026-11-04T12:00:00"'))
    after = {p.relative_to(tree).as_posix(): sha(p.read_bytes()) for p in tree.rglob('*') if p.is_file()}
    allowed = {'Display.Driver/nv4_mini.sys', 'Display.Driver/DisplayDriver.nvi', 'README-INSTALL.txt', 'ListDevices.txt', 'setup.cfg'} | {r['path'] for r in edits}
    require(all(before[n] == h or n in allowed for n, h in after.items()), 'Unexpected package modification')
    (tree / 'SHA256SUMS.txt').write_text(''.join(h+'  '+n+'\n' for n,h in sorted(after.items()) if n!='SHA256SUMS.txt'))
    (out / 'PACKAGE-CHANGES.json').write_text(json.dumps(dict(inf_changes=edits, timing_rule=LOCK['rule'],
        changed_files=sorted(n for n in after if before[n] != after[n]), display_dll_sha256=LOCK['display_dll_sha256']), indent=2)+'\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inputs', type=Path, required=True, help='Folder containing the three exact installers')
    ap.add_argument('--out', type=Path, required=True, help='New output folder; existing folders are refused')
    ap.add_argument('--sevenzip', type=Path, default=Path(r'C:\Program Files\7-Zip\7z.exe'))
    args = ap.parse_args()
    inputs = args.inputs.resolve(); out = args.out.resolve(); seven = args.sevenzip.resolve()
    require(not out.exists(), 'Output already exists; choose a new folder')
    require(seven.is_file(), '7-Zip not found: ' + str(seven))
    # Verify ALL three installers before extracting any input or creating output.
    for row in LOCK['inputs'].values():
        checked(inputs / row['filename'], row['sha256'])
    out.mkdir(parents=True)
    try:
        work = out / 'work'; work.mkdir()
        tree = out / 'XP-payload'
        extract(seven, inputs / LOCK['inputs']['baseline']['filename'], tree)
        original = checked(tree / 'Display.Driver/nv4_mini.sys', LOCK['inputs']['baseline']['module_sha256'])
        donors = {}
        for key in ('431', '384'):
            folder = work / ('donor-' + key)
            extract(seven, inputs / LOCK['inputs'][key]['filename'], folder, 'Display.Driver/nvlddmkm.sy_')
            expanded = folder / 'expanded'
            extract(seven, folder / 'Display.Driver/nvlddmkm.sy_', expanded)
            data = checked(expanded / 'nvlddmkm.sys', LOCK['inputs'][key]['module_sha256'])
            donors[key] = pefile.PE(data=data, fast_load=True)
        miniport, changes = build_miniport(original, donors, out)
        prepare_payload(tree, miniport, out)
        report = dict(title=LOCK['title'], miniport_sha256=sha(miniport), miniport_bytes=len(miniport),
                      display_dll_sha256=LOCK['display_dll_sha256'], inputs=LOCK['inputs'],
                      patch_entries=len(changes), source='three hash-verified user-supplied installers',
                      diagnostics_added=False, fifo_request_restored=True, vpr_431_retained=True,
                      live_XP_tested=False, installer_executed=False)
        (out / 'BUILD-REPORT.json').write_text(json.dumps(report, indent=2)+'\n')
        for name in ('INSTALL-REBUILT-XP.cmd', 'Install-Rebuilt-XP.vbs', 'XP-TEST.txt'):
            shutil.copyfile(HERE / name, out / name)
        print('PASS: exact clean candidate rebuilt. SHA-256:', sha(miniport))
        print('Full audit:', out / 'PATCHES.txt')
        print('XP payload:', tree)
    except Exception as exc:
        (out / 'BUILD-FAILED.txt').write_text(str(exc)+'\nDo not install this incomplete output.\n')
        raise


if __name__ == '__main__':
    main()
