"""Reassemble the code-only patch from source; never execute a driver.
SPDX-License-Identifier: GPL-3.0-only WITH NVIDIA-integration-exception
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def assemble(binutils, out):
    lock = json.loads((HERE / 'inputs-and-layout.json').read_text())
    aliases = dict(original_gp106_fecs=0x4f0630, original_gp106_gpccs=0x4f07a0,
                   original_gp106_gr=0x4f12b0, region_continue=0x7253b1,
                   region_reject=0x7253f4, previous_copy=0xec01cd,
                   after_copy=0x7271e8, original_arguments=0x7271da,
                   native_failure=0x7272c1)
    aliases.update({r['name'] + '_payload': r['output_va'] for r in lock['resources']})
    out.mkdir(parents=True, exist_ok=False)
    start = 0x10000 + lock['baseline_bytes']
    script = '\n'.join(f'{n} = 0x{v:x};' for n, v in aliases.items())
    script += f'\nSECTIONS {{ . = 0x{start:x}; .text : {{ *(.text*) }} /DISCARD/ : {{ *(.note*) *(.comment*) *(.eh_frame*) *(.idata*) *(.reloc*) }} }}\n'
    (out / 'clean.ld').write_text(script)

    def run(tool, *args):
        exe = binutils / ('i686-w64-mingw32-' + tool + '.exe')
        result = subprocess.run([str(exe), *map(str, args)], cwd=out,
                                capture_output=True, text=True, check=True)
        (out / (tool + '.log')).write_text(result.stdout + result.stderr)
        return result.stdout

    run('as', '--32', '-o', 'clean.o', HERE / 'src/clean.s')
    run('ld', '-m', 'i386pe', '--image-base', '0', '--disable-dynamicbase',
        '--disable-reloc-section', '-T', 'clean.ld', '-e', 'clean_begin',
        '-o', 'clean.exe', 'clean.o')
    run('objcopy', '-O', 'binary', '-j', '.text', 'clean.exe', 'clean.bin')
    symbols = {a[2]: int(a[0], 16) for line in run('nm', '-n', 'clean.exe').splitlines()
               if len(a := line.split()) == 3}
    code = (out / 'clean.bin').read_bytes()
    if len(code) != lock['code_bytes'] or symbols['clean_begin'] != start:
        raise RuntimeError('Unexpected code layout')
    return code, symbols


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binutils', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    code, symbols = assemble(args.binutils.resolve(), args.out.resolve())
    reference = bytes.fromhex((HERE / 'src/clean-code.hex').read_text())
    expected = json.loads((HERE / 'src/symbols.json').read_text())
    if code != reference or symbols != expected:
        raise RuntimeError('Reassembled code differs from the reviewed patch')
    print('PASS: source assembles to the exact reviewed code:', hashlib.sha256(code).hexdigest())
