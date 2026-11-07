"""Independent static and x86 execution checks for the clean candidate.
External memcpy is modeled; no OS driver or GPU code is loaded on this host.
SPDX-License-Identifier: GPL-3.0-only WITH NVIDIA-integration-exception
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.x86_const import *

HERE = Path(__file__).resolve().parent
LOCK = json.loads((HERE / 'inputs-and-layout.json').read_text())
SYMBOLS = json.loads((HERE / 'src/symbols.json').read_text())
BASE = 0x10000
CTX, NODE, SRC, DST, DESC, STACK, END = [0x4000000 + i*0x10000 for i in range(7)]
sha = lambda b: hashlib.sha256(b).hexdigest()
checks = []


def check(ok, name):
    if not ok:
        raise AssertionError(name)
    checks.append(name)


class Machine:
    def __init__(self, raw, base):
        self.bias = base-BASE
        pe = pefile.PE(data=raw)
        pe.relocate_image(base)
        mapped = pe.get_memory_mapped_image()
        self.u = Uc(UC_ARCH_X86, UC_MODE_32)
        self.u.mem_map(base, (len(mapped)+4095)&~4095)
        self.u.mem_write(base, mapped)
        self.u.mem_map(CTX, 0x70000)
        self.copies = []
        self.stops = set()
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.put(CTX+0x714, 0x130)
        self.put(CTX+0x710, 6)

    def hook(self, u, addr, size, _):
        if addr == 0x470d10+self.bias:
            sp = u.reg_read(UC_X86_REG_ESP)
            ret, dst, src, n = struct.unpack('<4I', u.mem_read(sp, 16))
            if not 0 < n <= 256:
                raise AssertionError('Unexpected modeled copy size')
            self.copies.append(n)
            u.mem_write(dst, bytes(u.mem_read(src, n)))
            u.reg_write(UC_X86_REG_EAX, dst)
            u.reg_write(UC_X86_REG_ESP, sp+16)
            u.reg_write(UC_X86_REG_EIP, ret)
        elif addr in self.stops:
            u.emu_stop()

    def put(self, addr, value):
        self.u.mem_write(addr, struct.pack('<I', value))

    def get(self, addr):
        return struct.unpack('<I', self.u.mem_read(addr, 4))[0]

    def call(self, va, *args):
        sp = STACK+0x8000
        self.u.mem_write(sp, struct.pack('<'+'I'*(len(args)+1), END, *args))
        self.u.reg_write(UC_X86_REG_ESP, sp)
        self.u.reg_write(UC_X86_REG_EFLAGS, 2)
        self.u.emu_start(va+self.bias, END, count=100000)
        if self.u.reg_read(UC_X86_REG_EIP) != END or self.u.reg_read(UC_X86_REG_ESP) != sp+4*(len(args)+1):
            raise AssertionError('Function failed to return with its stdcall ABI: '+hex(va))
        return self.u.reg_read(UC_X86_REG_EAX)


def static(raw, baseline, output):
    check(sha(raw) == LOCK['expected_miniport_sha256'], 'Exact released miniport SHA-256')
    check(sha(baseline) == LOCK['inputs']['baseline']['module_sha256'], 'Exact original miniport SHA-256')
    old = pefile.PE(data=baseline); new = pefile.PE(data=raw)
    check(new.generate_checksum() == new.OPTIONAL_HEADER.CheckSum, 'PE checksum')
    check(len(raw) == LOCK['output_bytes'] == new.OPTIONAL_HEADER.SizeOfImage, 'Image extent')
    # This allowlist is independent of the builder-generated patch ledger.
    ranges = [(0xd06956-BASE,4),(0x7253a9-BASE,8),(0x7271d4-BASE,6)]
    ranges += [(va-BASE,4) for va in (0xb7b458,0xb7b474,0xb7b484)]
    ranges += [(0xec07f0-BASE+i*12,8) for i in range(9)]
    ranges += [(va-BASE,4) for va in (0xec04c1,0xec04c8,0xec04dc,0xec04e3,0xec04d5,0xec04ce)]
    ranges += [(old.OPTIONAL_HEADER.get_field_absolute_offset(n),4) for n in ('SizeOfCode','SizeOfInitializedData','SizeOfImage','CheckSum')]
    ranges += [(old.sections[-1].get_field_absolute_offset(n),4) for n in ('Misc_VirtualSize','SizeOfRawData')]
    restored = bytearray(raw[:len(baseline)])
    for off,n in ranges:
        restored[off:off+n] = baseline[off:off+n]
    check(restored == baseline, 'Every original-image byte outside the independent allowlist is identical to SupraGSX')
    check(raw[len(baseline):len(baseline)+1024] == bytes.fromhex((HERE/'src/clean-code.hex').read_text()), 'Complete appended code equals reviewed source assembly')
    cursor = len(baseline)+1024
    for r in LOCK['resources']:
        check(raw[cursor:r['output_offset']] == bytes(r['output_offset']-cursor), 'Zero padding before '+r['name'])
        cursor = r['output_offset']+r['size']
        check(sha(raw[r['output_offset']:cursor]) == r['sha256'], 'Exact donor resource '+r['name'])
    check(raw[cursor:] == bytes(len(raw)-cursor), 'Final alignment padding')
    for i,(a,b) in enumerate(zip(old.OPTIONAL_HEADER.DATA_DIRECTORY,new.OPTIONAL_HEADER.DATA_DIRECTORY)):
        check((a.VirtualAddress,a.Size) == (b.VirtualAddress,b.Size), f'PE directory {i} unchanged')
        if a.Size:
            check(old.get_data(a.VirtualAddress,a.Size) == new.get_data(b.VirtualAddress,b.Size), f'PE directory {i} contents unchanged')
    # Explicitly identify the prior diagnostic suppression sites now native.
    for va,n,name in [(0x46e7a6,5,'FIFO call'),(0xc773be,5,'initialization call'),
                      (0xc7289a,6,'timer start 1'),(0xc77771,6,'timer start 2'),
                      (0x4453c0,5,'timer callback'),(0x644ca0,9,'GR status check'),
                      (0xc72320,6,'IOCTL entry'),(0x874890,8,'mode validator'),
                      (0x72716d,6,'WPR entry'),(0xd06920,0x36,'SEC2 guards')]:
        check(new.get_data(va-BASE,n) == old.get_data(va-BASE,n), 'Restored native '+name)
    cs=Cs(CS_ARCH_X86,CS_MODE_32)
    check([(i.mnemonic,i.op_str) for i in cs.disasm(new.get_data(0x46e7a6-BASE,5),0x46e7a6)] == [('call','0x4d10f0')], 'Native FIFO request targets 0x4D10F0')
    check(sha((output/'XP-payload/Display.Driver/nv4_disp.dll').read_bytes()) == LOCK['display_dll_sha256'], 'Display DLL exactly equals uninstrumented SupraGSX/Driver 69 DLL')
    inf=(output/'XP-payload/Display.Driver/nv4_dispi.inf').read_text(encoding='cp1252')
    check(inf.count(LOCK['rule']) == 1, 'ASUS 1066.56 MHz INF rule appears exactly once')
    check('nv_timingRestrictions_addreg' in inf.split('[Section012.SoftwareSettings]',1)[1].split('[',1)[0], 'P2200 software install applies timing section')


def resource_and_constructor_tests(raw, base):
    m=Machine(raw,base)
    for r in LOCK['resources']:
        if 'target_descriptor_va' in r:
            pointer=r['target_descriptor_va']+m.bias
        elif 'target_pointer_va' in r:
            pointer=m.get(r['target_pointer_va']+m.bias)
            check(sha(m.u.mem_read(pointer,r['size']))==r['sha256'], f'{base:x} relocated VPR pointer {r["name"]}')
            continue
        else:
            pointer=m.call(SYMBOLS['get_'+r['name']],CTX)
        n,p,flags=struct.unpack('<3I',m.u.mem_read(pointer,12))
        check(n==r['size'] and flags==0 and sha(m.u.mem_read(p,n))==r['sha256'], f'{base:x} relocated descriptor/getter {r["name"]}')
    # Execute the real baseline constructors, then the replacement callback writes.
    for name, slots in [('fecs',{0x28:'fecs_signature',0x34:'fecs_boot',0x38:'fecs_header'}),
                        ('gpccs',{0x24:'gpccs_signature',0x30:'gpccs_boot',0x34:'gpccs_header'}),
                        ('gr',{0x3e4:'gr_bundle'})]:
        m.u.mem_write(NODE,b'\xa5'*0x800)
        m.u.reg_write(UC_X86_REG_EBX,0x12345678);m.u.reg_write(UC_X86_REG_ESI,0x23456789);m.u.reg_write(UC_X86_REG_EDI,0x3456789a)
        m.call(SYMBOLS['gp106_'+name],CTX,NODE)
        check(all(m.get(NODE+off)==SYMBOLS['get_'+label]+m.bias for off,label in slots.items()),f'{base:x} real GP106 {name} constructor callback installation')
        check([m.u.reg_read(r) for r in (UC_X86_REG_EBX,UC_X86_REG_ESI,UC_X86_REG_EDI)]==[0x12345678,0x23456789,0x3456789a], f'{base:x} {name} constructor nonvolatile registers')


def regions(raw,base):
    m=Machine(raw,base);u=m.u;sp=STACK+0x8000
    field_reads=[]
    u.hook_add(UC_HOOK_MEM_READ,lambda *args:field_reads.append(1),begin=NODE,end=NODE+3)
    m.stops={0x7253ba+m.bias,0x7253f4+m.bias}
    cases=[(a,e,True,None) for a in range(32) for e in range(32)]
    cases += [(12,15,False,None),(0xffffffff,0xffffffff,True,None),(0xffffffff,15,True,None)]
    cases += [(12,15,True,i) for i in range(4)]
    for actual,expected,sixth_ok,bad in cases:
        # All six original comparisons execute, except the targeted fifth predicate.
        u.mem_write(sp,bytes(0x80));m.put(NODE,expected);m.put(NODE+4,91)
        for off,val in [(0x14,actual),(0x18,91 if sixth_ok else 92),(0x1c,11),(0x20,22),(0x24,33),(0x28,44)]:m.put(sp+off,val)
        if bad is not None:m.put(sp+[0x1c,0x20,0x24,0x28][bad],99)
        for reg,val in [(UC_X86_REG_ESP,sp),(UC_X86_REG_EDI,NODE),(UC_X86_REG_ESI,CTX),(UC_X86_REG_EBX,11),(UC_X86_REG_EBP,22),(UC_X86_REG_EAX,33),(UC_X86_REG_EDX,44),(UC_X86_REG_EFLAGS,2)]:u.reg_write(reg,val)
        old=bytes(u.mem_read(NODE,8))
        reads_before=len(field_reads)
        u.emu_start(0x725389+m.bias,END,count=100)
        accept=(actual==expected or (actual,expected)==(12,15)) and sixth_ok and bad is None
        if u.reg_read(UC_X86_REG_EIP)!=(0x7253ba if accept else 0x7253f4)+m.bias or u.reg_read(UC_X86_REG_ESP)!=sp or bytes(u.mem_read(NODE,8))!=old or len(field_reads)-reads_before != int(bad is None):
            raise AssertionError(('region mismatch',base,actual,expected,sixth_ok,bad))
    check(True,f'{base:x} region predicate: {len(cases)} cases including other-field rejection and no source mutation')


def sec2(raw,base):
    desc=next(r for r in LOCK['resources'] if r['name']=='sec2_desc')
    for mode in ('valid','old431','oldstock','wrong_id','wrong_length','capacity','null','boot','family'):
        m=Machine(raw,base);u=m.u
        u.mem_write(DESC,raw[desc['output_offset']:desc['output_offset']+desc['size']])
        source=bytes(range(56));u.mem_write(SRC,source);u.mem_write(DST,b'\xcc'*256)
        m.put(NODE+4,7);m.put(NODE+0xf4,256);m.put(NODE+0x168,DESC)
        changes={'old431':(DESC+12,0x017e4379),'oldstock':(DESC+12,0x014a7c8c),'wrong_id':(NODE+4,6),
                 'capacity':(NODE+0xf4,128),'null':(NODE+0x168,0),'boot':(DESC+0x5c,0xfc00),'family':(CTX+0x714,0x120)}
        if mode in changes:m.put(*changes[mode])
        u.reg_write(UC_X86_REG_EDI,NODE);u.reg_write(UC_X86_REG_ESI,CTX)
        length=55 if mode=='wrong_length' else 56
        check(m.call(0xec01cd,DST,SRC,length)==DST,f'{base:x} SEC2 {mode} return/stack')
        expected=bytearray(source[:length])
        if mode=='valid':
            expected=bytearray(84)
            for a,b in [(0x20,4),(0x24,8),(0x28,12),(0x30,0x14),(0x3c,0x18),(0x40,0x1c),(0x44,0x20),(0x48,0x24),(0x4c,0x30),(0x50,0x34)]:expected[a:a+4]=source[b:b+4]
            expected[0x2c:0x30]=u.mem_read(DESC+0x74,4)
        check(bytes(u.mem_read(DST,256))==bytes(expected)+b'\xcc'*(256-len(expected)) and bytes(u.mem_read(SRC,56))==source and m.copies==[len(expected)],f'{base:x} SEC2 {mode} exact copy and guards')


def gr_copy(raw,base):
    for name,fid in [('fecs',2),('gpccs',3)]:
        row=next(r for r in LOCK['resources'] if r['name']==name+'_signature')
        for mode in ('valid','other_signature','short_source','capacity','null','other_engine'):
            m=Machine(raw,base);u=m.u;sp=STACK+0x8000
            sig=bytearray(raw[row['output_offset']:row['output_offset']+192])
            if mode=='other_signature':sig[0]^=0x80
            m.put(NODE+4,9 if mode=='other_engine' else fid);u.mem_write(NODE+0x1c,bytes(sig))
            m.put(NODE+0x158,72 if mode=='short_source' else 76);m.put(NODE+0xf4,80 if mode=='capacity' else 256)
            source=bytes(range(76));u.mem_write(NODE+0x10c,source);old=bytes(u.mem_read(NODE,0x180))
            u.mem_write(DST-8,b'\xcc'*112)
            for reg,val in [(UC_X86_REG_ESP,sp),(UC_X86_REG_EDI,NODE),(UC_X86_REG_ESI,CTX),(UC_X86_REG_EBX,0 if mode=='null' else DST),(UC_X86_REG_EFLAGS,2)]:u.reg_write(reg,val)
            m.stops={0x7271e8+m.bias,0x7272c1+m.bias};u.emu_start(0x7271d4+m.bias,END,count=10000)
            reject=mode in ('short_source','capacity','null')
            expected=b'' if reject else source+bytes(8) if mode=='valid' else source
            check(u.reg_read(UC_X86_REG_EIP)==(0x7272c1 if reject else 0x7271e8)+m.bias and u.reg_read(UC_X86_REG_ESP)==sp,f'{base:x} {name} {mode} continuation/stack')
            check(bytes(u.mem_read(DST-8,112))==b'\xcc'*8+expected+b'\xcc'*(104-len(expected)) and bytes(u.mem_read(NODE,0x180))==old,f'{base:x} {name} {mode} bounded copy and source preservation')
            check(m.copies==([] if reject else [len(expected)]) and (not reject or u.reg_read(UC_X86_REG_EBX)==0x57),f'{base:x} {name} {mode} native rejection/copy count')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build',type=Path,required=True)
    ap.add_argument('--baseline',type=Path,required=True,help='nv4_mini.sys extracted from hash-verified original installer')
    args=ap.parse_args();out=args.build.resolve();raw=(out/'nv4_mini.sys').read_bytes()
    static(raw,args.baseline.read_bytes(),out)
    for base in (0x10000,0x10000000,0xb6200000):
        resource_and_constructor_tests(raw,base);regions(raw,base);sec2(raw,base);gr_copy(raw,base)
    report=dict(miniport_sha256=sha(raw),passed=True,checks=len(checks),details=checks,
                region_cases=3*1031,load_bases=['0x10000','0x10000000','0xb6200000'],
                limitations='x86 execution with modeled memcpy; no live GPU/OS acceptance',live_XP_tested=False)
    (out/'OFFLINE-VERIFICATION.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS:',len(checks),'offline checks, including 3093 region comparisons at three load bases')


if __name__=='__main__':
    main()
