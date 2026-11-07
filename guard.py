"""Readable, deterministic x86 guard emitter; no downloaded assembler required.
Every instruction is emitted alongside its assembly spelling and disassembled
independently by Capstone. All branches are relative: no added PE relocations.
SPDX-License-Identifier: GPL-3.0-only WITH NVIDIA-integration-exception
"""
import struct
BASE=0x10000
HOOK=0x45a392
ACCEPT=0x45a3a2
REJECT=0x45a398
ROW=bytes.fromhex('0014a0057800000000000800fb7b01000014a005c81430002000f40503000a00000000000001000000000000fb7b01000014a005c81430002000f40503000a000000000000010000000000000000000000000000')
assert len(ROW)==84

def saved_guard(start):
 code=bytearray(); lines=[]; labels={}; fixups=[]
 def emit(raw,asm):
  off=len(code);code.extend(bytes.fromhex(raw) if isinstance(raw,str) else raw);lines.append((off,asm))
 def label(n):labels[n]=start+len(code);lines.append((len(code),n+':'))
 def branch(op,target,asm):
  b=bytes.fromhex(op);emit(b+bytes(4),asm);fixups.append((len(code)-4,target))
 def fail():branch('0f85','reject','jne reject')
 def cmp32(prefix,value,asm):emit(bytes.fromhex(prefix)+struct.pack('<I',value),asm);fail()
 label('samsung_saved_guard')
 emit('6683fb08','cmp bx, 8')
 branch('0f85',ACCEPT,'jne native_accept') # Preserve native non-OEM behavior.
 emit('9c','pushfd');emit('60','pushad')
 # At the original hook, [esp+0x10] is the output; ESI is only requested width.
 emit('8b742434','mov esi, dword ptr [esp + 0x34]')
 emit('85f6','test esi, esi');branch('0f84','reject','je reject')
 cmp32('81bef82c0000',2,'cmp dword ptr [esi + 0x2cf8], 2')
 cmp32('81befc2c0000',8,'cmp dword ptr [esi + 0x2cfc], 8')
 emit('81be2c00000080000000','cmp dword ptr [esi + 0x2c], 0x80')
 branch('0f82','reject','jb reject')
 emit('81be2c00000000020000','cmp dword ptr [esi + 0x2c], 0x200')
 branch('0f87','reject','ja reject')
 cmp32('817e30',0xffffff00,'cmp dword ptr [esi + 0x30], 0xffffff00')
 cmp32('817e34',0x00ffffff,'cmp dword ptr [esi + 0x34], 0xffffff')
 cmp32('817e38',0xe0282d4c,'cmp dword ptr [esi + 0x38], 0xe0282d4c')
 cmp32('817d04',0x05a01400,'cmp dword ptr [ebp + 4], 0x5a01400')
 cmp32('817d08',0x00780020,'cmp dword ptr [ebp + 8], 0x780020')
 # EAX points at row+2. Check the complete 84-byte canonical record, including
 # BOTH timing copies, OEM source, 120 key, reserved fields and sync polarity.
 for off in range(0,len(ROW),4):
  value=struct.unpack_from('<I',ROW,off)[0];disp=off-2
  if off == 40:
   # Two recorded representations are valid. Keep the complete pair coupled.
   emit('8b5026', 'mov edx, dword ptr [eax + 0x26]')
   emit('85d2', 'test edx, edx')
   branch('0f84', 'known_pair', 'je known_pair')
   cmp32('81fa', 0x414ce8ff, 'cmp edx, 0x414ce8ff')
   label('known_pair')
   continue
  if off == 72:
   emit('395046', 'cmp dword ptr [eax + 0x46], edx')
   fail()
   continue
  prefix=bytes([0x81,0x78,disp&255])+struct.pack('<I',value)
  emit(prefix,f'cmp dword ptr [eax {"+" if disp>=0 else "-"} {abs(disp):#x}], {value:#x}');fail()
 emit('31d2','xor edx, edx');emit('b980000000','mov ecx, 0x80')
 label('checksum_loop')
 emit('02540e2f','add dl, byte ptr [esi + ecx + 0x2f]')
 emit('49','dec ecx');branch('0f85','checksum_loop','jne checksum_loop')
 emit('84d2','test dl, dl');fail()
 emit('61','popad');emit('9d','popfd');branch('e9',ACCEPT,'jmp native_accept')
 label('reject');emit('61','popad');emit('9d','popfd');branch('e9',REJECT,'jmp native_reject')
 for off,target in fixups:
  target=labels[target] if isinstance(target,str) else target
  struct.pack_into('<i',code,off,target-(start+off+4))
 return bytes(code),lines,labels

PRODUCER=0x875bdb
PROLOGUE=bytes.fromhex('8dbd90000000')

def producer(entry):
    code=bytearray(b'\x9c') # pushfd; compare without changing caller flags
    skip=[]
    checks={0:0x14001400,4:0x05a005a0,8:0x00200020,12:0x00780078,
            0x30:0x2d4ce028,0x34:0,0x50:10}
    for i in range(0,28,4):
        checks[0x70+i]=struct.unpack_from('<I',ROW,12+i)[0]
    for offset,value in checks.items():
        code.extend(b'\x81\xbd'+struct.pack('<I',offset)+struct.pack('<I',value)+b'\x0f\x85'+bytes(4))
        skip.append(len(code)-4)
    code.extend(bytes.fromhex('c7858c00000000000000')) # primary refresh = unspecified
    resume=len(code)
    for offset in skip:struct.pack_into('<i',code,offset,resume-offset-4)
    code.extend(b'\x9d'+PROLOGUE+b'\xe9')
    code.extend(struct.pack('<i',PRODUCER+6-(entry+len(code)+4)))
    return bytes(code)

def assemble(start):
    guard, lines, symbols=saved_guard(start)
    aligned=guard+bytes((-len(guard))%32)
    entry=start+len(aligned)
    symbols['samsung_producer']=entry
    return aligned+producer(entry),lines,symbols
