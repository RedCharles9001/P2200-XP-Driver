from pathlib import Path
import argparse, hashlib, json, re, shutil, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from guard import *
HERE=Path(__file__).resolve().parent
LOCK=json.loads((HERE/'rebuild-base/inputs-and-layout.json').read_text())
RULE='5120,1440,32,120,*,SAME028,ADD,OEM,97275,5320,48,32,1524,3,10,+-'
TITLE='P2200 Driver 76 G95SC Candidate'
sha=lambda data:hashlib.sha256(data).hexdigest()

def binary(original,out):
 assert sha(original)==LOCK['expected_miniport_sha256']
 pe=pefile.PE(data=original);assert len(original)==pe.OPTIONAL_HEADER.SizeOfImage
 assert pe.OPTIONAL_HEADER.ImageBase==BASE and pe.OPTIONAL_HEADER.FileAlignment==pe.OPTIONAL_HEADER.SectionAlignment==32
 assert all(s.PointerToRawData==s.VirtualAddress for s in pe.sections)
 assert pe.sections[-1].Characteristics==0xe8000060
 image=bytearray(original);changes=[]
 def patch(off,new,why):
  old=bytes(image[off:off+len(new)]);image[off:off+len(new)]=new
  changes.append(dict(offset=off,old_hex=old.hex(),new_hex=new.hex(),reason=why))
 start=BASE+len(original);code,lines,symbols=assemble(start)
 assert original[HOOK-BASE:HOOK-BASE+6]==bytes.fromhex('6683fb08750a')
 relocs={e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type==3}
 assert not any(HOOK-BASE-3<=x<HOOK-BASE+6 for x in relocs)
 patch(HOOK-BASE,b'\xe9'+struct.pack('<i',start-HOOK-5)+b'\x90','Saved OEM cap decision -> exact Samsung/DP/120 guard')
 assert original[PRODUCER-BASE:PRODUCER-BASE+6]==PROLOGUE
 assert not any(PRODUCER-BASE-3<=r<PRODUCER-BASE+6 for r in relocs)
 patch(PRODUCER-BASE,b'\xe9'+struct.pack('<i',symbols['samsung_producer']-PRODUCER-5)+b'\x90','SAME028 short OEM timing: initialize primary refresh before native copy')
 appended=code+bytes((-len(code))%32);image.extend(appended)
 changes.append(dict(offset=len(original),old_hex='',new_hex=appended.hex(),reason='Position-independent guarded code, followed by zero alignment padding'))
 for obj,name,value in [(pe.sections[-1],'Misc_VirtualSize',len(image)-pe.sections[-1].PointerToRawData),(pe.sections[-1],'SizeOfRawData',len(image)-pe.sections[-1].PointerToRawData),(pe.OPTIONAL_HEADER,'SizeOfImage',len(image)),(pe.OPTIONAL_HEADER,'SizeOfCode',pe.OPTIONAL_HEADER.SizeOfCode+len(appended)),(pe.OPTIONAL_HEADER,'SizeOfInitializedData',pe.OPTIONAL_HEADER.SizeOfInitializedData+len(appended))]:
  patch(obj.get_field_absolute_offset(name),struct.pack('<I',value),'Extend existing final section: '+name)
 checksum=pefile.PE(data=bytes(image),fast_load=True).generate_checksum()
 patch(pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),struct.pack('<I',checksum),'Recalculate PE checksum')
 replay=bytearray(original)
 for c in changes:
  o=c['offset'];old=bytes.fromhex(c['old_hex']);new=bytes.fromhex(c['new_hex'])
  assert replay[o:o+len(old)]==old
  if old:replay[o:o+len(old)]=new
  else:assert o==len(replay);replay.extend(new)
 assert replay==image
 frozen=HERE/'CANDIDATE-LOCK.json'
 if frozen.exists():assert sha(image)==json.loads(frozen.read_text())['miniport_sha256'], 'Rebuild differs from frozen Driver76 candidate'
 (out/'nv4_mini.sys').write_bytes(image)
 (out/'PATCHES.json').write_text(json.dumps(changes,indent=2)+'\n')
 (out/'PATCHES.txt').write_text('\n\n'.join(f"FILE {c['offset']:#x}: {c['reason']}\nOLD {c['old_hex'] or '<EOF>'}\nNEW {c['new_hex']}" for c in changes)+'\n')
 (out/'guard-assembly.txt').write_text('\n'.join(f'{start+o:08x} {a}' for o,a in lines)+'\n')
 decoder=Cs(CS_ARCH_X86,CS_MODE_32)
 guard_bytes=saved_guard(start)[0]; entry=symbols['samsung_producer']
 dis=list(decoder.disasm(guard_bytes,start))+list(decoder.disasm(code[entry-start:],entry))
 assert sum(i.size for i in dis)==len(guard_bytes)+len(code)-(entry-start)
 (out/'guard-disassembly.txt').write_text('\n'.join(f'{i.address:08x} {i.bytes.hex():24} {i.mnemonic} {i.op_str}' for i in dis)+'\n')
 report=dict(title=TITLE,miniport_sha256=sha(image),parent_sha256=sha(original),miniport_bytes=len(image),guard_va=start,guard_bytes=len(code),symbols=symbols,samsung_rule=RULE,asus_rule=LOCK['rule'],display_dll_sha256=LOCK['display_dll_sha256'],live_XP_tested=False,installer_executed=False,USB_copied=False)
 (out/'BUILD-REPORT.json').write_text(json.dumps(report,indent=2)+'\n')
 return bytes(image),report

def payload(clean,out,mini):
 tree=out/'XP-payload'
 shutil.copytree(clean/'XP-payload',tree)
 before={p.relative_to(tree).as_posix():sha(p.read_bytes()) for p in tree.rglob('*') if p.is_file()}
 assert before['Display.Driver/nv4_mini.sys']==LOCK['expected_miniport_sha256']
 assert before['Display.Driver/nv4_disp.dll']==LOCK['display_dll_sha256']
 (tree/'Display.Driver/nv4_mini.sys').write_bytes(mini)
 inf=tree/'Display.Driver/nv4_dispi.inf';text=inf.read_bytes().decode('cp1252')
 anchor='HKR,,NV_R&T,%REG_SZ_APPEND%,"R&T0000='+LOCK['rule']+'"'
 assert text.count(anchor)==1 and RULE not in text
 text=text.replace(anchor,anchor+'\r\nHKR,,NV_R&T,%REG_SZ_APPEND%,"R&T0000='+RULE+'"')
 assert text.count('Quadro P2200 (Driver 72 Clean RC1)')==1
 text=text.replace('Quadro P2200 (Driver 72 Clean RC1)','Quadro P2200 (Driver 76 G95SC Candidate)')
 text,n=re.subn(r'(DriverVer\s*=\s*)11/04/2026,',r'\g<1>11/06/2026,',text);assert n==1
 assert text.count('11/06/2026, 10.18.13.8269') == 1
 text = text.replace('11/06/2026, 10.18.13.8269','11/06/2026, 10.18.13.8271')
 inf.write_bytes(text.encode('cp1252'))
 for name in ('setup.cfg','ListDevices.txt'):
  p=tree/name;b=p.read_bytes();assert b'Driver 72 Clean RC1' in b;p.write_bytes(b.replace(b'Driver 72 Clean RC1',b'Driver 76 G95SC Candidate'))
 nvi=tree/'Display.Driver/DisplayDriver.nvi';b=nvi.read_bytes();assert b'2026-11-04T12:00:00' in b;nvi.write_bytes(b.replace(b'2026-11-04T12:00:00',b'2026-11-06T12:00:00'))
 (tree/'README-INSTALL.txt').write_text('Driver 76 G95SC candidate. OFFLINE VERIFIED ONLY; XP acceptance pending.\nDo not install as part of this build. See the enclosing candidate README.txt.\nSamsung SAME028 5120x1440 nominal120 at source32 with a narrowly scoped saved-mode guard.\nASUS AUSAA34 timing and Driver72 firmware retained. Keep Driver69 rollback.\n')
 after={p.relative_to(tree).as_posix():sha(p.read_bytes()) for p in tree.rglob('*') if p.is_file() and p.name!='SHA256SUMS.txt'}
 changed=[n for n,h in after.items() if before.get(n)!=h]
 assert set(changed)=={'Display.Driver/nv4_mini.sys','Display.Driver/nv4_dispi.inf','Display.Driver/DisplayDriver.nvi','setup.cfg','ListDevices.txt','README-INSTALL.txt'}
 (tree/'SHA256SUMS.txt').write_text(''.join(h+'  '+n+'\n' for n,h in sorted(after.items())))
 (out/'PACKAGE-CHANGES.json').write_text(json.dumps(dict(changed_files=changed,before=before,after=after,samsung_rule=RULE,asus_rule=LOCK['rule']),indent=2)+'\n')


if __name__=='__main__':
 ap=argparse.ArgumentParser(description='Build and verify all 635 Driver 76 payload files.')
 ap.add_argument('--rebuild-base','--clean72',dest='clean72',type=Path,required=True,help='Intermediate output produced by rebuild-base/rebuild.py')
 ap.add_argument('--out',type=Path,required=True)
 args=ap.parse_args()
 args.out.mkdir(parents=True,exist_ok=False)
 mini,_=binary((args.clean72/'nv4_mini.sys').read_bytes(),args.out)
 payload(args.clean72,args.out,mini)
 expected=json.loads((HERE/'review/payload-sha256.json').read_text())
 tree=args.out/'XP-payload'
 actual={p.relative_to(tree).as_posix():sha(p.read_bytes()) for p in tree.rglob('*') if p.is_file()}
 if actual!=expected:raise SystemExit('Payload verification FAILED')
 if json.loads((args.out/'PATCHES.json').read_text())!=json.loads((HERE/'review/PATCHES.json').read_text()):raise SystemExit('Patch ledger mismatch')
 print('PASS: patch ledger, miniport and all',len(actual),'extracted release files match.')
