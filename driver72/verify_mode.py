"""Saved-mode replay against the actual clean miniport and display DLL.
The source mode cache and link state are modeled; execution stops before hardware
programming. This does not prove physical DP output or monitor acceptance.
SPDX-License-Identifier: GPL-3.0-only WITH NVIDIA-integration-exception
"""
from pathlib import Path
import argparse,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE
from unicorn.x86_const import *
HERE=Path(__file__).resolve().parent
BASE=0x10000
MINI_IMAGE=DISPLAY_RAW=EDID=None
def replay(hz, rate=30):
    def machine(base,image):
        cpu=Uc(UC_ARCH_X86,UC_MODE_32)
        cpu.mem_map(base,(len(image)+4095)&~4095)
        cpu.mem_write(base,image)
        cpu.mem_map(0x1000,0xe000)
        cpu.mem_map(0x4000000,0x40000)
        return cpu
    u=machine(BASE,MINI_IMAGE)
    device,out,opt,edid,rule,records,src_req,buf,meta,table,end=[0x4000000+i*0x4000 for i in range(11)]
    def put(addr,fmt,*v):u.mem_write(addr,struct.pack("<"+fmt,*v))
    def get(addr,fmt):return struct.unpack("<"+fmt,u.mem_read(addr,struct.calcsize("<"+fmt)))
    def call(addr,*args):
        put(0xb000,"I"*(1+len(args)),end,*args)
        u.reg_write(UC_X86_REG_ESP,0xb000)
        try:u.emu_start(addr,end,count=2000000)
        except Exception as e:raise RuntimeError(hex(u.reg_read(UC_X86_REG_EIP))) from e
        assert u.reg_read(UC_X86_REG_EIP)==end and u.reg_read(UC_X86_REG_ESP)==0xb004+4*len(args)
        return u.reg_read(UC_X86_REG_EAX)
    put(out,"I",0x400)
    put(out+8,"HH",3840,2160)
    put(out+0x18,"I",108000)
    put(out+0x2c,"I",256)
    u.mem_write(out+0x30,EDID)
    put(out+0x2cf8,"2I",2,8)
    put(device+0x6d0,"2I",out,1)
    put(device+0x1ac,"I",0x400)
    put(device+0x60,"I",0xffffffff)
    put(device+0x194,"II",table,records)
    put(device+0x1360,"I",meta)
    put(opt+0x28,"I",records)
    u.mem_write(rule,b"3840,2160,32,120,*,AUSAA34,ADD,OEM,106656,4000,48,32,2222,3,5,+-\0\0")
    assert call(0x876870,records,rule,1)==1
    call(0x871e30,out+0x30,256,out+0x234,0x400)
    assert call(0x876e20,opt,out+0x30,256,0x400,out+0x234)==0
    count=get(out+0x234,"I")[0]
    rows=[get(out+0x238+84*i,"3H")+(get(out+0x238+84*i+12,"I")[0],) for i in range(count)]
    assert (3840,2160,60,53325) in rows and (3840,2160,120,106656) in rows
    put(table,"8I",3840,2160,32,60,3840,2160,32,120)
    put(src_req,"I4H",0x400,3840,2160,32,hz)
    events=[]
    def observe(emu,a,size,data):events.append(hex(a))
    for pc in (0x454ad4,0x454aaa,0x877e10,0x45b208,0xd69f33):
        u.hook_add(UC_HOOK_CODE,observe,begin=pc,end=pc)
    # Model the OS I/O transfer between two separate PE address spaces.
    mini=u
    dll=pefile.PE(data=DISPLAY_RAW,fast_load=True)
    disp=machine(dll.OPTIONAL_HEADER.ImageBase,dll.get_memory_mapped_image())
    def dp_write(addr,fmt,*values):disp.mem_write(addr,struct.pack("<"+fmt,*values))
    def dp_read(addr,fmt):return struct.unpack("<"+fmt,disp.mem_read(addr,struct.calcsize("<"+fmt)))
    dp_write(device+0xa04,"I",opt)
    dp_write(device+0x6dc,"I",0x400)
    dp_write(src_req,"4I",3840,2160,hz,6)
    dp_write(0xb000,"6I",end,device,0,src_req,0,0)
    disp.reg_write(UC_X86_REG_ESP,0xb000)
    heap=0x4030000
    wire=[]
    boundary=[]
    def display_hook(cpu,addr,size,data):
        nonlocal heap
        sp=cpu.reg_read(UC_X86_REG_ESP)
        ra=dp_read(sp,"I")[0]
        def finish(value,cleanup):
            cpu.reg_write(UC_X86_REG_EAX,value)
            cpu.reg_write(UC_X86_REG_ESP,sp+4+cleanup)
            cpu.reg_write(UC_X86_REG_EIP,ra)
        if addr==0x24dd3c: # EngAllocMem
            heap+=0x100
            finish(heap,12)
        elif addr==0x24dd24:
            _,code,srcbuf,n,dstbuf,length,actual=dp_read(sp+4,"7I")
            if code==0x232fec:
                assert n==length==0x5c
                mini.mem_write(buf,bytes(cpu.mem_read(srcbuf,n)))
                io=buf+0x400
                put(io+4,"5I",io+0x80,buf,n,buf,length)
                mini.reg_write(UC_X86_REG_ESP,0xa000)
                mini.reg_write(UC_X86_REG_EBX,io)
                mini.reg_write(UC_X86_REG_EBP,device)
                mini.emu_start(0xc7519e,0xc76028,count=1000000)
                assert mini.reg_read(UC_X86_REG_EIP)==0xc76028 and get(io+0x84,"I")== (0x5c,)
                wire.append(get(buf+0x34,"I")[0])
                cpu.mem_write(dstbuf,bytes(mini.mem_read(buf,length)))
            elif code==0x232ee0 and ra in (0x47273,0x356baa):
                dp_write(dstbuf+12,"2I",rate,4) # reported link state, or HBR2 negative control
                dp_write(dstbuf+0x2c,"I",0x32) # DP query flags and depth capability
            else:
                # Peripheral queries do not supply mode timing in this fixture.
                if code not in (0x232014,0x2320a0,0x232ee0,0x233224):
                    raise RuntimeError(("unknown ioctl",hex(code),hex(ra)))
            dp_write(actual,"I",length)
            finish(0,28)
        elif addr==0x3a800: # RM I/O boundary, caller cleans stack
            finish(0,0)
        elif addr==0x49885:
            cpu.emu_stop()
        elif addr==0x481a0:
            boundary.append(dict(mask=dp_read(sp+4,"I")[0],depth=dp_read(sp+28,"I")[0]))
            cpu.emu_stop()
        elif addr==0x47e50:
            boundary.append(dict(dp_clock=dp_read(sp+8,"I")[0],rate=dp_read(sp+12,"I")[0],
                                 lanes=dp_read(sp+16,"I")[0],depth=dp_read(sp+20,"I")[0]))
    for pc in (0x24dd3c,0x24dd24,0x3a800,0x47e50,0x481a0,0x49885):
        disp.hook_add(UC_HOOK_CODE,display_hook,begin=pc,end=pc)
    try:disp.emu_start(0x48dd0,end,count=2000000)
    except Exception as e:raise RuntimeError((hex(disp.reg_read(UC_X86_REG_EIP)),hex(mini.reg_read(UC_X86_REG_EIP)),events,wire)) from e
    expected=106656 if hz==120 else 53325
    assert events==["0x454ad4","0x45b208","0xd69f33"] and wire==[expected]
    if rate==30:
        depth=2 if hz==120 else 3
        assert boundary==[dict(dp_clock=expected,rate=rate,lanes=4,depth=depth),dict(mask=0x400,depth=depth)]
        assert disp.reg_read(UC_X86_REG_EIP)==0x481a0
    else:
        assert boundary==[] and disp.reg_read(UC_X86_REG_EIP)==0x49885
    return dict(request=hz,rate_code=rate,mini_events=events,reply_clocks=wire,display_events=boundary,stop=hex(disp.reg_read(UC_X86_REG_EIP)))

if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build',type=Path,required=True)
    ap.add_argument('--edid',type=Path,default=HERE/'test-asus-edid.bin')
    args=ap.parse_args();lock=json.loads((HERE/'inputs-and-layout.json').read_text())
    raw=(args.build/'nv4_mini.sys').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==lock['expected_miniport_sha256']
    DISPLAY_RAW=(args.build/'XP-payload/Display.Driver/nv4_disp.dll').read_bytes()
    assert hashlib.sha256(DISPLAY_RAW).hexdigest()==lock['display_dll_sha256']
    MINI_IMAGE=pefile.PE(data=raw,fast_load=True).get_memory_mapped_image()
    EDID=args.edid.read_bytes()
    assert len(EDID)==256 and all(sum(EDID[i:i+128])%256==0 for i in (0,128))
    results=[replay(60),replay(120),replay(120,20)]
    report=dict(passed=True,miniport_sha256=hashlib.sha256(raw).hexdigest(),edid_sha256=hashlib.sha256(EDID).hexdigest(),
                cases=results,live_XP_tested=False,limitations=__doc__)
    (args.build/'MODE-VERIFICATION.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: saved 4K60 and 4K120 reach the DP boundary with HBR3 x4; 4K120 rejects HBR2 x4.')
