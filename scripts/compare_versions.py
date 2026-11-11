"""Read selected Nikon RAR SFX archives as data, without executing EXEs."""
import hashlib
import json
import pathlib
import struct
import subprocess
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'work/vendor/key'))
import decrypt_firmware as fw
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM, ARM_REG_PC, ARM_REG_LR

keys=fw.load_key(str(ROOT/'work/analysis/key.json'))
cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB);cs.detail=True
library=ROOT/'Библиотека старых прошивок'
sources=[library/'F-Z6II-V102W.exe',library/'F-Z6II-V110W.exe',
         library/'F-Z6II-V160W.exe',library/'Z6_2_0162.bin',
         ROOT/'work/inputs/Z6_2_0170.bin']
report={'archives_executed':False,'versions':[]}
for source in sources:
    if source.suffix.lower()=='.exe':
        members=subprocess.check_output(['tar','-tf',str(source)],text=True).splitlines()
        bins=[s for s in members if s.lower().endswith('.bin')]
        assert len(bins)==1
        raw=subprocess.check_output(['tar','-xOf',str(source),bins[0]])
        name=pathlib.PureWindowsPath(bins[0]).name
    else:
        raw=source.read_bytes();name=source.name
    dec=fw.decrypt(raw,*keys)
    modules=fw.validate_firmware(dec[32:])
    version={'file':name,'source':str(source.relative_to(ROOT)),
             'sha256':hashlib.sha256(raw).hexdigest(),'module_crcs_passed':len(modules),
             'package_crc_passed':True,'modules':[]}
    for modname,start,size in modules:
        if not modname.startswith('eg'):continue
        d=dec[32+start:32+start+size]
        match=struct.pack('<HHIIIIII',3840,2160,30000,1001,0,983041,144000000,120000000)
        pos=d.find(match)
        assert pos>=0 and d.find(match,pos+1)<0
        stride=next(n for n in [28,32] if d[pos+n:pos+n+20]==match[:20]
                    and struct.unpack_from('<II',d,pos+n+20)==(72000000,60000000))
        first=pos
        while first>=stride and struct.unpack_from('<HH',d,first-stride)==(3840,2160):first-=stride
        count=34 if first<pos else 30
        table=d[first:first+count*stride]
        peak_rows=[]
        for i in range(count):
            row=table[i*stride:(i+1)*stride]
            w,h,rate,ticks=struct.unpack_from('<HHII',row)
            if w==3840 and h==2160:
                peak,mean=struct.unpack_from('<II',row,20)
                peak_rows.append({'row':i,'fps':rate/ticks,'maximum_mbps':peak/1e6,'average_mbps':mean/1e6})
        signature=bytes.fromhex('c9f31111');p=d.find(signature)
        assert p>=0 and d.find(signature,p+1)<0
        threshold=[]
        for ins in cs.disasm(d[p:p+240],0x10020000+p):
            if ins.mnemonic.startswith('ldr') and len(ins.operands)>1 and ins.operands[0].reg==ARM_REG_LR:
                op=ins.operands[1]
                if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC:
                    literal=((ins.address+4)&~3)+op.mem.disp
                    threshold.append({'load_address':hex(ins.address),'literal_address':hex(literal),
                                      'value':struct.unpack_from('<I',d,literal-0x10020000)[0]})
        version['modules'].append({'name':modname,'size':size,'sha256':hashlib.sha256(d).hexdigest(),
            'table_address':hex(0x10020000+first),'stride':stride,'count':count,
            'table_sha256':hashlib.sha256(table).hexdigest(),'4k_rows':peak_rows,
            'encoder_ubfx_address':hex(0x10020000+p),'encoder_pc_literal_loads':threshold})
    report['versions'].append(version)
    print(json.dumps({'version':name,'crc_modules':len(modules),'modules':version['modules']},ensure_ascii=False),flush=True)
(ROOT/'work/analysis/version_comparison.json').write_text(json.dumps(report,indent=2)+'\n')
