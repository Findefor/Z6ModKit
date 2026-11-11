"""Validate Z6 II bitrate candidates entirely in host RAM with Unicorn.

Emulates only mode selection/copy and the encoder configuration fragment.
memcpy is stubbed; no encoder, sensor, card or update loader is emulated.
No modified firmware is written.
"""
import gc
import hashlib
import json
import pathlib
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE, RAM, STACK = 0x10020000, 0x20000000, 0x20030000
ARG, OUTPUT, STOP, CFG = RAM+0x100, RAM+0x200, RAM+0x400, RAM+0x1000
SETTINGS, PARAMS = RAM+0x2000, RAM+0x3000
CASES = [
    {'name': 'master', 'path': 'work/analysis/Z6_2_0170/eg1850_mas_01700.bin',
     'table': 0x1091D594, 'getter': 0x10523E0A, 'selector': 0x10523D08,
     'memcpy': 0x1035D1EC, 'encoder': 0x104BE39A, 'config_start': 0x104BE3B8,
     'config_end': 0x104BE492, 'threshold_literal': 0x104BE72C,
     'get_config': 0x104884E8, 'encoder_call': 0x104A4DA8},
    {'name': 'slave', 'path': 'work/analysis/Z6_2_0170/eg1850_sla_01700.bin',
     'table': 0x101DCB08, 'getter': 0x10108AF6, 'selector': 0x101089F4,
     'memcpy': 0x101671A0, 'encoder': 0x100A2322, 'config_start': 0x100A2340,
     'config_end': 0x100A241A, 'threshold_literal': 0x100A26B4,
     'get_config': 0x1010A63A, 'encoder_call': 0x100A804A},
]
PROFILES = {'stock': (144,120), 'candidate_156_140': (156,140), 'z30_analogy_200_168': (200,168)}
report = {'scope': 'Offline only; no sensor, encoder output, SD/CFexpress, boot or flashing validation',
          'record_size_z6ii': 32, 'record_size_z30': 28, 'modules': [], 'checks': []}
disassembly = []
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

def row_info(row):
    w,h,timebase,ticks,reserved,m,n,peak,mean,extra = struct.unpack('<HHIIIHHIII',row)
    return dict(width=w,height=h,timebase=timebase,ticks=ticks,fps=timebase/ticks,
                reserved=reserved,m=m,n=n,maximum_mbps=peak/1e6,average_mbps=mean/1e6,extra=extra)

tables=[]
for case in CASES:
    data=(ROOT/case['path']).read_bytes()
    assert struct.unpack_from('<I',data,0x1400c)[0] == BASE+0x6c
    table=data[case['table']-BASE:case['table']-BASE+34*32]
    tables.append(table)
    module = {**case, 'sha256': hashlib.sha256(data).hexdigest(),
              'rows': [dict(index=i, address=hex(case['table']+i*32), **row_info(table[i*32:(i+1)*32])) for i in range(34)],
              'profiles': {}, 'candidate_spans': []}
    assert struct.unpack_from('<I',data,case['threshold_literal']-BASE)[0] == 156250
    module['level_switch_threshold_bps'] = 156250 * 1024
    for start,end in [(case['getter'],case['getter']+30),(case['config_start'],case['config_end'])]:
        disassembly.append('\n'+case['name']+' '+hex(start))
        disassembly.extend(f'{i.address:08x}  {i.bytes.hex():10} {i.mnemonic:8} {i.op_str}'
                           for i in cs.disasm(data[start-BASE:end-BASE],start))
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    uc.mem_map(BASE,(len(data)+4095)&~4095)
    uc.mem_write(BASE,data)
    uc.mem_map(RAM,0x40000)
    copied=[]
    clear_ins = next(i for i in cs.disasm(data[case['get_config']-BASE:case['get_config']-BASE+24],case['get_config']) if i.mnemonic=='bl')
    clear_address = int(clear_ins.op_str.lstrip('#'),0)
    def hook(u, address, size, user):
        if address == STOP:
            u.emu_stop()
        elif address == case['memcpy']:
            dest,source,length=(u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2])
            assert length == 32 and RAM <= dest < RAM+0x40000-length
            copied.append(source)
            u.mem_write(dest,bytes(u.mem_read(source,length)))
            u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
        elif address == clear_address:
            dest,length=u.reg_read(UC_ARM_REG_R0),u.reg_read(UC_ARM_REG_R1)
            assert length==32 and RAM<=dest<RAM+0x40000-length
            u.mem_write(dest,b'\0'*length)
            u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    uc.hook_add(UC_HOOK_CODE,hook)
    modes=[]
    for family,count in [(0,5),(1,10),(2,2)]:
        for fps in range(count):
            for quality in [0,1]:
                modes.append((family,fps,quality))
    for profile,(maximum,average) in PROFILES.items():
        expected=bytearray(table)
        for index in [4,6,8]:
            struct.pack_into('<II',expected,index*32+20,maximum*1000000,average*1000000)
        uc.mem_write(case['table'],bytes(expected))
        rows_seen=set()
        for mode in modes:
            uc.mem_write(ARG,bytes(mode))
            uc.mem_write(OUTPUT-16,b'\xa5'*64)
            uc.reg_write(UC_ARM_REG_SP,STACK)
            uc.reg_write(UC_ARM_REG_R0,ARG)
            uc.reg_write(UC_ARM_REG_R1,OUTPUT)
            uc.reg_write(UC_ARM_REG_LR,STOP|1)
            copied.clear()
            uc.emu_start(case['getter']|1,STOP,count=1000)
            assert len(copied)==1
            index=(copied[0]-case['table'])//32
            assert 0<=index<34 and copied[0] == case['table']+index*32
            assert bytes(uc.mem_read(OUTPUT,32)) == expected[index*32:(index+1)*32]
            assert bytes(uc.mem_read(OUTPUT-16,16)) == b'\xa5'*16
            assert bytes(uc.mem_read(OUTPUT+32,16)) == b'\xa5'*16
            rows_seen.add(index)
        assert rows_seen==set(range(34))
        # Actual instructions after allocation, ending immediately after Level selection.
        uc.mem_write(CFG,b'\0'*256)
        uc.mem_write(STACK,b'\0'*128)
        struct.pack_into('<I',entry:=bytearray(4),0,average*1000000>>10)
        uc.mem_write(STACK+0x38,bytes(entry))
        for reg,value in [(UC_ARM_REG_SP,STACK),(UC_ARM_REG_R4,CFG),(UC_ARM_REG_R5,1),
                          (UC_ARM_REG_R6,2160),(UC_ARM_REG_R7,3840),(UC_ARM_REG_R8,29),
                          (UC_ARM_REG_R9,maximum*1000000>>10)]:
            uc.reg_write(reg,value)
        uc.emu_start(case['config_start']|1,case['config_end'],count=1000)
        cfg=bytes(uc.mem_read(CFG,128))
        max_internal=struct.unpack_from('<I',cfg,0x1c)[0]
        average_internal=struct.unpack_from('<I',cfg,0x18)[0]
        encoded_max=struct.unpack_from('<H',cfg,0x42)[0]
        level=cfg[0x61]
        assert max_internal == maximum*1000000>>10
        assert average_internal == average*1000000>>10
        assert encoded_max == (((max_internal>>4)&0x3ffff)<<1)&65535
        assert level == (51 if maximum<160 else 61)
        module['profiles'][profile] = {'selector_cases_passed':len(modes), 'rows_seen':len(rows_seen),
            'candidate_maximum_mbps':maximum,'candidate_average_mbps':average,
            'encoder_maximum_internal':max_internal,'encoder_average_internal':average_internal,
            'encoder_packed_maximum':encoded_max,'encoder_level_parameter':level,
            'guard_bytes_pass':True}
        linked=[]
        for fps in range(5):
            for quality in [0,1]:
                settings=bytearray(256)
                settings[0x66:0x69]=bytes([0,fps,quality])
                uc.mem_write(SETTINGS,bytes(settings))
                uc.mem_write(PARAMS-16,b'\xa5'*96)
                uc.reg_write(UC_ARM_REG_SP,STACK)
                uc.reg_write(UC_ARM_REG_R0,SETTINGS)
                uc.reg_write(UC_ARM_REG_R1,PARAMS)
                uc.reg_write(UC_ARM_REG_LR,STOP|1)
                copied.clear()
                uc.emu_start(case['get_config']|1,STOP,count=2000)
                row_index=fps*2+quality
                wanted=list(struct.unpack_from('<II',expected,row_index*32+20))
                # Stock code halves each encoder's requested rates for 4K 50/60p.
                if fps<2: wanted=[v>>1 for v in wanted]
                actual=list(struct.unpack('<II',bytes(uc.mem_read(PARAMS+8,8))))
                assert actual==wanted,(profile,fps,quality,actual,wanted)
                # Run the actual caller's conversion/argument preparation instructions.
                uc.mem_write(STACK,b'\0'*128)
                uc.reg_write(UC_ARM_REG_SP,STACK)
                uc.reg_write(UC_ARM_REG_R9,PARAMS)
                uc.reg_write(UC_ARM_REG_R0,29)
                uc.reg_write(UC_ARM_REG_R8,1)
                uc.emu_start((case['encoder_call']-22)|1,case['encoder_call'],count=100)
                mean_arg,max_arg=struct.unpack('<II',bytes(uc.mem_read(STACK,8)))
                assert [max_arg,mean_arg]==[v>>10 for v in wanted]
                uc.mem_write(CFG,b'\0'*256)
                uc.mem_write(STACK,b'\0'*128)
                uc.mem_write(STACK+0x38,struct.pack('<I',mean_arg))
                for reg,value in [(UC_ARM_REG_SP,STACK),(UC_ARM_REG_R4,CFG),(UC_ARM_REG_R5,1),
                                  (UC_ARM_REG_R6,2160),(UC_ARM_REG_R7,3840),
                                  (UC_ARM_REG_R8,29),(UC_ARM_REG_R9,max_arg)]:
                    uc.reg_write(reg,value)
                uc.emu_start(case['config_start']|1,case['config_end'],count=1000)
                configured=bytes(uc.mem_read(CFG,128))
                assert struct.unpack_from('<I',configured,0x1c)[0]==max_arg
                assert struct.unpack_from('<I',configured,0x18)[0]==mean_arg
                level=configured[0x61]
                assert level==(51 if max_arg<156250 else 61)
                linked.append({'fps_index':fps,'quality_index':quality,
                               'requested_maximum_bps':wanted[0],'requested_average_bps':wanted[1],
                               'encoder_level_parameter':level})
        module['profiles'][profile]['parameter_pipeline_cases_passed']=len(linked)
        module['profiles'][profile]['parameter_pipeline']=linked
    for index in [4,6,8]:
        module['candidate_spans'].append({'row':index,'module_offset':hex(case['table']-BASE+index*32+20),
            'virtual_address':hex(case['table']+index*32+20),
            'before_hex':table[index*32+20:index*32+28].hex(),
            'after_200_168_hex':struct.pack('<II',200000000,168000000).hex()})
    report['modules'].append(module)
    del uc; gc.collect()
assert tables[0]==tables[1]
report['checks'].append('Master/slave tables are byte-identical across all 34 records')
z30=(ROOT/'work/analysis/Z_30_0120/eg2090_0120a0.bi.bin').read_bytes()[0x6f3154:0x6f3154+30*28]
assert all(z30[i*28:(i+1)*28] == tables[0][(i+4)*32:(i+4)*32+28] for i in range(30))
report['checks'].append('First 28 bytes of Z6 II rows 4..33 exactly match all 30 Z30 rows')
report['selector_cases_total']=sum(p['selector_cases_passed'] for m in report['modules'] for p in m['profiles'].values())
report['parameter_pipeline_cases_total']=sum(p['parameter_pipeline_cases_passed'] for m in report['modules'] for p in m['profiles'].values())
(ROOT/'work/analysis/bitrate_analysis.json').write_text(json.dumps(report,indent=2)+'\n')
(ROOT/'work/analysis/code_evidence.txt').write_text('\n'.join(disassembly)+'\n')
print(json.dumps({'selector_cases_passed':report['selector_cases_total'],
                  'parameter_pipeline_cases_passed':report['parameter_pipeline_cases_total'],
                  'checks':report['checks'],
                  'profile_levels':{m['name']:{k:v['encoder_level_parameter'] for k,v in m['profiles'].items()} for m in report['modules']}},indent=2))
