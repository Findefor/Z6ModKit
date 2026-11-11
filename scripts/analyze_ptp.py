"""Offline validation of Z6 II C1.70 service dispatch and video property getters.

Executes original instructions in host memory only. Hardware/USB and capability
sources are explicit stubs. Does not connect to a camera or generate a patch.
"""
import argparse
import json
import struct
from pathlib import Path
from fw_inspect import Firmware, ROOT, BASE, SHA256
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--device-snapshot', type=Path,
                    help='Optional existing local JSON for operation coverage; never opens USB')
args = parser.parse_args()

RAM, CMD, BUF, STOP, STACK = 0x20000000, 0x20000100, 0x20001000, 0x20002000, 0x2000f000
FW = Firmware()
u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
u.mem_map(BASE, (len(FW.data)+4095)&~4095)
u.mem_write(BASE, FW.data)
u.mem_map(RAM, 0x10000)
u.mem_map(0xc188b000, 0x2000)
events, writes, capabilities = [], [], {}
region_available, special_transfer = False, False


def ret(value=None):
    if value is not None:
        u.reg_write(UC_ARM_REG_R0, value)
    u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def hook(cpu, address, size, _):
    r0, r1, r2, r3 = [cpu.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
    if address == STOP:
        cpu.emu_stop()
    elif address in (0x1035d2dc, 0x103f8e26):
        assert RAM <= r0 and r0+r1 <= RAM+0x10000
        cpu.mem_write(r0, b'\0'*r1)
        ret()
    elif address == 0x1035d254:
        assert RAM <= r0 and r0+r2 <= RAM+0x10000
        cpu.mem_write(r0, bytes(cpu.mem_read(r1, r2)))
        ret()
    elif address == 0x1063f598:
        ret(BUF)
    elif address in (0x1063f682, 0x1063f7b6, 0x104b53c6):
        assert r2 <= 256
        events.append({'kind': 'transfer', 'via': hex(address), 'source': hex(r1),
                       'length': r2, 'data_hex': bytes(cpu.mem_read(r1, r2)).hex()})
        ret(1)
    elif address == 0x1063f710:
        assert r2 <= 5
        events.append({'kind': 'response', 'status': hex(r1),
                       'parameters': list(struct.unpack('<'+'I'*r2, cpu.mem_read(r3, 4*r2))) if r2 else []})
        ret(1)
    elif address == 0x106373ca:
        assert r0 in capabilities, hex(r0)
        events.append({'kind': 'capability_read', 'id': hex(r0), 'value': capabilities[r0]})
        ret(capabilities[r0])
    elif address == 0x103a6c64:
        assert r0 == 8
        events.append({'kind': 'dynamic_region_query', 'region': 8, 'available': region_available})
        assert not region_available  # Its live contents have not been obtained.
        ret(0)
    elif address == 0x103c81dc:
        events.append({'kind': 'memory_class_stub', 'address': hex(r0), 'special': special_transfer})
        ret(int(special_transfer))


def memory_write(cpu, access, address, size, value, _):
    if not RAM <= address < RAM+0x10000:
        writes.append({'address': hex(address), 'size': size, 'value': hex(value)})


u.hook_add(UC_HOOK_CODE, hook)
u.hook_add(UC_HOOK_MEM_WRITE, memory_write)


def run(address, r0=0, r1=0):
    events.clear(); writes.clear()
    u.reg_write(UC_ARM_REG_SP, STACK)
    u.reg_write(UC_ARM_REG_R0, r0)
    u.reg_write(UC_ARM_REG_R1, r1)
    u.reg_write(UC_ARM_REG_LR, STOP|1)
    u.emu_start(address|1, STOP, count=20000)
    assert u.reg_read(UC_ARM_REG_PC) == STOP, 'Instruction budget exhausted'
    return u.reg_read(UC_ARM_REG_R0), list(events), list(writes)


def table(address):
    result = []
    for n in range(512):
        row = FW.words(address+n*28, 7)
        if row[0] == 0:
            return result
        assert row[0] <= 0xffff
        result.append({'address': hex(address+n*28), 'code': hex(row[0]),
                       'direction_field': row[1], 'context': hex(row[2]),
                       'callbacks': [hex(x) for x in row[3:]]})
    raise AssertionError('Missing table terminator')


report = {'firmware_sha256': SHA256, 'camera_io': False,
          'scope': 'Original ARM/Thumb routines in Unicorn; synthetic RAM and capability inputs; no hardware validation',
          'stubs': ['memclear/memcpy', 'USB buffers/transfers/responses', 'capability backend',
                    'memory region 8 unavailable', 'memory-class selection for transfer'],
          'tables': {}, 'service_gate_checks': [], 'address_filter_checks': [],
          'memory_transfer_checks': [], 'video_getter_checks': []}
for index in range(9):
    pointer, _, _ = run(0x1047b7e8, index)
    if pointer:
        report['tables'][str(index)] = {'address': hex(pointer), 'entries': table(pointer)}
report['service_subcommands'] = {'address': '0x119f496c', 'entries': table(0x119f496c)}
assert len(report['service_subcommands']['entries']) == 175
outer_codes = {e['code'] for t in report['tables'].values() for e in t['entries']}
report['advertised_operation_coverage'] = {'checked': False, 'unique_outer_codes': len(outer_codes)}
if args.device_snapshot:
    live = json.loads(args.device_snapshot.read_text())
    assert set(live['device_info']['operations']) <= outer_codes
    report['advertised_operation_coverage'].update(
        checked=True, matched=len(live['device_info']['operations']), missing=[])

# Test the real outer guard and both F003 and F032 preflight paths. No F001
# (service entry), F002 (exit) or memory-write handler is ever executed.
for active in (0, 1):
    for code, param2, param3 in [(0xf003, 1, 0), (0xf032, 0xc188c060, 8)]:
        u.mem_write(CMD, struct.pack('<IHH6I', 32, 1, 0x94ff, 1, code, param2, param3, 0, 0))
        u.mem_write(0xc188bc38, struct.pack('<II', 0, 0x1047c205))
        u.mem_write(0xc188bc40, struct.pack('<I', active))
        value, ev, wr = run(0x10776db4, 0, CMD)
        assert value == active
        if not active:
            assert ev == [{'kind': 'response', 'status': '0xa004', 'parameters': [0]*5}]
        assert all(w['address'] == '0xc188bc38' for w in wr)
        report['service_gate_checks'].append({'active': active, 'subcommand': hex(code),
                                             'passed': bool(value), 'events': ev, 'global_writes': wr})

# Execute the model-identity branch using synthetic service state. It returns
# a padded model string, not device-specific calibration or a serial number.
u.mem_write(CMD, struct.pack('<IHH6I', 32, 1, 0x94ff, 1, 0xf003, 1, 0, 0, 0))
value, ev, wr = run(0x10776dba, 0, CMD)
transfer = next(e for e in ev if e['kind'] == 'transfer')
assert bytes.fromhex(transfer['data_hex']) == b'Z 6_2\0'+b'\0'*122
assert not any(e['kind'] not in ('transfer', 'response') for e in ev)
assert all(w['address'] == '0xc188bc38' for w in wr)
report['identity_branch_check'] = {'events': ev, 'global_writes': wr}

# The address filter is a deny-list, not an unrestricted read: known code,
# slave RAM and other protected ranges return zero. Region 8 is not modeled.
for start, length, expected in [(0x10020000,16,0), (0xc1000000,16,0),
                               (0xc2b90000,16,0), (0xcc200000,16,0),
                               (0,16,0), (0xc188c060,8,1),
                               (0xc17ffffc,8,0), (0xc2b8fffc,8,0)]:
    value, ev, wr = run(0x104b5314, start, start+length-1)
    assert value == expected
    assert not wr
    report['address_filter_checks'].append({'start': hex(start), 'length': length,
                                            'accepted': bool(value), 'events': ev})
u.mem_write(0xc188c060, bytes.fromhex('a501000100010001'))
for special_transfer in (False, True):
    u.mem_write(CMD, struct.pack('<IHH6I', 32, 1, 0x94ff, 1, 0xf032, 0xc188c060, 8, 0, 0))
    value, ev, wr = run(0x104b5488, 0, CMD)
    transfer = next(e for e in ev if e['kind'] == 'transfer')
    assert value == 1 and transfer['source'] == '0xc188c060' and transfer['length'] == 8
    assert transfer['data_hex'] == 'a501000100010001' and not wr
    report['memory_transfer_checks'].append({'events': ev})

for cap1, cap2, expected in [(0,0,0), (1,0,1), (0,1,2), (1,1,0)]:
    capabilities = {0x126e: cap1, 0x12a4: cap2}
    value, ev, wr = run(0x104d0b68)
    assert value == expected and not wr
    report['video_getter_checks'].append({'property':'0xd0bf', 'inputs':capabilities,
                                         'output':value,'events':ev})
for cap, expected in [(0,1), (1,0)]:
    capabilities = {0x126d: cap}
    value, ev, wr = run(0x104d0e62)
    assert value == expected and not wr
    report['video_getter_checks'].append({'property':'0xd0cc', 'inputs':capabilities,
                                         'output':value,'events':ev})
for cap1, cap2, expected in [(0,0,0), (1,0,1), (0,1,1), (1,1,1)]:
    capabilities = {0x1688: cap1, 0x16bf: cap2}
    value, ev, wr = run(0x104d0a8c)
    assert value == expected and not wr
    report['video_getter_checks'].append({'property':'0xd0bb', 'inputs':capabilities,
                                         'output':value,'events':ev})

report['findings'] = {
    'service_transport':'0x94fd/0x94fe/0x94ff select a subcommand from PTP parameter 1',
    'guard':'0x104c966c checks callback 0x1047c205 reading state at 0xc188bc40; inactive returns 0xa004 except F001',
    'read_memory':'F032 uses PTP parameter 2 as source address and parameter 3 as length; preflight 0x104b5386, executor 0x104b5488',
    'candidate_ram':'0xc188c060 is the PTP cache for video properties, not the encoder pixel buffer',
    'service_entry':'F001 executor 0x1047c278 calls 0x10505a4a, 0x104b6c10, 0x104939c6 and 0x1047c238; sets state only after asynchronous transition succeeds',
    'service_exit':'F002 executor 0x1047c392 calls 0x1047c322; extensive cleanup and state transition, not just clearing one bit',
    'entry_review':'0x1047c238 calls 0x1038602e, signals an RTOS event and waits for completion. Downstream effects not fully reviewed; do not execute entry/exit yet',
    'dynamic_region_8':'Descriptor at 0xc185ec88; getter 0x103a6c64 -> 0x102484aa / 0x103c1d62. Initial RAM image has zero source/length; live initialized values are required',
    'limitations':['No live service state or RAM read established', 'F001 entry side effects not fully traced',
                   'Dynamic protected region 8 is unresolved', 'Memory reads can have side effects outside ordinary RAM',
                   'The existence of a memory reader does not establish internal 10-bit AVC support']}
(ROOT/'work/analysis/ptp_research.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
ranges = [(0x1047b2a8,18),(0x1047b7e8,82),(0x104c9580,114),(0x104c966c,158),
          (0x1047c204,26),(0x104b5314,114),(0x104b5386,64),(0x104b5488,94),
          (0x104d0a8c,36),(0x104d0b68,70),(0x104d0e62,24),
          (0x1047c238,64),(0x1047c278,120),(0x1038602e,32),(0x1047c322,112),
          (0x103a6c64,60),(0x102484aa,32),(0x103c1d62,124)]
(ROOT/'work/analysis/ptp_research_code.txt').write_text('\n\n'.join(FW.listing(a,n) for a,n in ranges)+'\n')
print(json.dumps({'tables':{k:len(v['entries']) for k,v in report['tables'].items()},
                  'service_subcommands':175, 'gate_checks':4, 'identity_branch':True,
                  'address_filter_checks':8, 'memory_transfer_checks':2, 'video_getter_checks':10},indent=2))
