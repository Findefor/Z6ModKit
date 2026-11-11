"""Offline C1.70 F02D/F030 checks. No USB, camera client, or patch generation.

Runs original handler instructions with synthetic region 8, copy/clear and
transport stubs. Does not model service transitions or physical NVRAM.
"""
import hashlib
import json
import struct

from fw_inspect import Firmware, ROOT, BASE, SHA256
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)

FW = Firmware()
RAM, CMD, STOP, STACK = 0x20000000, 0x20000100, 0x20002000, 0x2000f000
SOURCE, TX, LENGTH = 0x21000000, 0x22000000, 0x1fffc
original = bytes((i * 17 + 3) % 256 for i in range(LENGTH))
redacted = original[:4] + b'\0\0' + original[6:]
u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
fw_length = (len(FW.data) + 4095) & ~4095
u.mem_map(BASE, fw_length)
u.mem_write(BASE, FW.data)
u.mem_protect(BASE, fw_length, UC_PROT_READ | UC_PROT_EXEC)
u.mem_map(RAM, 0x10000)
u.mem_map(SOURCE, 0x20000)
u.mem_write(SOURCE, original)
u.mem_protect(SOURCE, 0x20000, UC_PROT_READ)
u.mem_map(TX, 0x20000)
u.mem_map(0xc188b000, 0x1000)
u.mem_write(0xc188b788, struct.pack('<I', TX - 12))
events, stores, settings = [], [], {}


def ret(value=0):
    u.reg_write(UC_ARM_REG_R0, value)
    u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def hook(cpu, address, size, _):
    r0, r1, r2, r3 = [cpu.reg_read(r) for r in
                      (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
    if address == STOP:
        cpu.emu_stop()
    elif address == 0x1035d2dc:
        assert RAM <= r0 and r0 + r1 <= RAM + 0x10000
        cpu.mem_write(r0, b'\0' * r1)
        ret()
    elif address == 0x103a6c64:
        assert r0 == 8 and RAM <= r1 < RAM + 0x10000 - 20
        if settings['available']:
            cpu.mem_write(r1, struct.pack('<5I', SOURCE, 0, 0, LENGTH, 0))
        events.append({'region_8_available_stub': settings['available']})
        ret(int(settings['available']))
    elif address == 0x1035d254:
        assert (r0, r1, r2) == (TX, SOURCE, LENGTH)
        cpu.mem_write(r0, bytes(cpu.mem_read(r1, r2)))
        events.append({'copy_stub': 'source to separate TX buffer', 'length': r2})
        ret(TX)
    elif address == 0x1063f682:
        assert r0 == CMD and r3 == 0x1388
        assert TX <= r1 and r1 + r2 <= TX + LENGTH
        outgoing = bytes(cpu.mem_read(r1, r2))
        offset = r1 - TX
        assert outgoing == redacted[offset:offset+r2]
        events.append({'transfer_stub': True, 'offset': offset, 'length': r2,
                       'sha256': hashlib.sha256(outgoing).hexdigest(),
                       'success': settings['transfer_ok']})
        ret(int(settings['transfer_ok']))
    elif address == 0x1063f710:
        assert r0 == CMD and r2 == 5
        events.append({'response': hex(r1),
                       'parameters': list(struct.unpack('<5I', cpu.mem_read(r3, 20)))})
        ret(1)
    elif address == 0x104b48c6:
        assert r0 == 8
        events.append({'commit_helper_stub': hex(address), 'region': r0,
                       'success': settings['commit_ok']})
        ret(int(settings['commit_ok']))
    else:
        assert any(a <= address < b for a, b in (
            (0x104b4ec8, 0x104b4fc6), (0x104b517a, 0x104b51b4),
            (0x104b4684, 0x104b4688), (0x104b4746, 0x104b4748),
            (0x1063f598, 0x1063f5a0), (0x1063f5ac, 0x1063f5b0),
            (0x103c31e4, 0x103c31f4))), hex(address)


def write_hook(cpu, access, address, size, value, _):
    assert (RAM <= address and address + size <= RAM + 0x10000 or
            TX <= address and address + size <= TX + LENGTH), hex(address)
    if TX <= address < TX + LENGTH:
        stores.append({'offset': address - TX, 'size': size, 'value': value})


u.hook_add(UC_HOOK_CODE, hook)
u.hook_add(UC_HOOK_MEM_WRITE, write_hook)


def run(address, offset=0, length=LENGTH, available=True,
        transfer_ok=True, commit_ok=True):
    settings.update(available=available, transfer_ok=transfer_ok, commit_ok=commit_ok)
    events.clear()
    stores.clear()
    u.mem_write(RAM, b'\0' * 0x10000)
    u.mem_write(TX, b'\xa5' * 0x20000)
    code = 0xf030 if address == 0x104b517a else 0xf02d
    u.mem_write(CMD, struct.pack('<IHH6I', 32, 1, 0x94ff, 1, code,
                                 offset, length, 0, 0))
    u.reg_write(UC_ARM_REG_SP, STACK)
    u.reg_write(UC_ARM_REG_R0, 0)
    u.reg_write(UC_ARM_REG_R1, CMD)
    u.reg_write(UC_ARM_REG_LR, STOP | 1)
    u.emu_start(address | 1, STOP, count=2000)
    assert u.reg_read(UC_ARM_REG_PC) == STOP, 'Instruction budget exhausted'
    assert bytes(u.mem_read(SOURCE, LENGTH)) == original
    assert bytes(u.mem_read(TX + LENGTH, 4)) == b'\xa5' * 4
    return {'return': u.reg_read(UC_ARM_REG_R0), 'events': list(events),
            'original_TX_stores': list(stores), 'source_unchanged': True}


report = {
    'firmware_sha256': SHA256, 'camera_io': False,
    'scope': 'Original handlers and offset/buffer getters; synthetic region 8',
    'stubs': ['region 8 descriptor', 'memclear/memcpy', 'transfer/response',
              'F030 commit helper 0x104b48c6'],
    'preflight_checks': [], 'read_checks': [], 'commit_dispatch_checks': [],
}
for name, offset, length, available, expected in (
    ('whole_region', 0, LENGTH, True, 1),
    ('last_byte', LENGTH-1, 1, True, 1),
    ('redaction_overlap', 3, 4, True, 1),
    ('zero_length', 0, 0, True, 0),
    ('too_long', 0, LENGTH+1, True, 0),
    ('offset_at_end', LENGTH, 1, True, 0),
    ('cross_end', LENGTH-1, 2, True, 0),
    ('region_unavailable', 0, LENGTH, False, 0),
    ('uint32_sum_wrap_preflight_only', 0xfffffff0, 0x20, True, 1),
):
    result = run(0x104b4ec8, offset, length, available)
    assert result['return'] == expected and not result['original_TX_stores']
    assert not any('commit_helper_stub' in e for e in result['events'])
    report['preflight_checks'].append(dict(case=name, offset=offset,
                                           length=length, **result))

for name, offset, length, available, transfer_ok, expected, nested in (
    ('whole_region', 0, LENGTH, True, True, 1, 0x2001),
    ('redaction_overlap', 3, 4, True, True, 1, 0x2001),
    ('last_byte', LENGTH-1, 1, True, True, 1, 0x2001),
    ('transfer_failed', 0, LENGTH, True, False, 0, 0x2007),
    ('region_unavailable', 0, LENGTH, False, True, 0, 0xa001),
):
    result = run(0x104b4f1a, offset, length, available, transfer_ok)
    assert result['return'] == expected
    response = next(e for e in result['events'] if 'response' in e)
    assert response == {'response': '0x2001', 'parameters': [nested, 0, 0, 0, 0]}
    expected_stores = [{'offset': n, 'size': 1, 'value': 0} for n in (4, 5)]
    assert result['original_TX_stores'] == (expected_stores if available else [])
    assert not any('commit_helper_stub' in e for e in result['events'])
    report['read_checks'].append(dict(case=name, **result))

for commit_ok in (True, False):
    result = run(0x104b517a, commit_ok=commit_ok)
    assert result['return'] == int(commit_ok)
    assert len([e for e in result['events'] if 'commit_helper_stub' in e]) == 1
    response = next(e for e in result['events'] if 'response' in e)
    assert response['parameters'][0] == (0x2001 if commit_ok else 0xa001)
    report['commit_dispatch_checks'].append(dict(commit_stub_success=commit_ok, **result))

report['findings'] = {
    'F02D': 'Copies the whole region into a separate TX buffer; zeros bytes 4 and 5 in TX; sends requested slice. No commit path in inspected handler.',
    'bounds': 'Preflight accepts a wrapping uint32 offset+length sum. Malformed case tested only in preflight, never executor. A client must validate without wrap and use a fixed bounded request.',
    'F030': 'Original executor calls 0x104b48c6(8). That helper, reviewed statically, requests 0x103c258c with callback and waits for event 0x03010006. Backend persistence not emulated.',
    'backup': 'F02D is a redacted configuration snapshot, not complete firmware, RAM or a verified restorable backup.',
    'limits': 'No full-camera or entry/exit emulation. Synthetic source is read protected. Does not establish that a complete service session has no persistent side effects or fault recovery.',
}

# Follow the newly resolved lower transition route only as far as its packet
# submission. Initialized RAM comes from the original scatter-load image;
# runtime registration is seeded from the statically checked startup loop.
v = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
v.mem_map(BASE, fw_length)
v.mem_write(BASE, FW.data)
v.mem_protect(BASE, fw_length, UC_PROT_READ | UC_PROT_EXEC)
v.mem_map(RAM, 0x10000)
v.mem_map(0xc1800000, 0xb0000)
v.mem_write(0xc1800000, FW.data[0x123a1c14-BASE:0x123a1c14-BASE+0xaedb8])
assert FW.words(0x11990a14, 4) == (15, 0x10206cbb, 0x10206cc5, 0x10434e69)
v.mem_write(0xc18a7c20, struct.pack('<II', 0x102054ff, 0x11990a14))
v.mem_write(0xc1887b00, struct.pack('<I', 0x11990924))
packets = []


def transition_hook(cpu, address, size, _):
    if address == STOP:
        cpu.emu_stop()
    elif address == 0x10205698:
        subsystem = cpu.reg_read(UC_ARM_REG_R0)
        desc = cpu.reg_read(UC_ARM_REG_R1)
        pointer, length, channel, message_id = struct.unpack('<4I', cpu.mem_read(desc, 16))
        assert subsystem == 15 and (length, channel, message_id) == (8, 1, 9)
        packets.append({'subsystem': subsystem, 'length': length, 'channel': channel,
                        'message_id': message_id,
                        'payload_hex': bytes(cpu.mem_read(pointer, length)).hex()})
        cpu.reg_write(UC_ARM_REG_R0, 1)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
    elif address == 0x10205632:
        cpu.reg_write(UC_ARM_REG_R0, 0)  # Pending transport checks, no hardware.
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
    else:
        assert any(a <= address < b for a, b in (
            (0x10206dfc, 0x10206e28), (0x102054fe, 0x1020555a),
            (0x10434e68, 0x10434e90), (0x104355ea, 0x1043568e),
            (0x10434ffe, 0x1043501e))), hex(address)


v.hook_add(UC_HOOK_CODE, transition_hook)
report['transition_packet_checks'] = []
for mode in (0, 1):
    packets.clear()
    v.reg_write(UC_ARM_REG_SP, STACK)
    v.reg_write(UC_ARM_REG_R0, mode)
    v.reg_write(UC_ARM_REG_R1, STOP | 1)
    v.reg_write(UC_ARM_REG_LR, STOP | 1)
    v.emu_start(0x10206e05, STOP, count=2000)
    assert v.reg_read(UC_ARM_REG_PC) == STOP and len(packets) == 1
    assert bytes.fromhex(packets[0]['payload_hex']) == bytes([9, 0, 0, 0, mode, 0, 0, 0])
    report['transition_packet_checks'].append({'mode': mode, **packets[0]})
report['transition_packet_scope'] = {
    'original_path': '10206E04 -> registered 102054FE -> 10434E6C -> 10434FFE -> packet submission 10205698',
    'registration': 'Startup 102055A2/102055AE obtains table 11990924; row 15 registers 102054FF with row context through 10206CBA',
    'stubs': ['packet submission 10205698', 'pending transport check 10205632'],
    'seeded_runtime_state': ['C18A7C20 handler/context', 'C1887B00 registration table pointer'],
    'limitation': 'Verifies serialization of both mode values, not transport completion, receiving processor identity, NVRAM effects, or recovery on power loss.',
}
out = ROOT / 'work/analysis'
(out / 'config_read.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
ranges = [(0x104b4ec6, 0x100), (0x104b5174, 0x40), (0x104b48c6, 0x52),
          (0x1063f598, 0x18), (0x103c31e4, 0x10), (0x103c258c, 0x78),
          (0x102055a0, 0x2c), (0x10206cba, 0xa), (0x10206dfc, 0x2c),
          (0x102054fe, 0x5c), (0x10434e68, 0x28), (0x10434ffe, 0x20)]
(out / 'config_read_code.txt').write_text('\n\n'.join(FW.listing(a, n) for a, n in ranges)+'\n')
print(json.dumps({k: len(report[k]) for k in
                  ('preflight_checks', 'read_checks', 'commit_dispatch_checks',
                   'transition_packet_checks')}, indent=2))
