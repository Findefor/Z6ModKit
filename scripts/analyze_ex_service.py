"""Offline original-code checks of MCU subsystem 15/message 9 and its reply.

No USB. Physical settings and callbacks are explicit synthetic inputs/stubs.
No claim of full-camera boot, peripheral emulation, or physical fault recovery.
"""
import hashlib
import json
import struct

from ex_inspect import ExFirmware, ROOT, BASE, SHA256
from fw_inspect import Firmware, BASE as MASTER_BASE
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)

FW = ExFirmware()
initial = FW.initial_ram()
STOP, STACK, WIRE = 0x08010000, 0x2003bff0, 0x2003b000
REGIONS = 0x2000e79c
callbacks = [struct.unpack_from('<2I', initial, 0xd3c4+i*8) for i in range(6)]
assert struct.unpack_from('<2I', initial, 0xd32c+15*8) == (0x0802ec9d, 0x0802f96d)
u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
u.mem_map(BASE, 0x81000)
u.mem_write(BASE, FW.data)
u.mem_protect(BASE, 0x81000, UC_PROT_READ | UC_PROT_EXEC)
u.mem_map(0x20000000, 0x40000)
events, stores, queue_behavior, copies = [], [], [], []


def ret(cpu, value=0):
    cpu.reg_write(UC_ARM_REG_R0, value)
    cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))


def ex_hook(cpu, address, size, _):
    regs = [cpu.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
    r0, r1, r2 = regs
    if address in (0x080204c8, 0x08020552):
        assert 0x20000000 <= r0 and r0+r2 <= 0x20040000
        if BASE <= r1 < BASE+len(FW.data):
            copies.append((r1, r0, r2))
        cpu.mem_write(r0, bytes(cpu.mem_read(r1, r2)))
        ret(cpu, r0)
    elif address == 0x0802060a:
        assert 0x20000000 <= r0 and r0+r1 <= 0x20040000
        cpu.mem_write(r0, b'\0'*r1)
        ret(cpu, r0)
    elif address == 0x080214fe:
        assert r0 == 0x200140dc and r1 == 0x20
        events.append({'schedule_event': r1})
        ret(cpu, 1)
    elif address in {fn & ~1 for fn, _ in callbacks}:
        events.append({'callback_stub': hex(address), 'region': r0, 'data': hex(r1)})
        ret(cpu, 1)
    elif address == 0x08032000:
        assert r0 == 0x20014108
        descriptor = bytes(cpu.mem_read(r0, 24))
        ptr = struct.unpack_from('<I', descriptor, 4)[0]
        length = struct.unpack_from('<H', descriptor, 2)[0]
        assert (descriptor[0], descriptor[8], length) == (15, 2, 8)
        payload = bytes(cpu.mem_read(ptr, length))
        assert payload == bytes([10, 0, 0, 0, 0, 0, 0, 0])
        value = queue_behavior.pop(0) if queue_behavior else 0
        events.append({'reply_queue_stub': value, 'payload': payload.hex()})
        ret(cpu, value)
    elif address == 0x08042304:
        assert r0 == 1
        events.append({'sleep_stub': 1})
        ret(cpu)
    else:
        assert any(a <= address < b for a, b in (
            (0x08031e70, 0x08031f1a), (0x0802f96c, 0x0802fb08),
            (0x0802f484, 0x0802f574), (0x0802ec0c, 0x0802eca8),
            (0x0802ede0, 0x0802ee42), (0x0802f5f8, 0x0802f65e),
            (0x0802f43c, 0x0802f47e), (0x080426a8, 0x080426b0),
            (0x0802fb80, 0x0802fbbc), (0x080204c8, 0x08020638),
            (0x0804b990, 0x0804b9ac))), hex(address)


def write_hook(cpu, access, address, size, value, _):
    assert 0x20000000 <= address and address+size <= 0x20040000, hex(address)
    if address < 0x2003a000:
        stores.append((address, size))


u.hook_add(UC_HOOK_CODE, ex_hook)
u.hook_add(UC_HOOK_MEM_WRITE, write_hook)


def call(cpu, address, r0=0, r1=0, r2=0, count=200000):
    for reg, value in ((UC_ARM_REG_R0, r0), (UC_ARM_REG_R1, r1), (UC_ARM_REG_R2, r2),
                       (UC_ARM_REG_SP, STACK), (UC_ARM_REG_LR, STOP | 1)):
        cpu.reg_write(reg, value)
    cpu.emu_start(address | 1, STOP, count=count)
    assert cpu.reg_read(UC_ARM_REG_PC) == STOP, 'instruction limit'
    return cpu.reg_read(UC_ARM_REG_R0)


def setup(changed):
    u.mem_write(0x20000000, initial)
    call(u, 0x0802ede0)  # Original flash source pointer initializer.
    call(u, 0x0802f5f8)  # Original RAM destination pointer initializer.
    call(u, 0x0802ec9c, 0x08032001, 15)  # Original subsystem registration setter.
    u.mem_write(0x20011754, struct.pack('<II', 18, 0x2000d32c))
    rows = []
    for i in range(9):
        row = struct.unpack('<5I', u.mem_read(REGIONS+i*20, 20))
        _, src, dst, size, flag = row
        assert 0x08004000 <= src < 0x08010000 and 0x20038000 <= dst < 0x2003a000
        # Module calibration sectors are not a dump of this camera. Use their
        # bytes only as a stable source, with deliberately different RAM bytes.
        data = bytes(u.mem_read(src, size))
        if i in changed:
            data = bytes([data[0] ^ 0x5a]) + data[1:]
        u.mem_write(dst, data)
        rows.append(row)
    events.clear(); stores.clear(); queue_behavior.clear()
    return rows


def receive(mode, queued_errors=0):
    wire = bytearray(256)
    struct.pack_into('<BBH', wire, 0, 15, 2, 8)
    wire[8:16] = bytes([9, 0, 0, 0, mode, 0, 0, 0])
    wire[0xfc:0xfe] = b'\1\1'
    u.mem_write(WIRE, bytes(wire))
    events.clear(); stores.clear(); copies.clear()
    call(u, 0x08031e70, 1, WIRE)
    assert events == [{'schedule_event': 0x20}]
    queue_behavior[:] = [0xffff] * queued_errors + [0]
    call(u, 0x0802f484, 0x20)
    assert bytes(u.mem_read(BASE, len(FW.data))) == FW.data
    return list(events)


report = {'camera_io': False, 'ex_sha256': SHA256,
          'initial_ram_sha256': hashlib.sha256(initial).hexdigest(),
          'scope': 'Original EX scatter-load, receive dispatcher, handler, callback dispatcher and reply formatter; original master reply decoder and worker',
          'ex_stubs': ['memcpy/memclear with RAM-only destination bounds', 'event scheduler', 'six configuration callbacks (side effects reviewed separately)',
                       'reply queue insertion and sleep'], 'checks': []}
eligible = {1, 3, 4, 5, 6, 8}
for name, mode, changed, errors in (
    ('entry_unchanged', 0, set(), 0),
    ('entry_all_RAM_regions_differ', 0, set(range(9)), 0),
    ('exit_all_RAM_regions_differ', 1, set(range(9)), 0),
    ('entry_reply_queue_full_twice', 0, eligible, 2),
    ('exit_reply_queue_full_twice', 1, eligible, 2),
):
    rows = setup(changed)
    before = [bytes(u.mem_read(row[2], row[3])) for row in rows]
    ev = receive(mode, errors)
    actual = {i for i, row in enumerate(rows) if bytes(u.mem_read(row[2], row[3])) != before[i]}
    expected = changed & eligible if mode == 0 else set()
    # Parent descriptors overlap child slices. Audit direct copies and all
    # region snapshots, not an assumed disjoint region map.
    assert copies == [(rows[i][1], rows[i][2], rows[i][3]) for i in sorted(expected)]
    expected_affected = set(expected)
    for parent, children in ((0,{1}), (2,{3,4,5,6}), (7,{8})):
        if expected & children:
            expected_affected.add(parent)
    assert actual == expected_affected
    notified = [e['region'] for e in ev if 'callback_stub' in e]
    assert notified == [region for _, region in callbacks if region in expected]
    assert len([e for e in ev if 'sleep_stub' in e]) == errors
    report['checks'].append({'case': name, 'mode': mode, 'refreshed_slices': sorted(expected),
                             'affected_overlapping_regions': sorted(actual),
                             'callback_regions': notified, 'events': ev, 'flash_unchanged': True})
    # Repeat after a simulated lost reply: all original state changes above
    # are preserved, but the host is assumed not to have received the response.
    if mode == 0 and changed == set(range(9)):
        repeat = receive(0)
        assert not any('callback_stub' in e for e in repeat)
        report['checks'].append({'case': 'repeat_entry_after_reply_not_delivered',
                                 'callback_regions': [], 'events': repeat,
                                 'limitation': 'Only this MCU branch is repeated; host may reject retry while its callback is pending.'})

report['region_table'] = [dict(id=a, flash_source=hex(b), ram_destination=hex(c),
                              length=d, refresh_on_entry=bool(e)) for a,b,c,d,e in rows]
report['callback_table'] = [{'function': hex(a & ~1), 'region': b} for a,b in callbacks]

# Confirm that reply 0A/status0 is the master service transition acknowledgement.
master = Firmware()
m = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
m.mem_map(MASTER_BASE, (len(master.data)+4095)&~4095)
m.mem_write(MASTER_BASE, master.data)
m.mem_protect(MASTER_BASE, (len(master.data)+4095)&~4095, UC_PROT_READ | UC_PROT_EXEC)
m.mem_map(0xc1800000, 0xb0000)
m.mem_write(0xc1800000, master.data[0x123a1c14-MASTER_BASE:0x123a1c14-MASTER_BASE+0xaedb8])
m.mem_map(0x20000000, 0x40000)
m.mem_map(BASE, 0x11000)  # Return sentinel only, no MCU code executed here.
master_events = []


def master_hook(cpu, address, size, _):
    r0, r1 = [cpu.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1)]
    if address == 0x1035c98c:
        assert r0 == 0xc2b2374c and r1 in (0x40, 0x80)
        master_events.append({'event_signal': r1})
        ret(cpu, 1)
    elif address == 0x1047c21e:
        master_events.append({'transition_event': hex(r0), 'success': r1})
        ret(cpu)
    else:
        assert any(a <= address < b for a,b in (
            (0x10434eb4, 0x10434ed8), (0x10435022, 0x1043504e),
            (0x10206cc4, 0x10206d9e), (0x10385a94, 0x10385b64),
            (0x10385caa, 0x10385f22), (0x1038602e, 0x10386050))), hex(address)


m.hook_add(UC_HOOK_CODE, master_hook)
for mode in (0, 1):
    for status in (0, 1):
        master_events.clear()
        m.mem_write(WIRE, bytes([10,0,0,0,status,0,0,0]))
        out = WIRE+0x100
        assert call(m, 0x10434eb4, WIRE, 8, out) == 1
        decoded = struct.unpack('<I', m.mem_read(out,4))[0]
        m.mem_write(0xc18a7c28, struct.pack('<I', 0x10385a95))
        m.mem_write(0xc18a7b7c, bytes([mode]))
        m.mem_write(0xc18a7ba4, struct.pack('<I', 0x1047c21f))
        call(m, 0x10206cc4, decoded)
        assert master_events == [{'event_signal': 0x80}]
        call(m, 0x10385caa, 0x80)
        assert master_events[-1] == {'transition_event': hex(0x03010003+mode),
                                     'success': int(status == 0)}
        assert bytes(m.mem_read(0xc18a7ba4,4)) == b'\0'*4
        report['checks'].append({'case': 'master_reply', 'mode': mode, 'status': status,
                                 'events': list(master_events), 'pending_callback_cleared': True})

# With the response absent, the pending callback blocks another transition.
for mode in (0, 1):
    master_events.clear()
    m.mem_write(0xc18a7ba4, struct.pack('<I', 0x1047c21f))
    result = call(m, 0x1038602e, mode, 0x1047c21f)
    assert result == 0 and not master_events
    report['checks'].append({'case': 'retry_with_reply_missing', 'mode': mode,
                             'request_accepted': False, 'pending_callback': 'unchanged'})
    # A reply arriving later clears this pending operation through the same
    # original decoder/worker; a subsequent request is accepted at this layer.
    m.mem_write(WIRE, bytes([10,0,0,0,0,0,0,0]))
    m.mem_write(0xc18a7b7c, bytes([mode]))
    assert call(m, 0x10434eb4, WIRE, 8, WIRE+0x100) == 1
    decoded = struct.unpack('<I',m.mem_read(WIRE+0x100,4))[0]
    call(m, 0x10206cc4, decoded)
    call(m, 0x10385caa, 0x80)
    assert call(m, 0x1038602e, mode, 0x1047c21f) == 1
    assert master_events[-1] == {'event_signal': 0x40}
    report['checks'].append({'case': 'late_reply_then_new_request', 'mode': mode,
                             'request_accepted': True, 'events': list(master_events),
                             'limitation': 'This low-level request only; whole PTP service state and other cleanup effects are outside the test.'})
assert struct.unpack_from('<I', master.data, 0x123a1c14-MASTER_BASE+0xa7ba4)[0] == 0
report['findings'] = {
    'receiver': 'EX/MCU, registration RAM 2000D32C row15 -> 0802F96C; message9 -> event20 -> 0802EC0C',
    'entry': 'Mode0 refreshes differing eligible flash-backed configuration slices into working RAM, then invokes their registered callbacks.',
    'exit': 'Mode1 skips the refresh and callbacks in this handler and formats reply0A/status0. No persistent service-mode bit appears in this branch.',
    'reply_retry': '0802FB80 retries queue insertion while it returns FFFF, sleeping1 between attempts; no iteration limit is present in this loop. This is not proof of delivery.',
    'missing_reply': 'Master pending callback remains until reply handling; 1038602E rejects another transition while pending. A late reply clears this callback and permits a new low-level request. Complete PTP recovery and cleanup side effects remain unverified.',
    'reset_limit': 'Master initialized pending callback is zero; EX scatter-load restores defaults. This is software initialization evidence, not proof of physical reset routing, battery-removal recovery or a complete boot.',
    'persistence_limit': 'No direct flash write in the emulated message9 path. Configuration callbacks are stubbed; some original callbacks control peripheral buses. No claim of a side-effect-free whole service session.',
}
report['master_stubs'] = ['event queue signal', 'transition completion callback; registration pointers supplied explicitly']
report['static_callback_review'] = {
    'method': 'Static review, not additional emulation checks; callbacks run only for changed regions.',
    'region1': '08024BB2 -> 08029418 compares 2001F737 with region+117. Crossing into/out of value5 reaches 0802B40C/0802B234 -> 0802AE98 -> 080449B0, sends one-byte values to peripheral address D6, registers0..7. Separate ex_peripherals analysis favors BQ25882; physical identity and board-level POR remain unverified.',
    'region1_second_callback': '0803671C -> event80000 -> worker08036744 -> 0803616C; reviewed isolated-event branch updates RAM from region offsets11C/11E/392.',
    'region4': '08024BB2 -> 080294F4(r1=0) updates RAM and copies0x48 bytes through 08024998; normalization branch is skipped.',
    'region5': '08030E20 -> event200 -> worker08030E34 -> 08030D08 -> 08031CB4 -> worker08031A8C; isolated branch copies200189C0 to200189BC.',
    'region3': '0802BBC0 -> 0802E1B4 -> worker0802E1C4 -> 0802DB1C -> 0802D824 -> 0802DCE8; queue0802D7F4 -> 0802D91C -> 0802D8E4 -> 08045894 sends commands04/0F/10/1C/1D/1E over SPI2 base40003800, GPIO PE8/PA4 and PE14. Init0802E168 ->0802DA40 rebuilds commands. Device identity and NVM/POR behavior remain unverified.',
    'region6': '08036730 -> event40000 -> worker08036744 -> 080361B6. 080350CC copies0x42 bytes and signals worker08034DE0; 08035FC0 ->0803C77C signals event2000 ->0803C5C4. Idle branch0803C79C ->08035400 writes TIM2 ARR4000002C; busy branch defers with RAM flag. See ex_peripherals.json for isolated worker checks and static timer-init mapping.',
    'separate_save': 'Command7 -> event10 -> 0802F57C -> 08032120 is a separate save path. No direct call to08032120 found in the reviewed callback chains; this does not prove absence of all persistent peripheral effects.',
}
out = ROOT/'work/analysis'
(out/'ex_service.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
ranges = [(0x08003804,0x12c),(0x08031d34,0x76),(0x08031e70,0xaa),
          (0x0802f9e2,0xe),(0x0802faec,0xc),(0x0802f484,0x2c),
          (0x0802ec0c,0x84),(0x0802ede0,0x62),(0x0802f5f8,0x66),
          (0x0802f43c,0x42),(0x0802fb80,0x3c)]
(out/'ex_service_code.txt').write_text('\n\n'.join(FW.listing(a,n) for a,n in ranges)+'\n')
print(json.dumps({'checks':len(report['checks']),'camera_io':False,
                  'entry_refresh_regions':sorted(eligible)},indent=2))
