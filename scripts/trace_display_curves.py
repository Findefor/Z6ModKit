"""Trace the per-frame display controls and local lookup-bank writes on both Z6 II masters."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import NamedTuple

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                               UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_SP)

from analyze_frame_producer import ARG, BUILDS, C162_PACKAGE, CFG, OBJ, PATH, PIXELS, Trace, load_master
from compare_hdmi_card import DISPLAY_BANK, SITES as VIDEO, depth_surface, frame_packet
from trace_nlog_control import SITES as CONTROL, map_global, r


class Sites(NamedTuple):
    select: int
    driver_control: int
    interrupt_mask: int
    hdmi_entry: int
    hdmi_setting: int
    hdmi_command: int
    hdmi_color: int


SITES = {
    'C1.62': Sites(0x104494e2, 0x1046fa64, 0x103c7682, 0x104da078, 0x104d9b78, 0x104dbf30, 0x104d901c),
    'C1.70': Sites(0x1044a3a2, 0x10470938, 0x103c84b2, 0x104dd968, 0x104dd468, 0x104df820, 0x104dc90c),
}


def apply_gate(t, control, video, request, nlog, hlg):
    # Firmware registration, ordered bulk read and destination byte are distinct checks.
    reg = video.depth_registration+24
    prop, _, _, _, callback = t.unpack(reg, '5I')
    assert prop == 0x126f
    count, keys = t.unpack(t.unpack(reg+8, 'I')[0], '2I')
    assert count == 8 and t.unpack(keys+4, '4I') == (prop, 0x1689, 0x126e, 0x12a4)
    t.put(ARG, '7I', 0, request, 0, nlog, hlg, 0, 0)
    t.run(callback & ~1, 0, ARG, 0, OBJ, stop=control.queued)
    key, = t.unpack(r(t, UC_ARM_REG_R1), 'I')
    value, = t.unpack(r(t, UC_ARM_REG_R2), 'I')
    assert (key, value) == (0x1689, request * bool(nlog or hlg))
    t.run(control.bulk_read, stop=control.bulk_read+12)
    assert t.unpack(r(t, UC_ARM_REG_R0)+0x23c, 'I') == (key,)
    t.put(ARG+0x23c, 'I', value)
    t.run(video.snapshot_depth+0x26, stop=video.snapshot_depth+0x2e,
          regs=((UC_ARM_REG_R4, CFG+0xac), (UC_ARM_REG_R5, ARG)))
    assert t.unpack(CFG+0x470, 'B') == (value,)
    return value


def local_banks(t, s, video, outlet, packet):
    select = s.select
    root = t.unpack(select+0x6e, 'I')[0]-0x4c
    map_global(t, root)
    t.put(root, 'B', outlet//2)
    t.put(root+0x34, 'I', CFG)
    t.put(root+0x20, 'I', ARG)
    t.put(ARG+4, 'II', 0, 0)  # displacement of the register and table windows
    t.put(ARG+0x16, 'B', 0x8b)  # optional interrupt channel disabled in the fixture
    t.cpu.mem_write(OBJ, packet)
    local_entry = select+0x80e
    t.run(video.dispatch, outlet, OBJ, stop=local_entry)
    assert r(t, UC_ARM_REG_R0) == OBJ and r(t, UC_ARM_REG_R1) == 0
    # Resume at the local handler's cache-miss/update path.
    t.run(select+0x7d8, stop=select+0x7de, regs=((UC_ARM_REG_R4, OBJ+4),))
    enum, style = (r(t, reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1))
    assert (enum, style) == (packet[0xa8], packet[5])
    t.cpu.mem_write(DISPLAY_BANK, bytes(0x2000))
    t.cpu.mem_write(0x24040000, bytes(0x3000))
    map_global(t, t.unpack(s.driver_control+0x178, 'I')[0])

    def skip_interrupt_mask(cpu, address, size, _):
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    writes = []

    def on_write(cpu, access, address, size, value, _):
        writes.append((address, size))

    sources = []

    def on_upload(cpu, address, size, _):
        src = r(t, UC_ARM_REG_R2)
        assert r(t, UC_ARM_REG_R1) == 1
        assert t.unpack(r(t, UC_ARM_REG_SP), 'I') == (src+128,)
        sources.append(src)

    hook = t.cpu.hook_add(UC_HOOK_CODE, skip_interrupt_mask, begin=s.interrupt_mask, end=s.interrupt_mask)
    upload_sites = [select+0xd0, select+0x112]
    observers = [t.cpu.hook_add(UC_HOOK_CODE, on_upload, begin=a, end=a) for a in upload_sites]
    monitor = t.cpu.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=0x24040000, end=0x24042fff)
    try:
        t.run(select, enum, style, stop=select+0x11e)
    finally:
        for handle in [monitor, hook, *observers]:
            t.cpu.hook_del(handle)
    banks = []
    assert len(sources) in (0, 2)
    for start, src in zip((0x24040100, 0x24042100), sources):
        expected = t.unpack(src, '96H')
        assert all(value < 4096 for value in expected)
        assert expected[:32] == expected[32:64] == expected[64:]
        assert t.unpack(start, '96H') == expected
        banks.append(hashlib.sha256(bytes(t.cpu.mem_read(start, 192))).hexdigest())
    assert len(writes) == 48*len(sources)
    assert sorted(writes) == [(base+4*i, 4) for base in (0x24040100, 0x24042100)[:len(sources)]
                              for i in range(48)]
    return banks


def hdmi_color_settings(t, video, s):
    # Command and frame use different memory. The two command states below
    # are positive controls. No source curve is assumed for either value.
    root = t.unpack(video.gate+0x62, 'I')[0]
    map_global(t, root)
    t.put(root+0x1c, 'I', CFG)
    command, iterator, pair = ARG+0x500, ARG+0x600, ARG+0x700
    results = []
    for state in (0, 1):
        for style in (0, 1):
            by_curve = []
            for enum in (0, 1, 2):
                frame = depth_surface(t, video, 0, int(enum == 1), int(enum == 2), PIXELS+1)
                t.put(CFG+0x7e4, 'B', style)
                outlet, _, packet = frame_packet(t, video, frame, 0, 2)
                assert outlet == 1 and packet[5] == style and packet[4] == 1
                t.cpu.mem_write(OBJ, packet)
                t.put(command+0x14, 'I', iterator)
                t.put(iterator, '3I', pair, 1, 0)
                t.put(pair, '2I', 0, state)
                t.put(CFG+0x1f4, 'I', 0xdeadbeef)
                t.run(s.hdmi_command, command, stop=s.hdmi_command+0x30)
                assert t.unpack(CFG+0x1f4, 'I') == (state,)
                assert t.unpack(iterator, '3I') == (pair+8, 1, 1)
                t.put(CFG+0x2f0, 'B', 0xff)  # force a cache miss
                t.run(video.gate+0x136, stop=video.gate+0x13a, regs=((UC_ARM_REG_R4, OBJ+4),))
                payload = r(t, UC_ARM_REG_R0)
                assert payload == OBJ+4 and r(t, UC_ARM_REG_R1) == 1
                # The entry initializes r6/r7 to zero. Resume after the first matrix call.
                t.run(s.hdmi_color+0x4a, stop=s.hdmi_color+0x92,
                      regs=((UC_ARM_REG_R4, root), (UC_ARM_REG_R6, 0), (UC_ARM_REG_R7, 0),
                            (UC_ARM_REG_R8, payload)))
                by_curve.append((r(t, UC_ARM_REG_R6), r(t, UC_ARM_REG_R7)))
            expected = ((4, 4) if state else (4, 0)) if style == 0 else ((3, 6) if state else (1, 2))
            assert by_curve == [expected]*3
            results.append(dict(state=state, packet_style=style, table_indices=expected))
    return results


def compare(version, path):
    s, video, control = SITES[version], VIDEO[version], CONTROL[version]
    t = Trace(load_master(path, version), BUILDS[version][1])
    t.cpu.mem_map(DISPLAY_BANK, 0x2000)
    t.cpu.mem_map(0x24040000, 0x3000)
    results = {}
    for mode in range(6):
        for request in (0, 1):
            samples = []
            for enum in (0, 1, 2):
                nlog, hlg = int(enum == 1), int(enum == 2)
                frame = depth_surface(t, video, 0, nlog, hlg, PIXELS+1)
                gate = apply_gate(t, control, video, request, nlog, hlg)
                outlet, record, packet = frame_packet(t, video, frame, 0, mode)
                local = outlet != 1
                selector = enum if local and gate else 0
                hlg_field = hlg if outlet == 1 else 0
                assert (record[0x2b], packet[0xa8]) == (selector, selector)
                assert (record[0x64], packet[0xe8]) == (hlg_field, hlg_field)
                if local:
                    banks = local_banks(t, s, video, outlet, packet)
                    assert len(banks) == (0 if selector == outlet == 0 else 2)
                else:
                    t.cpu.mem_write(OBJ, packet)
                    t.run(video.dispatch, outlet, OBJ, stop=s.hdmi_entry)
                    assert r(t, UC_ARM_REG_R0) == OBJ
                    t.run(video.gate+0xe4, stop=s.hdmi_setting, regs=((UC_ARM_REG_R4, OBJ+4),))
                    assert r(t, UC_ARM_REG_R0) == hlg_field
                    banks = []
                samples.append((record, packet, banks))
            changes = []
            for enum, (record, packet, banks) in enumerate(samples):
                record_diff = [i for i, v in enumerate(record) if v != samples[0][0][i]]
                packet_diff = [i for i, v in enumerate(packet) if v != samples[0][1][i]]
                exp_rec = [0x64] if mode//2 == 1 and enum == 2 else []
                exp_pkt = [0xe8] if exp_rec else []
                if mode//2 != 1 and request and enum:
                    exp_rec, exp_pkt = [0x2b], [0xa8]
                assert (record_diff, packet_diff) == (exp_rec, exp_pkt)
                changes.append(dict(packet_delta_from_off=packet_diff, table_sha256=banks))
            if mode//2 != 1 and request:
                assert samples[1][2][1] != samples[2][2][1]
            results[f'mode_{mode}_gate_request_{request}'] = changes
    return {'frame_matrix': results, 'hdmi_color_state': hdmi_color_settings(t, video, s)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', nargs='?', type=Path, default=C162_PACKAGE)
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit('Run without -O to enable trace assertions.')
    results = {v: compare(v, p) for v, p in [('C1.62', args.source_162), ('C1.70', args.master_170)]}
    assert results['C1.62'] == results['C1.70']
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
