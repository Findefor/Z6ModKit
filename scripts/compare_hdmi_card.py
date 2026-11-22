"""Compare Z6 II frame layouts and HDMI display registers in two original EG masters."""
import argparse
import json
import sys
from pathlib import Path
from typing import NamedTuple

from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                               UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)

from analyze_frame_producer import (ARG, BUILDS, C162_PACKAGE, CFG, OBJ, PATH,
                                    CTX, JOB, PIXELS, POOL, STACK, Trace, load_master)


class Sites(NamedTuple):
    surface: int
    display: int
    diagnostic: int
    pack: int
    enqueue: int
    ring_pop: int
    serialize: int
    dispatch: int
    gate: int
    input_surface: int
    mode_selector: int
    job_selector: int
    snapshot: int
    job_builder: int
    job_dispatch: int
    port_parser: int
    resolve_id: int
    depth_registration: int
    snapshot_depth: int


SITES = {
    'C1.62': Sites(0x103086A2, 0x104D98AA, 0x10290EB0, 0x1026A446, 0x103E4534,
                   0x103E314A, 0x103E35F6, 0x104D6822, 0x104D9EFE, 0x10307E58,
                   0x103150B8, 0x10264826, 0x1026A0DA, 0x102B9AEE, 0x102BB0A8,
                   0x103B55AC, 0x103B615C, 0x118F0950, 0x103548F4),
    'C1.70': Sites(0x10308EDA, 0x104DD19A, 0x102910DC, 0x1026A582, 0x103E5364,
                   0x103E3F7A, 0x103E4426, 0x104DA112, 0x104DD7EE, 0x10308690,
                   0x10315A2C, 0x10264962, 0x1026A216, 0x102B9EA2, 0x102BB45C,
                   0x103B6308, 0x103B6EB8, 0x11909208, 0x10355830),
}

# Offsets of the short blocks preparing arguments for the diagnostic formatter.
# The first block starts just before r7 is advanced to the descriptor.
LABELS = (
    (0, 10, 'YCbCrFormat'), (0x3e, 8, 'DataFormat'),
    (0x76, 8, 'LineBytesY'), (0xae, 8, 'LineBytesC'),
    (0x2e8, 8, 'AddressY'), (0x320, 8, 'AddressC'),
    (0x358, 12, 'AddressC-AddressY Offset'),
)


def read_named_fields(trace, diagnostic):
    record = OBJ + 0x18
    fields = {}
    for offset, size, name in LABELS:
        trace.run(diagnostic + offset, stop=diagnostic + offset + size,
                  regs=((UC_ARM_REG_R7, record - 0x28 if offset == 0 else record),))
        string = trace.cpu.reg_read(UC_ARM_REG_R1)
        label = bytes(trace.cpu.mem_read(string, 40)).split(b'=', 1)[0].strip().decode('ascii')
        assert label == name
        fields[name] = trace.cpu.reg_read(UC_ARM_REG_R2)
    assert fields['AddressC'] - fields['AddressY'] == fields['AddressC-AddressY Offset']
    return fields


def set_depth_state(trace, sites, depth, nlog, hlg):
    # Use the registered callback with its normal (no override) inputs.
    property_id, _, _, _, callback = trace.unpack(sites.depth_registration, '5I')
    assert property_id == 0x126d
    callback &= ~1
    inputs = ARG + 0x1000
    trace.put(inputs, '7I', 0, depth, 0, 0, 0, 0, 0)
    trace.run(callback, 0, inputs, 0, 0, stop=callback+0x20)
    trace.cpu.reg_write(UC_ARM_REG_R0, 0)  # ordinary mode helper result
    trace.cpu.emu_start((callback+0x24) | 1, callback+0x58, count=32)
    assert trace.cpu.reg_read(UC_ARM_REG_PC) == callback+0x58
    key, = trace.unpack(trace.cpu.reg_read(UC_ARM_REG_R1), 'I')
    effective, = trace.unpack(trace.cpu.reg_read(UC_ARM_REG_R2), 'I')
    assert (key, effective) == (0x16a5, depth)
    # Supply the value that would be kept by the asynchronous property store.
    trace.run(sites.snapshot_depth, stop=sites.snapshot_depth+4)
    assert trace.cpu.reg_read(UC_ARM_REG_R0) == key
    trace.put(inputs+0x230, '3I', 0, nlog, hlg)
    trace.run(sites.snapshot_depth+8, stop=sites.snapshot_depth+0x26, regs=(
        (UC_ARM_REG_R0, effective), (UC_ARM_REG_R4, CFG+0xac), (UC_ARM_REG_R5, inputs)))
    assert trace.unpack(CFG+0x46c, '4B') == (depth, 0, nlog, hlg)


def depth_surface(trace, sites, depth, nlog, hlg, allocation):
    trace.cpu.mem_write(CFG, bytes(0x500))
    trace.put(CFG, 'BB', 1, 0)
    trace.put(CFG + 0xac, 'I', 4)
    trace.put(CFG + 0xec, '4H', 0, 0, 3840, 2160)
    set_depth_state(trace, sites, depth, nlog, hlg)
    trace.put(CFG + 0x4d4, '3B', 2, 2, 4)
    trace.put(OBJ + 4, 'I', POOL)
    trace.put(POOL, 'I', allocation)
    trace.run(sites.surface, OBJ, CFG)
    fields = read_named_fields(trace, sites.diagnostic)
    assert trace.unpack(OBJ + 0x1e, '4H') == (3840, 2176, 3840, 2160)
    y = (allocation + 511) & ~511
    assert (fields['AddressY'], fields['AddressC']) == (y, y + 0xc70e00)
    expected = (1, 2, 5760, 5760) if depth == 0 else (2, 0, 3840, 3840)
    assert tuple(fields[key] for key in ('YCbCrFormat', 'DataFormat', 'LineBytesY', 'LineBytesC')) == expected
    return fields


DISPLAY_BANK = 0x20140000


def check_display(trace, sites, tag, bases, source_width, x, y):
    # Give the actual display driver a RAM register bank and two distinct
    # incoming addresses. The crop origin can move while the active size stays fixed.
    sentinel = 0xa5a5a5a5
    trace.cpu.mem_write(DISPLAY_BANK, bytes([0xa5]) * 4096)
    trace.put(CFG + 0x2dc, '8H', source_width, 2160, x, y, x+3840, y+2160, 0, 0)
    trace.put(OBJ, 'B', tag)
    trace.put(OBJ + 0xf0, 'II', *bases)
    trace.run(sites.display, OBJ, 0)
    ok = trace.cpu.reg_read(UC_ARM_REG_R0)
    control, dimensions = trace.unpack(DISPLAY_BANK+0x200, 'II')
    addresses = [trace.unpack(DISPLAY_BANK+n, 'I')[0] for n in (0x210, 0x220)]
    pitches = [trace.unpack(DISPLAY_BANK+n, 'I')[0] for n in (0x240, 0x250)]
    if tag not in (0, 1, 4):
        assert ok == 0 and [control, dimensions, *addresses, *pitches] == [sentinel] * 6
        return
    assert ok == 1 and dimensions == (3840 | (2160 << 16))
    assert control == (0x30300000 | tag)
    offset = x + y * source_width
    if tag == 1:
        pitch = source_width * 3 // 2
        offsets = [offset * 3 // 2] * 2
    else:
        pitch = source_width
        offsets = [offset, x + (y // 2) * source_width if tag == 4 else offset]
    assert pitches == [pitch, pitch]
    assert addresses == [base + delta for base, delta in zip(bases, offsets)]
    return {'control': hex(control), 'pitch_Y_C': pitches, 'base_offsets': offsets}


def frame_packet(trace, sites, fields, depth, mode):
    # Modes 2 and 3 dispatch to HDMI output 1. Stop at the history lock, then
    # resume after its six-entry bookkeeping, retaining the original stack.
    trace.put(STACK, '2I', 1, 0)
    lock = 0x1f6 if mode in (2, 3) else 0x25a
    trace.run(sites.pack, mode, CFG, CFG+0xd4, OBJ+0x18, stop=sites.pack+lock)
    trace.cpu.emu_start((sites.pack+0x294) | 1, sites.enqueue, count=30)
    assert trace.cpu.reg_read(UC_ARM_REG_PC) == sites.enqueue
    route, payload, rectangle, config = (trace.cpu.reg_read(r) for r in
                                         (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3))
    assert (route, rectangle) == ((0, 0, 1, 1, 3, 3)[mode], CFG+0xec)
    assert trace.unpack(payload, 'I') == (1,)
    assert trace.unpack(payload+0x18, '2I') == (fields['AddressY'], fields['AddressC'])
    tag = 4 if depth else 1
    assert trace.unpack(payload+0x28, 'B') == (tag,)
    # Keep the producer payload clear of the next emulated stack; hand it to
    # the original slot copier. Skip asynchronous scheduling and locking.
    record = bytes(trace.cpu.mem_read(payload, 112))
    trace.cpu.mem_write(ARG+0x100, record)
    ring = JOB + 0xc
    trace.cpu.mem_write(JOB, bytes(0x700))
    trace.put(ring, 'I', 2)
    trace.put(STACK+0xc, '2I', rectangle, config)
    trace.put(STACK+0x38, 'I', 0)
    trace.run(sites.enqueue+0x16c, stop=sites.enqueue+0x1c8,
              regs=((UC_ARM_REG_R4, JOB), (UC_ARM_REG_R7, ARG+0x100), (UC_ARM_REG_R8, 0)))
    trace.run(sites.ring_pop, ring, ARG+0x200, ARG+0x204, ARG+0x208)
    assert trace.cpu.reg_read(UC_ARM_REG_R0) == 1
    slot, = trace.unpack(ARG+0x200, 'I')
    assert slot == JOB+0xf8
    # Run the consumer's queue 0/1/3 to output 0/1/2 mapping and serialize its slot.
    trace.run(sites.serialize-0x126, route, 1, stop=sites.serialize-0xf4)
    outlet = trace.cpu.reg_read(UC_ARM_REG_R9)
    assert outlet == mode//2
    trace.cpu.mem_write(STACK, bytes(0x500))
    trace.run(sites.serialize, stop=sites.serialize+0x120, regs=(
        (UC_ARM_REG_R5, slot), (UC_ARM_REG_R6, 1), (UC_ARM_REG_R8, 0), (UC_ARM_REG_R9, outlet)))
    trace.cpu.emu_start((sites.serialize+0x120) | 1, sites.dispatch, count=1)
    assert trace.cpu.reg_read(UC_ARM_REG_PC) == sites.dispatch
    assert trace.cpu.reg_read(UC_ARM_REG_R0) == outlet
    packet = trace.cpu.reg_read(UC_ARM_REG_R1)
    assert trace.unpack(packet, 'B') == (0,) and trace.unpack(packet+4, 'B') == (tag,)
    assert trace.unpack(packet+0xf4, '2I') == (fields['AddressY'], fields['AddressC'])
    return outlet, record, bytes(trace.cpu.mem_read(packet, 0xfc))


def through_router(trace, sites, root, depth, mode):
    fields = depth_surface(trace, sites, depth, 1, 0, PIXELS + 1)
    outlet, _, packet = frame_packet(trace, sites, fields, depth, mode)
    tag = packet[4]
    assert outlet == 1
    trace.cpu.mem_write(OBJ, packet)
    trace.put(CFG+0x2ac, 'I', 1)
    trace.put(CFG+0x2c4, 'B', 0)
    trace.run(sites.gate, OBJ, stop=sites.gate+(0x11a if tag == 1 else 0x1c))
    trace.put(CFG+0x2c4, 'B', 1)
    trace.run(sites.gate, OBJ, stop=sites.gate+0x1c)
    # Enter the active display-state branch and use its original packet-to-
    # state copies. Skip unrelated transmitter setup before the plane writes.
    trace.run(sites.gate+0x9a, stop=sites.gate+0xc8,
              regs=((UC_ARM_REG_R4, OBJ+4), (UC_ARM_REG_R5, root)))
    assert trace.unpack(CFG+0x2dc, '8H') == (3840, 2176, 0, 0, 3840, 2160, 0, 0)
    trace.run(sites.display, OBJ+4, 1)
    assert trace.cpu.reg_read(UC_ARM_REG_R0) == 1
    assert trace.unpack(DISPLAY_BANK+0x200, 'II') == ((0x30300000 | tag), (2160 << 16) | 3840)
    for offset, key in ((0x210, 'AddressY'), (0x220, 'AddressC'), (0x240, 'LineBytesY'), (0x250, 'LineBytesC')):
        assert trace.unpack(DISPLAY_BANK+offset, 'I') == (fields[key],)
    return tag


def check_links(trace, sites, nodes, count):
    # Ports can declare a link at either endpoint. Terminal records contain
    # only their own IDs. Check each directed hop and run the final resolver.
    entries = {trace.unpack(nodes+16*i+2, 'B')[0]: nodes+16*i for i in range(count)}
    paths = {
        'hdmi': [1, 2, 3, 5, 7, 9, 0x0b, 0x0f, 0x14, 0x17],
        'card_a': [1, 2, 3, 5, 0x0d, 0x10, 0x15],
        'card_b': [1, 2, 4, 6, 0x0e, 0x11, 0x15],
    }
    for path in paths.values():
        for previous, current in zip(path, path[1:]):
            successors = trace.unpack(entries[previous]+7, '4B')
            predecessors = trace.unpack(entries[current]+3, '4B')
            assert current in successors or previous in predecessors, (previous, current)
    for index, parent, terminal in ((17, 12, 21), (18, 13, 21), (19, 14, 22)):
        entry = nodes + 16*index
        for field, expected in ((3, parent), (7, terminal)):
            node_id, = trace.unpack(entry+field, 'B')
            trace.run(sites.resolve_id, nodes, node_id, count)
            assert trace.cpu.reg_read(UC_ARM_REG_R0) == expected
        # Distinct fixture channel assignments show which terminal is consumed.
        channel = 8 if terminal == 21 else 9
        trace.put(nodes+16*terminal+1, 'B', channel)
        trace.put(ARG, 'BB', count, index)
        port, = trace.unpack(entry+12, 'I')
        trace.run(sites.port_parser+0x94, stop=sites.port_parser+0xde, regs=(
            (UC_ARM_REG_R4, port), (UC_ARM_REG_R5, ARG), (UC_ARM_REG_R6, nodes),
            (UC_ARM_REG_R9, STACK), (UC_ARM_REG_R10, 0), (UC_ARM_REG_R11, STACK+12)))
        assert trace.unpack(port+12, 'I')[0] & 15 == channel
    return {key: [f'{node:02X}' for node in path] for key, path in paths.items()}


def prepare_job(trace, sites, depth, nlog, hlg):
    # Use nonoverlapping fixture allocations for all three surfaces. The
    # input and HDMI constructors see the same context including mode bytes.
    card_obj, hdmi_obj = ARG+0x600, ARG+0x700
    trace.cpu.mem_write(card_obj, bytes(trace.cpu.mem_read(OBJ, 0x68)))
    hdmi = depth_surface(trace, sites, depth, nlog, hlg, 0x58000001)
    trace.cpu.mem_write(hdmi_obj, bytes(trace.cpu.mem_read(OBJ, 0x68)))
    trace.put(POOL, 'I', 0x60000001)
    trace.run(sites.input_surface, OBJ, CFG, 0x1a)
    source = read_named_fields(trace, sites.diagnostic)
    trace.run(sites.mode_selector, CFG)
    mode = trace.cpu.reg_read(UC_ARM_REG_R0)
    trace.run(sites.job_selector, mode)
    job = trace.cpu.reg_read(UC_ARM_REG_R0)
    assert job == 0x0a
    trace.cpu.mem_write(CTX, bytes(0x300))
    for offset, obj in ((0x94, OBJ), (0xa0, hdmi_obj), (0xa8, card_obj)):
        trace.put(CTX+offset, 'I', obj)
    trace.put(CTX+0x144, 'I', CFG)
    trace.put(CTX+0xd, 'B', mode)
    trace.run(sites.snapshot, CTX, JOB+4)
    for card_requested, override, expected in ((0, 0, (1, 0)), (1, 1, (0, 0)), (1, 0, (1, 1))):
        trace.put(CTX+0x30, 'I', card_requested)
        trace.put(CFG+0x2795, 'B', override)
        trace.run(sites.job_selector+0x2d8, stop=sites.job_selector+0x35e, regs=(
            (UC_ARM_REG_R3, 1), (UC_ARM_REG_R4, JOB), (UC_ARM_REG_R5, CTX),
            (UC_ARM_REG_R6, 0), (UC_ARM_REG_R7, ARG+0x300)))
        assert (trace.unpack(JOB+0x7f4, 'I')[0], trace.unpack(JOB+0x7fc, 'I')[0]) == expected

    # Actual job jump-table entry with its own ROM-initialized port table.
    jobs, = trace.unpack(sites.job_dispatch+0xe0, 'I')
    trace.cpu.mem_map(jobs & ~4095, 0x3000)
    trace.run(sites.job_dispatch, job, JOB, 0, stop=sites.job_builder)
    assert trace.cpu.reg_read(UC_ARM_REG_R0) == JOB
    args = [trace.cpu.reg_read(r) for r in (UC_ARM_REG_R1, UC_ARM_REG_R2)]
    trace.put(JOB+0x7e8, 'I', ARG+0x900)
    return mode, job, args, source, hdmi, card_obj


def shared_job(trace, sites, card):
    mode, job, args, source, hdmi, card_obj = prepare_job(trace, sites, 0, 1, 0)
    assert mode == 0x17
    assert (source['YCbCrFormat'], source['DataFormat']) == (1, 2)
    assert trace.unpack(OBJ+0x1a, '6H') == (6048, 6048, 4030, 2266, 4030, 2266)
    assert source['AddressC-AddressY Offset'] == 6048 * 2266
    trace.run(sites.job_builder, JOB, *args, stop=sites.job_builder+0xf4)
    nodes, count = trace.unpack(args[0], 'IB')
    assert count == 28
    for index, pitch, codes, pair in (
            (0, 6048, (0, 1), (source['AddressY'], source['AddressC'])),
            (21, 3984, (2, 0), (card['first'], card['second'])),
            (22, 5760, (0, 1), (hdmi['AddressY'], hdmi['AddressC']))):
        port, = trace.unpack(nodes + 16*index + 12, 'I')
        assert trace.unpack(port, '2I') == (pitch, pitch)
        assert trace.unpack(port+0x21, '2B') == codes
        assert trace.unpack(port+0x10, '2I') == pair
    for index, target, storage_width in ((17, 0x15, 3984), (18, 0x15, 3984), (19, 0x17, 3840)):
        assert trace.unpack(nodes+16*index+7, 'B') == (target,)
        settings, = trace.unpack(nodes+16*index+12, 'I')
        horizontal, vertical = trace.unpack(settings+0x2c, '2I')
        assert ((horizontal >> 16) & 0x3fff, (vertical >> 16) & 0x3fff) == (storage_width-1, 2175)
        assert trace.unpack(settings+0x1c, 'I')[0] & 0x300 == 0
    paths = check_links(trace, sites, nodes, count)
    trace.cpu.mem_write(OBJ, bytes(trace.cpu.mem_read(card_obj, 0x68)))
    trace.submit(0xa8, card, card['crop'])
    return {'mode': hex(mode), 'job': hex(job), 'entries': count, 'logical_paths': paths,
            'pitch_at_nodes_0_21_22': [6048, 3984, 5760],
            'fixture_planes_Y_C': {
                'source': [hex(source[k]) for k in ('AddressY', 'AddressC')],
                'card': [hex(card[k]) for k in ('first', 'second')],
                'hdmi': [hex(hdmi[k]) for k in ('AddressY', 'AddressC')]},
            'card_avc_displacement_bytes': card['crop']}


def compare(path, version):
    sites = SITES[version]
    trace = Trace(load_master(path, version), BUILDS[version][1])
    card = trace.construct(2, False, 1)
    fields = read_named_fields(trace, sites.diagnostic)
    assert (fields['YCbCrFormat'], fields['DataFormat']) == (2, 0)
    assert (fields['LineBytesY'], fields['LineBytesC']) == (3984, 3984)
    assert (fields['AddressY'], fields['AddressC']) == (card['first'], card['second'])
    common = shared_job(trace, sites, card)
    card = trace.construct(2, False, 1)
    trace.route_job(card, True)
    trace.submit(0x440, card, 0)
    layout = {}
    for depth in (0, 1):
        for nlog, hlg in ((0, 0), (1, 0), (0, 1)):
            for allocation in (0x58000001, PIXELS + 0x2000000):
                fields = depth_surface(trace, sites, depth, nlog, hlg, allocation)
        layout[str(depth)] = {k: v for k, v in fields.items() if k not in ('AddressY', 'AddressC')}

    # Resolve the same literal the display entry loads for its driver and state.
    root, = trace.unpack(sites.display + 0x2ba, 'I')
    trace.cpu.mem_map(root & ~4095, 4096)
    trace.put(root + 4, 'I', ARG)
    trace.put(ARG + 4, 'I', 0)  # register bank displacement
    trace.put(root + 0x1c, 'I', CFG)
    trace.cpu.mem_map(DISPLAY_BANK, 4096)
    for depth in (0, 1):
        for mode in (2, 3):
            layout[str(depth)]['display_tag'] = through_router(trace, sites, root, depth, mode)
    display = {}
    for tag in (0, 1, 4, 2):
        for source_width, x, y in ((3840, 0, 0), (3840, 2, 3), (4096, 4, 5)):
            case = check_display(trace, sites, tag, (PIXELS, PIXELS + 0x3140000), source_width, x, y)
            if case and (x, y) == (2, 3):
                display[str(tag)] = case
    return {'shared_job': common, 'depth_surface': layout, 'display_at_width_3840_crop_2_3': display,
            'card': {'pitch_Y_C': [card['pitch']] * 2, 'gap': card['gap'], 'slot_bytes': card['slot_bytes']}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', type=Path, nargs='?', default=C162_PACKAGE)
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit('Run without -O to enable trace assertions.')
    results = {v: compare(p, v) for v, p in [('C1.62', args.source_162), ('C1.70', args.master_170)]}
    assert results['C1.62'] == results['C1.70']
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
