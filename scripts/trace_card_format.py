"""Reproduce the image job's channel assignments and terminal storage format fields."""
import argparse
import json
import sys
from pathlib import Path

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_R11, UC_ARM_REG_SP)

from analyze_frame_producer import ARG, BUILDS, C162_PACKAGE, OBJ, PATH, STACK, Trace, load_master
from compare_hdmi_card import SITES, shared_job


# The allocator has the same block layout in these two hash-checked masters.
ALLOCATOR = {'C1.62': 0x1038A870, 'C1.70': 0x1038B584}
SERIALIZER = {'C1.62': 0x102BF006, 'C1.70': 0x102BF3BA}
IRQ_NAME_LOOKUP = {'C1.62': 0x103A1C62, 'C1.70': 0x103A298E}
CHANNEL_BANK = 0x20100400
BUSY_BANK = 0x20102040
SCRATCH = 0x23000000


def ensure_page(trace, address):
    if not any(lo <= address <= hi for lo, hi, _ in trace.cpu.mem_regions()):
        trace.cpu.mem_map(address & ~4095, 4096)


def identify_bank(trace, version):
    # Device registration and interrupt registration are adjacent in this
    # driver. Stop before the system calls and read their original arguments.
    register = trace.s.port_dispatch - 0x17c
    trace.run(register, stop=register+10)
    assert trace.cpu.reg_read(UC_ARM_REG_R0) == 0x146
    trace.run(register+0x12, stop=register+0x16)
    irq = trace.cpu.reg_read(UC_ARM_REG_R0)
    handler = trace.cpu.reg_read(UC_ARM_REG_R1) & ~1
    assert irq == 0x66
    trace.run(handler, stop=handler+2)
    bank = trace.cpu.reg_read(UC_ARM_REG_R0)
    assert bank == CHANNEL_BANK-0x400
    trace.put(bank+0x18, '3I', 4, 8, 16)
    writes = []
    def capture_status(cpu, access, address, size, value, user_data):
        writes.append((address-bank, size, value))
    hook = trace.cpu.hook_add(UC_HOOK_MEM_WRITE, capture_status, begin=bank, end=bank+0xff)
    trace.run(handler, stop=handler+0x12)
    trace.cpu.hook_del(hook)
    assert writes == [(0x18, 4, 4), (0x1c, 4, 8), (0x20, 4, 16)]
    name_lookup = IRQ_NAME_LOOKUP[version]
    trace.run(name_lookup, stop=name_lookup+14, regs=((UC_ARM_REG_R4, irq),))
    assert trace.cpu.reg_read(UC_ARM_REG_R2) == irq
    name = trace.cpu.reg_read(UC_ARM_REG_R1)
    assert bytes(trace.cpu.mem_read(name, 4)) == b'IIP\0'
    return {'name': 'IIP', 'irq': hex(irq), 'bank': hex(bank)}


def assign_channels(trace, version, nodes, count, busy=()):
    """Run the original scheduler's allocation loop on an idle or partially busy bank."""
    entry = ALLOCATOR[version]
    globals_page, limits = trace.unpack(entry+0x424, '2I')
    for addr in (globals_page, limits, BUSY_BANK, SCRATCH):
        ensure_page(trace, addr)
    trace.cpu.mem_write(SCRATCH, bytes(4096))
    trace.cpu.mem_write(limits, bytes(0x26))
    trace.cpu.mem_write(BUSY_BANK, bytes(64))
    for channel in busy:
        assert 0 <= channel < 16
        trace.put(BUSY_BANK+4*channel, 'I', 1)
    # Rebuild the per-type resource limits from the real initialization code.
    trace.run(entry-0x4f8, stop=entry-0x474)
    assert trace.unpack(limits+0x26, 'B') == (16,)
    trace.put(SCRATCH, 'IB3xI', nodes, count, SCRATCH+0x100)
    trace.put(STACK+0x5c, 'I', SCRATCH+0x400)
    trace.put(STACK+0x88, 'I', SCRATCH+0x500)
    for reg, value in ((UC_ARM_REG_R4, 0), (UC_ARM_REG_R6, SCRATCH),
                       (UC_ARM_REG_R11, 1), (UC_ARM_REG_SP, STACK)):
        trace.cpu.reg_write(reg, value)
    stop = entry+0x264
    trace.cpu.emu_start((entry+0x25c) | 1, stop, count=200000)
    assert trace.cpu.reg_read(UC_ARM_REG_PC) == stop
    node_channels = {}
    for i in range(count):
        channel, node = trace.unpack(nodes + 16*i + 1, '2B')
        assert node not in node_channels
        node_channels[node] = channel
    return node_channels


def write_terminal(trace, entry):
    """Run the dispatch and all 13 register writes to the RAM-backed channel bank."""
    channel, = trace.unpack(entry+1, 'B')
    assert channel < 16
    bank = CHANNEL_BANK + 0x40*channel
    trace.cpu.mem_write(bank, bytes([0xa5])*52)
    trace.put(ARG+0x40, 'IB', entry, 1)
    trace.run(trace.s.port_dispatch, 0, ARG+0x40, stop=trace.s.port_dispatch+0x22)
    assert trace.cpu.reg_read(UC_ARM_REG_R0) == entry
    assert trace.cpu.reg_read(UC_ARM_REG_R2) == (trace.s.channel_writer | 1)
    trace.run(trace.s.channel_writer, entry, stop=trace.s.channel_writer+0x186)
    assert trace.unpack(0x2010002c, 'I') == (channel,)
    return trace.unpack(bank, '13I')


def check_formats(trace, version, nodes):
    card_entry = nodes + 16*21
    hdmi_entry = nodes + 16*22
    actual = {}
    for node, entry, expected, pitch in ((1, nodes, 0x09010001, 6048),
                                         (0x15, card_entry, 0x09000201, 3984),
                                         (0x17, hdmi_entry, 0x09010001, 5760)):
        port, = trace.unpack(entry+12, 'I')
        words = write_terminal(trace, entry)
        assert words[0] == expected and words[4:6] == (pitch, pitch)
        assert words[9:11] == trace.unpack(port+0x10, '2I')
        actual[f'{node:02X}'] = f'0x{words[0]:08x}'

    # Keep both addresses, all dimensions and pitches fixed. Vary the two
    # descriptor bytes independently in a copy of the original card record.
    descriptor, test_entry, test_port = (SCRATCH+n for n in (0x600, 0x650, 0x680))
    trace.cpu.mem_write(descriptor, bytes(trace.cpu.mem_read(OBJ+0x18, 28)))
    trace.cpu.mem_write(test_entry, bytes(trace.cpu.mem_read(card_entry, 16)))
    card_port, = trace.unpack(card_entry+12, 'I')
    trace.put(test_entry+12, 'I', test_port)
    original = write_terminal(trace, card_entry)
    for ycbcr in (1, 2):
        for data_format, bank_code in ((0, 0), (2, 1), (5, 2)):
            trace.cpu.mem_write(test_port, bytes(trace.cpu.mem_read(card_port, 0x40)))
            trace.put(descriptor, 'BB', ycbcr, data_format)
            trace.run(SERIALIZER[version], descriptor, test_port)
            chroma_code = 2 if ycbcr == 2 else 0
            assert trace.unpack(test_port+0x21, '2B') == (chroma_code, bank_code)
            words = write_terminal(trace, test_entry)
            assert words[0] == (0x09000001 | chroma_code << 8 | bank_code << 16)
            assert words[1:] == original[1:]
    return actual


def inspect(path, version):
    sites = SITES[version]
    trace = Trace(load_master(path, version), BUILDS[version][1])
    card = trace.construct(2, False, 1)
    shared_job(trace, sites, card)
    nodes, = trace.unpack(sites.job_builder+0x42a, 'I')
    assignments = {'hardware': identify_bank(trace, version)}
    for busy in ((), (1,)):
        channels = assign_channels(trace, version, nodes, 28, busy=busy)
        selected = {f'{node:02X}': channels[node] for node in (1, 0x10, 0x11, 0x14, 0x15, 0x17)}
        expected = [8, 0x35, 0x36, 0x37, 2 if busy else 1, 3 if busy else 2]
        assert list(selected.values()) == expected
        assignments['busy_1' if busy else 'idle'] = {
            'channels': selected, 'terminal_control': check_formats(trace, version, nodes)}
    return assignments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', type=Path, nargs='?', default=C162_PACKAGE)
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit('Run without -O to enable trace assertions.')
    results = {v: inspect(p, v) for v, p in (('C1.62', args.source_162), ('C1.70', args.master_170))}
    assert results['C1.62'] == results['C1.70']
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
