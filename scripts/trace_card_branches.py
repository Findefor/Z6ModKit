"""Trace job 0x0A from its precision controls to the posted output descriptors."""
import argparse
import json
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R4,
                               UC_ARM_REG_R5, UC_ARM_REG_R6)

from analyze_frame_producer import ARG, BUILDS, C162_PACKAGE, CTX, JOB, PATH, Trace, load_master
from compare_hdmi_card import SITES, prepare_job
from trace_card_format import assign_channels, ensure_page


def complete_builder(trace, sites, depth, nlog, hlg, tiles, force_flag=None):
    card = trace.construct(2, False, 1)
    mode, _, args, source, hdmi, _ = prepare_job(trace, sites, depth, nlog, hlg)
    # Run the stock comparisons on the actual mode returned above. Stop after
    # the flags at +7C4..+7D4 have been stored, before the scheduler is read.
    trace.run(sites.job_selector+0x12c, stop=sites.job_selector+0x234, regs=(
        (UC_ARM_REG_R4, JOB), (UC_ARM_REG_R5, CTX), (UC_ARM_REG_R6, 0)))
    stock_flag, = trace.unpack(JOB+0x7cc, 'I')
    assert stock_flag == int(mode in (0x11, 0x17, 0x1b))
    flag = stock_flag if force_flag is None else force_flag
    if force_flag is not None:
        trace.put(JOB+0x7cc, 'I', force_flag)

    # Tile dimensions and storage live outside the image descriptor. The two
    # ancillary output objects are absent. Their queue gates remain disabled.
    columns, rows, exponents = tiles
    tile = ARG+0x1000
    trace.put(JOB+0x788, 'I', tile)
    trace.put(tile, 'I', tile+0x200)
    trace.put(tile+0x144, 'II', columns, rows)
    trace.put(tile+0x204, 'I', tile+0x280)
    trace.put(tile+0x280, 'I', tile+0x300)
    trace.put(tile+0x320, 'H', exponents)
    trace.run(sites.job_builder, JOB, *args)
    nodes, count = trace.unpack(args[0], 'IB')
    assert count == 28
    ports = {}
    for i in range(count):
        entry = nodes+16*i
        node, = trace.unpack(entry+2, 'B')
        ports[node], = trace.unpack(entry+12, 'I')
    assert nodes - ports[1] == 0xcc8
    block = bytes(trace.cpu.mem_read(ports[1], nodes - ports[1]))
    maximum, middle = (4095, 2048) if flag else (255, 128)
    assert ports[5] == ports[6] == 0  # topology nodes, no separate settings pointer
    for node in (3, 4):
        for ofs in (0x44, 0x48, 0x4c, 0x50):
            assert trace.unpack(ports[node]+ofs, 'H') == (maximum,)
    for node in (0x0d, 0x0e):
        assert trace.unpack(ports[node]+0x34, 'I') == (middle,)
        for ofs in (0x48, 0x4c, 0x50):
            assert trace.unpack(ports[node]+ofs, 'I')[0] & 0x7fff == maximum
    for node in (0x10, 0x11, 0x14):
        for ofs in (0x58, 0x60):
            assert trace.unpack(ports[node]+ofs, 'I') == (maximum,)
    assert (trace.unpack(ports[0x15]+0x21, '2B'), card['pitch']) == ((2, 0), 3984)
    assert (trace.unpack(ports[0x17]+0x22, 'B')[0], hdmi['LineBytesY']) == (
        (0, 3840) if depth else (1, 5760))
    summary = {'mode': hex(mode), 'job_7cc': flag, 'range_fields': [maximum, middle],
               'source_pitch': source['LineBytesY'], 'hdmi_pitch': hdmi['LineBytesY']}
    return nodes, count, block, summary


def post_outputs(trace, version, nodes, count):
    sites = SITES[version]
    parser = sites.port_parser
    writer = trace.s.channel_writer+0x274
    channels = assign_channels(trace, version, nodes, count)
    device_state, completions = trace.unpack(writer+0x262, '2I')
    for addr in (device_state, completions):
        ensure_page(trace, addr)

    # Only three parser side calls (resource registration, job token, event
    # tracking) and the writer's lock/event/unlock calls are modeled. They take
    # scalar values; all routing, descriptor updates and register writes run.
    def model_service(cpu, address, size, unused):
        assert size == 4
        cpu.reg_write(UC_ARM_REG_R0, 0)
        cpu.reg_write(UC_ARM_REG_PC, (address+4) | 1)

    for address in (parser+0x126, parser+0x134, parser+0x140,
                    writer+0x0e, writer+0x1c, writer+0x22):
        trace.cpu.hook_add(UC_HOOK_CODE, model_service, begin=address, end=address)

    table, = trace.unpack(writer+0x25a, 'I')
    nibbles, records = [], []
    for index, node, channel, target in ((17, 0x10, 0x35, 0x15),
                                         (18, 0x11, 0x36, 0x15),
                                         (19, 0x14, 0x37, 0x17)):
        entry = nodes+16*index
        assert trace.unpack(entry, '3B') == (0x0a, channel, node)
        assert channels[node] == channel
        settings, = trace.unpack(entry+12, 'I')
        word, = trace.unpack(settings+0x68, 'I')
        trace.put(ARG, 'BBB', count, index, 0)
        trace.run(parser, nodes, ARG)
        assert trace.unpack(settings+0x68, 'I') == (word,)
        assert trace.unpack(settings+0x0c, 'I')[0] & 15 == channels[target]
        bank, callback = trace.unpack(table+8*channel, '2I')
        assert callback == writer | 1
        assert bank == {0x10: 0x201009c0, 0x11: 0x201009e0, 0x14: 0x20100ba0}[node]
        trace.put(bank+0x10, 'II', 0, 0xffffffff)
        trace.put(ARG+0x40, 'IB', entry, 1)
        trace.run(trace.s.port_dispatch, 0, ARG+0x40)
        posted, trigger = trace.unpack(bank+0x10, '2I')
        assert (posted, trigger) == (settings, 0)
        nibbles.append((trace.unpack(posted+0x68, 'I')[0] >> 4) & 15)
        records.append(bytes(trace.cpu.mem_read(posted, 0xa0)))
    return nibbles, tuple(records)


def inspect(path, version):
    data = load_master(path, version)
    other_tiles = (1, 1, 0x0c0c)
    tiles = (32, 18, 0x0707)
    cases = (
        ('8-bit', 1, 0, 0, tiles, None, 0x10),
        ('10-bit', 0, 0, 0, tiles, None, 0x11),
        ('N-Log', 0, 1, 0, tiles, None, 0x17),
        ('HLG', 0, 0, 1, tiles, None, 0x1b),
        ('N-Log, flag forced to zero', 0, 1, 0, tiles, 0, 0x17),
        ('N-Log, single tile', 0, 1, 0, other_tiles, None, 0x17),
    )
    results, blocks, records = {}, {}, {}
    for label, depth, nlog, hlg, tile_case, override, expected_mode in cases:
        trace = Trace(data, BUILDS[version][1])
        nodes, count, block, result = complete_builder(trace, SITES[version], depth, nlog, hlg,
                                                       tile_case, override)
        assert result['mode'] == hex(expected_mode)
        nibbles, records[label] = post_outputs(trace, version, nodes, count)
        assert nibbles == ([4, 4, 0] if result['job_7cc'] else [0, 0, 0])
        result['posted_nibble_10_11_14'] = nibbles
        results[label], blocks[label] = result, block
    assert blocks['10-bit'] == blocks['N-Log'] == blocks['HLG']
    assert records['10-bit'] == records['N-Log'] == records['HLG']
    for different in ('8-bit', 'N-Log, flag forced to zero', 'N-Log, single tile'):
        assert blocks[different] != blocks['N-Log']
        assert records[different] != records['N-Log']
    return {'cases': results, 'matched_settings_bytes_at_fixed_depth': len(blocks['N-Log'])}


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
