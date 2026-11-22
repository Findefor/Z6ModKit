"""Trace mode and picture-parameter choices for stock Z6 II N-Log and HLG."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import NamedTuple

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                               UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R11)

from analyze_frame_producer import ARG, BUILDS, C162_PACKAGE, CFG, CTX, OBJ, PATH, STACK, Trace, load_master
from compare_hdmi_card import SITES as VIDEO


class Sites(NamedTuple):
    registration: int
    bulk_read: int
    record_gate: int
    first_record: int
    second_record: int
    normalize_first: int
    normalize_second: int
    select_tables: int
    select_profile: int
    read_property: int
    read_state: int
    profile_dispatch: int
    profile_record: int
    queued: int
    scalar_caller: int
    scalar: int
    profile_fetch: int
    profile_convert: int


SITES = {
    'C1.62': Sites(0x118ee6e8, 0x103549d0, 0x10353738, 0x102750a4, 0x102754a6,
                   0x10364ec0, 0x10364fde, 0x10365bb6, 0x1035aee4, 0x1034b45a,
                   0x1026c6aa, 0x103d86f8, 0x103d84da, 0x10327324, 0x102243bc, 0x10224d2c,
                   0x103d8366, 0x10274694),
    'C1.70': Sites(0x11906fa0, 0x1035590c, 0x10354670, 0x102751e0, 0x102755e2,
                   0x10365998, 0x10365ab6, 0x1036668e, 0x1035be38, 0x1034c37e,
                   0x1026c7e6, 0x103d9528, 0x103d930a, 0x10327c98, 0x10224404, 0x10224d74,
                   0x103d9196, 0x102747d0),
}


def r(trace, reg):
    return trace.cpu.reg_read(reg)


class ProfileTrace(Trace):
    def memory_helper(self, cpu, address, size, _):
        n = cpu.reg_read(UC_ARM_REG_R2)
        if address in (self.s.copy, self.s.copy+0x68) and n in (18, 20, 0x2a4):
            src, dst = cpu.reg_read(UC_ARM_REG_R1), cpu.reg_read(UC_ARM_REG_R0)
            cpu.mem_write(dst, bytes(cpu.mem_read(src, n)))
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        else:
            super().memory_helper(cpu, address, size, _)


def map_global(trace, address):
    if not any(lo <= address <= hi for lo, hi, _ in trace.cpu.mem_regions()):
        trace.cpu.mem_map(address & ~4095, 4096)


def properties(trace, sites, requested):
    # Run each registered callback until it submits (key, value) to the queue.
    result = {}
    for i, (key, effective) in enumerate(((0x126e, 0x1688), (0x12a4, 0x16bf))):
        registration = sites.registration + 24*i
        assert trace.unpack(registration, 'I') == (key,)
        callback, = trace.unpack(registration+16, 'I')
        trace.put(ARG, '6I', 0, int(requested == key), 0, 0, 0, 0)
        trace.run(callback & ~1, 0, ARG, 0, OBJ, stop=sites.queued)
        assert r(trace, UC_ARM_REG_R0) == 1
        prop, = trace.unpack(r(trace, UC_ARM_REG_R1), 'I')
        value, = trace.unpack(r(trace, UC_ARM_REG_R2), 'I')
        assert (prop, value) == (effective, int(requested == key))
        result[prop] = value
    return result


def snapshot(trace, sites, video, values, gate):
    address = ARG+0x1200
    trace.run(sites.bulk_read, stop=sites.bulk_read+12)
    count = r(trace, UC_ARM_REG_R2)
    keys = trace.unpack(r(trace, UC_ARM_REG_R0), f'{count}I')
    assert count == 222 and keys[0x234//4:0x23c//4] == (0x1688, 0x16bf)
    # Model the property service's ordered output, including the mode gate.
    for i, key in enumerate(keys):
        trace.put(address+4*i, 'I', values.get(key, 0))
    trace.put(address+0x174, 'I', gate)
    trace.run(video.snapshot_depth+8, stop=video.snapshot_depth+0x26, regs=(
        (UC_ARM_REG_R0, 0), (UC_ARM_REG_R4, CFG+0xac), (UC_ARM_REG_R5, address)))
    trace.run(sites.record_gate, stop=sites.record_gate+14, regs=(
        (UC_ARM_REG_R4, CFG+0x2c90), (UC_ARM_REG_R5, address), (UC_ARM_REG_R7, 0), (UC_ARM_REG_R9, 1)))
    assert trace.unpack(CFG+0x2ce5, 'B') == (gate,)


def record_tables(trace, sites, gate, expected):
    trace.put(CTX+0x144, 'I', CFG)
    for wide, builder, norm, offset, delta in (
            (False, sites.first_record, sites.normalize_first, 0x57, 0x4c),
            (True, sites.second_record, sites.normalize_second, 0x7a, 0x76)):
        trace.put(OBJ+offset, 'B', 0xff)
        trace.run(builder, stop=builder+(0x2e if wide else 0x2c), regs=(
            (UC_ARM_REG_R4, OBJ+delta), (UC_ARM_REG_R5, CTX), (UC_ARM_REG_R8, 0),
            (UC_ARM_REG_R9, 1), (UC_ARM_REG_R11, 1)))
        assert trace.unpack(OBJ+offset, 'B') == (expected if gate else 0,)
        trace.put(CTX, 'I', OBJ)
        trace.run(norm, stop=norm+10, regs=((UC_ARM_REG_R4, CTX), (UC_ARM_REG_R5, ARG)))
        assert trace.unpack(ARG+0x20, 'B') == (expected if gate else 0,)
    trace.put(ARG+0x2b, 'B', 1)
    trace.put(ARG+0x22, 'B', 0)
    trace.put(ARG+0x54, 'I', OBJ+0x200)
    trace.run(sites.select_tables, stop=sites.select_tables+0x46, regs=(
        (UC_ARM_REG_R4, ARG), (UC_ARM_REG_R5, 0)))
    selected, = trace.unpack(OBJ+0x206, 'B')
    assert selected == (3 if gate and expected else 2)
    return selected, trace.unpack(ARG+0x64, '3I')


def named_profile(trace, sites, values):
    def get(cpu, address, size, _):
        key = cpu.reg_read(UC_ARM_REG_R0)
        assert key in (0x1623, 0x1688, 0x16bf, 0x1b41, 0x40000101)
        cpu.reg_write(UC_ARM_REG_R0, values.get(key, 0))
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
    hooks = [trace.cpu.hook_add(UC_HOOK_CODE, get, begin=a, end=a)
             for a in (sites.read_state, sites.read_property)]
    try:
        trace.run(sites.select_profile, stop=sites.select_profile+0x86)
    finally:
        for hook in hooks:
            trace.cpu.hook_del(hook)
    selected = r(trace, UC_ARM_REG_R1)
    if selected == 0:
        return {'selector': 0}
    # Pass the dispatcher its actual mode, then run its ROM-record lookup.
    trace.run(sites.profile_dispatch, 0, selected, stop=sites.profile_dispatch+0x10c)
    trace.run(sites.profile_dispatch+0x114, stop=sites.profile_dispatch+0x11a,
              regs=((UC_ARM_REG_R5, selected),))
    assert (r(trace, UC_ARM_REG_R0), r(trace, UC_ARM_REG_R1)) == (0, selected)
    dest = r(trace, UC_ARM_REG_R2)
    map_global(trace, dest)
    map_global(trace, dest+0x2a3)
    trace.run(sites.profile_record, 0, selected, dest, stop=sites.profile_record+0xea)
    rom = r(trace, UC_ARM_REG_R4)
    profile_id, profile = trace.unpack(dest+0x50, 'II')
    assert profile_id == 1
    name = bytes(trace.cpu.mem_read(profile+3, 20)).split(b'\0', 1)[0].decode()
    assert name == 'STANDARD'
    settings = bytes(trace.cpu.mem_read(rom, 20))
    assert settings[2:] == (b'\x80' * 8 if selected == 2 else bytes.fromhex('80 84 82 82 80 80 80 80')) + b'\xff' * 10
    # Resume the actual parameter copies and fetch the live picture preset
    # through the same getter used when assembling the video context.
    trace.cpu.emu_start((sites.profile_record+0xea) | 1, sites.profile_record+0x12a, count=80)
    assert r(trace, UC_ARM_REG_PC) == sites.profile_record+0x12a
    assert bytes(trace.cpu.mem_read(dest+0x1a, 18)) == settings[2:]
    trace.run(sites.profile_fetch+0xe, stop=sites.profile_fetch+0x14)
    assert r(trace, UC_ARM_REG_R1) == dest and r(trace, UC_ARM_REG_R2) == 0x2a4
    trace.run(sites.profile_fetch+0x1a, stop=sites.profile_fetch+0x20,
              regs=((UC_ARM_REG_R5, CFG+0x4f0),))
    trace.run(sites.profile_convert, CFG+0x4f0, ARG+0x900, ARG+0x940)
    converted = list(trace.unpack(ARG+0x904, '3B'))
    assert converted == ([128, 128, 128] if selected == 2 else [132, 130, 130])
    return {'selector': selected, 'name': name, 'record_address': hex(rom),
            'base_address': hex(profile), 'record_sha256': hashlib.sha256(settings).hexdigest(),
            'converted_fields_4_5_6': converted}


def scalar_control(trace, sites, expected):
    # Two distinguishable 16-bit values and a configurable non-log ceiling.
    root, = trace.unpack(sites.scalar+0x120, 'I')
    map_global(trace, root)
    trace.put(root+0x50, 'I', ARG+0x1800)
    trace.put(root+0x58, 'I', ARG+0x2000)
    trace.put(root+0x44, 'I', OBJ+0x200)
    trace.put(ARG, 'B', 6)
    trace.put(STACK+0x1c, 'I', 0)
    trace.put(STACK+0x60, '3I', 100, 100, 50)
    observed = []
    for normal, nlog, limit in ((0x300, 0x900, 0x700), (0x500, 0x600, 0x400)):
        trace.put(ARG+0x2000+0x33c, '4I', 0, limit, normal, nlog)
        trace.run(sites.scalar_caller, stop=sites.scalar_caller+0x10,
                  regs=((UC_ARM_REG_R5, ARG), (UC_ARM_REG_R6, CFG)))
        scalar = r(trace, UC_ARM_REG_R6)
        assert scalar == (min(nlog, 0x800) if expected == 1 else min(normal, limit))
        # Supply the caller's other factor as 0.5 in Q8 and run its stores.
        trace.run(sites.scalar_caller+0x42, stop=sites.scalar_caller+0x5c, regs=(
            (UC_ARM_REG_R1, 128), (UC_ARM_REG_R6, scalar), (UC_ARM_REG_R11, root)))
        assert trace.unpack(OBJ+0x232, '3H') == (scalar, 128, scalar//2)
        observed.append(scalar)
    return observed


def inspect(version, path):
    sites, video = SITES[version], VIDEO[version]
    trace = ProfileTrace(load_master(path, version), BUILDS[version][1])
    other_copy = trace.s.copy + 0x68
    trace.cpu.hook_add(UC_HOOK_CODE, trace.memory_helper, begin=other_copy, end=other_copy)
    trace.put(CFG, 'BB', 1, 0)
    trace.put(CFG+0xac, 'I', 4)
    trace.put(CFG+0xec, '4H', 0, 0, 3840, 2160)
    trace.put(CFG+0x4d4, '3B', 2, 2, 4)
    results = {}
    for name, requested, expected, mode in [('off', 0, 0, 0x11), ('N-Log', 0x126e, 1, 0x17), ('HLG', 0x12a4, 2, 0x1b)]:
        values = properties(trace, sites, requested)
        for gate in (0, 1):
            snapshot(trace, sites, video, values, gate)
            table, pointers = record_tables(trace, sites, gate, expected)
        trace.run(video.mode_selector, CFG)
        assert r(trace, UC_ARM_REG_R0) == mode
        trace.run(video.job_selector, mode)
        assert r(trace, UC_ARM_REG_R0) == 0x0a
        profile = named_profile(trace, sites, values)
        scalars = scalar_control(trace, sites, expected)
        assert profile['selector'] == {'off': 0, 'N-Log': 2, 'HLG': 3}[name]
        results[name] = {'mode': hex(mode), 'job': '0x0a', 'record_enum': expected,
                         'table': table, 'pointers': list(map(hex, pointers)), 'profile': profile,
                         'fixture_scalar_results': scalars}
    assert results['N-Log']['pointers'] == results['HLG']['pointers'] != results['off']['pointers']
    assert results['N-Log']['profile']['record_sha256'] != results['HLG']['profile']['record_sha256']
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', type=Path, nargs='?', default=C162_PACKAGE)
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit('Run without -O to enable trace assertions.')
    out = {v: inspect(v, p) for v,p in (('C1.62', args.source_162), ('C1.70', args.master_170))}
    for name in ('N-Log', 'HLG'):
        assert out['C1.62'][name]['profile']['record_sha256'] == out['C1.70'][name]['profile']['record_sha256']
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
