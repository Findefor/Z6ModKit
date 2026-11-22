"""Follow Z6 II profile override bytes into the video settings records, offline."""
import argparse
import json
from pathlib import Path
from typing import NamedTuple

if __name__ == '__main__' and not __debug__:
    raise SystemExit('Run without -O to enable trace assertions.')

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                               UC_ARM_REG_R7, UC_ARM_REG_R8)

from analyze_frame_producer import ARG, BUILDS, C162_PACKAGE, CFG, CTX, JOB, OBJ, PATH, STACK, load_master
from trace_card_format import IRQ_NAME_LOOKUP, ensure_page
from trace_nlog_control import ProfileTrace, SITES, named_profile, properties


class Sites(NamedTuple):
    narrow_flag: int
    normalize: int
    process: int
    triplet_written: int
    mode_switch: int
    wide_flag: int
    bind_inputs: int
    reuse: int
    pack: int


SITES_READERS = {
    'C1.62': Sites(0x102750da, 0x10364e70, 0x10365afe, 0x103654f0, 0x102682fc,
                   0x1027551a, 0x10275652, 0x102d47f0, 0x1035c524),
    'C1.70': Sites(0x10275216, 0x10365948, 0x103665d6, 0x10365fc8, 0x10268438,
                   0x10275656, 0x1027578e, 0x102d4ba4, 0x102fa924),
}


class DriverSites(NamedTuple):
    narrow_call: int
    output_args: int
    attach_record: int
    bind_section: int
    read_section: int
    field_call: int
    writer: int
    initialize: int


DRIVER = {
    'C1.62': DriverSites(0x10267d5a, 0x102d4792, 0x10264dd0, 0x102c0320,
                         0x102e763a, 0x102e7e72, 0x1036e12e, 0x1036b414),
    'C1.70': DriverSites(0x10267e96, 0x102d4b46, 0x10264f0c, 0x102c06d4,
                         0x102e7946, 0x102e817e, 0x1036e92a, 0x1036bc10),
}


def identify_banks(trace, version):
    initialize = DRIVER[version].initialize
    for base in (0x20380000, 0x203c0000):
        ensure_page(trace, base)
    trace.run(initialize, stop=initialize+0x1e)
    for index, base in enumerate((0x20380000, 0x203c0000)):
        assert trace.unpack(base, 'II') == (3, 3)
        assert trace.unpack(base+0xc, 'I') == (1,)
        argument = initialize + (0x38 if index == 0 else 0x44)
        trace.run(argument, stop=argument+2)
        irq = trace.cpu.reg_read(UC_ARM_REG_R0)
        assert irq == 0x63 + index
        lookup = IRQ_NAME_LOOKUP[version]
        trace.run(lookup, stop=lookup+14, regs=((UC_ARM_REG_R4, irq),))
        name = trace.cpu.reg_read(UC_ARM_REG_R1)
        assert bytes(trace.cpu.mem_read(name, 7)) == f'MIPU_{index}\0'.encode()


def write_banks(trace, version, parameters):
    d = DRIVER[version]
    request, worker, wrapper, device = ARG+0x2400, ARG+0x2900, ARG+0x2b00, ARG+0x2c00
    trace.put(wrapper+0xc, 'I', CTX)
    trace.put(CTX+0x64, 'I', 1)
    trace.run(d.attach_record, stop=d.attach_record+0x18,
              regs=((UC_ARM_REG_R1, wrapper), (UC_ARM_REG_R4, request)))
    pointer, = trace.unpack(request+0x35c, 'I')
    assert pointer == parameters
    trace.run(d.bind_section, stop=d.bind_section+0xc,
              regs=((UC_ARM_REG_R5, worker), (UC_ARM_REG_R7, pointer)))
    trace.run(d.read_section, stop=d.read_section+6, regs=((UC_ARM_REG_R5, worker),))
    section = trace.cpu.reg_read(UC_ARM_REG_R1)
    assert section == parameters+0x380
    control, = trace.unpack(parameters+0x430, 'H')
    low, = trace.unpack(parameters+0x434, 'B')
    words = []
    for index in (0, 1):
        trace.put(device+4, 'B', index)
        register = 0x20380ddc + (index << 18)
        trace.put(register, 'I', 0xdeadbeef)

        def observe_writer(cpu, address, size, unused):
            assert cpu.reg_read(UC_ARM_REG_R0) == device
            assert cpu.reg_read(UC_ARM_REG_R1) == parameters+0x430

        hook = trace.cpu.hook_add(UC_HOOK_CODE, observe_writer, begin=d.writer, end=d.writer)
        try:
            trace.run(d.field_call, stop=d.field_call+10,
                      regs=((UC_ARM_REG_R4, section), (UC_ARM_REG_R5, device)))
        finally:
            trace.cpu.hook_del(hook)
        word, = trace.unpack(register, 'I')
        assert word == (control << 8) | low
        words.append(word)
    return words


class ReaderTrace(ProfileTrace):
    def memory_helper(self, cpu, address, size, unused):
        length = cpu.reg_read(UC_ARM_REG_R2)
        if address in (self.s.copy, self.s.copy + 0x68) and length in (6, 10, 11, 14, 24, 52):
            src, dst = cpu.reg_read(UC_ARM_REG_R1), cpu.reg_read(UC_ARM_REG_R0)
            cpu.mem_write(dst, bytes(cpu.mem_read(src, length)))
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        else:
            super().memory_helper(cpu, address, size, unused)


def run_case(trace, version, mode, enum, field_change=None, narrow_flag=1):
    s, old = SITES_READERS[version], SITES[version]
    d = DRIVER[version]
    cpu = trace.cpu
    record, wide_record, wide_args = ARG+0xa00, ARG+0xc00, ARG+0xd00
    work = OBJ+0x280
    output, auxiliary, parameters = work+0x7c, ARG+0x1700, CFG+0x93c
    for address, length in ((CTX, 0x200), (JOB, 0x900), (record, 0x400),
                            (output, 0x80), (auxiliary, 0x300), (parameters, 0x500)):
        cpu.mem_write(address, bytes(length))
    trace.run(old.profile_convert, CFG+0x4f0, record, record+0xe)
    if field_change:
        offset, byte = field_change
        trace.put(record+offset, 'B', byte)
    # Live call site passes 1 in narrow argument +8. Also exercise 0 as a control.
    trace.run(d.narrow_call, stop=d.narrow_call+4)
    trace.run(d.narrow_call+0x10, stop=d.narrow_call+0x14)
    assert trace.unpack(STACK+0x24, 'I') == (1,)
    if not narrow_flag:
        trace.put(STACK+0x24, 'I', 0)
    trace.run(s.narrow_flag, stop=s.narrow_flag+10,
              regs=((UC_ARM_REG_R4, record), (UC_ARM_REG_R6, STACK+0x1c)))
    trace.put(record+0x57, 'B', enum)
    trace.put(record+0x61, 'B', 1)
    trace.put(record+0x52, 'H', 288)  # Fixed interior sample of the control range.
    trace.put(CTX, 'I', record)
    trace.put(CTX+0x144, 'I', CFG)
    for pointer in (8, 0xc, 0x10, 0x14):
        trace.put(CTX+pointer, 'I', ARG+0x1100)
    trace.put(CTX+0x18, 'I', output)
    trace.put(CTX+0x28, 'I', auxiliary)
    trace.run(s.normalize, CTX)
    normalized = CTX+0x2c
    assert trace.unpack(normalized, '14B') == trace.unpack(record, '14B')
    assert trace.unpack(normalized+0x22, 'B') == (narrow_flag,)
    early = []

    def capture(cpu, address, size, unused):
        early.append(trace.unpack(output+0xe, '3B'))

    hook = cpu.hook_add(UC_HOOK_CODE, capture, begin=s.triplet_written, end=s.triplet_written)
    try:
        trace.run(s.process, normalized)
    finally:
        cpu.hook_del(hook)
    triplet = trace.unpack(output+0xe, '3B')
    table, = trace.unpack(normalized+0x70, 'I')
    assert early == [tuple(x-y for x, y in zip(trace.unpack(record+4, '3B'), (116, 108, 108)))]
    assert triplet == (early[0][0], early[0][1] if narrow_flag else 20, early[0][2])
    # The middle field takes part in a signed direction test around 20.
    guard = s.process+0x174
    inputs_copy = ARG+0xf00
    for sign in (-1, 0, 1):
        trace.put(inputs_copy+0xf, 'B', early[0][1])
        trace.put(inputs_copy+0x12, 'b', sign)
        cpu.reg_write(UC_ARM_REG_R5, inputs_copy)
        cpu.emu_start(guard | 1, guard+0x14, count=7)
        if cpu.reg_read(UC_ARM_REG_PC) == guard+0x12:
            cpu.emu_start((guard+0x12) | 1, guard+0x14, count=1)
        assert cpu.reg_read(UC_ARM_REG_PC) == guard+0x14
        expected = 20 if (early[0][1]-20)*sign < 0 else early[0][1]
        assert trace.unpack(inputs_copy+0xf, 'B') == (expected,)
    # Stock mode dispatch builds the wide caller's cache flag at argument +0x10.
    trace.put(CTX+0xd, 'B', mode)
    trace.run(s.mode_switch-0x3a, stop=s.mode_switch-0x2c,
              regs=((UC_ARM_REG_R4, CTX), (UC_ARM_REG_R5, work)))
    trace.run(s.mode_switch, stop=s.mode_switch+0xde,
              regs=((UC_ARM_REG_R4, CTX), (UC_ARM_REG_R6, 1), (UC_ARM_REG_R7, 0)))
    assert trace.unpack(STACK+0x20, 'II') == (output, work+0xfc)
    assert trace.unpack(STACK+0x2c, 'I') == (1,)
    trace.run(s.mode_switch+0xde, stop=s.mode_switch+0xf4,
              regs=((UC_ARM_REG_R4, CTX), (UC_ARM_REG_R5, work)))
    trace.run(d.output_args, stop=d.output_args+0xc,
              regs=((UC_ARM_REG_R2, STACK+0x38), (UC_ARM_REG_R4, JOB)))
    assert trace.unpack(JOB+0xd0, 'I') == (parameters,)
    trace.run(s.wide_flag, stop=s.wide_flag+10,
              regs=((UC_ARM_REG_R4, wide_record), (UC_ARM_REG_R7, STACK+0x1c)))
    trace.run(s.bind_inputs, stop=s.bind_inputs+0x2a,
              regs=((UC_ARM_REG_R4, wide_record), (UC_ARM_REG_R6, wide_args),
                    (UC_ARM_REG_R7, STACK+0x1c), (UC_ARM_REG_R8, 0)))
    trace.put(JOB, 'I', wide_record)
    trace.run(s.reuse, stop=s.reuse+0x38, regs=((UC_ARM_REG_R4, JOB), (UC_ARM_REG_R5, wide_args)))
    assert trace.unpack(JOB+0x148, 'I') == (output,)
    trace.put(wide_record+0x94, 'B', 1)
    trace.run(s.pack, JOB)
    wide_table, = trace.unpack(JOB+0x818, 'I')
    table_byte = trace.unpack(table+min(triplet[2], 40), 'b')[0]
    wide_byte = trace.unpack(wide_table+min(triplet[0], 48)*4, 'b')[0]
    assert trace.unpack(JOB+0x83c, 'b') == (wide_byte,)
    return dict(early=early[0], triplet=triplet, table_set=trace.unpack(output+6, 'B')[0],
                field6_lookup=table_byte, control18=trace.unpack(output+0x18, 'B')[0],
                field4_lookup=wide_byte, signed_index=trace.unpack(JOB+0x83f, 'b')[0],
                parameter430=trace.unpack(parameters+0x430, 'H')[0],
                mipu_registers=write_banks(trace, version, parameters),
                table_addresses=[hex(table), hex(wide_table)])


def inspect(version, path):
    trace = ReaderTrace(load_master(path, version), BUILDS[version][1])
    helper = trace.s.copy + 0x68
    trace.cpu.hook_add(UC_HOOK_CODE, trace.memory_helper, begin=helper, end=helper)
    identify_banks(trace, version)
    s = SITES[version]
    assert named_profile(trace, s, properties(trace, s, 0)) == {'selector': 0}
    rows = {}
    for name, key, enum, mode in [('N-Log', 0x126e, 1, 0x17), ('HLG', 0x12a4, 2, 0x1b)]:
        named_profile(trace, s, properties(trace, s, key))
        rows[name] = run_case(trace, version, mode, enum)
        if name == 'N-Log':
            # Off selects no override. Hold the preceding STANDARD record constant.
            rows['off_held_standard'] = run_case(trace, version, 0x11, 0)
            for offset, byte in ((4, 132), (5, 130), (6, 130), (6, 144)):
                rows[f'nlog_field{offset}_{byte}'] = run_case(trace, version, mode, enum, (offset, byte))
        else:
            rows['hlg_narrow_flag0'] = run_case(trace, version, mode, enum, narrow_flag=0)
    for name in ('HLG', 'nlog_field4_132', 'hlg_narrow_flag0'):
        observed = rows[name]
        assert (observed['field4_lookup'], observed['signed_index'], observed['parameter430']) == (8, 6, 30)
        assert observed['mipu_registers'] == [0x1e00, 0x1e00]
    for name in ('N-Log', 'off_held_standard', 'nlog_field5_130', 'nlog_field6_130', 'nlog_field6_144'):
        assert rows[name]['mipu_registers'] == [0, 0]
    assert rows['N-Log']['control18'] == rows['HLG']['control18'] == 54
    assert rows['nlog_field6_144']['control18'] == 56
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', type=Path, nargs='?', default=C162_PACKAGE)
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    results = {v: inspect(v, p) for v, p in [('C1.62', args.source_162), ('C1.70', args.master_170)]}
    for name in results['C1.70']:
        def comparable(v):
            return {k: val for k, val in results[v][name].items() if k != 'table_addresses'}
        assert comparable('C1.62') == comparable('C1.70'), name
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
