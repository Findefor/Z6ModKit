"""Trace readers of the N-Log-dependent control value on stock Z6 II master images."""
import argparse
import json
from pathlib import Path
from typing import NamedTuple

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_LR as LR, UC_ARM_REG_PC as PC,
                               UC_ARM_REG_R0 as R0, UC_ARM_REG_R1 as R1, UC_ARM_REG_R2 as R2,
                               UC_ARM_REG_R4 as R4, UC_ARM_REG_R5 as R5, UC_ARM_REG_R6 as R6,
                               UC_ARM_REG_R7 as R7, UC_ARM_REG_R9 as R9, UC_ARM_REG_R11 as FP)

from analyze_frame_producer import ARG, BUILDS, C162_PACKAGE, CFG, CTX, OBJ, PATH, STACK, Trace, load_master
from trace_card_format import IRQ_NAME_LOOKUP
from trace_nlog_control import SITES as CONTROL, map_global


class Sites(NamedTuple):
    readers: int
    history: int
    product_get: int
    package: int
    program: int
    irq_register: int
    status: int
    override: int


SITES = {
    'C1.62': Sites(0x10220a7e, 0x1037410c, 0x102e9464, 0x1023b0a0, 0x102385ea, 0x1020aa30, 0x103c0278, 0x103c2378),
    'C1.70': Sites(0x10220ac6, 0x10374908, 0x102e9770, 0x1023b160, 0x102386aa, 0x1020aa34, 0x103c1014, 0x103c3114),
}


class ReaderTrace(Trace):
    def memory_helper(self, cpu, address, size, unused):
        count = cpu.reg_read(R2)
        if address in (self.s.copy - 4, self.s.copy, self.s.copy + 0x68) and count in (19, 60):
            cpu.mem_write(cpu.reg_read(R0), bytes(cpu.mem_read(cpu.reg_read(R1), count)))
            cpu.reg_write(PC, cpu.reg_read(LR))
        else:
            super().memory_helper(cpu, address, size, unused)


def inspect(version, path):
    image = load_master(path, version)
    t = ReaderTrace(image, BUILDS[version][1])
    s = SITES[version]
    caller = CONTROL[version].scalar_caller
    root, = t.unpack(CONTROL[version].scalar + 0x120, 'I')
    history_middle, = t.unpack(s.history + 0x3a0, 'I')
    gate_a, = t.unpack(s.history + 0x398, 'I')
    gate_b, = t.unpack(s.product_get + 0x1b0, 'I')
    literal, = t.unpack(s.package + 0x670, 'I')
    command = literal - 0xac
    record, params = OBJ + 0x200, OBJ + 0x380
    inputs, out_a, out_b = ARG + 0xa00, ARG + 0xb00, ARG + 0xd00
    # Load the original startup copy which includes the fixed-point lookup table.
    src, dst, count, routine = t.unpack(0x10034000, '4I')
    assert routine == 0x1002006c and dst <= root < dst + count
    for page in range(dst & ~4095, (dst + count + 4095) & ~4095, 4096):
        map_global(t, page)
    t.cpu.mem_write(dst, bytes(t.cpu.mem_read(src, count)))
    for addr in (history_middle - 120, history_middle + 119, command, command + 0xff, 0x2006b000, 0x20068000):
        map_global(t, addr)
    for addr in (t.s.copy - 4, t.s.copy + 0x68):
        t.cpu.hook_add(UC_HOOK_CODE, t.memory_helper, begin=addr, end=addr)

    def service(cpu, address, size, unused):
        if address == s.status:
            assert cpu.reg_read(R0) == 2
            t.put(cpu.reg_read(R1), 'H', 0)
        else:
            assert cpu.reg_read(R0) == 0x294
        cpu.reg_write(R0, 0)
        cpu.reg_write(PC, cpu.reg_read(LR))

    for a in (s.status, s.override):
        t.cpu.hook_add(UC_HOOK_CODE, service, begin=a, end=a)
    t.put(root + 0x44, 'I', record)
    t.put(root + 0x50, 'I', ARG + 0x1800)
    t.put(root + 0x58, '3I', ARG + 0x2000, ARG + 0x2400, ARG + 0x2800)
    t.put(ARG + 0x2000 + 0x33c, '4I', 0, 0x700, 0x300, 0x900)
    t.put(ARG + 0x2000 + 0xe4, 'H', 1)
    t.put(ARG + 0x2400 + 0xa4, 'H2x3I', 111, 112, 113, 114)
    t.put(ARG, 'B', 6)
    t.put(inputs, 'I', CTX)
    t.put(CTX + 0x144, 'I', CFG)
    t.put(inputs + 0x1c, 'I', CTX)
    t.put(inputs + 0x50, 'I', out_a)
    t.put(inputs + 0x64, 'I', out_b)

    def read_key(key, enabled_a=True, enabled_b=True):
        t.put(CTX + 0x2b8, 'I', key)
        t.put(gate_a + 4, 'I', int(enabled_a))
        t.put(gate_b + 4, 'I', int(enabled_b))
        t.put(out_a + 0x1b4, '2H', 0xffff, 0xffff)
        t.put(out_b + 0xc8, 'H', 0xffff)
        t.run(s.readers, stop=s.readers + 0x92, regs=((R4, inputs), (R5, inputs), (FP, inputs)))
        return t.unpack(out_a + 0x1b4, '2H') + t.unpack(out_b + 0xc8, 'H')

    # Immediately after configuration, the stock caller starts this subunit
    # through the shared controller; all five registered handlers reference it.
    t.run(s.program + 0xac, stop=s.program + 0xb2)
    assert all(t.unpack(0x20068000 + offset, 'I') == (2,) for offset in (8, 0x100, 0x104))
    irqs = {}
    for index, offset in enumerate((0, 8, 16, 24, 36)):
        site = s.irq_register + offset
        t.run(site, stop=site + 4)
        irq, handler = t.cpu.reg_read(R0), t.cpu.reg_read(R1) & ~1
        assert irq == 0x5e + index
        t.run(handler + 0x14, stop=handler + 0x16)
        assert t.cpu.reg_read(R4) == 0x20068000
        lookup = IRQ_NAME_LOOKUP[version]
        t.run(lookup, stop=lookup + 14, regs=((R4, irq),))
        name = bytes(t.cpu.mem_read(t.cpu.reg_read(R1), 6)).rstrip(b'\0').decode()
        assert name == f'PPC_{index}'
        irqs[hex(irq)] = name

    rows = []
    expected_history = {}
    for key, enabled, factor, override in ((11, 0, 128, 0), (12, 1, 128, 0),
                                          (13, 1, 192, 0), (14, 1, 192, 1), (15, 0, 32, 0)):
        t.put(CFG + 0x46e, 'B', enabled)
        t.put(CFG + 0x824, 'I', override)
        t.put(CTX + 8, 'I', key)
        t.put(STACK + 0x1c, 'I', 0)
        t.put(STACK + 0x60, '3I', 100, 100, 50)
        t.run(caller, stop=caller + 0x10, regs=((R5, ARG), (R6, CFG)))
        scalar = t.cpu.reg_read(R6)
        assert scalar == (2048 if enabled else 768)
        # Inject the independent second operand at the multiplier boundary.
        t.run(caller + 0x42, stop=caller + 0x5c, regs=((R1, factor), (R6, scalar), (FP, root)))
        triple = (scalar, factor, (scalar * factor) >> 8)
        assert t.unpack(record + 0x32, '3H') == triple
        t.put(root + 2, 'H', 0x7fff)  # Force a cache miss in the per-record calculation.
        t.put(STACK + 4, 'I', 0)
        t.put(STACK + 0x2c, 'I', 0)
        t.run(caller + 0x5c, stop=caller + 0x108, regs=((R4, params), (R5, ARG),
              (R7, inputs), (R9, 256), (FP, root)))
        triple = (256, 256, 256) if override else triple
        assert t.unpack(record + 0x32, '3H') == triple
        control, = t.unpack(params + 0x46, 'H')
        assert control == triple[0] // 4
        product = triple[2]
        fields = t.unpack(params + 0x1e, 'H3I')
        expected = (600,) + (product >> 2,) * 3 if product > 256 else (111, 112, 113, 114)
        assert fields == expected
        # This entry permits a null optional context and writes the real global descriptor.
        t.run(s.package, 0, params)
        assert t.unpack(command + 0x76, 'H3I') == fields
        assert t.unpack(command + 0xa0, 'H') == (control,)
        # The dispatcher supplies command+0x5c to the actual register writer.
        # MMIO is represented by local memory; no physical device is involved.
        t.cpu.mem_write(0x2006b370, bytes([0xa5]) * 16)
        t.put(0x2006b398, 'I', 0xa5a5a5a5)
        t.run(s.program, stop=s.program + 8)
        assert t.unpack(0x2006b370, '4I') == fields
        packed, = t.unpack(0x2006b398, 'I')
        upper, = t.unpack(command + 0xa2, 'H')
        assert packed == (upper << 11) | control
        t.run(caller + 0x6c4, stop=caller + 0x754, regs=((R4, params), (R6, inputs), (R7, root)))
        assert t.unpack(record, 'I') == t.unpack(history_middle - 120, 'I') == (key,)
        expected_history[key] = triple
        assert read_key(key) == triple
        rows.append(dict(key=key, nlog=bool(enabled), injected_factor=factor, override=bool(override),
                         history_fields=triple, command_fields_76_78_7c_80=fields, command_field_a0=control,
                         registers_370_through_37c=fields, register_398=packed))
    # Verify independent gates, key mismatch, rotation and four-record retention.
    assert read_key(11) == read_key(99) == (0xffff,) * 3
    assert all(read_key(k) == expected_history[k] for k in (12, 13, 14, 15))
    assert read_key(12, False, True) == (0xffff, 0xffff, expected_history[12][2])
    assert read_key(12, True, False) == (*expected_history[12][:2], 0xffff)
    return dict(controller_irqs=irqs, command_base=hex(command), four_key_history=hex(history_middle - 120), rows=rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', nargs='?', type=Path, default=C162_PACKAGE)
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    if not __debug__:
        parser.error('Run without -O to enable trace assertions.')
    result = {v: inspect(v, p) for v, p in [('C1.62', args.source_162), ('C1.70', args.master_170)]}
    assert result['C1.62']['rows'] == result['C1.70']['rows']
    print(json.dumps(result, indent=2))
