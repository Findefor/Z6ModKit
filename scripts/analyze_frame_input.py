"""Trace C1.70 master frame descriptors using synthetic addresses in Unicorn."""
import argparse
import json
import struct
import sys

from fw_inspect import BASE, Firmware
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_EXEC, UC_PROT_READ
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

RAM = 0x20000000
WRAPPER, DESCRIPTOR, STACK, STOP = (RAM + n for n in (0x1000, 0x2000, 0xD000, 0xF000))
CONTEXT = 0xC1D41C40
RING = CONTEXT + 0x68
HANDLES = 0xC1808D50
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]


class FrameTrace:
    def __init__(self, firmware):
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        size = (len(firmware) + 4095) & ~4095
        self.cpu.mem_map(BASE, size)
        self.cpu.mem_write(BASE, firmware)
        self.cpu.mem_protect(BASE, size, UC_PROT_EXEC | UC_PROT_READ)
        for page, size in [(RAM, 0x10000), (CONTEXT & ~4095, 4096),
                           (HANDLES & ~4095, 4096), (0xC1806000, 4096)]:
            self.cpu.mem_map(page, size)
        self.cpu.hook_add(UC_HOOK_CODE, self.hook)
        self.writes = []
        self.geometry = None
        self.allocation = DESCRIPTOR
        self.put(HANDLES + 0x34, WRAPPER)
        self.put(0xC1806FC0, 0x104D9AE9)  # Hardware writer resolved to the capture hook.
        self.put(RING + 0x258, 28, 28)     # Exercise the 29 -> 0 wrap.

    def put(self, address, *words):
        self.cpu.mem_write(address, struct.pack('<' + 'I' * len(words), *words))

    def words(self, address, count):
        return struct.unpack('<' + 'I' * count, self.cpu.mem_read(address, 4 * count))

    def hook(self, cpu, address, size, user_data):
        if address not in (0x1035D1EC, 0x1035D2DC, 0x103DEB78, 0x103DEB5A,
                           0x104D9ADE, 0x1054E720, 0x104D94CA, 0x104D9B02,
                           0x104D9AE8, 0x104BE39A):
            return
        a, b, c, d = [cpu.reg_read(r) for r in REGS]
        if address == 0x1035D1EC:
            assert c == 20
            cpu.mem_write(a, bytes(cpu.mem_read(b, c)))
        elif address == 0x1035D2DC:
            assert b == 20
            cpu.mem_write(a, bytes(b))
        elif address == 0x104D94CA:
            cpu.mem_write(b, bytes([1]))  # Synthetic active encoder bank.
            cpu.reg_write(REGS[0], 1)
        elif address == 0x1054E720:
            cpu.reg_write(REGS[0], self.allocation)
        elif address == 0x104D9AE8:
            self.writes.append((a, b))
        elif address == 0x104BE39A:
            self.geometry = (c, d)
            cpu.reg_write(REGS[0], 0)
        # Lock, context lookup and driver synchronization return immediately.
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    def run(self, start, *args, stop=STOP):
        self.cpu.reg_write(UC_ARM_REG_SP, STACK)
        self.cpu.reg_write(UC_ARM_REG_LR, STOP | 1)
        for reg, arg in zip(REGS, args):
            self.cpu.reg_write(reg, arg)
        self.cpu.emu_start(start | 1, stop, count=10000)
        assert self.cpu.reg_read(UC_ARM_REG_PC) == stop
        return self.cpu.reg_read(REGS[0])

    def format_record(self, width, rows, pitch_a, pitch_b, displacement, first, second):
        # The adapter has already copied 32 bytes into its stack frame.
        raw = bytearray(32)
        for offset, value in [(2, pitch_a), (4, pitch_b), (10, width),
                              (12, rows), (14, displacement)]:
            struct.pack_into('<H', raw, offset, value)
        struct.pack_into('<II', raw, 20, first, second)
        self.cpu.mem_write(STACK + 0x28, bytes(raw))
        self.cpu.mem_write(STACK + 0x0C, bytes([0xA5]) * 20)
        # Stop at either the submission call or the diagnostic branch.
        self.cpu.reg_write(UC_ARM_REG_SP, STACK)
        accepted = width <= pitch_a == pitch_b
        endpoint = 0x10488286 if accepted else 0x1048827C
        self.cpu.emu_start(0x10488239, endpoint, count=100)
        assert self.cpu.reg_read(UC_ARM_REG_PC) == endpoint
        if accepted:
            record = bytes(self.cpu.mem_read(STACK + 0x0C, 20))
            assert struct.unpack('<HHIHHIHH', record) == (
                width, rows, first + displacement, pitch_a, 0, second + displacement, pitch_b, 0)
            self.cpu.mem_write(RAM + 0x3000, record)
            assert self.run(0x104A5210, RAM + 0x3000) == 1
        return accepted

    def frame_batch(self, width, rows, pitch, group, bank):
        self.put(CONTEXT + 0x0C, group << 16)
        expected = []
        for i in range(3):
            a, b = 0x50000000 + i * 0x1000000, 0x60000000 + i * 0x1000000
            delta = 16 * (i + 1)
            assert self.format_record(width, rows, pitch, pitch, delta, a, b)
            expected.append((rows * pitch * 3 // 2, a + delta, b + delta))
        if group == 3:
            expected = [expected[2], expected[0], expected[1]]
        assert self.run(0x104A46E6, bank, 0) == 1
        assert self.words(RING + 0x258, 2) == (1, 1)
        assert self.words(WRAPPER + (0x0C if bank == 1 else 0x14), 1) == (DESCRIPTOR,)
        assert self.words(DESCRIPTOR, 1) == (3,)
        assert self.words(DESCRIPTOR + 0x4C, 1) == (expected[-1][0],)
        assert self.cpu.mem_read(DESCRIPTOR + 0x50, 2) == struct.pack('<H', pitch)
        for i, entry in enumerate(expected):
            assert self.words(DESCRIPTOR + 4 + 12 * i, 3) == entry
        writes = [(0x464, 0x10)]
        for i, (_, a, b) in enumerate(expected):
            index = 4 * i + (0 if bank == 1 else 0x20)
            writes.extend([(0x438, index), (0x43C, a), (0x438, index + 1), (0x43C, b)])
        assert self.writes == writes
        return expected[-1][0]

    def slot_spacing(self, family, pixel_width, pixel_height, expected_spacing):
        self.cpu.mem_write(CONTEXT + 0x0C, bytes([family]))
        start = 0x40000000
        self.put(CONTEXT + 0x40, start)
        self.put(CONTEXT + 0x50, 0xA5A5A5A5, 0xA5A5A5A5, 0xA5A5A5A5)
        self.run(0x104A4CD0, stop=0x104A4E08)
        assert self.geometry == (pixel_width, pixel_height)
        assert self.cpu.reg_read(REGS[2]) == CONTEXT + 0x50
        slots = self.words(CONTEXT + 0x50, 3)
        assert slots == (start, start + expected_spacing, 0)
        # The preceding stop is the wrapper call site. Run the real constructor
        # with the captured arguments and choose the synthetic allocation.
        args = [self.cpu.reg_read(reg) for reg in REGS]
        self.allocation = WRAPPER
        self.cpu.mem_write(WRAPPER, bytes([0xA5]) * 0x44)
        assert self.run(0x104BE682, *args) == 0
        assert self.words(args[3], 1) == (WRAPPER,)
        assert self.words(WRAPPER + 8, 1) == (CONTEXT + 0x50,)
        self.cpu.reg_write(UC_ARM_REG_R4, WRAPPER)
        self.writes.clear()
        self.run(0x104BEF12, stop=0x104BEF2A)
        assert self.writes == [(0x404, slots[0]), (0x408, slots[1])]
        return slots[1] - slots[0]


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if sys.flags.optimize:
        raise SystemExit('Run without -O so the trace assertions execute.')
    firmware = Firmware().data
    result = {}
    for label, width, rows, pitch, group, bank in [
            ('4k', 3840, 2160, 3840, 1, 1), ('fhd', 1920, 1080, 1920, 3, 2),
            ('hd', 1280, 720, 1280, 1, 2), ('padded', 1920, 1080, 2048, 3, 1)]:
        result[label + '_descriptor_size'] = FrameTrace(firmware).frame_batch(width, rows, pitch, group, bank)
    for family, width, height, spacing in [(0, 3840, 2160, 0xBDD800), (1, 1920, 1080, 0x2FD000),
                                           (2, 1280, 720, 0x2FD000)]:
        result['family_%d_slot_spacing' % family] = FrameTrace(firmware).slot_spacing(family, width, height, spacing)
    trace = FrameTrace(firmware)
    for pitch_a, pitch_b in [(1984, 1920), (1919, 1919)]:
        assert not trace.format_record(1920, 1080, pitch_a, pitch_b, 0, 0, 0)
    result['rejected_geometry_cases'] = 2
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
