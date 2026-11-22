"""Compare original Z6 II frame constructors and AVC submission in local Thumb emulation."""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import NamedTuple

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_EXEC, UC_PROT_READ
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                               UC_ARM_REG_R9, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP)

from fw_inspect import BASE, PATH, ROOT, SHA256


class Sites(NamedTuple):
    pooled: int
    general: int
    slot: int
    job_route: int
    job_build: int
    package_job: int
    worker_switch: int
    worker_case: int
    port_dispatch: int
    span: int
    event_a8: int
    event_408: int
    submit: int
    copy_to_queue: int
    adapter: int
    channel_writer: int
    alias_table: int
    clear: int
    copy: int


BUILDS = {
    'C1.62': ('cc0ca6e2584bc28f7cf3ebf7771b3e6222a377d72c52019ac1535b5d2154679b',
              Sites(0x10308FE4, 0x103044C4, 0x1029A1AA, 0x102C7076, 0x102B8818,
                    0x102BB25A, 0x103B3830, 0x103B369A, 0x103BE9DA, 0x1026A0A0,
                    0x1026B0A4, 0x102C9034, 0x10486644, 0x10487E0C, 0x10487368,
                    0x103BF3AE, 0xC2B27ADC, 0x1035C384, 0x1035C294)),
    'C1.70': (SHA256,
              Sites(0x1030981C, 0x10304CFC, 0x1029A3D6, 0x102C742A, 0x102B8BCC,
                    0x102BB60E, 0x103B458C, 0x103B43F6, 0x103BF776, 0x1026A1DC,
                    0x1026B1E0, 0x102C93E8, 0x10487514, 0x10488CDC, 0x10488238,
                    0x103C014A, 0xC2B2A79C, 0x1035D2DC, 0x1035D1EC)),
}
# Only descriptor/control memory is mapped. All pixel addresses stay unmapped.
RAM = 0x20000000
OBJ, POOL, CFG, EVENT, CTX, JOB, ARG, STACK, STOP = (
    RAM + offset for offset in (0x100, 0x300, 0x1000, 0x4000, 0x4400, 0x5000, 0x6000, 0x9000, 0xF000))
PIXELS = 0x50000000
C162_PACKAGE = ROOT / 'Библиотека старых прошивок' / 'Z6_2_0162.bin'
C162_PACKAGE_HASH = 'cb0bef25b66a1cdc8a055897240d292fb4865ca432bac991aa3d777d7a6d0328'
ARG_REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)


class Trace:
    def __init__(self, data, sites):
        self.s = sites
        self.cpu = cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        size = (len(data) + 4095) & ~4095
        cpu.mem_map(BASE, size)
        cpu.mem_write(BASE, data)
        cpu.mem_protect(BASE, size, UC_PROT_READ | UC_PROT_EXEC)
        cpu.mem_map(RAM, 0x10000)
        for addr in (sites.clear, sites.copy):
            cpu.hook_add(UC_HOOK_CODE, self.memory_helper, begin=addr, end=addr)
        # The job stores its output records in the firmware's RAM work area.
        self.nodes, self.job_input, self.job_first = self.unpack(sites.job_build + 0x464, '3I')
        source, dest, length, copier = self.unpack(0x10034020, '4I')
        assert copier == 0x1002006c and dest <= self.job_input < self.nodes + 18 * 16 <= dest + length
        start = dest & ~4095
        cpu.mem_map(start, ((dest + length + 4095) & ~4095) - start)
        cpu.mem_write(dest, data[source-BASE:source-BASE+length])
        cpu.mem_map(0x20100000, 4096)  # Model channel registers as local RAM.
        cpu.mem_map(sites.alias_table & ~4095, 4096)  # Identity translation fixture.
        self.pool_table, = self.unpack(sites.pooled + 0x270, 'I')
        cpu.mem_map((self.pool_table + 4 * 0x2c) & ~4095, 4096)

    def memory_helper(self, cpu, address, size, unused):
        dst, src, n = (cpu.reg_read(reg) for reg in ARG_REGS[:3])
        if address == self.s.clear:
            assert src in (20, 24, 28, 32, 52)
            cpu.mem_write(dst, bytes(src))
        else:
            assert n == 28
            cpu.mem_write(dst, bytes(cpu.mem_read(src, n)))
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    def put(self, address, fmt, *args):
        self.cpu.mem_write(address, struct.pack('<' + fmt, *args))

    def unpack(self, address, fmt):
        return struct.unpack('<' + fmt, self.cpu.mem_read(address, struct.calcsize('<' + fmt)))

    def run(self, addr, *args, stop=STOP, regs=()):
        cpu = self.cpu
        for reg, val in zip(ARG_REGS, args):
            cpu.reg_write(reg, val)
        for reg, val in regs:
            cpu.reg_write(reg, val)
        cpu.reg_write(UC_ARM_REG_SP, STACK)
        cpu.reg_write(UC_ARM_REG_LR, STOP | 1)
        cpu.emu_start(addr | 1, stop, count=5000)
        assert cpu.reg_read(UC_ARM_REG_PC) == stop, hex(addr)

    def pooled_slot(self, selector, index):
        self.put(CFG, 'BB', selector, 2)
        self.put(self.pool_table + 4 * 0x2c, 'I', PIXELS)
        self.run(self.s.pooled + 0x10c, stop=self.s.pooled + 0x126,
                 regs=((UC_ARM_REG_R4, 0x2c), (UC_ARM_REG_R5, CFG), (UC_ARM_REG_R7, 18)))
        base, total, capacity, count = self.unpack(STACK, '4I')
        assert (base, total, count) == (PIXELS, capacity * 18, 18)
        assert capacity == (0xc6cc00 if selector == 2 else 0x339800)
        self.put(POOL, 'I', POOL + 0x40)
        self.put(POOL + 0x40 + 4, '4I', base, total, capacity, count)
        self.run(self.s.slot + 0x16, POOL - 4, index, ARG, stop=self.s.slot + 0x32)
        slot, length = self.unpack(ARG, '2I')
        assert (slot, length) == (base + (index % count) * capacity, capacity)
        return slot, length

    def construct(self, selector, general, index):
        if general:
            slot, capacity = PIXELS + 0x800001, None  # Independent allocation fixture.
            self.put(ARG, '2I', slot, 0)
        else:
            slot, capacity = self.pooled_slot(selector, index)
        self.cpu.mem_write(OBJ, b'\xa5' * 0x68)
        self.put(OBJ + 4, 'I', ARG)
        if general:
            # Synthetic context family 1 uses the same ROM dimension selector.
            self.put(CFG, 'B', 1)
            self.put(CFG + 0x231, 'B', selector)
            self.run(self.s.general, OBJ, CFG, 0)
        else:
            self.run(self.s.pooled, OBJ, CFG)
        tag, = self.unpack(OBJ + 0x18, 'B')
        p, q, w, h, active_w, active_h, crop = self.unpack(OBJ + 0x1a, '7H')
        first, second = self.unpack(OBJ + 0x2c, '2I')
        assert (active_w, active_h) == [(1280, 720), (1920, 1080), (3840, 2160)][selector]
        assert p == q == w and first == ((slot + 511) & ~511)
        if general:
            assert (tag, crop, second - first) == (1, 0, p * h)
        else:
            assert (tag, crop, second - first) == (2, 128 if selector == 2 else 0,
                                                   (p * (h + 4) + 255) & ~255)
        self.run(self.s.span, stop=self.s.span + 0x2c, regs=((UC_ARM_REG_R4, OBJ + 0x18),))
        span = self.cpu.reg_read(UC_ARM_REG_R1)
        assert span == second - first + (p * h) // tag
        return dict(active=[active_w, active_h], pitch=p, storage_rows=h, tag=tag,
                    gap=second - first, crop=crop, first=first, second=second,
                    span_by_tag=span, slot_bytes=capacity)

    def route_job(self, frame, match, event=0x440):
        # Run the destination selector and both real address serializers.
        width, height = frame['active']
        self.cpu.mem_write(JOB, bytes(0x800))
        # The caller supplies a copy of the input object on its stack. Give its
        # record distinct addresses to reveal substitutions for the unused output.
        input_pair = (0x43000000, 0x44000000)
        self.cpu.mem_write(ARG + 0x100, bytes(self.cpu.mem_read(OBJ + 0x18, 28)))
        self.put(ARG + 0x100 + 20, 'II', *input_pair)
        if event == 0x440:
            self.put(STACK + 0x40, 'IHH', 1, width if match else width - 2, height)
            self.run(self.s.job_route, stop=self.s.job_route + 0x5e,
                     regs=((UC_ARM_REG_R4, JOB+0x75c), (UC_ARM_REG_R6, OBJ+0x18)))
            assert self.unpack(JOB + 0x764, 'II') == ((OBJ+0x18, 0) if match else (0, OBJ+0x18))
            assert self.unpack(OBJ + 0x26, 'HH') == (0, 0)
            self.put(JOB + 0x75c, 'I', ARG + 0x100)
        else:
            # Family 1 also binds the +408 object as the first job output;
            # the +418 object's other descriptor supplies a distinct output.
            self.put(CTX + 0x408, 'I', OBJ)
            self.put(CTX + 0x418, 'I', ARG + 0x500)
            self.cpu.mem_write(ARG + 0x514, bytes(self.cpu.mem_read(OBJ + 0x18, 28)))
            self.put(ARG + 0x514 + 20, 'II', 0x45000000, 0x46000000)
            self.run(self.s.job_route + 0x1280, stop=self.s.job_route + 0x1310,
                     regs=((UC_ARM_REG_R4, CTX), (UC_ARM_REG_R5, JOB+0x75c),
                           (UC_ARM_REG_R6, CFG), (UC_ARM_REG_R7, ARG + 0x100)))
            assert self.cpu.reg_read(UC_ARM_REG_R5) == 0x10
            assert self.unpack(JOB+0x764, 'II') == (OBJ+0x18, ARG+0x514)
        # One synthetic tile for the remaining scaling setup.
        control = RAM + 0x7000
        self.put(JOB + 0x788, 'I', control)
        self.put(control, 'I', control + 0x200)
        self.put(control + 0x144, 'II', 1, 1)
        self.put(control + 0x204, 'I', control + 0x280)
        self.put(control + 0x280, 'I', control + 0x300)
        self.put(control + 0x320, 'H', 0x0c0c)
        self.run(self.s.job_build, JOB, ARG + 0x200, ARG + 0x400)
        assert self.unpack(ARG + 0x200, 'IB') == (self.nodes, 18)
        self.run(self.s.package_job, stop=self.s.package_job + 0x14,
                 regs=((UC_ARM_REG_R5, ARG + 0x400 - 0x2c), (UC_ARM_REG_R7, JOB)))
        assert self.unpack(JOB + 0x7a0, '3I') == (0x42193009, ARG + 0x400, JOB)
        self.run(self.s.worker_switch, stop=self.s.worker_case, regs=((UC_ARM_REG_R4, JOB + 0x790),))
        assert (self.cpu.reg_read(UC_ARM_REG_R0), self.cpu.reg_read(UC_ARM_REG_R1)) == (JOB + 0x790, 0)
        expected = (frame['first'], frame['second'])
        assert self.unpack(self.job_input + 0x10, 'II') == input_pair
        destination = self.job_first if match else self.nodes - 0x40
        assert self.unpack(destination + 0x10, 'II') == expected
        assert self.unpack(destination, 'II') == (frame['pitch'],) * 2
        # The initialized job entries 0, 9 and 17 refer to the three port
        # descriptions. Select two channel IDs in the bank writer's 0..15 family.
        assert self.unpack(self.nodes + 12, 'I') == (self.job_input,)
        entry = self.nodes + 16 * (9 if match else 17)
        assert self.unpack(entry + 12, 'I') == (destination,)
        channel = 3 if match else 12
        self.cpu.mem_write(ARG, bytes(self.cpu.mem_read(entry, 16)))
        self.put(ARG + 1, 'B', channel)
        self.put(ARG + 0x40, 'IB', ARG, 1)
        self.run(self.s.port_dispatch, 0, ARG + 0x40, stop=self.s.port_dispatch + 0x22)
        assert self.cpu.reg_read(UC_ARM_REG_R2) == (self.s.channel_writer | 1)
        assert self.cpu.reg_read(UC_ARM_REG_R0) == ARG
        bank = 0x20100400 + channel * 0x40
        self.cpu.mem_write(bank, bytes([0xa5]) * 52)
        self.put(0x2010002c, 'I', 0xa5a5a5a5)
        self.run(self.s.channel_writer, ARG, stop=self.s.channel_writer + 0x186)
        assert self.unpack(0x2010002c, 'I') == (channel,)
        assert self.unpack(bank + 0x10, 'II') == (frame['pitch'],) * 2
        assert self.unpack(bank + 0x20, 'I') == (width | (height << 16),)
        assert self.unpack(bank + 0x24, '4I') == (*expected, 0, 0)
        control_word, = self.unpack(bank, 'I')
        assert control_word == (0x09000201 if frame['tag'] == 2 else 0x09000001)
        frame['channel_control'] = f'0x{control_word:08x}'

    def submit(self, event, frame, crop, blocked=False):
        self.put(EVENT + 0xc, 'I', CTX)
        self.put(CTX + 0x144, 'I', CFG)
        self.put(CTX + 0x4f4, 'I', CFG)
        self.put(CTX + 0x30, 'I', 1)
        self.put(CTX + event, 'I', OBJ)
        self.put(CFG + 0x98, 'B', 1)
        self.put(CFG + 0xfc, 'I', int(event == 0x440) ^ int(blocked))
        entry = {0xa8: self.s.event_a8, 0x408: self.s.event_408, 0x440: self.s.event_408 + 0x38}[event]
        self.run(entry, EVENT, stop=STOP if blocked else self.s.submit)
        if blocked:
            return
        args = self.cpu.reg_read(UC_ARM_REG_R0)
        assert self.unpack(args, '3I') == (OBJ + 0x18, 1, 0)
        # Preserve the captured submission across the queue-stack change.
        self.cpu.mem_write(ARG, bytes(self.cpu.mem_read(args, 12)))
        self.run(self.s.copy_to_queue, stop=self.s.copy_to_queue + 0x18,
                 regs=((UC_ARM_REG_R8, ARG), (UC_ARM_REG_R9, 0)))
        self.cpu.mem_write(STACK + 0x28, bytes(self.cpu.mem_read(STACK, 32)))
        self.run(self.s.adapter, stop=self.s.adapter + 0x4e)
        w, h, first, p, second, q = self.unpack(STACK + 0xc, 'HHIH2xIH2x')
        assert (w, h, p, q) == (*frame['active'], frame['pitch'], frame['pitch'])
        assert (first, second) == (frame['first'] + crop, frame['second'] + crop)


def inspect(path, version):
    digest, sites = BUILDS[version]
    data = path.read_bytes()
    if version == 'C1.62' and hashlib.sha256(data).hexdigest() == C162_PACKAGE_HASH:
        # Optional package input uses the repository's existing local extraction setup.
        sys.path.insert(0, str(ROOT / 'work/vendor/key'))
        import decrypt_firmware as fw
        body = fw.decrypt(data, *fw.load_key(str(ROOT / 'work/analysis/key.json')))[32:]
        modules = fw.validate_firmware(body)
        [(start, size)] = [(start, size) for name, start, size in modules if name == 'eg1850_mas_0162a']
        data = body[start:start + size]
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f'{version}: unsupported master image')
    trace = Trace(data, sites)
    for selector in (0, 1, 2):
        frame = trace.construct(selector, False, 0)
        trace.submit(0xa8, frame, frame['crop'])
    assert trace.pooled_slot(2, 18) == trace.pooled_slot(2, 0)
    for match in (False, True):
        frame = trace.construct(2, False, 1)
        trace.route_job(frame, match)
        trace.submit(0x440, frame, 0)
        trace.submit(0x440, frame, 0, blocked=True)
    general = trace.construct(2, True, 0)
    trace.route_job(general, True, event=0x408)
    trace.submit(0x408, general, 0)
    trace.submit(0x408, general, 0, blocked=True)
    for result in (frame, general):
        del result['first'], result['second']
    return {'pooled_4k': frame, 'general_4k_family_1': general}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', type=Path, nargs='?', default=C162_PACKAGE,
                        help='original C1.62 EG master, or stock package with the local extraction setup')
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit('Run without -O to enable trace assertions.')
    older = inspect(args.source_162, 'C1.62')
    newer = inspect(args.master_170, 'C1.70')
    assert older == newer
    print(json.dumps({'C1.62': older, 'C1.70': newer}, indent=2))


if __name__ == '__main__':
    main()
