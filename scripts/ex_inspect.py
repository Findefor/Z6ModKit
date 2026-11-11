"""Read-only helpers for the original C1.70 EX/MCU image."""
import hashlib
import re
import struct
from pathlib import Path

import numpy as np
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x08000000
SHA256 = '9c65cad554ed02f83d37fbc825a8eb9efe79e3f32f98894dd5dd73edee416983'


class ExFirmware:
    def __init__(self):
        self.data = (ROOT/'work/analysis/Z6_2_0170/ex1850_012000.bi.bin').read_bytes()
        assert hashlib.sha256(self.data).hexdigest() == SHA256
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def words(self, address, count):
        return struct.unpack_from('<'+'I'*count, self.data, address-BASE)

    def listing(self, address, size):
        result = []
        for i in self.cs.disasm(self.data[address-BASE:address-BASE+size], address):
            line = f'{i.address:08x} {i.mnemonic:8} {i.op_str}'
            m = re.search(r'\[pc, #(-?0x[0-9a-f]+|\d+)\]', i.op_str)
            if m:
                loc = ((i.address+4)&~3)+int(m[1], 0)
                if BASE <= loc <= BASE+len(self.data)-4:
                    line += f' ; [{loc:08x}]={self.words(loc, 1)[0]:08x}'
            result.append(line)
        return '\n'.join(result)

    def refs(self, value):
        needle = struct.pack('<I', value)
        return [BASE+m.start() for m in re.finditer(re.escape(needle), self.data)]

    def branch_refs(self, target):
        h = np.frombuffer(self.data[:len(self.data)//2*2], dtype='<u2')
        a, b = h[:-1], h[1:]
        indexes = np.flatnonzero(((a&0xf800)==0xf000) &
                                (((b&0xd000)==0xd000) | ((b&0xd000)==0x9000)))
        result = []
        for offset in indexes*2:
            ins = next(self.cs.disasm(self.data[offset:offset+4], BASE+int(offset)), None)
            if ins and ins.mnemonic in ('bl', 'b.w') and ins.op_str == f'#{target:#x}':
                result.append(ins.address)
        return result

    def initial_ram(self):
        """Execute only the seven original scatter-load copy/zero/unpack entries."""
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_PROT_READ, UC_PROT_EXEC
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_PC)
        cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        cpu.mem_map(BASE, 0x81000)
        cpu.mem_write(BASE, self.data)
        cpu.mem_protect(BASE, 0x81000, UC_PROT_READ | UC_PROT_EXEC)
        cpu.mem_map(0x20000000, 0x40000)
        for address in range(0x080038cc, 0x0800393c, 16):
            src, dst, length, function = self.words(address, 4)
            for reg, value in ((UC_ARM_REG_R0, src), (UC_ARM_REG_R1, dst),
                               (UC_ARM_REG_R2, length), (UC_ARM_REG_LR, 0x08010001),
                               (UC_ARM_REG_SP, 0x2003ff00)):
                cpu.reg_write(reg, value)
            cpu.emu_start(function | 1, 0x08010000, count=300000)
            assert cpu.reg_read(UC_ARM_REG_PC) == 0x08010000
        return bytes(cpu.mem_read(0x20000000, 0x40000))
