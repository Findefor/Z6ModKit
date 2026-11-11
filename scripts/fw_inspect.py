"""Small offline inspection helpers for the unmodified Z6 II C1.70 master."""
import argparse
import hashlib
import pathlib
import re
import struct

import numpy as np
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = 0x10020000
PATH = ROOT / 'work/analysis/Z6_2_0170/eg1850_mas_01700.bin'
SHA256 = 'bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4'


class Firmware:
    def __init__(self):
        self.data = PATH.read_bytes()
        assert hashlib.sha256(self.data).hexdigest() == SHA256
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def words(self, address, count):
        return struct.unpack_from('<' + 'I' * count, self.data, address - BASE)

    def instructions(self, address, size):
        return self.cs.disasm(self.data[address-BASE:address-BASE+size], address)

    def listing(self, address, size):
        lines = []
        for i in self.instructions(address, size):
            s = f'{i.address:08x} {i.bytes.hex():10} {i.mnemonic:8} {i.op_str}'
            match = re.search(r'\[pc, #(-?0x[0-9a-f]+|\d+)\]', i.op_str)
            if match:
                loc = ((i.address + 4) & ~3) + int(match[1], 0)
                s += f' ; [{loc:08x}]={self.words(loc, 1)[0]:08x}'
            lines.append(s)
        return '\n'.join(lines)

    def refs(self, value):
        needle = struct.pack('<I', value)
        offset, result = 0, []
        while True:
            offset = self.data.find(needle, offset)
            if offset < 0:
                return result
            result.append(BASE + offset)
            offset += 1

    def branch_refs(self, target):
        # Thumb-2 BL and unconditional B.W candidates, independently decoded
        # with Capstone. Raw scan can include data; callers need CFG review.
        h = np.frombuffer(self.data[:len(self.data)//2*2], dtype='<u2')
        a, b = h[:-1], h[1:]
        mask = ((a & 0xf800) == 0xf000) & (((b & 0xd000) == 0xd000) | ((b & 0xd000) == 0x9000))
        idx = np.flatnonzero(mask)
        x, y = a[idx].astype(np.int64), b[idx].astype(np.int64)
        s = (x >> 10) & 1
        i1, i2 = (~((y >> 13) ^ s)) & 1, (~((y >> 11) ^ s)) & 1
        imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((x & 0x3ff) << 12) | ((y & 0x7ff) << 1)
        imm = np.where(s != 0, imm - (1 << 25), imm)
        hits = idx[(BASE + 2*idx + 4 + imm) == target]
        return [BASE + 2*int(i) for i in hits
                if any(ins.mnemonic in ('bl', 'b.w') and int(ins.op_str.lstrip('#'), 0) == target
                       for ins in self.instructions(BASE+2*int(i), 4))]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('address', type=lambda x: int(x, 0))
    parser.add_argument('--size', type=lambda x: int(x, 0), default=128)
    parser.add_argument('--refs', action='store_true')
    parser.add_argument('--calls', action='store_true')
    args = parser.parse_args()
    fw = Firmware()
    if args.refs:
        print(' '.join(hex(a) for a in fw.refs(args.address)))
    elif args.calls:
        print(' '.join(hex(a) for a in fw.branch_refs(args.address)))
    else:
        print(fw.listing(args.address, args.size))
