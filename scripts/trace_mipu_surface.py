"""Compare MIPU plane registers and the common IIP source using one backing object."""
import argparse
import json
import sys
from pathlib import Path
from typing import NamedTuple

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_LR as LR, UC_ARM_REG_PC as PC, UC_ARM_REG_R0 as R0,
                               UC_ARM_REG_R1 as R1, UC_ARM_REG_R2 as R2, UC_ARM_REG_R4 as R4, UC_ARM_REG_R5 as R5,
                               UC_ARM_REG_R6 as R6, UC_ARM_REG_R7 as R7)
from analyze_frame_producer import ARG, BUILDS, C162_PACKAGE, CFG, CTX, JOB, OBJ, PATH, POOL, Trace, load_master
from compare_hdmi_card import SITES as VIDEO, prepare_job
from trace_nlog_control import map_global


class Sites(NamedTuple):
    frame_source: int
    request_surface: int
    request_header: int
    bind_section: int
    describe_planes: int
    bind_driver: int
    driver_planes: int
    pool_init: int
    list_push: int
    heap_alloc: int
    heap_free: int
    slot_acquire: int


SITES = {
    'C1.62': Sites(0x102643ec, 0x10265066, 0x10264dc0, 0x102c0320,
                   0x102bf83a, 0x102c0e62, 0x102e7302, 0x102cd41c, 0x1034b04a, 0x1034b2cc, 0x1034b31a, 0x10299f4e),
    'C1.70': Sites(0x10264528, 0x102651a2, 0x10264efc, 0x102c06d4,
                   0x102bfbee, 0x102c1216, 0x102e760e, 0x102cd7d0, 0x1034bf6e, 0x1034c1f0, 0x1034c23e, 0x1029a17a),
}


class SurfaceTrace(Trace):
    def memory_helper(self, cpu, address, size, unused):
        n = cpu.reg_read(R2)
        if address == self.s.copy and n in (0xb0, 0xcc):
            src, dst = cpu.reg_read(R1), cpu.reg_read(R0)
            cpu.mem_write(dst, bytes(cpu.mem_read(src, n)))
            cpu.reg_write(PC, cpu.reg_read(LR))
        else:
            super().memory_helper(cpu, address, size, unused)


def seed_pool(t, s, pool, allocation, surface):
    # Exercise the stock lists and callbacks. Supply local heap storage,
    # successful slot allocation and locks for this single-frame fixture.
    heap = ARG+0x2800

    def services(cpu, address, size, unused):
        nonlocal heap
        if address == s.heap_alloc:
            n = cpu.reg_read(R0)
            assert n in (8, 12, 0x68)
            cpu.reg_write(R0, heap)
            heap += (n+7) & ~7
        elif address == s.slot_acquire:
            t.put(cpu.reg_read(R2), '2I', allocation, 0x2000000)
            cpu.reg_write(R0, 1)
        cpu.reg_write(PC, cpu.reg_read(LR))

    for a in (s.heap_alloc, s.heap_free, s.slot_acquire, t.s.clear-0x11c, t.s.clear-0x122):
        t.cpu.hook_add(UC_HOOK_CODE, services, begin=a, end=a)
    t.cpu.hook_add(UC_HOOK_CODE, t.memory_helper, begin=t.s.copy-4, end=t.s.copy-4)
    t.run(s.pool_init, stop=s.pool_init+14, regs=((R4, pool), (R5, 0)))
    assert all(t.unpack(pool+8, '2I'))
    manager = t.unpack(surface+0x708, 'I')[0]+0x28
    map_global(t, manager)
    t.put(manager, 'I', ARG+0x2600)
    t.put(OBJ+4, '4I', POOL, 0, 0, 0)
    t.run(s.list_push, pool+0x10, OBJ)
    assert t.unpack(pool+0x18, 'I') == (1,)


def inspect(image, version, allocation, instance, profile, pooled):
    t = SurfaceTrace(image, BUILDS[version][1])
    v, s = VIDEO[version], SITES[version]
    requested = {'N-Log': (1, 0), 'HLG': (0, 1)}[profile]
    t.construct(2, False, 1)
    mode, job, builder_args, *_ = prepare_job(t, v, 0, *requested)
    assert (mode, job) == ((0x17 if profile == 'N-Log' else 0x1b), 0xa)
    t.put(POOL, 'I', allocation)
    t.run(v.input_surface, OBJ, CFG, 0x1a)
    planes = t.unpack(OBJ+0x2c, '2I')
    # Both stock slot selectors inspect the same pool and static pointer.
    pool, = t.unpack(s.request_surface+0x39a, 'I')
    static, = t.unpack(s.request_surface+0x39e, 'I')
    map_global(t, pool)
    map_global(t, static)
    t.put(pool+0x18, 'I', 0)
    t.put(static, 'I', 0 if pooled else OBJ)
    if pooled:
        t.cpu.mem_write(OBJ+0x18, bytes([0xa5])*28)
        seed_pool(t, s, pool, allocation, v.input_surface)
    t.put(CTX+0x94, 'I', 0)
    t.run(s.frame_source, stop=s.frame_source+(0x2a if pooled else 0x12), regs=((R4, CTX),))
    assert t.unpack(CTX+0x94, 'I') == (OBJ,)
    if pooled:
        assert t.unpack(OBJ+0x2c, '2I') == planes
        assert t.unpack(pool+0x78, 'I') == (1,)  # frame-source getter enqueued for the request
    t.run(v.snapshot, CTX, JOB+4)
    t.run(v.job_builder, JOB, *builder_args, stop=v.job_builder+0xf4)
    nodes, count = t.unpack(builder_args[0], 'IB')
    port, = t.unpack(nodes+12, 'I')
    assert count == 28 and t.unpack(nodes+2, 'B') == (1,)
    assert t.unpack(port+0x10, '2I') == planes

    req, driver, tables = ARG+0x1000, ARG+0x1800, ARG+0x1a00
    handle, task = ARG+0x2200, ARG+0x2300
    t.put(req+4, 'I', 1)
    t.run(s.request_surface, stop=s.request_surface+0x52,
          regs=((R4, CTX), (R5, 1), (R6, req+4)))
    assert t.unpack(req+0x1d8, '2I') == planes
    t.put(task+0xc, 'I', CTX)
    for gate in (0, 1):
        t.put(CTX+0x64, 'I', gate)
        t.run(s.request_header, CTX, task, req)
        assert t.unpack(req+0x35c, 'I') == (CFG+0x93c if gate else 0,)
    assert t.unpack(req+0x378, 'B') == (1 if pooled else 2,)
    if pooled:
        assert t.unpack(pool+0x78, 'I') == (0,)
    t.run(s.bind_driver, driver, tables)
    t.run(s.bind_section-0x5c, req, 0, driver, stop=s.bind_section+0xc)
    assert t.unpack(driver+0xa0, 'I') == (CFG+0x93c+0x380,)
    t.run(s.describe_planes, req, driver)
    addresses, = t.unpack(driver+0x24, 'I')
    assert (t.unpack(addresses+0x58, 'I')[0], t.unpack(addresses+0x78, 'I')[0]) == planes
    bank = 0x20380000 + (instance << 18)
    t.cpu.mem_map(bank, 4096)
    t.put(handle+4, 'B', instance)
    t.run(s.driver_planes, stop=s.driver_planes+0x32, regs=((R4, handle), (R5, driver)))
    assert (t.unpack(bank+0x488, 'I')[0], t.unpack(bank+0x498, 'I')[0]) == planes
    return dict(mode=hex(mode), pooled=pooled, instance=instance, iip_source_node='01',
                plane_registers=[hex(bank+0x488), hex(bank+0x498)], shared_Y_C=list(map(hex, planes)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_162', nargs='?', type=Path, default=C162_PACKAGE)
    parser.add_argument('--master-170', type=Path, default=PATH)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('Run without -O to enable trace assertions.')
    results = {}
    for version, path in [('C1.62', args.source_162), ('C1.70', args.master_170)]:
        image = load_master(path, version)
        results[version] = [inspect(image, version, address, instance, profile, pooled)
                            for profile in ('N-Log', 'HLG') for instance in (0, 1)
                            for address in (0x60000001, 0x62000001) for pooled in (False, True)]
    assert results['C1.62'] == results['C1.70']
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
