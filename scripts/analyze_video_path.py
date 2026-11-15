"""Inspect AVC configuration and selected video-state callbacks entirely offline.

Original Thumb instructions run in host RAM. Register writes and the property
queue are intercepted; no encoder, ISP, camera, USB, or modified image is used.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BASE, RAM = 0x10020000, 0x20000000
CFG, ARG, QUEUE, OUT, STACK, STOP = [RAM + n for n in
                                  (0x1000, 0x3000, 0x4000, 0x5000, 0xe000, 0xf000)]
CASES = [
    dict(name='master', file='eg1850_mas_01700.bin',
         sha256='bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4',
         constructor=(0x104be3b8, 0x104be5c0),
         writer=(0x104be748, 0x104be976), register_write=0x104d9ae8),
    dict(name='slave', file='eg1850_sla_01700.bin',
         sha256='3fd8c2cbdf57fadb03f6d69b596b58a8703efdd61ae82572d5afeea0241a9ed5',
         constructor=(0x100a2340, 0x100a2548),
         writer=(0x100a26d0, 0x100a28fe), register_write=0x100a02ba),
]


class Bits:
    def __init__(self, data):
        self.data, self.position = data, 0

    def read(self, count):
        if self.position + count > len(self.data) * 8:
            raise ValueError('Truncated SPS')
        value = 0
        for _ in range(count):
            value = (value << 1) | ((self.data[self.position // 8] >>
                                    (7 - self.position % 8)) & 1)
            self.position += 1
        return value

    def ue(self):
        zeros = 0
        while self.read(1) == 0:
            zeros += 1
            if zeros > 31:
                raise ValueError('Overlong Exp-Golomb value')
        return (1 << zeros) - 1 + self.read(zeros)


def parse_sps(nal):
    """Parse the reviewed High-profile SPS subset, rejecting unsupported syntax."""
    assert nal[0] & 31 == 7
    rbsp = bytearray()
    zeros = 0
    for byte in nal[1:]:
        if zeros == 2 and byte == 3:
            zeros = 0
            continue
        rbsp.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    b = Bits(rbsp)
    result = dict(profile_idc=b.read(8), constraint_byte=b.read(8), level_idc=b.read(8),
                  seq_parameter_set_id=b.ue())
    assert result['profile_idc'] == 100
    result['chroma_format_idc'] = b.ue()
    assert result['chroma_format_idc'] == 1
    result['bit_depth_luma_minus8'] = b.ue()
    result['bit_depth_chroma_minus8'] = b.ue()
    result['qpprime_y_zero_transform_bypass_flag'] = b.read(1)
    assert b.read(1) == 0  # No scaling matrix in these templates.
    result['log2_max_frame_num_minus4'] = b.ue()
    result['pic_order_cnt_type'] = b.ue()
    if result['pic_order_cnt_type'] == 0:
        result['log2_max_pic_order_cnt_lsb_minus4'] = b.ue()
    else:
        assert result['pic_order_cnt_type'] == 2
    result['max_num_ref_frames'] = b.ue()
    result['gaps_in_frame_num_value_allowed_flag'] = b.read(1)
    width, height = b.ue() + 1, b.ue() + 1
    frame = b.read(1)
    if not frame:
        result['mb_adaptive_frame_field_flag'] = b.read(1)
    result['direct_8x8_inference_flag'] = b.read(1)
    crop = [b.ue() for _ in range(4)] if b.read(1) else [0, 0, 0, 0]
    result.update(coded_width=width * 16, coded_height=height * 16 * (2 - frame),
                  crop_offsets=crop, width=width * 16 - 2 * (crop[0] + crop[1]),
                  height=height * 16 * (2 - frame) - 2 * (2 - frame) * (crop[2] + crop[3]))
    assert b.read(1) == 1  # VUI present.
    assert b.read(1) == 0  # No aspect-ratio information.
    assert b.read(1) == 0  # No overscan information.
    assert b.read(1) == 1  # Video signal type present.
    result['video_format'] = b.read(3)
    result['video_full_range_flag'] = b.read(1)
    assert b.read(1) == 1  # Colour description present.
    result.update(colour_primaries=b.read(8), transfer_characteristics=b.read(8),
                  matrix_coefficients=b.read(8))
    assert b.read(1) == 0  # No chroma-location information.
    assert b.read(1) == 1  # Timing information present.
    result.update(num_units_in_tick=b.read(32), time_scale=b.read(32),
                  fixed_frame_rate_flag=b.read(1))
    # HRD/trailing syntax is outside this bounded parser.
    return result


def analyze():
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
        UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

    report = dict(scope='Offline fragments and SPS templates; no hardware capability or pixel validation',
                  firmware='Nikon Z6 II C1.70', modules=[], callbacks=[], sps_templates=[])
    for case in CASES:
        data = (ROOT / 'work/analysis/Z6_2_0170' / case['file']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == case['sha256']
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        size = (len(data) + 4095) & ~4095
        u.mem_map(BASE, size)
        u.mem_write(BASE, data)
        u.mem_protect(BASE, size, UC_PROT_READ | UC_PROT_EXEC)
        u.mem_map(RAM, 0x10000)
        events, queue_events, queue_result = [], [], 1

        def hook(cpu, address, size, _):
            if address == STOP:
                cpu.emu_stop()
                return
            if address == case['register_write']:
                offset, value = [cpu.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1)]
                assert 0xe00 <= offset <= 0xe6c and offset % 4 == 0
                events.append(dict(offset=hex(offset), value=value))
                cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
            elif case['name'] == 'master' and address == 0x10327c98:
                n, ids, values = [cpu.reg_read(r) for r in
                                  (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
                assert n == 1
                queue_events.append(dict(property=hex(struct.unpack('<I', cpu.mem_read(ids, 4))[0]),
                                         value=struct.unpack('<I', cpu.mem_read(values, 4))[0]))
                cpu.reg_write(UC_ARM_REG_R0, queue_result)
                cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

        u.hook_add(UC_HOOK_CODE, hook)

        def run(start, stop=STOP, registers=()):
            u.reg_write(UC_ARM_REG_SP, STACK)
            u.reg_write(UC_ARM_REG_LR, STOP | 1)
            for register, value in registers:
                u.reg_write(register, value)
            u.emu_start(start | 1, stop, count=4000)
            assert u.reg_read(UC_ARM_REG_PC) == stop, 'Instruction budget exhausted'
            return u.reg_read(UC_ARM_REG_R0)

        module = dict(name=case['name'], sha256=case['sha256'],
                      constructor_range=[hex(x) for x in case['constructor']],
                      writer_range=[hex(x) for x in case['writer']],
                      register_write_stub=hex(case['register_write']), configurations=[], packing_checks=[])
        configurations = [('4k_144_120',3840,2160,29,144,120),
                          ('4k_156_140',3840,2160,29,156,140),
                          ('4k_200_168',3840,2160,29,200,168),
                          ('synthetic_fhd_29',1920,1080,29,60,50),
                          ('synthetic_fhd_119',1920,1080,119,144,120),
                          ('synthetic_hd_59',1280,720,59,60,50)]
        for name, width, height, fpscode, peak, mean in configurations:
            u.mem_write(CFG - 16, b'\xa5' * 544)
            initial = bytearray(512)
            for offset, length in [(0x48,26),(0x70,16),(0xf,8)]:
                initial[offset:offset+length] = b'\xa5' * length
            u.mem_write(CFG, bytes(initial))
            u.mem_write(STACK, bytes(128))
            for offset, value in {4:0, 0x38:mean*1000000>>10, 0x44:0, 0x48:0,
                                  0x4c:1, 0x50:0, 0x54:0, 0x58:0, 0x5c:5,
                                  0x60:1, 0x64:1, 0x68:1, 0x6c:1}.items():
                u.mem_write(STACK + offset, struct.pack('<I', value))
            run(*case['constructor'], registers=[(UC_ARM_REG_R4,CFG),(UC_ARM_REG_R5,1),
                (UC_ARM_REG_R6,height),(UC_ARM_REG_R7,width),(UC_ARM_REG_R8,fpscode),
                (UC_ARM_REG_R9,peak*1000000>>10)])
            config = bytes(u.mem_read(CFG, 512))
            assert config[0x60] == 100
            assert struct.unpack_from('<II', config, 0x70) == (0, 1)
            assert config[0x78:0x80] == bytes(8)
            assert config[0xf] == 5 and struct.unpack_from('<I', config, 0x10)[0] == 1
            assert config[0x14:0x17] == bytes([1,1,1])
            assert bytes(u.mem_read(CFG-16,16)) == b'\xa5'*16
            assert bytes(u.mem_read(CFG+512,16)) == b'\xa5'*16
            events.clear()
            run(*case['writer'], registers=[(UC_ARM_REG_R0, CFG)])
            regs = {e['offset']: e['value'] for e in events}
            assert regs['0xe30'] == 100 and regs['0xe48'] == 0x400
            assert regs['0xe34'] == config[0x61]
            assert regs['0xe68'] == 0x3701 and regs['0xe6c'] == 0x0101
            module['configurations'].append(dict(name=name, width=width, height=height,
                fps_code=fpscode, maximum_mbps=peak, average_mbps=mean,
                profile_like_field=config[0x60], level_field=config[0x61],
                fields_70_74=[0,1], fields_78_79=[0,0], writes=list(events)))

        # Marker inputs establish byte/bit packing only, not valid encoder modes.
        for offset, value, register, mask, shift in [(0x60,0x5a,0xe30,255,0),
                (0x78,2,0xe48,31,5),(0x79,2,0xe48,31,0),
                (0x78,0x22,0xe48,31,5),(0x79,0x22,0xe48,31,0)]:
            u.mem_write(CFG, config)
            u.mem_write(CFG+offset, bytes([value]))
            events.clear()
            run(*case['writer'], registers=[(UC_ARM_REG_R0,CFG)])
            packed = next(e['value'] for e in events if e['offset'] == hex(register))
            expected = (0 if register == 0xe30 else 0x400) | ((value & mask) << shift)
            assert packed == expected
            module['packing_checks'].append(dict(field=hex(offset), marker=value,
                register=hex(register), packed=packed, hardware_support_tested=False))
        report['modules'].append(module)

        if case['name'] != 'master':
            continue
        # Execute the real SPS/PPS selector, including its out-of-range no-write case.
        for selector, address, length in [(0,0x108abfe4,24),(1,0x108abffc,25),(2,0x108ac015,24)]:
            u.mem_write(OUT, bytes(16))
            u.mem_write(STACK, struct.pack('<I',OUT+12))
            run(0x104a441e, registers=[(UC_ARM_REG_R0,selector),(UC_ARM_REG_R1,OUT),
                (UC_ARM_REG_R2,OUT+4),(UC_ARM_REG_R3,OUT+8)])
            sps, size, pps, pps_size = struct.unpack('<4I', u.mem_read(OUT,16))
            assert (sps,size,pps,pps_size) == (address,length,0x108abfd8+4*selector,4)
            decoded = parse_sps(data[sps-BASE:sps-BASE+size])
            assert (decoded['profile_idc'],decoded['bit_depth_luma_minus8'],
                    decoded['bit_depth_chroma_minus8'],decoded['width'],decoded['height']) == (100,0,0,1920,1080)
            report['sps_templates'].append(dict(selector=selector, settings_index=selector+7,
                address=hex(address), file_offset=hex(address-BASE), length=length,
                pps_address=hex(pps), pps_length=pps_size, decoded=decoded))
        u.mem_write(OUT, b'\xa5'*16)
        u.mem_write(STACK,struct.pack('<I',OUT+12))
        run(0x104a441e,registers=[(UC_ARM_REG_R0,3),(UC_ARM_REG_R1,OUT),
                               (UC_ARM_REG_R2,OUT+4),(UC_ARM_REG_R3,OUT+8)])
        assert bytes(u.mem_read(OUT,16)) == b'\xa5'*16
        report['sps_invalid_selector_no_write'] = True

        # The argument words are synthetic. Their full upstream population is
        # not emulated; only the callbacks' arithmetic/queue decisions are proved.
        for kind, callback, property_id in [('flag_1688',0x1033a8b6,0x1688),('flag_16bf',0x1033a98c,0x16bf)]:
            inputs = list(itertools.product((0,1),repeat=4 if kind=='flag_1688' else 3))
            for values in inputs:
                request, gate, override = values[:3]
                force = values[3] if kind=='flag_1688' else 0
                result = force if kind=='flag_1688' and override else (0 if gate or override else request)
                words = [0, request, 0, gate, override, force]
                u.mem_write(ARG, struct.pack('<6I', *words))
                u.mem_write(QUEUE, bytes(0x120))
                queue_events.clear()
                queue_result = 1
                returned = run(callback, registers=[(UC_ARM_REG_R1,ARG),(UC_ARM_REG_R3,QUEUE)])
                assert queue_events == [dict(property=hex(property_id),value=result)]
                assert returned==1 and struct.unpack('<I',u.mem_read(QUEUE+0x110,4))[0]==1
                report['callbacks'].append(dict(kind=kind,address=hex(callback),words=words,
                    queue=list(queue_events),return_value=returned))
            for current, accepted in [(1,1),(0,1),(0,0)]:
                words = [1,1,current,0,0,0]
                u.mem_write(ARG, struct.pack('<6I', *words))
                u.mem_write(QUEUE, bytes(0x120))
                queue_events.clear()
                queue_result = accepted
                returned = run(callback, registers=[(UC_ARM_REG_R1,ARG),(UC_ARM_REG_R3,QUEUE)])
                unchanged = current == 1
                assert queue_events == ([] if unchanged else [dict(property=hex(property_id),value=1)])
                assert returned == (1 if unchanged else accepted)
                assert struct.unpack('<I',u.mem_read(QUEUE+0x110,4))[0] == (0 if unchanged else 1)
                report['callbacks'].append(dict(kind=kind,address=hex(callback),words=words,
                    queue=list(queue_events),queue_stub_return=accepted,return_value=returned))

    for key in ['configurations','packing_checks']:
        assert report['modules'][0][key] == report['modules'][1][key]
    report['paired_module_results_match'] = True
    report['limits'] = [
        'Constructor starts after allocation with synthetic configuration and specified registers/stack; reviewed fields start poisoned, other fields zero.',
        'Register-writer calls are captured, not delivered to hardware; markers are not a firmware patch.',
        'SPS templates are used only by the reviewed settings[66]==1, settings[67] in 7/8/9 branch, not every recording mode.',
        'SPS parsing stops after VUI timing; full SPS conformance and actual produced video were not checked.',
        'Property queue is stubbed; upstream callback arguments, ISP and asynchronous consumers are not modeled.',
        'The meanings of hardware fields 74/78/79 remain inferred; hardware 10-bit support is unresolved.',
    ]
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'work/analysis/video_path.json')
    args = parser.parse_args()
    report = analyze()
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(configuration_cases=sum(len(m['configurations']) for m in report['modules']),
        packing_cases=sum(len(m['packing_checks']) for m in report['modules']),
        sps_templates=len(report['sps_templates']),invalid_sps_selector=1,
        callback_cases=len(report['callbacks'])),indent=2))
