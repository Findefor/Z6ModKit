"""Offline checks of EX region1 peripheral writes; no camera or bus access.

Executes original callback/configuration code. I2C, GPIO and RTOS calls are
explicit recording stubs, not a model of hardware or its power-on reset.
"""
import hashlib
import json
import struct

from ex_inspect import ExFirmware, BASE, ROOT, SHA256
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

FW = ExFirmware()
INITIAL = FW.initial_ram()
STOP, STACK, CONFIG = 0x08010000, 0x2003BFF0, 0x20038010
SHADOW = bytes.fromhex('a52d52e3bc6aff52')
FIRMWARE_SHADOW = bytes.fromhex('0080a000008d3300cd06')


def run(old, new, normalize=0, mismatched_readback=False, seed=SHADOW, reinitialize=False):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, 0x81000)
    cpu.mem_write(BASE, FW.data)
    cpu.mem_protect(BASE, 0x81000, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(0x20000000, 0x40000)
    cpu.mem_write(0x20000000, INITIAL)
    cpu.mem_write(0x2001F737, bytes([old]))
    cpu.mem_write(CONFIG + 0x117, bytes([new]))
    cpu.mem_write(0x2001F59A, seed)
    # Synthetic runtime handles. Their addresses/pins do not identify the board.
    cpu.mem_write(0x2001F5AC, struct.pack('<II', 0x2003A000, 0x2003A020))
    cpu.mem_write(0x2003A008, struct.pack('<II', 0x40020000, 8))
    cpu.mem_write(0x2003A028, struct.pack('<I', 0x40005400))
    events, registers = [], {}

    def ret(value=0):
        cpu.reg_write(UC_ARM_REG_R0, value)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    def hook(_, address, size, data):
        a, b, c, d = [cpu.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        if address in (0x08040520, 0x080404F0, 0x080404C0, 0x08043AE8, 0x08043E3C):
            ret()
        elif address in (0x08040330, 0x08040340, 0x08040554):
            ret(a)  # Resource mapping is outside this initializer check.
        elif address == 0x08021188:
            ret({0x40: 0x2003A000, 0x29: 0x2003A000, 0: 0x2003A020}[a])
        elif address == 0x080438F4:
            events.append({'gpio_configuration_stub': True})
            ret()
        elif address in (0x0802AE98, 0x0802AE48):
            ptr, length = struct.unpack('<II', cpu.mem_read(cpu.reg_read(UC_ARM_REG_SP), 8))
            assert b == 0xD6 and 0 <= c <= 7 and d == 1 and length == 1
            assert 0x20000000 <= ptr < 0x20040000
            if address == 0x0802AE98:
                value = bytes(cpu.mem_read(ptr, 1))[0]
                registers[c] = value
                events.append({'write': c, 'value': value})
            else:
                value = registers[c]
                if mismatched_readback:
                    value ^= 1
                cpu.mem_write(ptr, bytes([value]))
                events.append({'read': c, 'value': value})
            ret()
        elif address == 0x08043ADA:
            events.append({'gpio_stub_level': c})
            ret()
        elif address == 0x08024988:
            events.append({'ram_notification_stub': True})
            ret()
        else:
            assert any(lo <= address < hi for lo, hi in (
                (0x08029418, 0x080294A2), (0x08028CF0, 0x08028D0A),
                (0x08028ED8, 0x08028EFC), (0x0802B218, 0x0802B230),
                (0x0802B170, 0x0802B214),
                (0x0802B234, 0x0802B408), (0x0802B40C, 0x0802B5EA),
                (0x0802B014, 0x0802B126))), hex(address)

    def write_hook(_, access, address, size, value, data):
        assert 0x20000000 <= address and address + size <= 0x20040000

    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    if reinitialize:
        cpu.reg_write(UC_ARM_REG_SP, STACK)
        cpu.reg_write(UC_ARM_REG_LR, STOP | 1)
        cpu.emu_start(0x0802B171, STOP, count=100000)
        assert cpu.reg_read(UC_ARM_REG_PC) == STOP
        assert bytes(cpu.mem_read(0x2001F59A, 10)) == FIRMWARE_SHADOW
    callback_shadow = bytes(cpu.mem_read(0x2001F59A, 8)).hex()
    for register, value in ((UC_ARM_REG_R0, CONFIG), (UC_ARM_REG_R1, normalize),
                            (UC_ARM_REG_SP, STACK), (UC_ARM_REG_LR, STOP | 1)):
        cpu.reg_write(register, value)
    cpu.emu_start(0x08029419, STOP, count=100000)
    assert cpu.reg_read(UC_ARM_REG_PC) == STOP
    assert bytes(cpu.mem_read(BASE, len(FW.data))) == FW.data
    return {'old_field': old, 'new_field': new, 'normalize': normalize,
            'initial_register_shadow': seed.hex(), 'mismatched_readback': mismatched_readback,
            'reinitialized_shadow': reinitialize,
            'callback_register_shadow': callback_shadow,
            'events': events, 'final_register_shadow': bytes(cpu.mem_read(0x2001F59A, 8)).hex(),
            'peripheral_program_status': struct.unpack('<I', cpu.mem_read(0x2000EDA0, 4))[0],
            'flash_unchanged': True}


checks = []
for old, new, normalize in ((0, 0, 0), (0, 5, 0), (5, 0, 0), (5, 5, 0), (0, 5, 1)):
    result = run(old, new, normalize)
    writes = [(e['write'], e['value']) for e in result['events'] if 'write' in e]
    if normalize or (old == 5) == (new == 5):
        assert writes == []
    elif new == 5:
        assert writes == [(0, 0), (1, 0xC0), (2, 0x52), (3, 0xE0),
                          (4, 0), (5, 0x6A), (7, 0xD0), (6, 0xF3)]
    else:
        # The disable-mode builder leaves several descriptor bytes unchanged;
        # this fixture starts them at the original scatter-load zero values.
        assert writes == [(6, 0xF7), (0, 0xA0), (1, 0xC0), (2, 0x52),
                          (3, 0xE0), (4, 0), (5, 0x6A), (7, 0x52)]
    checks.append(result)

fault = run(0, 5, mismatched_readback=True)
# Original helper retries each readback three times, then sends register1=C0.
for register in (0, 1, 3):
    assert len([e for e in fault['events'] if e.get('read') == register]) == 3
assert len([e for e in fault['events'] if e == {'write': 1, 'value': 0xC0}]) == 6
assert fault['peripheral_program_status'] == 1
checks.append(fault)
reset = run(0, 0, reinitialize=True)
assert reset['final_register_shadow'] == '0080a000008d3300'
assert not any('write' in e for e in reset['events'])
checks.append(reset)

# Execute the original initializer before the transition, instead of interpreting
# arbitrary SHADOW test bytes as camera settings. These are still isolated cases:
# the descriptor starts at scatter-load defaults, not a live camera state.
for old, new, expected in (
        (0, 5, [(0, 0), (1, 0xC0), (2, 0xA0), (3, 0),
                (4, 0), (5, 0x8D), (7, 0x80), (6, 0x33)]),
        (5, 0, [(6, 0x33), (0, 0xA0), (1, 0xC0), (2, 0xA0),
                (3, 0), (4, 0), (5, 0x8D), (7, 0)])):
    result = run(old, new, reinitialize=True)
    assert result['callback_register_shadow'] == FIRMWARE_SHADOW[:8].hex()
    assert [(e['write'], e['value']) for e in result['events'] if 'write' in e] == expected
    checks.append(result)


def run_fault_predicate(reg01, reg11):
    """Execute only the original post-read predicate, not a fault or POR model."""
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, 0x81000)
    cpu.mem_write(BASE, FW.data)
    cpu.mem_protect(BASE, 0x81000, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(0x20000000, 0x40000)
    stack, target, marker = 0x2003B000, 0x2003A000, 0x12345678
    cpu.mem_write(stack + 0xC, bytes([reg01]))
    cpu.mem_write(stack + 0x10, bytes([reg11]))
    from unicorn.arm_const import UC_ARM_REG_R5, UC_ARM_REG_R6
    for register, value in ((UC_ARM_REG_SP, stack), (UC_ARM_REG_R5, marker),
                            (UC_ARM_REG_R6, target)):
        cpu.reg_write(register, value)
    writes = []

    def write_hook(_, access, address, size, value, data):
        assert (address, size, value) == (target, 4, marker)
        writes.append(value)

    cpu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    cpu.emu_start(0x0802AFFB, 0x0802AFEC, count=50)
    assert cpu.reg_read(UC_ARM_REG_PC) == 0x0802AFEC
    assert cpu.reg_read(UC_ARM_REG_R0) == 1
    expected = bool((reg01 & 0x80) and (reg11 & 0x08))
    assert writes == ([marker] if expected else [])
    assert bytes(cpu.mem_read(BASE, len(FW.data))) == FW.data
    return {'case': 'post_read_fault_predicate', 'reg01_fixture': reg01,
            'reg11_fixture': reg11, 'predicate_store': expected,
            'flash_unchanged': True,
            'limitations': 'Original 0802AFFA..0802B00C only; synthetic read results and output pointer. No I2C transaction or chip behavior is emulated.'}


checks.extend(run_fault_predicate(reg01, reg11)
              for reg01 in (0, 0x80) for reg11 in (0, 8, 0x10, 0x80))


def run_region6(rate, busy):
    """Original queue endpoint and isolated event2000 worker, modeled TIM2 ARR."""
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, 0x81000)
    cpu.mem_write(BASE, FW.data)
    cpu.mem_protect(BASE, 0x81000, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(0x20000000, 0x40000)
    cpu.mem_write(0x20000000, INITIAL)
    cpu.mem_map(0x40000000, 0x1000)
    cpu.mem_write(0x200187E8, struct.pack('<I', 0x40000000))
    cpu.mem_write(0x200188B4, struct.pack('<I', busy))
    cpu.mem_write(0x4000002C, struct.pack('<I', 0xBADC0FFE))
    payload = bytearray(range(0x42))
    payload[0x3A] = rate
    cpu.mem_write(CONFIG, bytes(payload))
    events, mmio = [], []

    def hook(_, address, size, data):
        a, b, c = [cpu.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if address == 0x080204C8:
            assert c == 0x42 and a in (0x20018964, 0x20018922)
            cpu.mem_write(a, bytes(cpu.mem_read(b, c)))
        elif address == 0x080214FE:
            assert a == 0x200188D8 and b == 0x2000
            events.append(b)
        else:
            assert any(lo <= address < hi for lo, hi in (
                (0x0803C77C, 0x0803C798), (0x0803C5C4, 0x0803C664),
                (0x0803C79C, 0x0803C7B4), (0x08035400, 0x0803542A))), hex(address)
            return
        cpu.reg_write(UC_ARM_REG_R0, 0)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    def writes(_, access, address, size, value, data):
        if address == 0x4000002C:
            assert size == 4
            mmio.append(value)
        else:
            assert 0x20000000 <= address and address + size <= 0x20040000

    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.hook_add(UC_HOOK_MEM_WRITE, writes)
    for function, argument in ((0x0803C77C, CONFIG), (0x0803C5C4, 0x2000)):
        for register, value in ((UC_ARM_REG_R0, argument), (UC_ARM_REG_SP, STACK), (UC_ARM_REG_LR, STOP | 1)):
            cpu.reg_write(register, value)
        cpu.emu_start(function | 1, STOP, count=10000)
        assert cpu.reg_read(UC_ARM_REG_PC) == STOP
    assert events == [0x2000]
    expected = 50_000_000 // (1_000_000 // rate) - 1
    if busy:
        assert mmio == []
        assert struct.unpack('<I', cpu.mem_read(0x200188C0, 4))[0] == 1
    else:
        assert mmio == [expected]
        assert bytes(cpu.mem_read(0x20018922, 0x42)) == bytes(payload)
        assert struct.unpack('<I', cpu.mem_read(0x200187F4, 4))[0] == expected
    assert bytes(cpu.mem_read(BASE, len(FW.data))) == FW.data
    return {'case': 'region6_event2000', 'rate_fixture': rate, 'busy_fixture': busy,
            'event': '0x2000', 'tim2_arr_writes': mmio, 'flash_unchanged': True,
            'limitations': 'Synthetic compact settings and state, modeled MMIO backing. Physical timer frequency and full boot are not emulated.'}


checks.extend(run_region6(rate, busy) for rate, busy in ((50, 0), (60, 0), (50, 1)))

report = {'camera_io': False, 'ex_sha256': SHA256,
          'initial_ram_sha256': hashlib.sha256(INITIAL).hexdigest(),
          'checks': checks,
          'scope': 'Original region1 callback08029418, mode builders, programming routines, write/readback helper and initializer; eight isolated post-read fault predicate cases; original region6 endpoint and isolated event2000 worker with modeled TIM2 ARR.',
          'stubs': ['I2C transfer, synthetic one-byte registers with optional read mismatch',
                    'GPIO set, with synthetic runtime descriptor', 'RTOS lock/time and bus setup',
                    'resource mapping and GPIO setup for initializer', 'downstream RAM notification08024988',
                    'region6 memcpy, event signal, and memory backing for TIM2 ARR'],
          'findings': {
              'condition': 'Only a changed region1 invoking its callback, and transition of field+117 into/out of5, reaches this I2C programming path.',
              'address': 'Driver takes addressD6 on I2C1, corresponding to 7-bit I2C6B. Register-map inference strongly favors TI BQ25882; physical marking and part ID are unverified.',
              'wiring_static': 'Index0 ->0804D998[0]=A0 ->descriptor2000E45C ->I2C1 base40005400, PB8/PB9 AF4. Resource40 ->PE0 input; resource29 ->PC9 output. Pin-to-chip wiring is not established. Driver belongs to BatCmSvc task10010, worker08027E58.',
              'part_discriminator': '0802AFA4 reads01,0802AFD4 reads11. Original predicate0802AFFA..0802B00C requires bit7 of01 and bit3 of11. BQ25882 SLVSE40C REG11[3] is SYS_SHORT_FLAG; BQ25883 SLUSDL3A calls it reserved/zero. This favors82, but shared driver code or an undocumented variant is not excluded.',
              'read_scope_static': 'Five direct calls to0802AE48: 0B,10,01,11 and dynamic readback. The six callers of readback0802B014 use00/01/03. No REG25 part-ID read found in this bounded driver analysis; not proof for all indirect paths in EX.',
              'into5': 'Writes registers0,1,2,3,4,5,7,6; register0=00 and register1=C0. Other values depend on existing register shadow and descriptor fields.',
              'outof5': 'Writes registers6,0,1,2,3,4,5,7; register0=A0 and register1=C0. It also preserves descriptor fields from prior state.',
              'readback': 'Registers0/1/3 are read back; masks FF/3F/1F and upper bounds A0/18/19. Three mismatches trigger a register1=C0 fallback, which can return transport success despite mismatched values.',
              'boot': '08024C70 obtains region1 and calls080294B0 with normalize=1; this invokes08029418 through the normalized branch, skipping service-time peripheral programming. Initializer0802B170, called at08027256 and from bus-error cleanup0802ACD4, rewrites the ten-byte RAM register shadow to0080A000008D3300CD06. It does not itself send these bytes to the chip; complete startup and physical POR remain unverified.',
              'region6': '0803C77C queues0x42 bytes, event2000 ->0803C5C4. If [2001887C+38] is zero,0803C79C copies settings and08035400 writes TIM2 ARR4000002C. Otherwise [+44]=1 defers applying settings. Original ARR arithmetic is floor(50M/floor(1M/rate))-1.',
              'region6_init': 'Resource index2 ->0804DA90[2]=81 ->descriptor2000E4FC ->TIM2 base40000000. 080353C6 copies base into200187E8. Init08035508 ->08035708 ->080353B4 ->080462CC ->080498F8 writes CR1/PSC/ARR/EGR. Static evidence, not full boot emulation.',
              'power_loss': 'TI documents register defaults after true POR for BQ25882/83, powered from BAT or VBUS. Applying that to this board is conditional on chip identity and actual loss of both supplies. 01=C0 is HIZ/ILIM control, not REG_RST. No original flash writes in these emulated routines; no physical POR/recovery test. SPI target remains unidentified.'},
          'datasheet_comparison': {
              'evidence_type': 'Manual comparison to manufacturer documentation, not hardware measurement or emulation of POR',
              'bq25882': {'document': 'SLVSE40C, September 2019', 'url': 'https://www.ti.com/lit/ds/symlink/bq25882.pdf', 'mirror': 'https://www.tij.co.jp/jp/lit/ds/symlink/bq25882.pdf', 'sections': ['8.3.1', '8.4.1', '8.5.1-8.5.8', '8.5.18', '8.5.38']},
              'bq25883': {'document': 'SLUSDL3A, April 2019', 'url': 'https://www.ti.com/lit/ds/symlink/bq25883.pdf', 'sections': ['5', '8.3.1', '8.5.18', '8.5.38']},
              'part_id': 'REG25[6:3]: BQ25882=0010, BQ25883=0011. Not read from a camera.',
              'register_shadow_warning': 'Firmware shadow0080A000008D3300CD06 and arbitrary test seed are not TI POR defaults; initializer changes RAM only.'}}
(ROOT/'work/analysis/ex_peripherals.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
print(json.dumps({'checks': len(checks), 'camera_io': False, 'write_sequences_verified': True}))
