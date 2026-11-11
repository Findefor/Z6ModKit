"""Offline fault injection into Z6 II C1.70 service-exit routines.

Runs original Thumb instructions, with explicit RTOS/hardware/cleanup stubs.
Never opens USB or calls the camera client. Not a full-camera emulator.
"""
import json
import struct

from fw_inspect import Firmware, ROOT, BASE, SHA256
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

FW = Firmware()
RAM, CMD, STOP, STACK = 0x20000000, 0x20000100, 0x20002000, 0x2000f000
STATE = 0xc188bc40
u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
u.mem_map(BASE, (len(FW.data)+4095)&~4095)
u.mem_write(BASE, FW.data)
u.mem_map(RAM, 0x10000)
u.mem_map(0xc188b000, 0x2000)
cleanup_stubs = {
    0x104939ca, 0x1049385e, 0x104b7e6a, 0x104942b0, 0x10494468,
    0x10494f5e, 0x104b7adc, 0x104c988e, 0x104b77c0, 0x104b81de,
    0x104b6f6e, 0x104b6e34, 0x104b70ee,
}
events, scenario, mode = [], {}, 1


def ret(value=0):
    u.reg_write(UC_ARM_REG_R0, value)
    u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def hook(cpu, address, size, _):
    r0, r1, r2, r3 = [cpu.reg_read(r) for r in
                      (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
    if address == STOP:
        cpu.emu_stop()
    elif address == 0x1035d2dc:
        assert RAM <= r0 and r0+r1 <= RAM+0x10000
        cpu.mem_write(r0, b'\0'*r1)
        ret()
    elif address in cleanup_stubs:
        events.append({'cleanup_stub': hex(address)})
        ret()
    elif address == 0x103c3114:
        assert r0 == 0x126
        events.append({'native_setting_stub': '0x126', 'value': 0})
        ret()
    elif address == 0x10505a4a:
        assert r0 == 1
        events.append({'preparatory_transition_stub': '0x2001'})
        ret(0x2001)
    elif address == 0x104c3b74:
        assert r0 == 0x80000000
        ret()
    elif address == 0x1038602e:
        assert r0 == mode and r1 == 0x1047c21f
        events.append({'request_accepted': scenario['accepted']})
        ret(scenario['accepted'])
    elif address == 0x104c3bc6:
        assert r0 == 0x80000000 and r2 == 0x7d0
        cpu.mem_write(STATE+0x10, struct.pack('<II', scenario['event'], scenario['result']))
        events.append({'wait_status': scenario['wait_status'], 'timeout_argument': r2,
                       'event': hex(scenario['event']), 'result': scenario['result']})
        ret(scenario['wait_status'])
    elif address == 0x1063f710:
        assert r0 == CMD and r2 == 5
        events.append({'response': hex(r1),
                       'parameters': list(struct.unpack('<5I', cpu.mem_read(r3, 20)))})
        ret(1)
    elif address == 0x1047c376:
        events.append({'original_transition_return': r0})
    else:
        assert (0x1047c238 <= address < 0x1047c278 or
                0x1047c2f0 <= address < 0x1047c3da), hex(address)


u.hook_add(UC_HOOK_CODE, hook)


def run(address, active, mode_arg):
    events.clear()
    u.mem_write(RAM, b'\0'*0x10000)
    u.mem_write(STATE, struct.pack('<6I', active, 0, 0, 0, 0, 0))
    u.reg_write(UC_ARM_REG_SP, STACK)
    u.reg_write(UC_ARM_REG_R0, mode_arg)
    u.reg_write(UC_ARM_REG_R1, CMD)
    u.reg_write(UC_ARM_REG_LR, STOP|1)
    u.emu_start(address|1, STOP, count=2000)
    assert u.reg_read(UC_ARM_REG_PC) == STOP
    return {'return': u.reg_read(UC_ARM_REG_R0),
            'service_flag_after': struct.unpack('<I', u.mem_read(STATE, 4))[0],
            'events': list(events)}


report = {
    'firmware_sha256': SHA256, 'camera_io': False,
    'scope': 'Original exit and transition-wrapper instructions; synthetic RAM and injected backend outcomes',
    'stubs': ['cleanup callees listed individually in traces', 'RTOS event clear/request/wait',
              'native setting 0x126 returns 0', 'preparatory transition returns 0x2001',
              'memclear', 'PTP response transport'],
    'transition_checks': [], 'exit_checks': [],
}
for mode in (0, 1):
    expected_event = 0x03010003+mode
    cases = [
        ('acknowledged', 1, 0, expected_event, 1, 1),
        ('request_rejected', 0, 0, 0, 0, 0),
        ('wait_error_or_timeout', 1, 1, 0, 0, 0),
        ('negative_acknowledgement', 1, 0, expected_event, 0, 0),
        ('wrong_event', 1, 0, expected_event+10, 1, 0),
    ]
    for name, accepted, wait_status, event, result, expected in cases:
        scenario = dict(accepted=accepted, wait_status=wait_status, event=event, result=result)
        check = run(0x1047c238, 1, mode)
        assert check['return'] == expected and check['service_flag_after'] == 1
        report['transition_checks'].append(dict(case=name, mode=mode, **check))
        if mode == 1:
            check = run(0x1047c392, 1, 0)
            response = next(e for e in check['events'] if 'response' in e)
            transition = next(e for e in check['events'] if 'original_transition_return' in e)
            assert transition['original_transition_return'] == expected
            assert check['return'] == 1 and check['service_flag_after'] == 0
            assert response == {'response': '0x2001', 'parameters': [0x2001, 0, 0, 0, 0]}
            report['exit_checks'].append(dict(case=name, **check))
check = run(0x1047c392, 0, 0)
assert check['return'] == 1 and check['service_flag_after'] == 0
assert not any('request_accepted' in e for e in check['events'])
report['exit_checks'].append(dict(case='already_inactive', **check))
assert 0x1047c1dc in FW.branch_refs(0x1047b51e)
assert 0x1047b5ae in FW.branch_refs(0x1047c322)
assert FW.words(0x119f1dc8, 7)[5] == 0x1047c1bd
initial_flag = FW.words(0x123a1c14 + STATE - 0xc1800000, 1)[0]
assert initial_flag == 0
report['findings'] = {
    'exit_result': 'F002 reports outer and nested 0x2001 and clears local service flag even when original transition wrapper returns 0',
    'limitation': 'Injected backend faults do not show that a real camera will fail; cleanup callees may provide other recovery effects and were not emulated',
    'timeout': '0x7d0 is the original wait argument; time unit has not been established',
    'cleanup_callers': [hex(a) for a in FW.branch_refs(0x1047c322)],
    'cleanup_pointer_references': [hex(a) for a in FW.refs(0x1047c323)],
    'close_session': 'PTP 0x1003 table row 0x119f1dc8 -> executor 0x1047c1bc -> call 0x1047c1dc to 0x1047b51e -> state check 0x1047c0d6 -> cleanup call 0x1047b5ae to 0x1047c322; same cleanup as F002, not an independent recovery mechanism',
    'disconnect': 'Other callers in 0x104665a4/0x10466640/0x10466666/0x1046667c reach shared cleanup; exact physical-disconnect event mapping is unresolved',
    'power_cycle': 'Initial RAM flag is zero (verified in scatter-load data); persistent side effects of downstream service transition remain unresolved',
    'retry_after_failed_transition': 'Guard rejects F002 when local service flag is zero; after cleanup clears it, simply retrying F002 is not established as recovery',
}
report['research_sources'] = [
    {'url': 'https://onlinemanual.nikonimglib.com/z7II_z6II/en/14_troubleshooting_01.html',
     'finding': 'Nikon documents battery removal/reinsertion for ordinary troubleshooting, not service-mode recovery'},
    {'url': 'https://www.reddit.com/r/Cameras/comments/13uzilb/nikon_service_menu/',
     'finding': 'D3100 service-menu discussion; no verified Z6 II recovery procedure'},
    {'url': 'https://forum-monitor.net.ru/threads/640354/page-2',
     'finding': 'Developer discusses Tornado EOS and mixed-model Shutter Counter; does not establish Z6 II service recovery'},
    {'url': 'https://nikonhacker.com/',
     'finding': 'At this check, domain displays Virtualmin welcome page rather than the historic forum'},
    {'url': 'https://github.com/simeonpilgrim/nikon-firmware-tools/blob/main/PTP%20Tools/CameraModels/Base.cs',
     'finding': 'Legacy model-specific service implementation; not validation of Z6 II C1.70'},
]
report['research_conclusion'] = 'No reproducible first-hand Z6 II C1.70 service-mode fault recovery was found in the reviewed public sources. Absence of a found report is not proof that recovery is impossible.'
out = ROOT/'work/analysis/service_recovery.json'
out.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
ranges = [(0x1047c238,0x40),(0x1047c278,0x78),(0x1047c2f0,0xea),
          (0x1047b51e,0xc2),(0x1047c1bc,0x3a),(0x1047c0d6,0xe),
          (0x1038602e,0x20),(0x10206e04,0x24)]
(ROOT/'work/analysis/service_recovery_code.txt').write_text(
    '\n\n'.join(FW.listing(a,n) for a,n in ranges)+'\n')
print(json.dumps({'transition_checks':len(report['transition_checks']),
                  'exit_checks':len(report['exit_checks']),
                  'fault_cases_reporting_success':4, 'camera_io':False},indent=2))
