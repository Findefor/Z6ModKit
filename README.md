# Z6ModKit

Offline research into Nikon Z6 II C1.70 firmware, internal video parameters,
the service protocol, and the limits of service-session recovery.

**Internal 10-bit N-Log recording has not been demonstrated. This repository
does not contain an installable patch or a validated recovery procedure.**
It publishes analysis scripts, reproducible experiments, and their results so
other researchers can inspect the evidence and extend or correct it.

По-русски: это открытое офлайн-исследование Nikon Z6 II. Возможность записи
N-Log 10 бит на карту пока не доказана; готовой модификации здесь нет.

- [Detailed research report](docs/RESEARCH.md): methods, addresses, findings,
  limitations, and open questions.
- [Contributing](CONTRIBUTING.md): how to reproduce results and submit evidence.
- [Recorded results](work/analysis): JSON reports and source-image hashes.

## What the evidence currently shows

| Area | Finding and verification boundary |
| --- | --- |
| 4K 24/25/30p bitrate | Matching master/slave tables contain stock maximum/average values of 144/120 Mbps. A 156/140 Mbps candidate was examined in the firmware model; physical encoding, recording reliability, and image quality remain untested. |
| H.264 level selection | At a maximum bitrate of 160 Mbps or above, the examined code selects a parameter corresponding to Level 6.1. Copying the Z30's 200/168 Mbps settings is therefore not a validated Z6 II modification. |
| Service exit, `F002` | An outer success response can coexist with a failed lower-level transition. The response alone does not establish recovery. |
| Configuration read, `F02D` | The analyzed path transfers a copy with two bytes masked and has nested error paths. Its output is not a complete recovery image. |
| EX service receiver | Entry refreshes differing eligible configuration regions from flash into working RAM and invokes callbacks. The examined exit handler formats an acknowledgment without performing that refresh. A pending master callback can reject another transition until a reply arrives. |
| Region1 peripheral callback | A transition of field `+0x117` into or out of value `5` programs I²C1 address `0x6B`. Register layout and a distinguishing fault-bit test strongly favor the TI BQ25882 charger. TI documents reset on genuine POR; physical part identity and board-level loss of both BAT/VBUS supplies remain unverified. |
| Region3 peripheral path | Static tracing identifies SPI2 commands `04/0F/10/1C/1D/1E` and software reinitialization. A top-display interpretation is an inference, not an established device identification. |
| Region6 timing path | Isolated execution of the original event worker confirms immediate or deferred settings application and a write to TIM2's auto-reload register. Static tracing finds timer reinitialization. Complete boot and physical recovery remain untested. |

The scripts execute **narrow paths of original ARM/Thumb code in Unicorn**, with
explicit replacements for selected dependencies. They do not emulate an entire
camera, its sensors, external chips, power domains, or USB transport. Stubbed
callbacks and synthetic inputs are identified in the reports. No camera I/O is
performed by the published scripts.

The current recorded coverage is 264 bitrate checks, 16 service-exit checks,
18 configuration-access/serialization checks, 14 EX service checks, and
20 EX peripheral checks (9 region1, 8 charger fault-predicate, 3 region6). These counts describe the
included cases, not hardware validation or exhaustive coverage. Region3's
peripheral findings are static analysis.

**Service entry is not established to be free of hardware side effects.**
Neither successful replies nor the absence of flash writes in selected paths
proves that a complete session is harmless. Recovery after a broken transfer,
loss of power, or battery removal has not been established on a physical board.

## Reproduce the offline experiments

The recorded environment is macOS arm64, Python 3.9, and the pinned packages in
[`requirements.txt`](requirements.txt). Other environments have not been
validated here. Run commands from the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

You must supply your own lawfully obtained firmware. Firmware packages,
extracted modules, key tables, device dumps, live USB/PTP clients, and private
research notes are not distributed in this repository.

For the main C1.70 experiments, place the original extracted modules at:

```text
work/analysis/Z6_2_0170/eg1850_mas_01700.bin
work/analysis/Z6_2_0170/eg1850_sla_01700.bin
work/analysis/Z6_2_0170/ex1850_012000.bi.bin
```

Compare their SHA-256 hashes with [`modules.json`](work/analysis/modules.json).
The master/EX inspectors reject unexpected images. Addresses in the reports
refer to these exact modules and their stated load addresses; do not carry
them over to another model or firmware version without re-establishing them.

```sh
.venv/bin/python scripts/analyze_bitrate.py
.venv/bin/python scripts/analyze_service_recovery.py
.venv/bin/python scripts/analyze_config_read.py
.venv/bin/python scripts/analyze_ex_service.py
.venv/bin/python scripts/analyze_ex_peripherals.py
.venv/bin/python scripts/analyze_ptp.py
```

Inspect the resulting JSON files under `work/analysis`, including their scope,
stub lists, inputs, and assertions. These commands regenerate report files;
successful execution means the modeled checks passed, not that a camera was
modified or tested. The protocol analysis can run without the optional private
device snapshot; no live device connection is needed.

### Optional extraction and version comparison

[`scripts/recover_and_extract.py`](scripts/recover_and_extract.py) expects
`work/inputs/Z6_2_0170.bin` and `work/inputs/Z_30_0120.bin`. It also requires
`extract_key.py` and `decrypt_firmware.py` from the pinned
[WonderLantern key-tool revision](https://github.com/WonderLantern/nikon-fw-key-tool/tree/33426e892afd329a3b366b73776bcf53b9ac4ee8),
placed in `work/vendor/key/`. Source paths and hashes are recorded in
[`work/vendor/sources.json`](work/vendor/sources.json).

```sh
.venv/bin/python scripts/recover_and_extract.py
```

This helper validates input package/module CRCs and table fingerprints, writes
local extracted modules and a private `work/analysis/key.json`, and regenerates
the public module manifest. It does not write a modified firmware image.

[`scripts/compare_versions.py`](scripts/compare_versions.py) additionally needs
that local key file and the following locally obtained version library:

```text
Библиотека старых прошивок/F-Z6II-V102W.exe
Библиотека старых прошивок/F-Z6II-V110W.exe
Библиотека старых прошивок/F-Z6II-V160W.exe
Библиотека старых прошивок/Z6_2_0162.bin
work/inputs/Z6_2_0170.bin
```

```sh
.venv/bin/python scripts/compare_versions.py
```

The comparison reads EXE archives as data through `tar`; it does not execute
them. Archive support depends on the local `tar` implementation. Firmware,
keys, and extracted binaries remain local and are excluded from version control.

## Research directions and contributions

Useful next work includes confirming the BQ25882 inference at I²C `0x6B`
from Z6 II board markings, documenting reset and power-domain wiring from
attributable repair/parts sources, checking callback
dependencies beyond the isolated paths, and tracing the ISP-to-internal-encoder
path for bit depth and N-Log handling. The current evidence does not establish
whether internal 10-bit N-Log is technically achievable.

Submit a [research finding](https://github.com/Findefor/Z6ModKit/issues/new?template=research-finding.yml)
or a [correction / reproducibility issue](https://github.com/Findefor/Z6ModKit/issues/new?template=correction.yml)
with the exact image hash, address basis, evidence type, and verification
boundaries. Use [Discussions](https://github.com/Findefor/Z6ModKit/discussions)
for conceptual questions, related projects, and collaboration.
See [CONTRIBUTING.md](CONTRIBUTING.md) before sharing files or traces.

## Sources

- [Nikon Z6 II downloads and manuals](https://downloadcenter.nikonimglib.com/en/products/556/Z_6II.html).
- [WonderLantern key tool, pinned revision](https://github.com/WonderLantern/nikon-fw-key-tool/tree/33426e892afd329a3b366b73776bcf53b9ac4ee8).
- [WonderLantern Z30, pinned revision](https://github.com/WonderLantern/wonder-lantern-z30/tree/b602735fbcdc47eec6300f0422b30a68110fc237).
- [NikonUnlock PR #1](https://github.com/summershrimp/NikonUnlock/pull/1): an external report of a normal service cycle does not test interrupted-session recovery.
- [Z6 II QEMU research, pinned revision](https://github.com/Fly-beep-256/z62_qemu/tree/1a79b9dbdc7bef89f942baf0335b80cb6ba47e71).
- [ST RM0402](https://www.st.com/resource/en/reference_manual/rm0402-stm32f412-advanced-armbased-32bit-mcus-stmicroelectronics.pdf): MCU reset behavior does not establish reset behavior of unidentified external Nikon peripherals.
- [TI BQ25882](https://www.ti.com/lit/ds/symlink/bq25882.pdf) and [BQ25883](https://www.ti.com/lit/ds/symlink/bq25883.pdf): register fingerprint, distinguishing fault bit, and conditions for charger POR; see the detailed report for the inference boundary.

See the [detailed report](docs/RESEARCH.md) for source-specific reasoning and
remaining gaps. This is independent research and is not affiliated with Nikon.
