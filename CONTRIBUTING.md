# Contributing to Z6ModKit

The aim is to make Nikon Z6 II firmware research reproducible and correctable.
Useful contributions include better traces, independently reproduced results,
counterexamples, source-backed hardware identification, and narrower or clearer
claims. A negative result is useful when its conditions are recorded.

Start with the [README](README.md) and [research report](docs/RESEARCH.md).
The published tools are offline analysis tools; this repository does not supply
a camera modification or an established recovery procedure.

## Label the evidence

Use these terms consistently, including when several apply to one finding:

| Tag | Meaning |
| --- | --- |
| `static` | A conclusion from bytes, disassembly, control flow, or an attributable document. Record the exact source and address basis. |
| `emulated` | A result from executing original code in a specified model. List initial state, synthetic inputs, replaced functions, and modeled peripherals. |
| `hardware-reported` | An observation from a physical device, whether your own or a cited third-party report. State who observed it, on which configuration, and what the available evidence actually verifies. |
| `inferred` | An interpretation supported by other evidence but not established directly. Give the reasoning, alternatives, and what would distinguish them. |
| `unverified` | An open claim, proposed behavior, or missing verification step. State what remains unknown. |

An emulator result does not by itself prove physical behavior. A success status
does not prove that all nested operations succeeded. A normal service exit is
not a test of interrupted-session recovery, and a register address alone does
not identify a chip. Keep the direct observation separate from its interpretation.

## Submit a finding or correction

Use the repository's **Research finding** issue template for new evidence and
**Correction or reproducibility issue** for a script failure, unsupported claim,
or contradiction. Link an existing issue when extending the same investigation.
Use [Discussions](https://github.com/Findefor/Z6ModKit/discussions) for conceptual
questions, related work, and collaboration.

Include enough information for another researcher to locate and check the claim:

1. **Provenance:** source URL and pinned revision, document edition/page, or
   original observation. Identify second-hand reports as such.
2. **Target:** exact model and firmware, module name and SHA-256, architecture,
   load base, and whether each address is a file offset or a runtime address.
   Mark unknown fields explicitly rather than guessing.
3. **Method:** repository commit, relevant script/function, environment and
   dependency versions, input conditions, and minimal reproduction commands.
4. **Result:** expected and observed behavior, the smallest relevant sanitized
   output, and an assertion or counterexample where appropriate.
5. **Boundary:** what was stubbed, synthetic, or omitted; alternative explanations;
   and the exact parts that remain unverified.

Existing hardware observations may be submitted with the same distinctions.
Describe what already happened, including any failure or recovery limitation.
No new hardware experiment is required to contribute, and issue discussion is
not an instruction to try service commands on a camera.

## Code and report changes

Run the same public checks as GitHub Actions from the repository root:

```sh
.venv/bin/python -m pip check
.venv/bin/python scripts/check_repository.py --with-dependencies
.venv/bin/python scripts/fw_inspect.py --help
.venv/bin/python scripts/analyze_ptp.py --help
```

See the [quick start](README.md#quick-start) to install dependencies. The file
checker uses Git's tracked-file list, so stage intended new public files with
`git add` before checking them locally. It checks Python syntax, JSON parsing,
local document link destinations, and prohibited input/generated filenames.
The dependency check decodes and executes one synthetic Thumb instruction.
CI does not contain firmware or rerun firmware-dependent research; affected
experiments still need the documented local inputs and report review below.
These checks do not replace reviewing content and attachments for private data.

- Keep changes focused and preserve offline execution. Do not add automatic
  device discovery, USB/PTP access, firmware flashing, or hidden network calls
  to an analysis script.
- Reject unsupported firmware hashes before executing image-derived code.
  Make load addresses and any intentionally synthetic state explicit.
- Document replacements for original functions. A stub returning success is a
  model assumption; do not report the skipped operation as verified.
- Prefer a minimal case that tests the claim, including an error or boundary
  case where it changes the conclusion. Do not inflate coverage by counting
  repeated identical checks.
- Run the affected offline scripts against the documented inputs, inspect the
  resulting report diff, and update the relevant report and interpretation
  together. If inputs are unavailable, state that execution was not performed.
- Keep generated public reports deterministic where practical. Do not commit
  machine-specific absolute paths or private device snapshots.
- Explain in the pull request what changed, why it matters, what ran, and what
  is still unverified. Correct or supersede old claims explicitly instead of
  leaving contradictory statements in different reports.

## What may be shared

Share your analysis, minimal scripts, hashes, addresses, public-source links,
and sanitized observations. Preserve attribution and any upstream notices;
link to third-party source at a pinned revision rather than copying it without
checking its terms.

Do **not** upload firmware packages, complete extracted modules, key tables,
full device/memory/configuration dumps, credentials, or private material.
Remove device serial numbers, owner names, image metadata, usernames, local
paths, and other identifiers from logs and screenshots. Check attachments and
the staged diff as well as visible issue text; `.gitignore` does not protect
an attachment, a pasted log, or an already tracked file.

When source material cannot be shared, provide its hash, provenance, a precise
description of the method, and the smallest non-sensitive result that supports
the claim. State the resulting verification limit.

Original contributions are submitted under the repository's [MIT License](LICENSE).
Only contribute material you have the right to share under those terms; preserve
third-party attribution and license notices.
