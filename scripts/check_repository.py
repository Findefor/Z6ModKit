"""Check tracked public files without firmware, camera access, or report writes."""
import argparse
import ast
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def check_files():
    names = subprocess.check_output(
        ['git', 'ls-files', '-z'], cwd=ROOT
    ).decode('utf-8').strip('\0').split('\0')
    tracked = set(names)
    errors = []
    counts = {'python': 0, 'json': 0, 'local_links': 0}
    for name in names:
        path = ROOT / name
        parts = Path(name).parts
        if (path.suffix.lower() in {'.bin', '.exe', '.dmg', '.zip', '.pyc'}
                or path.name == 'key.json' or path.name.startswith(('camera_', '.env'))
                or any(p in {'.venv', '__pycache__', 'inputs'} for p in parts)):
            errors.append(f'{name}: private input or generated file must not be tracked')
            continue
        try:
            source = path.read_text(encoding='utf-8')
            if path.suffix == '.py':
                ast.parse(source, filename=name)
                counts['python'] += 1
            elif path.suffix == '.json':
                json.loads(source)
                counts['json'] += 1
            links = []
            if path.suffix == '.md':
                # Inline Markdown links/images used by the repository documents.
                links = re.findall(r'\]\(([^\s)]+)\)', source)
            elif path.suffix == '.html':
                links = re.findall(r'''(?:src|href)=["']([^"']+)["']''', source)
            for link in links:
                url = urlsplit(link)
                if url.scheme or url.netloc or not url.path:
                    continue
                counts['local_links'] += 1
                target = (path.parent / unquote(url.path)).resolve()
                try:
                    relative = target.relative_to(ROOT).as_posix()
                except ValueError:
                    errors.append(f'{name}: link escapes the repository: {link}')
                    continue
                if relative not in tracked and not any(
                        entry.startswith(relative.rstrip('/') + '/') for entry in tracked):
                    errors.append(f'{name}: link target is not tracked: {link}')
        except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
            errors.append(f'{name}: {exc}')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'Public file checks passed: {len(names)} files, {counts}')


def check_dependencies():
    """Exercise native libraries with synthetic Thumb code, not Nikon firmware."""
    import numpy as np
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
    from unicorn.arm_const import UC_ARM_REG_R0

    code = bytes.fromhex('2a20')  # movs r0, #42
    if np.frombuffer(code, dtype='<u2').tolist() != [0x202a]:
        raise SystemExit('NumPy little-endian decoding failed')
    instructions = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(code, 0x1000))
    if len(instructions) != 1 or instructions[0].mnemonic != 'movs':
        raise SystemExit('Capstone Thumb decoding failed')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0x1000, 0x1000)
    cpu.mem_write(0x1000, code)
    cpu.emu_start(0x1001, 0x1002, count=1)
    if cpu.reg_read(UC_ARM_REG_R0) != 42:
        raise SystemExit('Unicorn Thumb execution failed')
    print('Dependency smoke check passed: NumPy, Capstone, Unicorn')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-dependencies', action='store_true',
                        help='Also exercise the pinned native analysis libraries')
    args = parser.parse_args()
    check_files()
    if args.with_dependencies:
        check_dependencies()
