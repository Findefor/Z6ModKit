"""Look for exact, uniformly sampled N-Log forward tables in stock C1.70."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct


def nlog_code(reflectance):
    if reflectance < 0.328:
        return 650 * (reflectance + 0.0075) ** (1 / 3)
    return 150 * math.log(reflectance) + 619


def candidate_tables():
    for count in (256, 1024, 4096):
        for upper in (1, 8):
            for denominator in (count - 1, count):
                values = [nlog_code(upper * i / denominator) for i in range(count)]
                for rounding, quantize in [('nearest', lambda x: int(x + 0.5)), ('floor', int)]:
                    codes = [quantize(v) for v in values]
                    for shift in (0, 6):
                        data = struct.pack(f'<{count}H', *(v << shift for v in codes))
                        yield (count, upper, denominator, rounding, shift), data


def matches(data, table):
    start = 0
    while True:
        offset = data.find(table, start)
        if offset < 0:
            return
        yield offset
        start = offset + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / 'work/analysis/modules.json').read_text())
    package = next(m for m in manifest['images'] if m['name'] == 'Z6_2_0170.bin')
    tables = list(candidate_tables())
    if len(set(data for _, data in tables)) != len(tables):
        raise ValueError('Duplicate test representations')
    # Unaligned positive control and one changed word as a negative control.
    control = tables[0][1]
    if list(matches(b'x' + control, control)) != [1] or list(matches(bytes([control[0] ^ 1]) + control[1:], control)):
        raise ValueError('Search controls failed')
    modules = [m for m in package['modules'] if m['name'].startswith('eg1850_')]
    if len(modules) != 2:
        raise ValueError('Expected C1.70 master and slave')
    for module in modules:
        image = (root / module['path']).read_bytes()
        if hashlib.sha256(image).hexdigest() != module['sha256']:
            raise ValueError('Unexpected image: ' + module['name'])
        hits = [{'representation': params, 'file_offset': hex(offset)}
                for params, table in tables for offset in matches(image, table)]
        print(json.dumps({'module': module['name'], 'tables': len(tables), 'exact_matches': hits}))
    print('10-bit codes, nearest integer (reflectance -> code):',
          {r: int(nlog_code(r) + 0.5) for r in (0, 0.18, 0.9, 1.0)})


if __name__ == '__main__':
    main()
