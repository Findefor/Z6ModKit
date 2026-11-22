"""Test exact N-Log forward-table representations in original EG modules."""
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


def knot_tables():
    # Endpoint-inclusive samples at regular intervals in x or sqrt(x).
    # Scaling before rounding tests tables that retain fractional code values.
    for count in (17, 33, 65, 129, 257, 513, 1025):
        for upper in (1, 8):
            for power in (1, 2):
                values = [nlog_code(upper * (i/(count-1))**power) for i in range(count)]
                for scale in (1, 4, 16, 64):
                    for fractional in ((False,) if scale == 1 else (False, True)):
                        codes = ([int(v * scale + .5) for v in values] if fractional
                                 else [int(v + .5) * scale for v in values])
                        yield (count, upper, power, scale, fractional), struct.pack(f'<{count}H', *codes)


def matches(data, table):
    start = 0
    while True:
        offset = data.find(table, start)
        if offset < 0:
            return
        yield offset
        start = offset + 1


def exact_hits(image, tables):
    return [{'representation': params, 'file_offset': hex(offset)}
            for params, table in tables for offset in matches(image, table)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--knots', type=Path, nargs='+', metavar='MODULE',
                        help='Check sparse tables in extracted C1.62 or C1.70 EG master/slave images')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / 'work/analysis/modules.json').read_text())
    package = next(m for m in manifest['images'] if m['name'] == 'Z6_2_0170.bin')
    tables = list(knot_tables() if args.knots else candidate_tables())
    if len(set(data for _, data in tables)) != len(tables):
        raise ValueError('Duplicate test representations')
    # Unaligned positive control and one changed word as a negative control.
    control = tables[0][1]
    if list(matches(b'x' + control, control)) != [1] or list(matches(bytes([control[0] ^ 1]) + control[1:], control)):
        raise ValueError('Search controls failed')
    if args.knots:
        old = json.loads((root / 'work/analysis/version_comparison.json').read_text())
        old_package = next(v for v in old['versions'] if v['file'] == 'Z6_2_0162.bin')
        known = {m['sha256']: m['name'] for p in (old_package, package) for m in p['modules']
                 if m['name'].startswith('eg1850_')}
        for path in args.knots:
            image = path.read_bytes()
            module = known.get(hashlib.sha256(image).hexdigest())
            if module is None:
                raise ValueError('Unexpected C1.62/C1.70 EG image')
            print(json.dumps({'module': module, 'knot_tables': len(tables), 'exact_matches': exact_hits(image, tables)}))
        return
    modules = [m for m in package['modules'] if m['name'].startswith('eg1850_')]
    if len(modules) != 2:
        raise ValueError('Expected C1.70 master and slave')
    for module in modules:
        image = (root / module['path']).read_bytes()
        if hashlib.sha256(image).hexdigest() != module['sha256']:
            raise ValueError('Unexpected image: ' + module['name'])
        print(json.dumps({'module': module['name'], 'tables': len(tables), 'exact_matches': exact_hits(image, tables)}))
    print('10-bit codes, nearest integer (reflectance -> code):',
          {r: int(nlog_code(r) + 0.5) for r in (0, 0.18, 0.9, 1.0)})


if __name__ == '__main__':
    main()
