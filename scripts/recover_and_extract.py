"""Offline recovery only; requires valid CRCs and known table fingerprints.

Uses WonderLantern's reviewed primitives. Missing padding observations are
inferred from zero/FF byte-frequency pairs, then checked against independent
published table fingerprints and every input image's CRCs. Never writes inputs.
"""
import binascii
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'work/vendor/key'))
import extract_key as keytool
import decrypt_firmware as fw
import numpy as np

inputs = ROOT / 'work/inputs'
out = ROOT / 'work/analysis'
out.mkdir(exist_ok=True)
images = keytool.load_images(str(inputs))
norms = {keytool.recover_family(x[2]) for x in images}
assert len(norms) == 1 and None not in norms
t1, _ = keytool.fix_constant(images[0][2], next(iter(norms)))
assert t1 is not None
obs = keytool.collect_observations(images, t1)
t2d, t3d = keytool.solve_tables(obs)
assert len(t2d) == 256
missing = [i for i in range(256) if i not in t3d]
print('Padding coverage:', 256 - len(missing), '/ 256; frequency-inferred indices:', missing, flush=True)
t2 = np.array([t2d[i] for i in range(256)], dtype=np.uint8)
t3 = np.array([t3d.get(i, 0) for i in range(256)], dtype=np.uint8)
corrections = keytool.correct_t3(images, t1, t2, t3)
tables = {'T1': t1.tobytes(), 'T2': t2.tobytes(), 'T3': t3.tobytes()}
hashes = {k: hashlib.sha256(v).hexdigest() for k, v in tables.items()}
for k, digest in hashes.items():
    assert digest.startswith(keytool.EXPECTED_SHA[k]), (k, digest)
assert keytool.validate(str(inputs), images, t1, t2, t3)
key = {k: v.hex() for k, v in tables.items()}
key.update(self_check=hashes, sources=[{'file': n, 'sha256': s} for n, s, _ in images],
           padding_covered=256-len(missing), frequency_inferred_indices=missing,
           validation='All input module CRCs and package CRCs pass; published table fingerprints match')
(out / 'key.json').write_text(json.dumps(key, indent=2) + '\n')
manifest = {'keys_validated': True, 'images': []}
for name in ['Z6_2_0170.bin', 'Z_30_0120.bin']:
    raw = (inputs / name).read_bytes()
    dec = fw.decrypt(raw, t1, t2, t3)
    mods = fw.validate_firmware(dec[32:])
    dest = out / pathlib.Path(name).stem
    dest.mkdir(exist_ok=True)
    image = {'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'modules': []}
    for modname, offset, size in mods:
        data = dec[32+offset:32+offset+size]
        path = dest / (modname + '.bin' if not modname.lower().endswith('.bin') else modname)
        path.write_bytes(data)
        image['modules'].append({'name': modname, 'file_offset': offset+32, 'size': size,
                                 'sha256': hashlib.sha256(data).hexdigest(),
                                 'crc16_residue': binascii.crc_hqx(data, 0),
                                 'path': str(path.relative_to(ROOT))})
    manifest['images'].append(image)
    print(json.dumps(image), flush=True)
(out / 'modules.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('Extracted validated modules; no modified firmware created.', flush=True)
