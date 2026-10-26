"""Reproduce the five-stage evidence bundle without third-party dependencies."""

import io
import json
import platform
import unittest
from datetime import datetime
from pathlib import Path
from time import perf_counter

from app import dispatch
from saes import double_encrypt, meet_in_the_middle

ROOT = Path(__file__).resolve().parent


def main() -> int:
    output = ROOT / 'artifacts'
    output.mkdir(exist_ok=True)
    log = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), top_level_dir=str(ROOT))
    start = perf_counter()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    (output / 'unittest.txt').write_text(log.getvalue(), encoding='utf8')
    if not result.wasSuccessful():
        print(log.getvalue())
        return 1
    basic = dispatch('/api/block', {'action':'encrypt', 'data':'D728', 'key':'4AF5'})
    vectors = json.loads((ROOT / 'static/vectors.json').read_text())
    cross = dispatch('/api/cross', {'vectors':vectors})
    text = dispatch('/api/text', {'action':'encrypt', 'data':'Hello S-AES!', 'key':'2D55'})
    text_restore = dispatch('/api/text', {'action':'decrypt', 'data':text['hex'], 'key':'2D55'})
    modes = {}
    for mode, key in [('double','F123FE98'), ('triple32','F123FE98'), ('triple48','F123FE985678')]:
        cipher = dispatch('/api/multiple', {'action':'encrypt', 'mode':mode, 'key':key, 'data':'D728'})
        restored = dispatch('/api/multiple', {'action':'decrypt', 'mode':mode, 'key':key, 'data':cipher['hex']})
        modes[mode] = {'key':key, 'plaintext':'D728', 'ciphertext':cipher['hex'], 'restored':restored['hex']}
    pairs = [(p, double_encrypt(p, 0xF123, 0xFE98)) for p in (0xD728, 0x1234, 0xFFFF)]
    ambiguous = meet_in_the_middle(pairs[:1])
    recovered = meet_in_the_middle(pairs)
    attack = {'known_pairs':[{'plaintext':f'{p:04X}', 'ciphertext':f'{c:04X}'} for p,c in pairs],
              'one_pair_candidates':len(ambiguous['keys']), 'searched_per_side':recovered['searched_per_side'],
              'first_pair_matches':recovered['first_pair_matches'], 'three_pair_candidates':len(recovered['keys']),
              'recovered_keys':[f'{a:04X}{b:04X}' for a,b in recovered['keys']],
              'elapsed_seconds':recovered['elapsed_seconds']}
    cbc = dispatch('/api/cbc', {'action':'encrypt', 'data':'ABCDEFGH', 'key':'2D55', 'iv':'1234'})
    tamper = dispatch('/api/tamper', {'data':cbc['hex'], 'key':'2D55', 'iv':'1234',
                                    'index':0, 'operation':'xor', 'change':'0001'})
    replace = dispatch('/api/tamper', {'data':cbc['hex'], 'key':'2D55', 'iv':'1234',
                                     'index':0, 'operation':'replace', 'change':'0000'})
    evidence = {'generated_at':datetime.now().astimezone().isoformat(), 'python':platform.python_version(),
                'platform':platform.platform(), 'tests':result.testsRun, 'failures':len(result.failures),
                'errors':len(result.errors), 'elapsed_seconds':round(perf_counter()-start,4),
                'basic':basic, 'cross':cross, 'text':{'encrypted':text, 'restored':text_restore['text']},
                'multiple':modes, 'mitm':attack,
                'cbc':{'plaintext':'ABCDEFGH', 'key':'2D55', 'iv':'1234', 'ciphertext':cbc['hex'],
                       'bit_flip':tamper, 'replacement':replace},
                'limits':{'inter_group_testing':'Awaiting an independent student group; no group result claimed.',
                          'remote_submission':'Not published or submitted by this script.'}}
    (output / 'verification.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    print(f'{result.testsRun} tests passed. Evidence: artifacts/verification.json; log: artifacts/unittest.txt')
    print(json.dumps({'multiple':modes,'mitm':attack,'cbc_cipher':cbc['hex'],'cbc_blocks':tamper['blocks']},ensure_ascii=False,indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
