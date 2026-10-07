"""完整枚举及统计；计时不包含 GUI 渲染和导出。"""
from collections import Counter, defaultdict
from datetime import datetime
from time import perf_counter_ns
import csv
import json
from pathlib import Path
from .core import crypt, parse_bits, require_int

def parse_pairs(text):
    pairs = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        columns = line.split()
        if len(columns) != 2:
            raise ValueError(f'第 {number} 行应为：8位明文 空格 8位密文')
        pairs.append(tuple(parse_bits(column, 8) for column in columns))
    if not pairs:
        raise ValueError('至少输入一组明密文对')
    return pairs

def brute_force(pairs, progress=lambda value: None):
    if not pairs:
        raise ValueError('至少需要一组明密文对')
    for plain, cipher in pairs:
        require_int(plain, 8)
        require_int(cipher, 8)
    started_at = datetime.now().astimezone().isoformat()
    start = perf_counter_ns()
    candidates = []
    for key in range(1024):
        if all(crypt(plain, key) == cipher for plain, cipher in pairs):
            candidates.append(f'{key:010b}')
        if (key+1) % 32 == 0:
            progress(key+1)
    elapsed_ns = perf_counter_ns()-start
    return {'pairs':[[f'{p:08b}',f'{c:08b}'] for p,c in pairs],
            'candidates':candidates, 'candidate_count':len(candidates),
            'tested_keys':1024, 'elapsed_ns':elapsed_ns, 'elapsed_seconds':elapsed_ns/1e9,
            'started_at':started_at, 'finished_at':datetime.now().astimezone().isoformat()}

def collision_analysis(progress=lambda value: None):
    start = perf_counter_ns()
    mappings = [bytearray() for _ in range(1024)]
    rows, example = [], None
    for plain in range(256):
        groups = defaultdict(list)
        for key in range(1024):
            cipher = crypt(plain, key)
            groups[cipher].append(key)
            mappings[key].append(cipher)
        distribution = Counter(map(len, groups.values()))
        distribution[0] = 256-len(groups)
        rows.append({'plaintext':f'{plain:08b}', 'distinct_ciphertexts':len(groups),
                     'collision_groups':sum(len(keys)>1 for keys in groups.values()),
                     'max_group_size':max(map(len, groups.values())), 'key_total':sum(map(len,groups.values())),
                     'candidate_distribution':dict(sorted(distribution.items()))})
        if example is None:
            cipher, keys = next((c, ks) for c,ks in sorted(groups.items()) if len(ks)>1)
            example = {'plaintext':f'{plain:08b}','ciphertext':f'{cipher:08b}',
                       'keys':[f'{k:010b}' for k in keys]}
        progress((plain+1)*4)
    equivalent = defaultdict(list)
    for key, mapping in enumerate(mappings):
        equivalent[bytes(mapping)].append(f'{key:010b}')
    return {'rows':rows, 'example':example,
            'equivalent_key_groups':[keys for keys in equivalent.values() if len(keys)>1],
            'unique_mappings':len(equivalent), 'encryptions':262144,
            'elapsed_seconds':(perf_counter_ns()-start)/1e9}

def export_analysis(result, path):
    path = Path(path)
    with path.open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(result['rows'][0]))
        writer.writeheader()
        for row in result['rows']:
            writer.writerow({**row,'candidate_distribution':json.dumps(row['candidate_distribution'])})
    path.with_suffix('.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
