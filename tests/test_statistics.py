from sdes.analysis import collision_analysis, export_analysis
from sdes.core import crypt
import csv

def test_complete_collision_statistics(tmp_path):
    result=collision_analysis()
    assert result['encryptions']==262144
    assert len(result['rows'])==256
    for row in result['rows']:
        distribution=row['candidate_distribution']
        assert row['key_total']==1024
        assert sum(distribution.values())==256
        assert sum(size*count for size,count in distribution.items())==1024
        assert row['collision_groups']>0
        assert row['distinct_ciphertexts']==256-distribution[0]
    example=result['example']
    assert len(example['keys'])>1
    assert all(crypt(int(example['plaintext'],2),int(k,2))==int(example['ciphertext'],2) for k in example['keys'])
    signatures={}
    for key in range(1024):
        signature=bytes(crypt(p,key) for p in range(256))
        signatures.setdefault(signature,[]).append(f'{key:010b}')
    assert result['unique_mappings']==len(signatures)
    assert result['equivalent_key_groups']==[g for g in signatures.values() if len(g)>1]
    export_analysis(result,tmp_path/'statistics.csv')
    with (tmp_path/'statistics.csv').open(encoding='utf-8-sig') as stream:
        assert len(list(csv.DictReader(stream)))==256
