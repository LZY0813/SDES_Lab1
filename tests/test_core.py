import pytest
from sdes.core import (IP, IP_INVERSE, P10, P8, P4, EP, SBOX1, SBOX2,
    permute, sbox, subkeys, trace, crypt, parse_bits, encrypt_ascii, decrypt_ascii, parse_hex)
from sdes.analysis import brute_force, parse_pairs

def test_independently_derived_vector():
    expected = {
        'K1':'10100100', 'K2':'10010010', 'IP':'11011101',
        'round1':{'L':'1101','R':'1101','EP':'11101011','XOR':'01001111',
                  'SBox1':'11','SBox2':'11','P4':'1111','fk':'00101101'},
        'SW':'11010010',
        'round2':{'L':'1101','R':'0010','EP':'00010100','XOR':'10000110',
                  'SBox1':'00','SBox2':'11','P4':'0110','fk':'10110010'},
        'result':'11101000'}
    assert trace(0b11010111,0b1010000010)==expected
    assert crypt(0b11101000,0b1010000010,True)==0b11010111

def test_permutations():
    for byte in range(256):
        assert permute(permute(byte,8,IP),8,IP_INVERSE)==byte
        assert permute(permute(byte,8,IP_INVERSE),8,IP)==byte
    for width,table in [(10,P10),(10,P8),(8,IP),(8,IP_INVERSE),(4,EP),(4,P4)]:
        for bit in range(width):
            text=f'{1<<bit:0{width}b}'
            expected=int(''.join(text[position-1] for position in table),2)
            assert permute(1<<bit,width,table)==expected

def test_sbox_indices_and_modified_table():
    assert SBOX2==((0,1,2,3),(2,3,1,0),(3,0,1,2),(2,1,0,3))
    assert sbox(0b0100,SBOX2)==2
    assert sbox(0b1001,SBOX2)==2
    assert sbox(0b1110,SBOX2)==2
    for value in range(16):
        b=f'{value:04b}'
        for table in (SBOX1,SBOX2):
            assert sbox(value,table)==table[int(b[0]+b[3],2)][int(b[1:3],2)]

def test_assignment_key_schedule():
    assert subkeys(0b1010000010)==(0b10100100,0b10010010)
    assert subkeys(0)==(0,0)
    assert subkeys(1023)==(255,255)

def test_exhaustive_roundtrip():
    for key in range(1024):
        ciphertexts = [crypt(plain,key) for plain in range(256)]
        assert len(set(ciphertexts))==256
        for plain,cipher in enumerate(ciphertexts):
            assert crypt(cipher,key,True)==plain

@pytest.mark.parametrize('text,width',[('',8),('0000000',8),('000000000',8),('00000002',8),
    (' 0000000',8),('0000000\n',8),('００００００００',8),('000000000',10)])
def test_invalid_bits(text,width):
    with pytest.raises(ValueError): parse_bits(text,width)

def test_leading_zeros():
    assert parse_bits('00000001',8)==1
    assert len(trace(0,0)['result'])==8

@pytest.mark.parametrize('value',[-1,256,True,1.5])
def test_invalid_blocks(value):
    with pytest.raises(ValueError): crypt(value,0)

@pytest.mark.parametrize('value',[-1,1024,True,1.5])
def test_invalid_keys(value):
    with pytest.raises(ValueError): crypt(0,value)

@pytest.mark.parametrize('text',['',' ','Hello, S-DES!','a\nb\r\n\t', ''.join(map(chr,range(128)))])
def test_ascii_roundtrip(text):
    raw=encrypt_ascii(text,642)
    assert parse_hex(raw.hex(' '))==raw
    assert decrypt_ascii(raw,642)==text

def test_ascii_and_hex_validation():
    with pytest.raises(ValueError): encrypt_ascii('中文',0)
    for text in ('0','zz','0x12','0 1'):
        with pytest.raises(ValueError): parse_hex(text)
    with pytest.raises(ValueError): decrypt_ascii(bytes([crypt(200,0)]),0)
    with pytest.raises(ValueError): encrypt_ascii('',1024)

def test_all_candidates_and_filtering():
    key=642
    pairs=[(p,crypt(p,key)) for p in (215,0,1,2,3,4)]
    previous=set(f'{k:010b}' for k in range(1024))
    for count in range(1,len(pairs)+1):
        selected=pairs[:count]
        result=brute_force(selected)
        expected={f'{k:010b}' for k in range(1024) if all(crypt(p,k)==c for p,c in selected)}
        actual=set(result['candidates'])
        assert actual==expected and actual<=previous and f'{key:010b}' in actual
        assert result['tested_keys']==1024 and result['elapsed_ns']>0
        previous=actual
    assert brute_force([(0,0),(0,1)])['candidates']==[]
    assert parse_pairs('00000000 00000000\n\n')==[(0,0)]
    for text in ('','00000000','00000000 0000000x'):
        with pytest.raises(ValueError): parse_pairs(text)
    with pytest.raises(ValueError): brute_force([])
