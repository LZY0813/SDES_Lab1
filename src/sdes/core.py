"""整数表示；置换表从最高位起按 1 编号。"""
from functools import lru_cache

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INVERSE = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)
SBOX1 = ((1,0,3,2),(3,2,1,0),(0,2,1,3),(3,1,0,2))
SBOX2 = ((0,1,2,3),(2,3,1,0),(3,0,1,2),(2,1,0,3))

def require_int(value, width):
    if type(value) is not int or not 0 <= value < (1 << width):
        raise ValueError(f"数值必须是 0 到 {(1 << width)-1} 的整数")

def parse_bits(text, width):
    if len(text) != width or any(c not in '01' for c in text):
        raise ValueError(f"请输入恰好 {width} 位二进制，仅允许 0 和 1（不含空格）")
    return int(text, 2)

def permute(value, width, table):
    output = 0
    for position in table:
        output = (output << 1) | ((value >> (width-position)) & 1)
    return output

def rotate5(value, count):
    return ((value << count) | (value >> (5-count))) & 31

@lru_cache(maxsize=1024)
def subkeys(key):
    require_int(key, 10)
    selected = permute(key, 10, P10)
    left, right = selected >> 5, selected & 31
    # 严格按题目 Ki=P8(Shift^i(P10(K)))：两次移位均以 P10 结果为起点。
    first_state = (rotate5(left, 1) << 5) | rotate5(right, 1)
    second_state = (rotate5(left, 2) << 5) | rotate5(right, 2)
    return permute(first_state, 10, P8), permute(second_state, 10, P8)

def sbox(value, table):
    row = ((value >> 2) & 2) | (value & 1)
    column = (value >> 1) & 3
    return table[row][column]

def round_values(block, key):
    left, right = block >> 4, block & 15
    expanded = permute(right, 4, EP)
    mixed = expanded ^ key
    first, second = sbox(mixed >> 4, SBOX1), sbox(mixed & 15, SBOX2)
    joined = (first << 2) | second
    function = permute(joined, 4, P4)
    result = ((left ^ function) << 4) | right
    return {'L':f'{left:04b}', 'R':f'{right:04b}', 'EP':f'{expanded:08b}',
            'XOR':f'{mixed:08b}', 'SBox1':f'{first:02b}', 'SBox2':f'{second:02b}',
            'P4':f'{function:04b}', 'fk':f'{result:08b}'}

def fk(block, key):
    mixed = permute(block & 15, 4, EP) ^ key
    function = permute((sbox(mixed >> 4, SBOX1) << 2) | sbox(mixed & 15, SBOX2), 4, P4)
    return block ^ (function << 4)

def crypt(block, key, decrypt=False):
    require_int(block, 8)
    first, second = subkeys(key)
    if decrypt:
        first, second = second, first
    state = fk(permute(block, 8, IP), first)
    state = ((state & 15) << 4) | (state >> 4)
    return permute(fk(state, second), 8, IP_INVERSE)

def trace(block, key, decrypt=False):
    require_int(block, 8)
    first, second = subkeys(key)
    keys = (second, first) if decrypt else (first, second)
    initial = permute(block, 8, IP)
    round1 = round_values(initial, keys[0])
    state = int(round1['fk'], 2)
    swapped = ((state & 15) << 4) | (state >> 4)
    round2 = round_values(swapped, keys[1])
    return {'K1':f'{first:08b}', 'K2':f'{second:08b}', 'IP':f'{initial:08b}',
            'round1':round1, 'SW':f'{swapped:08b}', 'round2':round2,
            'result':f'{permute(int(round2["fk"],2),8,IP_INVERSE):08b}'}

def encrypt_ascii(text, key):
    subkeys(key)
    try:
        data = text.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError(f'位置 {exc.start+1} 存在非 ASCII 字符') from exc
    return bytes(crypt(byte, key) for byte in data)

def parse_hex(text):
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError('十六进制格式错误：每字节两位，可用空格或换行分隔') from exc

def decrypt_ascii(data, key):
    subkeys(key)
    decoded = bytes(crypt(byte, key, True) for byte in data)
    try:
        return decoded.decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('解密结果包含非 ASCII 字节，请检查密钥或密文') from exc
