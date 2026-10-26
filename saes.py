"""Teaching S-AES, following Stallings, 8th ed., Appendix D.

Blocks and keys are unsigned 16-bit integers. Nibbles are in column order:
0xABCD represents the matrix [[A, C], [B, D]]. This is not production AES.
"""

from functools import lru_cache
from time import perf_counter

S_BOX = (0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7)
INV_S_BOX = (0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
             0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE)


def validate_word(value: int, name: str = '分组或密钥') -> int:
    """Reject coercions, booleans, negative values and silent truncation."""
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise ValueError(f'{name}必须是 0 至 65535 的整数（16 bits）')
    return value


def parse_word(text: str, fmt: str = 'hex') -> int:
    """Accept exactly four hex digits or sixteen binary digits (spaces allowed)."""
    if not isinstance(text, str):
        raise ValueError('输入必须是字符串')
    compact = ''.join(text.split())
    if fmt == 'hex' and len(compact) == 4 and all(c in '0123456789abcdefABCDEF' for c in compact):
        return int(compact, 16)
    if fmt == 'bin' and len(compact) == 16 and all(c in '01' for c in compact):
        return int(compact, 2)
    raise ValueError('请输入恰好 4 位十六进制数或 16 位二进制数，并选择对应格式')


def gf_multiply(left: int, right: int) -> int:
    """Multiply in GF(2^4), modulo x^4 + x + 1 (0b10011)."""
    if type(left) is not int or type(right) is not int or not 0 <= left < 16 or not 0 <= right < 16:
        raise ValueError('有限域操作数必须是 0 至 15 的整数')
    result = 0
    for _ in range(4):
        if right & 1:
            result ^= left
        left <<= 1
        if left & 0x10:
            left ^= 0x13
        right >>= 1
    return result


_MUL = {factor: tuple(gf_multiply(factor, n) for n in range(16)) for factor in (2, 4, 9)}


def substitute(state: int, inverse: bool = False) -> int:
    box = INV_S_BOX if inverse else S_BOX
    return (box[(state >> 12) & 15] << 12 | box[(state >> 8) & 15] << 8
            | box[(state >> 4) & 15] << 4 | box[state & 15])


def shift_rows(state: int) -> int:
    """Swap the second row, so ShiftRows is its own inverse."""
    return (state & 0xF0F0) | ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8)


def mix_columns(state: int, inverse: bool = False) -> int:
    a, b, c, d = state >> 12, (state >> 8) & 15, (state >> 4) & 15, state & 15
    if inverse:
        twice, nine = _MUL[2], _MUL[9]
        return ((nine[a] ^ twice[b]) << 12 | (twice[a] ^ nine[b]) << 8
                | (nine[c] ^ twice[d]) << 4 | (twice[c] ^ nine[d]))
    four = _MUL[4]
    return ((a ^ four[b]) << 12 | (four[a] ^ b) << 8
            | (c ^ four[d]) << 4 | (four[c] ^ d))


@lru_cache(maxsize=65536)
def expand_key(key: int) -> tuple[int, int, int]:
    validate_word(key, '密钥')
    first, second = key >> 8, key & 255
    round_keys = [key]
    for constant in (0x80, 0x30):
        rotated_substituted = (S_BOX[second & 15] << 4) | S_BOX[second >> 4]
        first ^= constant ^ rotated_substituted
        second ^= first
        round_keys.append((first << 8) | second)
    return tuple(round_keys)


def encrypt_block(plaintext: int, key: int) -> int:
    validate_word(plaintext, '明文')
    validate_word(key, '密钥')
    key0, key1, key2 = expand_key(key)
    state = mix_columns(shift_rows(substitute(plaintext ^ key0))) ^ key1
    return shift_rows(substitute(state)) ^ key2


def decrypt_block(ciphertext: int, key: int) -> int:
    validate_word(ciphertext, '密文')
    validate_word(key, '密钥')
    key0, key1, key2 = expand_key(key)
    state = substitute(shift_rows(ciphertext ^ key2), inverse=True) ^ key1
    return substitute(shift_rows(mix_columns(state, inverse=True)), inverse=True) ^ key0


def trace_block(value: int, key: int, decrypt: bool = False) -> list[dict]:
    """Return every round state, in the actual order of computation."""
    validate_word(value)
    validate_word(key, '密钥')
    key0, key1, key2 = expand_key(key)
    steps = [('输入', value)]
    if decrypt:
        operations = [('轮密钥加 K₂', lambda x: x ^ key2), ('逆行移位', shift_rows),
                      ('逆半字节替代', lambda x: substitute(x, True)),
                      ('轮密钥加 K₁', lambda x: x ^ key1),
                      ('逆列混淆', lambda x: mix_columns(x, True)),
                      ('逆行移位', shift_rows), ('逆半字节替代', lambda x: substitute(x, True)),
                      ('轮密钥加 K₀', lambda x: x ^ key0)]
    else:
        operations = [('轮密钥加 K₀', lambda x: x ^ key0), ('半字节替代', substitute),
                      ('行移位', shift_rows), ('列混淆', mix_columns),
                      ('轮密钥加 K₁', lambda x: x ^ key1), ('半字节替代', substitute),
                      ('行移位', shift_rows), ('轮密钥加 K₂', lambda x: x ^ key2)]
    for label, operation in operations:
        value = operation(value)
        steps.append((label, value))
    return [{'step': label, 'value': f'{value:04X}', 'binary': f'{value:016b}',
             'matrix': [[f'{value >> 12:X}', f'{(value >> 4) & 15:X}'],
                        [f'{(value >> 8) & 15:X}', f'{value & 15:X}']]} for label, value in steps]


def double_encrypt(plaintext: int, key1: int, key2: int) -> int:
    return encrypt_block(encrypt_block(plaintext, key1), key2)


def double_decrypt(ciphertext: int, key1: int, key2: int) -> int:
    return decrypt_block(decrypt_block(ciphertext, key2), key1)


def triple_encrypt(plaintext: int, key1: int, key2: int, key3: int | None = None) -> int:
    """EDE: E(K3, D(K2, E(K1, P))); 32-bit mode uses K3 = K1."""
    return encrypt_block(decrypt_block(encrypt_block(plaintext, key1), key2), key1 if key3 is None else key3)


def triple_decrypt(ciphertext: int, key1: int, key2: int, key3: int | None = None) -> int:
    return decrypt_block(encrypt_block(decrypt_block(ciphertext, key1 if key3 is None else key3), key2), key1)


def meet_in_the_middle(pairs: list[tuple[int, int]]) -> dict:
    """Search ALL 2^16 keys on each side, retaining every middle collision.

    One known pair rarely identifies a unique 32-bit key. All supplied pairs
    filter candidates; return all survivors rather than claiming the first is true.
    """
    if not isinstance(pairs, (list, tuple)) or not 1 <= len(pairs) <= 8:
        raise ValueError('请提供 1 至 8 组明密文对')
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError('每组必须包含一个明文和一个密文')
        for value in pair:
            validate_word(value, '明密文')
    start = perf_counter()
    plaintext, ciphertext = pairs[0]
    middle_table: dict[int, list[int]] = {}
    for key1 in range(65536):
        middle_table.setdefault(encrypt_block(plaintext, key1), []).append(key1)
    keys, matches = [], 0
    for key2 in range(65536):
        for key1 in middle_table.get(decrypt_block(ciphertext, key2), ()):
            matches += 1
            if all(double_encrypt(p, key1, key2) == c for p, c in pairs[1:]):
                keys.append((key1, key2))
    return {'keys': keys, 'searched_per_side': 65536, 'first_pair_matches': matches,
            'middle_values': len(middle_table), 'elapsed_seconds': round(perf_counter() - start, 4)}


def pad_bytes(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise ValueError('消息必须为 bytes')
    count = 2 - len(data) % 2
    return data + bytes([count]) * count


def unpad_bytes(data: bytes) -> bytes:
    if not data or len(data) % 2 or data[-1] not in (1, 2) or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError('PKCS#7 填充无效，请检查密钥、IV 或密文是否被修改')
    return data[:-data[-1]]


def _blocks(data: bytes) -> list[int]:
    if not isinstance(data, bytes) or not data or len(data) % 2:
        raise ValueError('密文必须是非空且长度为 2 字节整数倍的 bytes')
    return [int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2)]


def encrypt_bytes(data: bytes, key: int) -> bytes:
    validate_word(key, '密钥')
    return b''.join(encrypt_block(block, key).to_bytes(2, 'big') for block in _blocks(pad_bytes(data)))


def decrypt_bytes(data: bytes, key: int) -> bytes:
    validate_word(key, '密钥')
    return unpad_bytes(b''.join(decrypt_block(block, key).to_bytes(2, 'big') for block in _blocks(data)))


def cbc_encrypt(data: bytes, key: int, iv: int) -> bytes:
    validate_word(key, '密钥')
    previous = validate_word(iv, 'IV')
    output = bytearray()
    for block in _blocks(pad_bytes(data)):
        previous = encrypt_block(block ^ previous, key)
        output.extend(previous.to_bytes(2, 'big'))
    return bytes(output)


def cbc_decrypt(data: bytes, key: int, iv: int, *, unpad: bool = True) -> bytes:
    validate_word(key, '密钥')
    previous = validate_word(iv, 'IV')
    output = bytearray()
    for block in _blocks(data):
        output.extend((decrypt_block(block, key) ^ previous).to_bytes(2, 'big'))
        previous = block
    return unpad_bytes(bytes(output)) if unpad else bytes(output)
