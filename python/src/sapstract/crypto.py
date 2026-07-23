"""Cryptographic primitives used by sapstract for legacy SAP RSEC/SSFS.

This module intentionally has no third-party dependencies.  DES tables below
are the standard FIPS 46-3 permutations and substitution boxes.  The RSEC
composition and tail handling are retained only for byte-for-byte SAP format
compatibility; they are not suitable for new protocol design.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Iterable, Sequence

BLOCK_SIZE = 8
RSEC_KEY_SIZE = 24
AES_BLOCK_SIZE = 16
AES128_KEY_SIZE = 16

# Runtime values recovered from the supplied SAP 753 rsecssfx implementation.
# A zero key passed to RSecPEncrypt/Decrypt selects DEFAULT_DATA_KEY internally.
DEFAULT_DATA_KEY = bytes.fromhex(
    "b1e09244ec19eb3401dfc846ab225820c71bc376581eb3e4"
)
DEFAULT_KEY_ENCRYPTION_KEY = bytes.fromhex(
    "9f60a6dd7e157d070cc357909aa290e9360eee472fda4772"
)
RECORD_HMAC_KEY = bytes.fromhex("e3a0611185416899f30eda877a80cc69")

_IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
)
_FP = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
)
_E = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
)
_P = (
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
)
_PC1 = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)
_PC2 = (
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_SBOXES: tuple[tuple[int, ...], ...] = (
    (
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
    ),
    (
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
    ),
    (
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
    ),
    (
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
    ),
    (
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
    ),
    (
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
    ),
    (
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
    ),
    (
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11,
    ),
)


def _permute(value: int, table: Sequence[int], input_bits: int) -> int:
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (input_bits - position)) & 1)
    return result


def _subkeys(key: bytes) -> tuple[int, ...]:
    if len(key) != BLOCK_SIZE:
        raise ValueError("DES keys must be exactly 8 bytes")
    key56 = _permute(int.from_bytes(key, "big"), _PC1, 64)
    c = key56 >> 28
    d = key56 & ((1 << 28) - 1)
    keys = []
    mask = (1 << 28) - 1
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & mask
        d = ((d << shift) | (d >> (28 - shift))) & mask
        keys.append(_permute((c << 28) | d, _PC2, 56))
    return tuple(keys)


def _feistel(right: int, subkey: int) -> int:
    expanded = _permute(right, _E, 32) ^ subkey
    substituted = 0
    for index, box in enumerate(_SBOXES):
        six = (expanded >> (42 - index * 6)) & 0x3F
        row = ((six & 0x20) >> 4) | (six & 1)
        column = (six >> 1) & 0x0F
        substituted = (substituted << 4) | box[row * 16 + column]
    return _permute(substituted, _P, 32)


def des_block(block: bytes, key: bytes, *, decrypt: bool = False) -> bytes:
    """Encrypt or decrypt one block with standard single DES."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("DES blocks must be exactly 8 bytes")
    keys: Iterable[int] = _subkeys(key)
    if decrypt:
        keys = reversed(tuple(keys))
    state = _permute(int.from_bytes(block, "big"), _IP, 64)
    left, right = state >> 32, state & 0xFFFFFFFF
    for subkey in keys:
        left, right = right, left ^ _feistel(right, subkey)
    result = _permute((right << 32) | left, _FP, 64)
    return result.to_bytes(8, "big")


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def triple_des_ecb(data: bytes, key: bytes, *, decrypt: bool = False) -> bytes:
    """Apply standard three-key Triple DES EDE in ECB mode.

    This is used only for reading version-1 SAP Local Protected Storage
    containers. New SSFS material uses the version-2 AES form.
    """

    _require_rsec_key(key)
    if len(data) % BLOCK_SIZE:
        raise ValueError("Triple DES ECB input must be a multiple of 8 bytes")
    output = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        if decrypt:
            block = des_block(block, key[16:24], decrypt=True)
            block = des_block(block, key[8:16])
            block = des_block(block, key[:8], decrypt=True)
        else:
            block = des_block(block, key[:8])
            block = des_block(block, key[8:16], decrypt=True)
            block = des_block(block, key[16:24])
        output.extend(block)
    return bytes(output)


def _aes_multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


def _aes_power(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _aes_multiply(result, value)
        value = _aes_multiply(value, value)
        exponent >>= 1
    return result


def _rotate_byte(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _make_aes_sboxes() -> tuple[tuple[int, ...], tuple[int, ...]]:
    # FIPS 197 S-box: multiplicative inverse in GF(2^8), followed by the
    # affine transform. Computing it avoids a dependency and a copied table.
    forward = []
    for value in range(256):
        inverse = 0 if value == 0 else _aes_power(value, 254)
        forward.append(
            inverse
            ^ _rotate_byte(inverse, 1)
            ^ _rotate_byte(inverse, 2)
            ^ _rotate_byte(inverse, 3)
            ^ _rotate_byte(inverse, 4)
            ^ 0x63
        )
    inverse = [0] * 256
    for index, value in enumerate(forward):
        inverse[value] = index
    return tuple(forward), tuple(inverse)


_AES_SBOX, _AES_INVERSE_SBOX = _make_aes_sboxes()


def _aes_expand_key(key: bytes) -> tuple[bytes, ...]:
    if len(key) != AES128_KEY_SIZE:
        raise ValueError("AES-128 keys must be exactly 16 bytes")
    expanded = bytearray(key)
    round_constant = 1
    while len(expanded) < 176:
        temporary = bytearray(expanded[-4:])
        if len(expanded) % AES128_KEY_SIZE == 0:
            temporary[:] = temporary[1:] + temporary[:1]
            temporary[:] = bytes(_AES_SBOX[value] for value in temporary)
            temporary[0] ^= round_constant
            round_constant = _aes_multiply(round_constant, 2)
        for value in temporary:
            expanded.append(expanded[-AES128_KEY_SIZE] ^ value)
    return tuple(bytes(expanded[offset : offset + 16]) for offset in range(0, 176, 16))


def _aes_add_round_key(state: list[int], round_key: bytes) -> None:
    for index, value in enumerate(round_key):
        state[index] ^= value


def _aes_shift_rows(state: list[int], *, inverse: bool = False) -> list[int]:
    shifted = [0] * AES_BLOCK_SIZE
    for row in range(4):
        for column in range(4):
            source_column = (column - row) % 4 if inverse else (column + row) % 4
            shifted[row + 4 * column] = state[row + 4 * source_column]
    return shifted


def _aes_mix_columns(state: list[int], *, inverse: bool = False) -> list[int]:
    mixed = state.copy()
    matrix = (
        ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))
        if inverse
        else ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    )
    for column in range(4):
        values = state[column * 4 : column * 4 + 4]
        for row in range(4):
            mixed[column * 4 + row] = (
                _aes_multiply(matrix[row][0], values[0])
                ^ _aes_multiply(matrix[row][1], values[1])
                ^ _aes_multiply(matrix[row][2], values[2])
                ^ _aes_multiply(matrix[row][3], values[3])
            )
    return mixed


def aes128_block(block: bytes, key: bytes, *, decrypt: bool = False) -> bytes:
    """Encrypt or decrypt one block with dependency-free standard AES-128."""

    if len(block) != AES_BLOCK_SIZE:
        raise ValueError("AES blocks must be exactly 16 bytes")
    round_keys = _aes_expand_key(key)
    state = list(block)
    if decrypt:
        _aes_add_round_key(state, round_keys[10])
        for round_index in range(9, 0, -1):
            state = _aes_shift_rows(state, inverse=True)
            state = [_AES_INVERSE_SBOX[value] for value in state]
            _aes_add_round_key(state, round_keys[round_index])
            state = _aes_mix_columns(state, inverse=True)
        state = _aes_shift_rows(state, inverse=True)
        state = [_AES_INVERSE_SBOX[value] for value in state]
        _aes_add_round_key(state, round_keys[0])
    else:
        _aes_add_round_key(state, round_keys[0])
        for round_index in range(1, 10):
            state = [_AES_SBOX[value] for value in state]
            state = _aes_shift_rows(state)
            state = _aes_mix_columns(state)
            _aes_add_round_key(state, round_keys[round_index])
        state = [_AES_SBOX[value] for value in state]
        state = _aes_shift_rows(state)
        _aes_add_round_key(state, round_keys[10])
    return bytes(state)


def aes128_cbc(
    data: bytes,
    key: bytes,
    *,
    iv: bytes = b"\x00" * AES_BLOCK_SIZE,
    decrypt: bool = False,
) -> bytes:
    """Apply raw AES-128-CBC without padding.

    SAP LPS performs its own random-prefix padding, so implicit PKCS padding
    here would make valid containers impossible to authenticate.
    """

    if len(key) != AES128_KEY_SIZE:
        raise ValueError("AES-128 keys must be exactly 16 bytes")
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("AES-CBC IVs must be exactly 16 bytes")
    if len(data) % AES_BLOCK_SIZE:
        raise ValueError("AES-CBC input must be a multiple of 16 bytes")
    output = bytearray()
    previous = iv
    for offset in range(0, len(data), AES_BLOCK_SIZE):
        block = data[offset : offset + AES_BLOCK_SIZE]
        if decrypt:
            clear = _xor(aes128_block(block, key, decrypt=True), previous)
            output.extend(clear)
            previous = block
        else:
            encrypted = aes128_block(_xor(block, previous), key)
            output.extend(encrypted)
            previous = encrypted
    return bytes(output)


def _rsec_stage(data: bytes, key: bytes, *, encrypt: bool) -> bytes:
    """Apply one SAP RSEC DES stage, including its partial-block tail mode."""
    if len(key) != BLOCK_SIZE:
        raise ValueError("RSEC DES stage keys must be exactly 8 bytes")
    if len(data) < BLOCK_SIZE:
        raise ValueError("RSEC inputs shorter than one DES block are unsupported")

    remainder = len(data) % BLOCK_SIZE
    full_length = len(data) - remainder
    output = bytearray()
    previous = b"\x00" * BLOCK_SIZE

    for offset in range(0, full_length, BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        if encrypt:
            transformed = des_block(_xor(block, previous), key)
            previous = transformed
        else:
            transformed = _xor(des_block(block, key, decrypt=True), previous)
            previous = block
        output.extend(transformed)

    if remainder:
        # SAP uses DES-ECB(last full ciphertext) as a keystream for the tail.
        seed = bytes(output[-BLOCK_SIZE:]) if encrypt else data[full_length-BLOCK_SIZE:full_length]
        stream = des_block(seed, key)
        output.extend(_xor(data[full_length:], stream[:remainder]))

    return bytes(output)


def _require_rsec_key(key: bytes) -> None:
    if len(key) != RSEC_KEY_SIZE:
        raise ValueError("RSEC keys must be exactly 24 bytes")


def rsec_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt bytes with SAP's legacy three-stage RSEC EDE composition."""
    _require_rsec_key(key)
    stage1 = _rsec_stage(data, key[:8], encrypt=True)
    stage2 = _rsec_stage(stage1, key[8:16], encrypt=False)
    return _rsec_stage(stage2, key[16:24], encrypt=True)


def rsec_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt bytes with SAP's legacy three-stage RSEC EDE composition."""
    _require_rsec_key(key)
    stage1 = _rsec_stage(data, key[16:24], encrypt=False)
    stage2 = _rsec_stage(stage1, key[8:16], encrypt=True)
    return _rsec_stage(stage2, key[:8], encrypt=False)


def unwrap_individual_key(
    wrapped: bytes, *, key_encryption_key: bytes = DEFAULT_KEY_ENCRYPTION_KEY
) -> bytes:
    """Decode the 57-byte type-2 ``SSFS_<SID>.KEY`` key payload."""
    if len(wrapped) != 57:
        raise ValueError("wrapped SSFS keys must be exactly 57 bytes")
    _require_rsec_key(key_encryption_key)
    key = key_encryption_key
    ciphertext = wrapped[:56]
    stage1 = _rsec_stage(ciphertext, key[16:24], encrypt=False)
    stage2 = _rsec_stage(stage1, key[8:16], encrypt=True)
    plaintext = _rsec_stage(stage2, key[:8], encrypt=False)
    last = wrapped[56]
    last ^= des_block(ciphertext[48:56], key[16:24])[0]
    last ^= des_block(stage2[48:56], key[8:16])[0]
    last ^= des_block(stage2[48:56], key[:8])[0]
    if plaintext[32] != 1:
        raise ValueError(f"unsupported wrapped SSFS key type {plaintext[32]}")
    return plaintext[33:56] + bytes([last])


def wrap_individual_key(
    key_to_wrap: bytes,
    *,
    key_encryption_key: bytes = DEFAULT_KEY_ENCRYPTION_KEY,
    random_bytes=os.urandom,
) -> bytes:
    """Encode a 24-byte master key in SAP's 57-byte type-2 key payload."""
    _require_rsec_key(key_to_wrap)
    _require_rsec_key(key_encryption_key)
    kek = key_encryption_key
    # The encrypted structure is 32 random bytes, a one-byte key type, and
    # the first 23 key bytes. RSEC's partial-tail construction carries the
    # final key byte separately as ciphertext byte 57.
    plaintext = random_bytes(32) + b"\x01" + key_to_wrap[:23]
    stage1 = _rsec_stage(plaintext, kek[:8], encrypt=True)
    stage2 = _rsec_stage(stage1, kek[8:16], encrypt=False)
    ciphertext = _rsec_stage(stage2, kek[16:24], encrypt=True)
    last = key_to_wrap[23]
    last ^= des_block(ciphertext[48:56], kek[16:24])[0]
    last ^= des_block(stage1[48:56], kek[8:16])[0]
    last ^= des_block(stage1[48:56], kek[:8])[0]
    return ciphertext + bytes([last])


def record_hmac(message: bytes) -> bytes:
    """Return the SSFS record HMAC-SHA1 (a format check, not a secret MAC)."""
    return hmac.new(RECORD_HMAC_KEY, message, hashlib.sha1).digest()
