import sys
from pathlib import Path

import numpy as np
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.cipher_engine import SPNCipher

cipher = SPNCipher()

def test_encrypt_single_block():
    """Mã hóa 1 block, kết quả phải là uint16 hợp lệ."""
    pt  = np.array([0x1234], dtype=np.uint16)
    ct  = cipher.encrypt(pt, key=0xABCD)
    assert ct.shape == (1,)
    assert ct.dtype == np.uint16

def test_encrypt_batch():
    """Mã hóa 100 block, shape phải giữ nguyên."""
    pts = np.random.randint(0, 65536, size=100, dtype=np.uint16)
    cts = cipher.encrypt(pts, key=0x1234)
    assert cts.shape == (100,)

def test_deterministic():
    """Cùng input + key → cùng output."""
    pt  = np.array([0xBEEF], dtype=np.uint16)
    ct1 = cipher.encrypt(pt, key=0x1111)
    ct2 = cipher.encrypt(pt, key=0x1111)
    assert np.array_equal(ct1, ct2)

def test_different_keys_give_different_ct():
    """Khóa khác nhau → bản mã khác nhau."""
    pt  = np.array([0xDEAD], dtype=np.uint16)
    ct1 = cipher.encrypt(pt, key=0x1111)
    ct2 = cipher.encrypt(pt, key=0x2222)
    assert not np.array_equal(ct1, ct2)

def test_substitute_uses_sbox_lookup():
    """Nibble đầu tiên phải đúng với SBOX."""
    block   = np.array([0x0000], dtype=np.uint16)  # nibble 0 = 0 → SBOX[0] = 14
    result  = cipher.substitute(block)
    top_nibble = (result[0] >> 12) & 0xF
    assert top_nibble == 14   # SBOX[0] = 14