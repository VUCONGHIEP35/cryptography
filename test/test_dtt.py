import sys
from pathlib import Path

import numpy as np
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.ddt_analyzer import DDT_Analyzer

SBOX_FULL = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]

def test_ddt_shape():
    analyzer = DDT_Analyzer(SBOX_FULL)
    ddt = analyzer.compute()
    assert ddt.shape == (16, 16)

def test_ddt_row_sum():
    """Mỗi hàng DDT phải tổng bằng 16 (tổng số cặp đầu vào)."""
    analyzer = DDT_Analyzer(SBOX_FULL)
    ddt = analyzer.compute()
    for dx in range(16):
        assert ddt[dx].sum() == 16, f"Hàng dx={dx} tổng sai: {ddt[dx].sum()}"

def test_ddt_diagonal():
    """ddt[0][0] phải bằng 16 (ΔX=0 luôn cho ΔY=0)."""
    analyzer = DDT_Analyzer(SBOX_FULL)
    ddt = analyzer.compute()
    assert ddt[0][0] == 16

def test_ddt_ground_truth_m1():
    """Đối chiếu với test case M1 tính tay."""
    # M1 xác nhận: với SBOX_FULL, ddt[11][2] là ô có giá trị cao nhất (= 8)
    analyzer = DDT_Analyzer(SBOX_FULL)
    ddt = analyzer.compute()
    best = analyzer.max_differential_prob(ddt)
    assert best["count"] == 8
    assert best["prob"] == 0.5

def test_identity_sbox_has_perfect_ddt():
    """S-Box đồng nhất (f(x)=x) → DDT là ma trận đường chéo."""
    identity = list(range(16))
    analyzer = DDT_Analyzer(identity)
    ddt = analyzer.compute()
    # Mọi ΔX đều cho đúng ΔY = ΔX, count = 16
    for dx in range(16):
        assert ddt[dx][dx] == 16