import numpy as np
import pytest
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.key_recovery import KeyRecovery

def test_inverse_sbox_creation():
    """Test 1: Kiểm tra xem Bảng S-Box ngược có được tạo đúng không"""
    attacker = KeyRecovery()
    
    # SBOX chuẩn: [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
    # SBOX[0] = 14 => Inverse_SBOX[14] phải bằng 0
    # SBOX[3] = 1 => Inverse_SBOX[1] phải bằng 3
    
    assert attacker.inv_sbox[14] == 0, "Lỗi tạo Inverse S-Box: Vị trí 14 phải ra 0"
    assert attacker.inv_sbox[1] == 3, "Lỗi tạo Inverse S-Box: Vị trí 1 phải ra 3"
    assert attacker.inv_sbox[7] == 15, "Lỗi tạo Inverse S-Box: Vị trí 7 phải ra 15"

def test_partial_decrypt_nibble():
    """Test 2: Kiểm tra hàm giải mã ngược 1 cụm 4-bit với dữ liệu tính tay (Hardcoded)"""
    attacker = KeyRecovery()
    
    # Giả sử ta có 2 bản mã C (chỉ lấy 16-bit)
    # C1 = 0xABCD (Hex)
    # C2 = 0x1234 (Hex)
    c_batch = np.array([0xABCD, 0x1234], dtype=np.uint16)
    
    # Ta muốn nhắm vào S-Box số 2 (index 1, đếm từ 0). 
    # Nghĩa là nó sẽ nhổ cái nibble 'B' (11) từ C1, và '2' (2) từ C2.
    sbox_idx = 1
    
    # Giả sử ta thử chìa khóa đoán (guess_nibble) là 5 (0101)
    guess_nibble = 5
    
    # --- TÍNH TAY KẾT QUẢ ĐỂ ĐỐI CHIẾU ---
    # Với C1 (0xABCD):
    # 1. Trích nibble index 1 -> 'B' (11)
    # 2. XOR với guess_key (5) -> 11 ^ 5 = 14
    # 3. Qua Inverse S-box của 14 -> bằng 0. (Kỳ vọng u_nibble của C1 = 0)
    
    # Với C2 (0x1234):
    # 1. Trích nibble index 1 -> '2' (2)
    # 2. XOR với guess_key (5) -> 2 ^ 5 = 7
    # 3. Qua Inverse S-box của 7 -> bằng 15. (Kỳ vọng u_nibble của C2 = 15)
    
    # --- CHẠY CODE CỦA AI ---
    u_result = attacker._partial_decrypt_nibble(c_batch, guess_nibble, sbox_idx)
    
    # --- ASSERTIONS ---
    assert u_result.shape == (2,), "Lỗi shape của mảng trả về"
    assert u_result[0] == 0, f"Sai logic giải mã C1! Kỳ vọng 0, nhận được {u_result[0]}"
    assert u_result[1] == 15, f"Sai logic giải mã C2! Kỳ vọng 15, nhận được {u_result[1]}"

    print("\n✅ Hàm giải mã ngược (Partial Decrypt) độc lập hoạt động đúng 100%!")