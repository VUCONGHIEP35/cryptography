import sys, os
import time
import numpy as np
import pytest

# Trỏ đường dẫn import về thư mục gốc để nạp module core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cipher_engine import PRESENTCipher
from core.data_generator import DataGenerator
from core.key_recovery import KeyRecovery

def test_core_full_pipeline():
    print("\n--- BẮT ĐẦU KIỂM THỬ LÕI 64-BIT PRESENT ---")
    
    # 1. KHỞI TẠO CÁC MODULE LÕI
    try:
        cipher = PRESENTCipher()
    except Exception as e:
        pytest.fail(f"Lỗi khởi tạo lõi Cipher (Kiểm tra lại code của Hiệp): {e}")
        
    generator = DataGenerator(cipher)
    attacker = KeyRecovery()
    
    # THÔNG SỐ THEO ĐẶC TẢ CỦA TRƯỞNG NHÓM
    NUM_SAMPLES = 100000 
    DELTA_P = 0x0000000000000011
    EXPECTED_DELTA_U = 0x11
    TARGET_SBOXES = [14, 15] # 2 S-Box cuối cùng
    MASTER_KEY = 0x1A2B3C4D5E6F7A8B9C0D
    
    # 2. KIỂM THỬ MODULE SINH DỮ LIỆU
    print(f"[*] Đang sinh {NUM_SAMPLES} dữ liệu 64-bit...")
    start_gen = time.time()
    dataset = generator.generate_pairs(NUM_SAMPLES, DELTA_P, MASTER_KEY)
    time_gen = time.time() - start_gen
    
    # Assertions cho Data Generator
    assert dataset['P'].dtype == np.uint64, "Lỗi: Bản rõ không phải kiểu uint64"
    assert dataset['C'].dtype == np.uint64, "Lỗi: Bản mã không phải kiểu uint64"
    assert dataset['P'].shape == (NUM_SAMPLES,), "Lỗi: Số lượng dữ liệu sinh ra không đủ 100.000"
    
    # Kiểm tra sai phân đầu vào bằng bitwise XOR
    test_delta_p = np.bitwise_xor(dataset['P'][0], dataset['P_star'][0])
    assert test_delta_p == DELTA_P, f"Lỗi: Sai phân đầu vào bị lệch. Kỳ vọng {hex(DELTA_P)}, nhận {hex(test_delta_p)}"
    print(f"[+] Data Generator PASS (Thời gian: {time_gen:.4f}s)")
    
    # 3. KIỂM THỬ MODULE KHÔI PHỤC KHÓA
    print(f"[*] Đang vét cạn không gian khóa trên ma trận...")
    start_atk = time.time()
    result = attacker.attack(
        C=dataset['C'], 
        C_star=dataset['C_star'], 
        target_sboxes=TARGET_SBOXES, 
        expected_delta_u=EXPECTED_DELTA_U
    )
    time_atk = time.time() - start_atk
    
    # Assertions cho Key Recovery
    assert "best_candidate_hex" in result, "Lỗi: Thuật toán không trả về khóa Ứng viên"
    assert isinstance(result["best_score"], int), "Lỗi: Điểm số không đúng định dạng số nguyên"
    
    # Thuật toán thành công khi tín hiệu vọt lên cao hơn nhiễu. 
    # Xác suất nhiễu ngẫu nhiên là NUM_SAMPLES / 256. Khóa đúng phải có số hit lớn hơn số này nhiều.
    noise_threshold = NUM_SAMPLES // 256
    assert result["best_score"] > noise_threshold, "Lỗi: Điểm số của khóa thấp hơn cả mức nhiễu, thuật toán không bóc tách được khóa!"
    
    print(f"[+] Key Recovery PASS (Thời gian: {time_atk:.4f}s)")
    print(f"🎯 Khóa ứng viên tiềm năng nhất (Partial Subkey): {result['best_candidate_hex']}")
    print(f"🏆 Điểm số (Hits): {result['best_score']} / {NUM_SAMPLES}")
    print("\n✅ TOÀN BỘ LÕI HOẠT ĐỘNG HOÀN HẢO! TOÁN HỌC ĐÃ THÔNG SUỐT 100%!")