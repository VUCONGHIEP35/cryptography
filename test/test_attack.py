import numpy as np
import pytest
import time
import sys, os

# Trỏ đường dẫn import về thư mục core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cipher_engine import SPNCipher
from core.data_generator import DataGenerator
from core.key_recovery import KeyRecovery

def test_key_recovery_logic():
    print("\n--- BẮT ĐẦU CHIẾN DỊCH BẺ KHÓA ---")
    
    # 1. KHỞI TẠO ĐỘNG CƠ
    cipher = SPNCipher()
    generator = DataGenerator(cipher)
    attacker = KeyRecovery()
    
    # Tham số tấn công chuẩn xác từ sách Stinson cho Toy Cipher này
    NUM_SAMPLES = 8000
    DELTA_P = 0x0B00           # Sai phân đầu vào mục tiêu
    EXPECTED_DELTA_U = 0x0606  # Sai phân trước S-box vòng cuối
    TARGET_SBOXES = [1, 3]     # Nhắm vào S-Box số 2 và 4 (index 1 và 3)
    
    MASTER_KEY = 0x8A2B
    EXPECTED_PARTIAL_KEY = "0x28" # Khóa con K5 tại vị trí 1 và 3
    
    # 2. SINH DỮ LIỆU
    print(f"[*] Đang sinh {NUM_SAMPLES} dữ liệu...")
    dataset = generator.generate_pairs(NUM_SAMPLES, DELTA_P, MASTER_KEY)
    
    # 3. TẤN CÔNG
    print("[*] Đang vét cạn 256 chìa khóa bằng Ma trận NumPy...")
    start_time = time.time()
    
    result = attacker.attack(
        C=dataset['C'], 
        C_star=dataset['C_star'], 
        target_sboxes=TARGET_SBOXES, 
        expected_delta_u=EXPECTED_DELTA_U
    )
    
    elapsed = time.time() - start_time
    
    # 4. BÁO CÁO KẾT QUẢ
    print(f"\n[+] Tốc độ bẻ khóa: {elapsed:.4f} giây")
    print(f"[+] Khóa thực tế (Ground Truth): {EXPECTED_PARTIAL_KEY}")
    print(f"[+] Khóa AI dò được: {result['best_candidate_hex']}")
    print(f"[+] Số điểm (Hits): {result['best_score']} / {NUM_SAMPLES} cặp")
    
    # 5. KIỂM THỬ (ASSERTIONS)
    assert result['best_candidate_hex'] == EXPECTED_PARTIAL_KEY, "LỖI: AI đã tìm sai Khóa!"
    
    # Điểm số của khóa đúng phải vượt xa xác suất ngẫu nhiên (8000 / 256 = 31 hits)
    assert result['best_score'] > (NUM_SAMPLES / 256) * 2, "LỖI: Tín hiệu nhiễu quá lớn, không bóc tách được khóa."
    
    print("\n✅ THUẬT TOÁN BẺ KHÓA HOẠT ĐỘNG HOÀN HẢO!")