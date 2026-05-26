import numpy as np
import pytest

# Trỏ đường dẫn import về thư mục core (nếu chạy pytest ở thư mục gốc)
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cipher_engine import SPNCipher
from core.data_generator import DataGenerator

def test_data_generator_logic():
    # 1. Thiết lập môi trường
    cipher = SPNCipher()
    generator = DataGenerator(cipher)
    
    NUM_SAMPLES = 10000
    DELTA_P = 0x0B00  # Sai phân đầu vào test: 0000 1011 0000 0000
    KEY = 0x1A2B
    
    # 2. Thực thi sinh dữ liệu
    dataset = generator.generate_pairs(NUM_SAMPLES, DELTA_P, KEY)
    
    # --- BẮT ĐẦU KIỂM THỬ (ASSERTIONS) ---
    
    # TEST 1: Kiểm tra kích thước mảng (Phải đúng 10.000)
    assert dataset["P"].shape == (NUM_SAMPLES,), "Mảng P sai kích thước"
    assert dataset["C_star"].shape == (NUM_SAMPLES,), "Mảng C* sai kích thước"
    
    # TEST 2: Kiểm tra kiểu dữ liệu (Phải là uint16 để tối ưu RAM)
    assert dataset["P"].dtype == np.uint16, "Dữ liệu không phải uint16"
    
    # TEST 3: KIỂM TRA LÕI TOÁN HỌC (Sinh tử)
    # Lấy toàn bộ mảng P XOR với mảng P*
    actual_delta_p = np.bitwise_xor(dataset["P"], dataset["P_star"])
    
    # Hàm np.all() sẽ trả về True CHỈ KHI tất cả 10.000 cặp đều có sai phân đúng bằng DELTA_P
    assert np.all(actual_delta_p == DELTA_P), "LỖI NGHIÊM TRỌNG: Sai phân P ^ P* không bằng Delta P mục tiêu!"
    
    # TEST 4: Đảm bảo Cipher Engine đã thực sự mã hóa (P khác C)
    assert not np.array_equal(dataset["P"], dataset["C"]), "Bản rõ và Bản mã giống hệt nhau (Lỗi mã hóa chưa chạy)"

    print("\n✅ Data Generator hoạt động hoàn hảo 100% trên 10.000 mẫu!")