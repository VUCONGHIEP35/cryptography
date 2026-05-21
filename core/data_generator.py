import numpy as np
# Lưu ý: Sửa lại tên import nếu đồng đội của cậu đặt tên class khác trong cipher_engine.py
from core.cipher_engine import PRESENTCipher 

class DataGenerator:
    def __init__(self, cipher_engine):
        """
        Nhận vào một instance của lõi mã hóa PRESENT 64-bit.
        """
        self.cipher = cipher_engine
        
        # NÂNG CẤP: Sử dụng bộ sinh ngẫu nhiên thế hệ mới của NumPy 
        # (Nhanh hơn và hỗ trợ số lớn 64-bit cực chuẩn)
        self.rng = np.random.default_rng()

    def generate_pairs(self, n_samples: int, delta_p: int, key: int) -> dict:
        """
        Sinh ra n_samples cặp văn bản rõ/mã 64-bit thỏa mãn sai phân đầu vào delta_p.
        
        Parameters:
        - n_samples: Số lượng cặp dữ liệu cần sinh (Nên đặt 100000).
        - delta_p: Sai phân đầu vào (uint64).
        - key: Khóa bí mật (hỗ trợ số nguyên lớn).
        """
        # 1. Sinh mảng bản rõ P 64-bit (giá trị trải dài từ 0 đến 2^64 - 1)
        P = self.rng.integers(0, 2**64, size=n_samples, dtype=np.uint64)
        
        # 2. Sinh mảng bản rõ thứ 2 (P*) thỏa mãn sai phân delta_p
        delta_p_uint = np.uint64(delta_p)
        P_star = np.bitwise_xor(P, delta_p_uint)
        
        # 3. Mã hóa hàng vạn dữ liệu qua Cipher Engine
        C = self.cipher.encrypt(P, key)
        C_star = self.cipher.encrypt(P_star, key)
        
        return {
            "P": P,
            "P_star": P_star,
            "C": C,
            "C_star": C_star
        }

# ==========================================
# TEST NHANH KHI NÂNG CẤP LÊN 64-BIT
# ==========================================
if __name__ == "__main__":
    import time
    
    # Khởi tạo lõi mã hóa
    cipher = PRESENTCipher()
    generator = DataGenerator(cipher)
    
    # THIẾT LẬP THÔNG SỐ THEO ĐÚNG ĐẶC TẢ CỦA TRƯỞNG NHÓM
    NUM_SAMPLES = 100000                 # Cần 100k cặp để chống lại tỷ lệ nhiễu của xác suất 2^-16
    DELTA_P = 0x0000000000000011         # Sai phân đầu vào mục tiêu
    SECRET_KEY = 0x1A2B3C4D5E6F7A8B9C0D  # Khóa bí mật test (80-bit dạng Hex)
    
    # Bấm giờ
    print(f"[*] Đang phân bổ RAM và xử lý ma trận {NUM_SAMPLES} phần tử 64-bit...")
    start_time = time.time()
    
    dataset = generator.generate_pairs(NUM_SAMPLES, DELTA_P, SECRET_KEY)
    
    elapsed = time.time() - start_time
    
    print(f"✅ Đã sinh thành công {NUM_SAMPLES} cặp vi phân!")
    print(f"⏱️ Thời gian thực thi: {elapsed:.4f} giây")
    print(f"Mảng C (5 phần tử đầu):")
    for i in range(5):
        print(f"  {hex(dataset['C'][i])}")
    
    # Kiểm chứng sai phân đầu vào bằng toán học
    test_delta = np.bitwise_xor(dataset['P'][0], dataset['P_star'][0])
    assert test_delta == DELTA_P, "LỖI NGHIÊM TRỌNG: Sai phân đầu vào bị lệch bit!"