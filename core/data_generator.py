import numpy as np
from cipher_engine import SPNCipher

class DataGenerator:
    def __init__(self, cipher_engine: SPNCipher):
        """
        Nhận vào một instance của lõi mã hóa đã được cấu hình.
        """
        self.cipher = cipher_engine

    def generate_pairs(self, n_samples: int, delta_p: int, key: int) -> dict:
        """
        Sinh ra n_samples cặp văn bản rõ/mã thỏa mãn sai phân đầu vào delta_p.
        
        Parameters:
        - n_samples: Số lượng cặp dữ liệu cần sinh (VD: 10000).
        - delta_p: Sai phân đầu vào (uint16).
        - key: Khóa bí mật (uint16).
        
        Returns:
        - Dictionary chứa 4 mảng numpy: P, P_star, C, C_star
        """
        # 1. Sinh hàng vạn bản rõ P ngẫu nhiên trong chớp mắt
        # Kích thước 16-bit nên giá trị nằm trong [0, 65535]
        P = np.random.randint(0, 65536, size=n_samples, dtype=np.uint16)
        
        # 2. Sinh mảng bản rõ thứ 2 (P*) thỏa mãn sai phân delta_p
        # Phép XOR được áp dụng cho toàn bộ mảng cùng lúc
        delta_p_uint = np.uint16(delta_p)
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
# TEST NHANH (Mô phỏng lại tư duy test độc lập)
# ==========================================
if __name__ == "__main__":
    import time
    
    # Khởi tạo lõi mã hóa
    cipher = SPNCipher()
    generator = DataGenerator(cipher)
    
    # Thiết lập thông số
    NUM_SAMPLES = 10000  # Sinh 10.000 cặp
    DELTA_P = 0x0B00     # Sai phân thử nghiệm (ví dụ)
    SECRET_KEY = 0x1A2B  # Khóa bí mật
    
    # Bấm giờ
    start_time = time.time()
    
    dataset = generator.generate_pairs(NUM_SAMPLES, DELTA_P, SECRET_KEY)
    
    elapsed = time.time() - start_time
    
    print(f"✅ Đã sinh thành công {NUM_SAMPLES} cặp vi phân!")
    print(f"⏱️ Thời gian thực thi: {elapsed:.4f} giây")
    print(f"Mảng C (5 phần tử đầu): {dataset['C'][:5]}")
    
    # Kiểm chứng sai phân đầu vào
    test_delta = np.bitwise_xor(dataset['P'][0], dataset['P_star'][0])
    assert test_delta == DELTA_P, "Sai phân đầu vào bị lỗi!"