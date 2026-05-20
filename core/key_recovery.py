import numpy as np

# Sử dụng lại SBOX từ hệ thống để tính SBOX ngược
SBOX = np.array([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], dtype=np.uint8)

class KeyRecovery:
    def __init__(self, sbox=SBOX):
        self.sbox = sbox
        
        # 1. Tự động tính Bảng S-Box ngược (Inverse S-Box)
        # Giúp giải mã từ V (đầu ra Sbox) ngược về U (đầu vào Sbox)
        self.inv_sbox = np.zeros(16, dtype=np.uint8)
        for i in range(16):
            self.inv_sbox[self.sbox[i]] = i

    def _partial_decrypt_nibble(self, c_batch: np.ndarray, guess_nibble: int, nibble_idx: int) -> np.ndarray:
        """
        Giải mã ngược 1 cụm 4-bit (nibble) cho hàng vạn bản mã CÙNG LÚC.
        c_batch: Mảng bản mã C (shape [N], uint16)
        guess_nibble: Khóa thử 4-bit (từ 0 đến 15)
        nibble_idx: Vị trí của S-box (0, 1, 2, 3 từ trái qua phải)
        """
        shift_amount = (3 - nibble_idx) * 4
        
        # Trích xuất 4-bit từ bản mã tại đúng vị trí
        c_nibbles = (c_batch >> shift_amount) & 0xF
        
        # XOR với khóa thử (Key Mixing ngược)
        v_nibbles = c_nibbles ^ guess_nibble
        
        # Cho qua Inverse S-Box (Sử dụng Advanced Indexing của NumPy)
        u_nibbles = self.inv_sbox[v_nibbles]
        
        return u_nibbles

    def attack(self, C: np.ndarray, C_star: np.ndarray, target_sboxes: list, expected_delta_u: int) -> dict:
        """
        Thực hiện tấn công khôi phục khóa con của vòng cuối.
        
        Parameters:
        - C, C_star: Hai mảng bản mã (shape [N])
        - target_sboxes: Danh sách vị trí S-box bị lộ lỗ hổng (VD: [1, 3] tương ứng S-box số 2 và 4)
        - expected_delta_u: Sai phân mục tiêu kỳ vọng trước khi qua S-box vòng cuối.
        """
        num_sboxes = len(target_sboxes)
        num_candidates = 16 ** num_sboxes # VD: 2 S-box -> 16^2 = 256 ứng viên khóa
        
        # Mảng lưu điểm số (số lần đụng độ) cho từng ứng viên khóa
        scores = np.zeros(num_candidates, dtype=np.int32)
        
        # Tạo bit-mask để chỉ so sánh sai phân tại đúng các S-box mục tiêu
        mask = 0
        for sbox_idx in target_sboxes:
            mask |= (0xF << ((3 - sbox_idx) * 4))
            
        expected_masked = expected_delta_u & mask

        # 2. VÉT CẠN CÁC ỨNG VIÊN KHÓA (Hypothesis Testing)
        for candidate in range(num_candidates):
            u_combined = np.zeros_like(C, dtype=np.uint16)
            u_star_combined = np.zeros_like(C_star, dtype=np.uint16)
            
            # Tách candidate (VD: 0xAB) thành các nibble ('A' và 'B') phân phối vào đúng S-Box
            for i, sbox_idx in enumerate(target_sboxes):
                # Lấy 4-bit của khóa thử tương ứng với S-box hiện tại
                nibble_shift = (num_sboxes - 1 - i) * 4
                guess_nibble = (candidate >> nibble_shift) & 0xF
                
                # Giải mã ngược cho toàn bộ mảng C và C* 
                u = self._partial_decrypt_nibble(C, guess_nibble, sbox_idx)
                u_star = self._partial_decrypt_nibble(C_star, guess_nibble, sbox_idx)
                
                # Dịch bit đưa U về lại đúng vị trí 16-bit ban đầu
                global_shift = (3 - sbox_idx) * 4
                u_combined |= (u.astype(np.uint16) << global_shift)
                u_star_combined |= (u_star.astype(np.uint16) << global_shift)
            
            # 3. CHẤM ĐIỂM (Scoring) BẰNG VECTORIZATION
            # Tính sai phân thực tế sau khi giải mã ngược bằng khóa thử này
            delta_u_actual = u_combined ^ u_star_combined
            
            # Đếm số lượng phần tử có sai phân thực tế khớp với sai phân kỳ vọng
            # Hàm np.count_nonzero chạy ngầm C, nhanh hơn vòng lặp Python cực kỳ nhiều
            hits = np.count_nonzero((delta_u_actual & mask) == expected_masked)
            
            # Ghi nhận điểm số
            scores[candidate] = hits
            
        # Tìm ứng viên có điểm cao nhất (argmax)
        best_candidate_idx = np.argmax(scores)
        best_score = scores[best_candidate_idx]
        
        # Format lại kết quả dưới dạng chuỗi Hex dễ đọc (VD: '0x3a')
        # Zfill đảm bảo đủ số lượng chữ số hex (1 Sbox = 1 chữ số)
        best_hex = "0x" + hex(best_candidate_idx)[2:].zfill(num_sboxes)
        
        return {
            "best_candidate_hex": best_hex,
            "best_score": int(best_score),
            "scores": scores.tolist()
        }

# ==========================================
# TEST TÍCH HỢP ĐẦY ĐỦ TỪ ĐẦU ĐẾN CUỐI
# ==========================================
if __name__ == "__main__":
    import time
    from cipher_engine import SPNCipher
    from data_generator import DataGenerator

    print("--- KHỞI ĐỘNG HỆ THỐNG MÔ PHỎNG TẤN CÔNG ---")
    
    # BƯỚC 1: Cấu hình hệ mật và sinh dữ liệu
    SECRET_KEY = 0x8A2B       # Giả sử khóa bí mật là 1000 1010 0010 1011
    # Ở vòng 5, theo thiết kế key schedule đơn giản, subkey 5 sẽ có một giá trị nhất định.
    # Trong bài lab của cuốn Stinson, thường nhắm vào S-box 2 và 4 (index 1 và 3).
    # Khóa con tại S-box 2 và 4 sẽ là mục tiêu chúng ta cần tìm ra.
    
    cipher = SPNCipher()
    generator = DataGenerator(cipher)
    
    NUM_SAMPLES = 8000
    DELTA_P = 0x0B00  # Sai phân đầu vào mục tiêu (được tính từ thuật toán Path Finder)
    EXPECTED_DELTA_U = 0x0606 # Sai phân kỳ vọng trước vòng cuối (để khớp với target_sboxes=[1, 3])
    
    print(f"1. Đang sinh {NUM_SAMPLES} cặp bản mã...")
    dataset = generator.generate_pairs(NUM_SAMPLES, DELTA_P, SECRET_KEY)
    
    # BƯỚC 2: Tấn công giải mã ngược
    attacker = KeyRecovery()
    
    print("2. Đang thực thi bẻ khóa (Vectorized Brute-force)...")
    start_time = time.time()
    
    # Bẻ khóa nhắm vào S-Box 2 (index 1) và S-Box 4 (index 3)
    result = attacker.attack(
        C=dataset['C'], 
        C_star=dataset['C_star'], 
        target_sboxes=[1, 3], 
        expected_delta_u=EXPECTED_DELTA_U
    )
    
    elapsed = time.time() - start_time
    
    print("\n--- KẾT QUẢ TẤN CÔNG ---")
    print(f"⏱️ Thời gian bẻ khóa: {elapsed:.4f} giây")
    print(f"🎯 Khóa ứng viên tiềm năng nhất (Partial Subkey): {result['best_candidate_hex']}")
    print(f"🏆 Điểm số cao nhất: {result['best_score']} / {NUM_SAMPLES} hits")