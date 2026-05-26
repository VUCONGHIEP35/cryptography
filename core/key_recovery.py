import numpy as np

# Bảng S-Box chuẩn của kiến trúc PRESENT
PRESENT_SBOX = np.array([0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2], dtype=np.uint8)

class KeyRecovery:
    def __init__(self, sbox=PRESENT_SBOX):
        self.sbox = sbox
        
        # 1. Khởi tạo Bảng S-Box ngược
        self.inv_sbox = np.zeros(16, dtype=np.uint8)
        for i in range(16):
            self.inv_sbox[self.sbox[i]] = i

    def _partial_decrypt_nibble(self, c_batch: np.ndarray, guess_nibble: int, sbox_idx: int) -> np.ndarray:
        """
        Giải mã ngược 1 cụm 4-bit (nibble) cho mảng bản mã 64-bit.
        """
        # Khối 64-bit có 16 S-box (index từ 0 đến 15)
        # sbox_idx = 0 nằm ở 4 bit cao nhất bên trái.
        shift_amount = (15 - sbox_idx) * 4
        
        # Ép kiểu uint64 cực kỳ nghiêm ngặt để giữ độ chính xác của bit
        c_nibbles = (c_batch >> np.uint64(shift_amount)) & np.uint64(0xF)
        
        # Key Mixing ngược
        v_nibbles = c_nibbles ^ np.uint64(guess_nibble)
        
        # Tra bảng S-Box ngược. Cần astype(uint8) để làm index mảng 16 phần tử
        u_nibbles = self.inv_sbox[v_nibbles.astype(np.uint8)]
        
        return u_nibbles.astype(np.uint64)

    def attack(self, C: np.ndarray, C_star: np.ndarray, target_sboxes: list, expected_delta_u: int) -> dict:
        """
        Thực hiện tấn công khôi phục khóa vòng cuối hệ 64-bit.
        """
        num_sboxes = len(target_sboxes)
        num_candidates = 16 ** num_sboxes
        
        scores = np.zeros(num_candidates, dtype=np.int32)
        
        # Tạo bit-mask 64-bit để lọc sai phân tại đúng các S-box mục tiêu
        mask = np.uint64(0)
        for sbox_idx in target_sboxes:
            mask |= (np.uint64(0xF) << np.uint64((15 - sbox_idx) * 4))
            
        expected_masked = np.uint64(expected_delta_u) & mask

        # 2. VÉT CẠN CÁC ỨNG VIÊN KHÓA TRÊN MA TRẬN
        for candidate in range(num_candidates):
            u_combined = np.zeros_like(C, dtype=np.uint64)
            u_star_combined = np.zeros_like(C_star, dtype=np.uint64)
            
            for i, sbox_idx in enumerate(target_sboxes):
                nibble_shift = (num_sboxes - 1 - i) * 4
                guess_nibble = (candidate >> nibble_shift) & 0xF
                
                u = self._partial_decrypt_nibble(C, guess_nibble, sbox_idx)
                u_star = self._partial_decrypt_nibble(C_star, guess_nibble, sbox_idx)
                
                # Dịch U về lại vị trí trên thang 64-bit
                global_shift = np.uint64((15 - sbox_idx) * 4)
                u_combined |= (u << global_shift)
                u_star_combined |= (u_star << global_shift)
            
            # 3. CHẤM ĐIỂM VECTORIZATION TỐC ĐỘ CAO
            delta_u_actual = u_combined ^ u_star_combined
            hits = np.count_nonzero((delta_u_actual & mask) == expected_masked)
            scores[candidate] = hits
            
        best_candidate_idx = np.argmax(scores)
        best_score = scores[best_candidate_idx]
        
        best_hex = "0x" + hex(best_candidate_idx)[2:].zfill(num_sboxes)
        
        return {
            "best_candidate_hex": best_hex,
            "best_score": int(best_score),
            "scores": scores.tolist()
        }