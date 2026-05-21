import numpy as np

# 1. Chuẩn S-Box của PRESENT
SBOX = np.array([0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2], dtype=np.uint8)
# 2. Chuẩn P-Box của PRESENT (Đan chéo 64 bit)
PBOX = np.array([
    0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
])

class PRESENTCipher:
    def __init__(self, sbox=SBOX, pbox=PBOX, rounds=5):
        self.sbox   = sbox
        self.pbox   = pbox
        self.rounds = rounds

    def substitute(self, block: np.ndarray) -> np.ndarray:
        """
        Áp dụng S-Box lên 16 nibble của khối 64-bit.
        """
        result = np.zeros_like(block, dtype=np.uint64)
        for i in range(16):               
            shift     = np.uint64((15 - i) * 4)
            nibble    = (block >> shift) & np.uint64(0xF)      
            subbed    = self.sbox[nibble].astype(np.uint64)
            result   |= (subbed << shift)             
        return result

    def permute(self, block: np.ndarray) -> np.ndarray:
        """
        Hoán vị bit theo PBOX (Chuẩn 64-bit).
        """
        result = np.zeros_like(block, dtype=np.uint64)
        for src_pos, dst_pos in enumerate(self.pbox):
            # Trích xuất bit ở vị trí src_pos (tính từ trái sang phải, mốc 63)
            bit = (block >> np.uint64(63 - src_pos)) & np.uint64(1)
            # Dịch bit đó về đích dst_pos
            shifted = bit << np.uint64(63 - dst_pos)
            result |= shifted
        return result

    def encrypt(self, plaintexts: np.ndarray, key: int) -> np.ndarray:
        """
        Mã hóa batch N bản rõ với 1 khóa (64-bit uint64).
        """
        subkeys = self._derive_subkeys(key)
        # Ép kiểu cực kỳ nghiêm ngặt thành uint64
        data    = plaintexts.copy().astype(np.uint64)

        for r in range(self.rounds - 1):   
            data = np.bitwise_xor(data, subkeys[r])   
            data = self.substitute(data)               
            data = self.permute(data)                  

        # Vòng cuối: không có Permutation
        data = np.bitwise_xor(data, subkeys[-2])
        data = self.substitute(data)
        data = np.bitwise_xor(data, subkeys[-1])       
        return data

    def _derive_subkeys(self, master_key: int) -> list:
        """Sinh subkeys bằng rotation 64-bit."""
        # Chuyển đổi giới hạn mặt nạ lên 64-bit (16 chữ F)
        k = np.uint64(master_key & 0xFFFFFFFFFFFFFFFF)
        subkeys = []
        for i in range(self.rounds + 1):
            subkeys.append(k)
            # Rotate left 1-bit trên nền 64-bit
            k = ((k << np.uint64(1)) | (k >> np.uint64(63))) 
        return subkeys