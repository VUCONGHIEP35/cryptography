import numpy as np

# 1. Chuẩn S-Box của PRESENT (Thay vì S-Box tự chế)
SBOX = np.array([0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2], dtype=np.uint8)
# 2. Chuẩn P-Box của PRESENT (Đan chéo 64 bit cực kỳ khéo léo)
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
        result = np.zeros_like(block)
        for i in range(16):               # 16 nibble × 4-bit = 64-bit
            shift     = (15 - i) * 4
            nibble    = (block >> shift) & 0xF      # trích 4-bit
            subbed    = self.sbox[nibble].astype(np.uint64)
            result   |= subbed << shift             # ghép lại
        return result

    def permute(self, block: np.ndarray) -> np.ndarray:
        """
        Hoán vị bit theo PBOX.
        block: shape [N], dtype uint16
        """
        result = np.zeros_like(block)
        for src_pos, dst_pos in enumerate(self.pbox):
            bit     = (block >> (63 - src_pos)) & 1
            shifted = (bit.astype(np.uint16) << np.uint16(15 - dst_pos)).astype(np.uint16)
            result = np.bitwise_or(result, shifted, dtype=np.uint16)
        return result

    def encrypt(self, plaintexts: np.ndarray, key: int) -> np.ndarray:
        """
        Mã hóa batch N bản rõ với 1 khóa.
        plaintexts: shape [N], dtype uint16
        key: uint16 (dùng làm subkey đơn giản cho tất cả vòng)
        """
        subkeys = self._derive_subkeys(key)
        data    = plaintexts.copy().astype(np.uint16)

        for r in range(self.rounds - 1):   # vòng 1 đến rounds-1
            data = np.bitwise_xor(data, subkeys[r])   # Key Mixing
            data = self.substitute(data)               # Substitution
            data = self.permute(data)                  # Permutation

        # Vòng cuối: không có Permutation
        data = np.bitwise_xor(data, subkeys[-2])
        data = self.substitute(data)
        data = np.bitwise_xor(data, subkeys[-1])       # whitening
        return data

    def _derive_subkeys(self, master_key: int) -> list:
        """Sinh subkeys đơn giản bằng rotation (đủ dùng cho demo)."""
        k = master_key & 0xFFFF
        subkeys = []
        for i in range(self.rounds + 1):
            subkeys.append(np.uint16(k))
            k = ((k << 1) | (k >> 15)) & 0xFFFF   # rotate left 1-bit
        return subkeys