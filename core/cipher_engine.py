import numpy as np

SBOX  = np.array([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], dtype=np.uint8)
PBOX  = np.array([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15])  # vị trí bit mới

class SPNCipher:
    def __init__(self, sbox=SBOX, pbox=PBOX, rounds=4):
        self.sbox   = sbox
        self.pbox   = pbox
        self.rounds = rounds

    def substitute(self, block: np.ndarray) -> np.ndarray:
        """
        Áp dụng S-Box lên tất cả 4 nibble của mỗi block 16-bit.
        block: shape [N], dtype uint16
        """
        result = np.zeros_like(block)
        for i in range(4):               # 4 nibble × 4-bit = 16-bit
            shift     = (3 - i) * 4
            nibble    = (block >> shift) & 0xF      # trích 4-bit
            subbed    = self.sbox[nibble].astype(np.uint16)
            result   |= subbed << shift             # ghép lại
        return result

    def permute(self, block: np.ndarray) -> np.ndarray:
        """
        Hoán vị bit theo PBOX.
        block: shape [N], dtype uint16
        """
        result = np.zeros_like(block)
        for src_pos, dst_pos in enumerate(self.pbox):
            bit     = (block >> (15 - src_pos)) & 1
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