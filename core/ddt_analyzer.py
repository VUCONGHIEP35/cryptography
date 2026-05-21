import numpy as np

class DDT_Analyzer:
    def __init__(self, sbox: list):
        self.sbox = np.array(sbox, dtype=np.uint8)
        self.size = len(sbox)   # 16 với S-Box 4-bit

    def compute(self) -> np.ndarray:
        """
        Tính ma trận DDT kích thước (size × size).
        ddt[dx][dy] = số cặp (x, x*) với x⊕x*=dx mà SBOX[x]⊕SBOX[x*]=dy
        """
        n   = self.size
        ddt = np.zeros((n, n), dtype=np.uint8)
        x_all = np.arange(n, dtype=np.uint8)   # [0, 1, ..., 15]

        for dx in range(n):
            x_star = x_all ^ dx                        # x* = x ⊕ Δx (vectorized)
            dy_all = self.sbox[x_all] ^ self.sbox[x_star]   # ΔY cho mỗi x
            # đếm tần suất từng dy
            for dy in range(n):
                ddt[dx][dy] = np.count_nonzero(dy_all == dy)

        return ddt

    def max_differential_prob(self, ddt: np.ndarray) -> dict:
        """Trả về ô có xác suất cao nhất (trừ ddt[0][0])."""
        masked = ddt.copy().astype(float)
        masked[0, 0] = 0
        dx, dy = np.unravel_index(masked.argmax(), masked.shape)
        return {
            "dx": int(dx), "dy": int(dy),
            "count": int(ddt[dx][dy]),
            "prob": round(ddt[dx][dy] / self.size, 4)
        }

