import math
import heapq
import itertools
import numpy as np
from typing import List, Tuple, Dict, Optional

class PathFinder:
    def __init__(self, ddt_matrix: np.ndarray, pbox: np.ndarray, rounds: int = 4):
        """
        Khởi tạo bộ tìm kiếm đường vi phân tối ưu.
        
        Args:
            ddt_matrix: Ma trận DDT 16x16 (numpy array) từ DDT_Analyzer.
            pbox: Mảng cấu hình P-Box từ SPNCipher.
            rounds: Số vòng SPN cần phân tích.
        """
        self.ddt = ddt_matrix
        self.pbox = pbox
        self.rounds = rounds
        self.size = ddt_matrix.shape[0]  # Mặc định là 16
        
        # Tiền xử lý: Chuyển bảng DDT thành ma trận trọng số W = -log2(p)
        self.W = self._build_weight_matrix()
        # Tìm trọng số nhỏ nhất của 1 S-Box (dùng làm heuristic cắt nhánh)
        self.min_w_sbox = self._get_min_weight()

    def _build_weight_matrix(self) -> np.ndarray:
        """Chuyển đổi xác suất thành trọng số chi phí đồ thị."""
        W = np.full((self.size, self.size), math.inf)
        for dx in range(self.size):
            for dy in range(self.size):
                count = self.ddt[dx][dy]
                if count > 0:
                    p = count / self.size
                    W[dx][dy] = -math.log2(p)
        
        # Ép trọng số Inactive S-box (dx=0 -> dy=0) bằng 0 để không bị tính phí
        W[0][0] = 0.0
        return W

    def _get_min_weight(self) -> float:
        """Lấy trọng số W nhỏ nhất khả thi (loại trừ 0.0 của Inactive S-Box)."""
        valid_weights = self.W[self.W > 0]
        if len(valid_weights) == 0:
            return 0.0
        return float(np.min(valid_weights))

    def _split_nibbles(self, val_16bit: int) -> List[int]:
        """Cắt delta 16-bit thành 4 nibble (4-bit)."""
        return [
            (val_16bit >> 12) & 0xF,
            (val_16bit >> 8) & 0xF,
            (val_16bit >> 4) & 0xF,
            val_16bit & 0xF
        ]

    def _join_nibbles(self, nibbles: List[int]) -> int:
        """Ghép 4 nibble lại thành delta 16-bit."""
        return (nibbles[0] << 12) | (nibbles[1] << 8) | (nibbles[2] << 4) | nibbles[3]

    def _permute(self, val_16bit: int) -> int:
        """Hoán vị bit qua P-Box (Ánh xạ chuẩn với class SPNCipher)."""
        result = 0
        for src_pos, dst_pos in enumerate(self.pbox):
            bit = (val_16bit >> (15 - src_pos)) & 1
            result |= (bit << (15 - dst_pos))
        return result

    def _transitions(self, delta_in: int) -> List[Tuple[int, float]]:
        """Tìm tất cả các chuyển trạng thái khả thi qua 1 vòng SPN."""
        nibbles_in = self._split_nibbles(delta_in)
        possible_outs = []

        for nb_in in nibbles_in:
            if nb_in == 0:
                # Tối ưu: Bỏ qua tính toán nếu S-Box không kích hoạt
                possible_outs.append([(0, 0.0)])
            else:
                valid_outs = []
                for nb_out in range(1, 16):
                    weight = self.W[nb_in][nb_out]
                    if weight < math.inf:
                        valid_outs.append((nb_out, float(weight)))
                possible_outs.append(valid_outs)

        results = []
        # Tích Đề-các: Tổ hợp đầu ra của 4 S-Box
        for combo in itertools.product(*possible_outs):
            nb_outs = [item[0] for item in combo]
            w_total = sum(item[1] for item in combo)
            
            # Ghép khối và xáo trộn qua P-Box để ra delta đầu vòng sau
            delta_out_before_pbox = self._join_nibbles(nb_outs)
            delta_next = self._permute(delta_out_before_pbox)
            
            results.append((delta_next, w_total))
            
        return results

    def find_best_path(self, delta_in: int) -> Dict:
        """
        Thực thi Branch and Bound để tìm đường vi phân có xác suất cao nhất.
        
        Args:
            delta_in: Sai phân 16-bit đầu vào.
            
        Returns:
            Dict chứa trọng số tốt nhất, xác suất tương ứng và lịch sử đường đi.
        """
        w_best = math.inf
        best_path = None
        
        # Priority Queue: (w_accumulated, round_index, current_delta, path_tuple)
        pq = []
        heapq.heappush(pq, (0.0, 0, delta_in, ()))

        while pq:
            w_acc, r, delta, path = heapq.heappop(pq)

            # BOUND: Tính cận dưới. Giả sử các vòng còn lại chỉ có 1 S-Box kích hoạt
            # và nó đạt được trọng số nhỏ nhất lý tưởng.
            w_lower = w_acc + (self.rounds - r) * self.min_w_sbox
            if w_lower >= w_best:
                continue

            # LÁ: Chạm đến vòng cuối cùng
            if r == self.rounds:
                if w_acc < w_best:
                    w_best = w_acc
                    best_path = path
                continue

            # BRANCH: Mở rộng nhánh
            for delta_next, w_round in self._transitions(delta):
                w_new = w_acc + w_round
                
                # Cắt nhánh sớm trước khi đẩy vào heap
                if w_new + (self.rounds - r - 1) * self.min_w_sbox < w_best:
                    new_path = path + ((delta_next, w_round),)
                    heapq.heappush(pq, (w_new, r + 1, delta_next, new_path))

        # Chuyển đổi ngược trọng số W về xác suất p thực tế
        final_prob = 2 ** (-w_best) if w_best < math.inf else 0.0

        return {
            "start_delta": hex(delta_in),
            "best_weight": round(w_best, 4),
            "probability": final_prob,
            "path": best_path
        }