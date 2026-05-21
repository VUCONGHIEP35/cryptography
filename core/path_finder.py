import math
import heapq
import numpy as np
from typing import List, Tuple, Dict, Optional

class PathFinder:
    def __init__(self, ddt_matrix: np.ndarray, pbox: np.ndarray, rounds: int = 4):
        self.ddt = ddt_matrix
        self.pbox = pbox
        self.rounds = rounds
        self.size = ddt_matrix.shape[0]  
        
        self.W = self._build_weight_matrix()
        self.min_w_sbox = self._get_min_weight()

    def _build_weight_matrix(self) -> np.ndarray:
        W = np.full((self.size, self.size), math.inf)
        for dx in range(self.size):
            for dy in range(self.size):
                count = self.ddt[dx][dy]
                if count > 0:
                    p = count / self.size
                    W[dx][dy] = -math.log2(p)
        W[0][0] = 0.0
        return W

    def _get_min_weight(self) -> float:
        valid_weights = self.W[self.W > 0]
        if len(valid_weights) == 0:
            return 0.0
        return float(np.min(valid_weights))

    def _split_nibbles(self, val_64bit: int) -> List[int]:
        return [(val_64bit >> ((15 - i) * 4)) & 0xF for i in range(16)]

    def _join_nibbles(self, nibbles: List[int]) -> int:
        result = 0
        for i in range(16):
            result |= (nibbles[i] << ((15 - i) * 4))
        return result    

    def _permute(self, val_64bit: int) -> int:
        result = 0
        for src_pos, dst_pos in enumerate(self.pbox):
            bit = (val_64bit >> (63 - src_pos)) & 1
            result |= (bit << (63 - dst_pos))
        return result

    def _transitions(self, delta_in: int, max_w_round: float) -> List[Tuple[int, float]]:
        nibbles_in = self._split_nibbles(delta_in)
        possible_outs = []

        for nb_in in nibbles_in:
            if nb_in == 0:
                possible_outs.append([(0, 0.0)])
            else:
                valid_outs = []
                for nb_out in range(1, 16):
                    weight = self.W[nb_in][nb_out]
                    if weight < math.inf:
                        valid_outs.append((nb_out, float(weight)))
                valid_outs.sort(key=lambda x: x[1])
                possible_outs.append(valid_outs)

        results = []

        def build_combinations(idx: int, current_w: float, current_nb_outs: List[int]):
            if current_w > max_w_round:
                return

            if idx == 16:
                delta_out = self._join_nibbles(current_nb_outs)
                delta_next = self._permute(delta_out)
                results.append((delta_next, current_w))
                return

            for nb_out, w in possible_outs[idx]:
                build_combinations(idx + 1, current_w + w, current_nb_outs + [nb_out])

        build_combinations(0, 0.0, [])
        return results

    # ĐÃ THÊM THAM SỐ global_limit VÀO ĐÂY
    # SỬA LẠI DÒNG NÀY: Thêm target_delta: int = None
    def find_best_path(self, delta_in: int, global_limit: float = 35.0, target_delta: int = None) -> Dict:
        def calc_heuristic(r_current, current_delta):
            active_count = sum(1 for nb in self._split_nibbles(current_delta) if nb != 0)
            remaining_rounds = self.rounds - r_current
            if remaining_rounds > 0:
                return (active_count * self.min_w_sbox) + (remaining_rounds - 1) * self.min_w_sbox
            return 0.0

        start_limit = calc_heuristic(0, delta_in)
        if start_limit == 0: 
            start_limit = self.rounds * self.min_w_sbox

        current_limit = start_limit
        
        while current_limit <= global_limit:
            w_best = current_limit
            best_path = None
            pq = []
            
            f_start = 0.0 + calc_heuristic(0, delta_in)
            heapq.heappush(pq, (f_start, 0, 0.0, delta_in, ()))

            visited = {}
            found = False
            
            while pq:
                f_score, neg_r, w_acc, delta, path = heapq.heappop(pq)
                r = -neg_r

                if f_score > w_best:
                    continue

                state_key = (r, delta)
                if state_key in visited and visited[state_key] <= w_acc:
                    continue
                visited[state_key] = w_acc

                if r == self.rounds:
                    # ĐÂY LÀ DÒNG QUAN TRỌNG NHẤT ĐỂ SĂN VÒNG LẶP:
                    # Nếu có mục tiêu (target_delta), đích đến bắt buộc phải khớp!
                    if target_delta is not None and delta != target_delta:
                        continue

                    if w_acc <= w_best:
                        w_best = w_acc
                        best_path = path
                        found = True
                    continue

                max_w_round = w_best - w_acc - (self.rounds - r - 1) * self.min_w_sbox
                
                if max_w_round >= 0:
                    for delta_next, w_round in self._transitions(delta, max_w_round):
                        w_new = w_acc + w_round
                        f_new = w_new + calc_heuristic(r + 1, delta_next)
                        
                        if f_new <= w_best:
                            new_path = path + ((delta_next, w_round),)
                            heapq.heappush(pq, (f_new, -(r + 1), w_new, delta_next, new_path))
            
            if found:
                final_prob = 2 ** (-w_best)
                return {
                    "start_delta": hex(delta_in),
                    "best_weight": round(w_best, 4),
                    "probability": final_prob,
                    "path": best_path
                }
                
            current_limit += 1.0

        return {
            "start_delta": hex(delta_in),
            "best_weight": math.inf,
            "probability": 0.0,
            "path": None
        }