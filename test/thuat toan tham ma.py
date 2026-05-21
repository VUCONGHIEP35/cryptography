import sys
from pathlib import Path
import math
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.cipher_engine import SBOX, PBOX
from core.ddt_analyzer import DDT_Analyzer
from core.path_finder import PathFinder

print("--- KHỞI ĐỘNG HỆ THỐNG TÌM KIẾM ĐƯỜNG VI PHÂN (4 VÒNG) ---")

# 1. Khởi tạo
analyzer = DDT_Analyzer(SBOX)
ddt_matrix = analyzer.compute()

ROUNDS = 4
finder = PathFinder(ddt_matrix, PBOX, rounds=ROUNDS)

# 2. Sinh điểm xuất phát (CHIẾN THUẬT TIÊM VACCINE)
# Đưa đường vi phân 0x11 (biết trước là rất tốt) lên đầu tiên để ép Kỷ lục xuống cực thấp!
start_deltas = [0x0000000000000011] 
for pos in range(16):
    for val in range(1, 16):
        delta = val << ((15 - pos) * 4)
        if delta != 0x11:  # Không thêm trùng lặp
            start_deltas.append(delta)

# 3. Quét với Kỷ lục toàn cục (Global Limit)
best_global_weight = 35.0  # Mốc trần ban đầu
best_global_prob = 0.0
best_global_paths = []

print(f"Đang quét {len(start_deltas)} điểm xuất phát tiềm năng...")
start_time = time.time()

for idx, delta_in in enumerate(start_deltas):
    print(f" Đang quét {idx + 1}/{len(start_deltas)} (Điểm xuất phát: {hex(delta_in)})...")
    
    # TRUYỀN best_global_weight VÀO ĐỂ CHẶT NHÁNH NGÕ CỤT SỚM
    result = finder.find_best_path(delta_in, global_limit=best_global_weight)
    
    if result["best_weight"] < best_global_weight:
        best_global_weight = result["best_weight"]
        best_global_prob = result["probability"]
        best_global_paths = [result]
        print(f"   => KỶ LỤC MỚI: Weight = {best_global_weight}!")
        
    elif result["best_weight"] == best_global_weight and result["best_weight"] < math.inf:
        best_global_paths.append(result)

end_time = time.time()

# 4. In kết quả cuối cùng
print("\n" + "="*50)
print(f" TÌM KIẾM HOÀN TẤT TRONG {round(end_time - start_time, 2)} GIÂY!")
print("="*50)
print(f"XÁC SUẤT VI PHÂN TỐT NHẤT {ROUNDS} VÒNG: 2^(-{best_global_weight}) (tương đương {best_global_prob})")
print(f"Có {len(best_global_paths)} đường đi cùng đạt được xác suất vô địch này.\n")

champ = best_global_paths[0]
print(f"[MẪU] ĐƯỜNG ĐI CHI TIẾT (Xuất phát: {champ['start_delta']}):")
for round_idx, step in enumerate(champ['path']):
    print(f"  Vòng {round_idx + 1} -> Đầu ra: {hex(step[0])} | Chi phí tích lũy vòng này: {step[1]}")