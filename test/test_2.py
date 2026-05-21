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

print("=========================================================")
print("   [+] HỆ THỐNG SĂN VÒNG LẶP VI PHÂN (ITERATIVE HUNTER)  ")
print("=========================================================")

# 1. Khởi tạo hệ thống
analyzer = DDT_Analyzer(SBOX)
ddt_matrix = analyzer.compute()

# SĂN CHU KỲ 2 VÒNG
ROUNDS = 2
finder = PathFinder(ddt_matrix, PBOX, rounds=ROUNDS)

# 2. Sinh 240 điểm xuất phát (1 S-Box kích hoạt)
start_deltas = []
for pos in range(16):
    for val in range(1, 16):
        delta = val << ((15 - pos) * 4)
        start_deltas.append(delta)

iterative_treasures = [] # Giỏ đựng "báu vật" (các vòng lặp tìm được)

print(f"[*] Bắt đầu thả lưới {len(start_deltas)} điểm xuất phát tiềm năng...")
start_time = time.time()

# 3. Quét và Lọc Vòng Lặp
for idx, delta_in in enumerate(start_deltas):
    # Log tiến độ (ẩn bớt cho đỡ rối màn hình, chỉ in mỗi 40 bước)
    if (idx + 1) % 40 == 0:
        print(f"    ... Đã quét {idx + 1}/{len(start_deltas)} ...")
    
    # Cho máy tính tự do tìm đường tốt nhất (2 vòng thì chạy cực nhanh)
    result = finder.find_best_path(delta_in, global_limit=35.0)
    
    # Kiểm tra xem có tìm được đường không
    if result["path"] is not None:
        # Lấy trạng thái Delta đầu ra của vòng cuối cùng
        final_delta = result["path"][-1][0]
        
        # ĐIỀU KIỆN SĂN VÒNG LẶP: Đầu ra phải giống hệt Đầu vào!
        if final_delta == delta_in:
            iterative_treasures.append(result)

end_time = time.time()

# 4. Báo cáo kết quả
print("\n" + "="*57)
print(f" [*] SĂN LÙNG HOÀN TẤT TRONG {round(end_time - start_time, 2)} GIÂY!")
print("="*57)

if not iterative_treasures:
    print("[-] Không tìm thấy vòng lặp nào. Hãy kiểm tra lại thuật toán!")
else:
    print(f"[+] ĐÃ TÌM THẤY {len(iterative_treasures)} BÁU VẬT VÒNG LẶP!\n")
    
    # Sắp xếp các vòng lặp theo chi phí từ RẺ NHẤT đến đắt nhất
    iterative_treasures.sort(key=lambda x: x["best_weight"])
    
    # In ra Top 3 vòng lặp xịn nhất
    print("🏆 TOP CÁC VÒNG LẶP VÔ ĐỊCH:")
    for i, treasure in enumerate(iterative_treasures[:3]):
        print(f"\n[{i+1}] ĐƯỜNG LẶP XUẤT PHÁT TỪ: {treasure['start_delta']}")
        print(f"    - Xác suất 2 vòng: 2^(-{treasure['best_weight']})")
        print("    - Hành trình chi tiết:")
        for round_idx, step in enumerate(treasure['path']):
            print(f"      + Vòng {round_idx + 1} -> Đầu ra: {hex(step[0])} | Chi phí: {step[1]}")