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

analyzer = DDT_Analyzer(SBOX)
ddt_matrix = analyzer.compute()

ROUNDS = 2
finder = PathFinder(ddt_matrix, PBOX, rounds=ROUNDS)

# TIÊM VACCINE: Đưa 0x11 (Trường hợp 2 S-Box) vào danh sách quét!
start_deltas = [0x11]
for pos in range(16):
    for val in range(1, 16):
        delta = val << ((15 - pos) * 4)
        if delta != 0x11:
            start_deltas.append(delta)

iterative_treasures = []

print(f"[*] Bắt đầu thả lưới {len(start_deltas)} điểm xuất phát tiềm năng...")
start_time = time.time()

# Khoi tao moc bang 35.0
best_global_weight = 35.0
for idx, delta_in in enumerate(start_deltas):
    # Ép AI: "Mày phải tìm đường nào quay về đúng delta_in cho tao!"
    result = finder.find_best_path(delta_in, global_limit=best_global_weight, target_delta=delta_in)
    
    if result["path"] is not None:
        iterative_treasures.append(result)

        if result['best_weight'] < best_global_weight:
            best_global_weight = result['best_weight']
            print(f"   => KỶ LỤC MỚI: Weight = {best_global_weight}!")

end_time = time.time()

print("\n" + "="*57)
print(f" [*] SĂN LÙNG HOÀN TẤT TRONG {round(end_time - start_time, 2)} GIÂY!")
print("="*57)

if not iterative_treasures:
    print("[-] Không tìm thấy vòng lặp nào.")
else:
    print(f"[+] ĐÃ TÌM THẤY {len(iterative_treasures)} BÁU VẬT VÒNG LẶP!\n")
    
    iterative_treasures.sort(key=lambda x: x["best_weight"])
    
    print("🏆 TOP CÁC VÒNG LẶP VÔ ĐỊCH:")
    for i, treasure in enumerate(iterative_treasures[:3]):
        print(f"\n[{i+1}] ĐƯỜNG LẶP XUẤT PHÁT TỪ: {treasure['start_delta']}")
        print(f"    - Xác suất 2 vòng: 2^(-{treasure['best_weight']})")
        print("    - Hành trình chi tiết:")
        for round_idx, step in enumerate(treasure['path']):
            print(f"      + Vòng {round_idx + 1} -> Đầu ra: {hex(step[0])} | Chi phí: {step[1]}")