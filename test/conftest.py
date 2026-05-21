import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.cipher_engine import SBOX, PBOX
from core.ddt_analyzer import DDT_Analyzer
from core.path_finder import PathFinder

# 1. Sinh DDT 16x16
analyzer = DDT_Analyzer(SBOX)
ddt_matrix = analyzer.compute()
# 2. Khởi tạo Kẻ tấn công

finder = PathFinder(ddt_matrix, PBOX, rounds=2)

delta_input = 0x0000000000000011 
best_path = finder.find_best_path(delta_input)

print(f"Xác suất cao nhất: {best_path['probability']}")
print("Lịch sử đường đi qua các vòng:")
for step in best_path['path']:
    print(hex(step[0]), f"| Chi phí: {step[1]}")