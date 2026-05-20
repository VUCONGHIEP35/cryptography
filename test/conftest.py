import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.cipher_engine import SBOX
from core.ddt_analyzer import DDT_Analyzer

analyzer = DDT_Analyzer(SBOX)

ddt_matrix = analyzer.compute()

# 3. In ma trận ra màn hình (định dạng đẹp)
print("--- Ma trận DDT (4-bit) ---")
size = len(SBOX)
print("    ", end="")
for i in range(size): print(f"{i:2x}", end=" ")
print("\n" + "----" * size)

for i in range(size):
    print(f"{i:x} |", end=" ")
    for j in range(size):
        val = ddt_matrix[i][j]
        print(f"{val:2d}" if val > 0 else " .", end=" ")
    print()