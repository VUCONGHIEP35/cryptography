import numpy as np

# Import hệ sinh thái của nhóm
from core.cipher_engine import SBOX, PBOX
from core.ddt_analyzer import DDT_Analyzer
from core.path_finder import PathFinder

def extract_targets():
    print("[*] Đang nạp Ma trận DDT...")
    ddt = DDT_Analyzer(SBOX).compute()
    
    # -------------------------------------------------------------
    # 1. CẤU HÌNH ĐẦU VÀO CHO RADAR
    # Đánh 4 vòng thì Radar chỉ quét 3 vòng (Để chừa vòng 4 cho AI bẻ khóa)
    ROUNDS_TO_SCAN = 3 
    DELTA_P = 0x0000000000000011 # Sai phân đầu vào mà nhóm đã chốt
    # -------------------------------------------------------------

    print(f"[*] Khởi động Radar IDA* quét đường đi {ROUNDS_TO_SCAN} vòng...")
    radar = PathFinder(ddt, PBOX, rounds=ROUNDS_TO_SCAN)
    
    # radar.find_best_path() sẽ trả về đường đi có xác suất cao nhất
    result = radar.find_best_path(DELTA_P)
    
    if result.get("path") is None:
        print("[-] Radar không tìm thấy đường đi nào!")
        return

    print("\n=== KẾT QUẢ TỪ RADAR ===")
    print(f"[*] Xác suất của đường đi: {result['probability']}")
    
    # -------------------------------------------------------------
    # 2. TRÍCH XUẤT EXPECTED_U VÀ TARGET_SBOXES
    # -------------------------------------------------------------
    # result['path'] là một danh sách các bước. Ta lấy Delta Output của vòng cuối cùng
    expected_u = result['path'][-1][0]
    
    # Tìm xem S-Box nào đang bị kích hoạt (nibble != 0)
    target_sboxes = []
    for i in range(16):
        # Dịch bit để lấy từng cụm 4-bit từ trái sang phải (S-Box 0 đến 15)
        shift = (15 - i) * 4
        nibble = (expected_u >> shift) & 0xF
        if nibble != 0:
            target_sboxes.append(i)

    print("\n🚀 HÃY COPY 2 DÒNG DƯỚI ĐÂY DÁN VÀO test_real_attack.py:\n")
    print("-" * 50)
    print(f"EXPECTED_U = {hex(expected_u)}")
    print(f"TARGET_SBOXES = {target_sboxes}")
    print("-" * 50)

if __name__ == '__main__':
    extract_targets()