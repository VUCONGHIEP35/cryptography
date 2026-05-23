import numpy as np
import time
from core.key_recovery import KeyRecovery

def run_stress_test():
    print("=== STRESS TEST: 4 S-BOX | 2 TRIỆU MẪU | ĐA LUỒNG ===")
    
    # 1. Giả lập một ma trận dữ liệu khổng lồ (2 triệu phần tử uint64)
    # Kích thước RAM: ~ 32MB. Rất nhẹ nhờ np.uint64!
    NUM_SAMPLES = 2_000_000
    print(f"[*] Đang sinh ma trận {NUM_SAMPLES} bản mã giả lập...")
    
    dataset = {
        'C1': np.random.randint(0, 2**64 - 1, NUM_SAMPLES, dtype=np.uint64),
        'C2': np.random.randint(0, 2**64 - 1, NUM_SAMPLES, dtype=np.uint64)
    }
    
    # 2. Cấu hình mục tiêu hạng nặng
    target_sboxes = [12, 13, 14, 15] # 4 S-Box
    expected_u = 0xABCD
    
    # 3. Kích hoạt Động cơ
    attacker = KeyRecovery()
    best_key, hits = attacker.attack(dataset, target_sboxes, expected_u)
    
    print("\n=== KẾT QUẢ ===")
    print(f"🎯 Khóa tốt nhất: {hex(best_key) if best_key is not None else 'None'}")
    print(f"🏆 Điểm đụng độ: {hits}")

if __name__ == '__main__':
    # Bắt buộc phải có dòng if __name__ == '__main__' khi dùng multiprocessing trên Windows
    run_stress_test()