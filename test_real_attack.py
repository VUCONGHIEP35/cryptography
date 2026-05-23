import numpy as np
import time

# Import hệ sinh thái lõi của nhóm
from core.cipher_engine import PRESENTCipher
from core.data_generator import DataGenerator
from core.key_recovery import KeyRecovery

def extract_target_subkey(full_subkey: int, target_sboxes: list) -> int:
    """Hàm phụ trợ: Trích xuất các bit khóa con thực tế để đối chiếu với AI"""
    extracted = 0
    num_sboxes = len(target_sboxes)
    for i, sbox_idx in enumerate(target_sboxes):
        shift = (15 - sbox_idx) * 4
        nibble = (full_subkey >> np.uint64(shift)) & 0xF
        extracted |= (nibble << ((num_sboxes - 1 - i) * 4))
    return extracted

def run_real_attack():
    print("=== CHIẾN DỊCH THÁM MÃ THỰC TẾ (REAL DATA) ===")
    
    # =======================================================
    # 1. CẤU HÌNH MỤC TIÊU (Lấy từ Radar IDA*)
    # Cậu hãy thay giá trị bằng kết quả 4 S-Box mà nhóm đã chốt nhé!
    # =======================================================
    DELTA_P = 0x0000000000000011
    
    # VÍ DỤ: Cấu hình nếu đánh 4 vòng - 2 S-Box
    # EXPECTED_U = 0x0900000000000900 
    # TARGET_SBOXES = [1, 14] 
    
    # CẬU DÁN CẤU HÌNH 4 S-BOX CỦA CẬU VÀO ĐÂY:
    EXPECTED_U =  0x0900090000000900 # <-- Thay bằng Delta U thật
    TARGET_SBOXES = [1, 5 , 13]        # <-- Thay bằng S-Box thật
    
    NUM_SAMPLES = 500_000 # Nửa triệu mẫu để khởi động
    
    # Kẻ tấn công không biết Khóa bí mật này, nó chỉ nằm trong bóng tối
    SECRET_KEY = 0x1A2B3C4D5E6F7A8B9C0D 
    ROUNDS = 4 # Ép lõi mã hóa chạy số vòng tương ứng với mục tiêu IDA*
    
    # =======================================================
    # 2. KHỞI TẠO ĐỘNG CƠ VÀ SINH DỮ LIỆU
    # =======================================================
    cipher = PRESENTCipher(rounds=ROUNDS)
    generator = DataGenerator(cipher)
    
    print(f"[*] Đang sinh {NUM_SAMPLES} cặp bản rõ/mã thật với chìa khóa bí mật...")
    start_time = time.time()
    
    # DataGenerator sẽ tự gọi cipher.encrypt() để nhả ra C1 và C2
    dataset = generator.generate_pairs(NUM_SAMPLES, DELTA_P, SECRET_KEY)
    
    print(f"    -> Sinh dữ liệu hoàn tất trong {time.time() - start_time:.4f} giây!")

    # =======================================================
    # 3. GIAI ĐOẠN TẤN CÔNG BẰNG LÕI ĐA LUỒNG
    # =======================================================
    print("\n[*] Kích hoạt Cỗ máy Key Recovery Đa luồng...")
    attacker = KeyRecovery()
    best_key, hits = attacker.attack(dataset, TARGET_SBOXES, EXPECTED_U)
    
    # =======================================================
    # 4. KIỂM CHỨNG SỰ THẬT
    # =======================================================
    print("\n=== KẾT QUẢ BÁO CÁO THỰC CHIẾN ===")
    
    # Lấy lén subkey thật của vòng cuối cùng từ cỗ máy mã hóa
    subkeys = cipher._derive_subkeys(SECRET_KEY)
    actual_round_key = subkeys[ROUNDS] 
    correct_target_key = extract_target_subkey(actual_round_key, TARGET_SBOXES)
    
    print(f"🔑 Khóa thật của hệ thống (Target Bits): 0x{correct_target_key:04x}")
    print(f"🎯 Khóa tìm được (AI Dự đoán)          : 0x{best_key:04x}" if best_key is not None else "🎯 Khóa tìm được (AI Dự đoán)          : None")
    print(f"🏆 Số điểm đụng độ (Hits)              : {hits}")
    
    if best_key == correct_target_key:
        print("\n=> 🟢 [THÀNH CÔNG RỰC RỠ]! Phương pháp Vi phân đã bóc trần chìa khóa thật!")
    else:
        print("\n=> 🔴 [THẤT BẠI]. Tín hiệu chưa đủ mạnh. Hãy kéo NUM_SAMPLES lên 1 triệu hoặc 2 triệu.")

if __name__ == '__main__':
    run_real_attack()