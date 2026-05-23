import numpy as np
import concurrent.futures
import multiprocessing
import time

PRESENT_SBOX = np.array([0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2], dtype=np.uint8)
INV_SBOX = np.zeros(16, dtype=np.uint8)
for i in range(16):
    INV_SBOX[PRESENT_SBOX[i]] = i

# Shared Memory cho Mặt nạ Boolean
shared_masks = None
shared_num_sboxes = None

def init_worker(masks, num_sboxes):
    global shared_masks, shared_num_sboxes
    shared_masks = masks
    shared_num_sboxes = num_sboxes

def evaluate_key_chunk(chunk_range):
    start_key, end_key = chunk_range
    best_key = None
    max_hits = -1
    
    masks = shared_masks
    num_sboxes = shared_num_sboxes
    
    for candidate in range(start_key, end_key):
        # Tách khóa 16-bit thành 4 cụm nibble (4-bit)
        guess_nibbles = [(candidate >> (4 * (num_sboxes - 1 - i))) & 0xF for i in range(num_sboxes)]
        
        # Bắt đầu với mặt nạ của S-Box đầu tiên
        combined_mask = masks[0][guess_nibbles[0]]
        
        # AND ( & ) với mặt nạ của các S-Box còn lại
        for i in range(1, num_sboxes):
            combined_mask = combined_mask & masks[i][guess_nibbles[i]]
            
        # Đếm số lượng True (Đụng độ thành công trên toàn bộ 4 S-Box)
        hits = np.count_nonzero(combined_mask)
        
        if hits > max_hits:
            max_hits = hits
            best_key = candidate
            
    return best_key, max_hits

class KeyRecovery:
    def precompute_boolean_masks(self, dataset: dict, targets: list, expected_u: int):
        """Tính toán trước 16 khả năng cho mỗi S-Box độc lập"""
        C1 = dataset['C1']
        C2 = dataset['C2']
        
        # Tách đích Delta U thành các cụm 4-bit tương ứng
        expected_nibbles = [(expected_u >> ((15 - sbox_idx) * 4)) & 0xF for sbox_idx in targets]
        
        masks = {} # Lưu trữ 64 mảng Boolean (Tiêu tốn siêu ít RAM ~ 128MB)
        
        for i, sbox_idx in enumerate(targets):
            masks[i] = {}
            shift_amount = np.uint64((15 - sbox_idx) * 4)
            c1_nibbles = ((C1 >> shift_amount) & np.uint64(0xF)).astype(np.uint8)
            c2_nibbles = ((C2 >> shift_amount) & np.uint64(0xF)).astype(np.uint8)
            exp_nibble = expected_nibbles[i]
            
            # Quét 16 khóa cho riêng S-Box này
            for guess in range(16):
                u1 = INV_SBOX[c1_nibbles ^ guess]
                u2 = INV_SBOX[c2_nibbles ^ guess]
                delta_u_part = u1 ^ u2
                # Tạo mảng Boolean True/False
                masks[i][guess] = (delta_u_part == exp_nibble)
                
        return masks

    def attack(self, dataset: dict, target_sboxes: list, expected_delta_u: int):
        num_sboxes = len(target_sboxes)
        total_keys = 16 ** num_sboxes
        
        print("[*] Bắt đầu Giai đoạn Tiền xử lý (Pre-computing Boolean Masks)...")
        start_time = time.time()
        # Chuẩn bị 64 mảng đạn đạo
        masks = self.precompute_boolean_masks(dataset, target_sboxes, expected_delta_u)
        print(f"    -> Tiền xử lý xong trong {time.time() - start_time:.4f} giây!")
        
        max_workers = multiprocessing.cpu_count()
        chunk_size = total_keys // max_workers
        chunks = [(i * chunk_size, (i + 1) * chunk_size if i != max_workers - 1 else total_keys) for i in range(max_workers)]

        print(f"[*] Bắt đầu Giai đoạn Lõi quét Đa luồng: Vét {total_keys} khóa trên {max_workers} luồng CPU...")
        start_time = time.time()

        best_global_key = None
        max_global_hits = -1

        with concurrent.futures.ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=init_worker,
            initargs=(masks, num_sboxes)
        ) as executor:
            
            results = executor.map(evaluate_key_chunk, chunks)
            
            for chunk_best_key, chunk_hits in results:
                if chunk_hits > max_global_hits:
                    max_global_hits = chunk_hits
                    best_global_key = chunk_best_key

        exec_time = time.time() - start_time
        print(f"[+] Hoàn thành quét Lõi Đa luồng trong: {exec_time:.4f} giây")
        return best_global_key, max_global_hits