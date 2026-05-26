from fastapi import FastAPI, HTTPException
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
import threading
import time

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import Any, List, Optional
import numpy as np

# Import các module lõi từ thư mục core
from core.ddt_analyzer import DDT_Analyzer
from core.cipher_engine import PRESENTCipher
from core.path_finder import PathFinder
from core.data_generator import DataGenerator
from core.key_recovery import KeyRecovery

# ==========================================
# 1. KHỞI TẠO FASTAPI & CẤU HÌNH CORS
# ==========================================
app = FastAPI(
    title="PRESENT Differential Cryptanalysis API",
    description="Backend API cho Toolkit Thám mã Vi phân (Nâng cấp hệ 64-bit)",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=4)
task_store: dict[str, dict[str, Any]] = {}
task_lock = threading.Lock()

@app.get("/")
def read_root():
    return {"message": "Hệ thống Backend (PRESENT 64-bit) đã sẵn sàng! Hãy truy cập /docs để xem API."}

# ==========================================
# 2. DATA MODELS (PYDANTIC) - BẮT LỖI ĐẦU VÀO
# ==========================================
class DDTRequest(BaseModel):
    sbox: List[int] = Field(..., description="Mảng cấu hình S-Box 16 phần tử")

    @field_validator('sbox')
    def validate_sbox(cls, v):
        if len(v) != 16:
            raise ValueError("S-Box phải có chính xác 16 phần tử")
        return v

class GenerateRequest(BaseModel):
    sbox: List[int] = Field(..., description="Mảng cấu hình S-Box 16 phần tử")
    pbox: List[int] = Field(..., description="Mảng cấu hình P-Box 64 phần tử")
    key: int = Field(..., ge=0, description="Khóa bí mật")
    samples: int = Field(10000, gt=0, description="Số lượng cặp bản rõ (N)")
    # delta_p giờ đây hỗ trợ lên tới 64-bit (0xFFFFFFFFFFFFFFFF)
    delta_p: int = Field(..., ge=1, le=18446744073709551615, description="Sai phân bản rõ 64-bit")

    @field_validator('pbox')
    def validate_pbox(cls, v):
        if len(v) != 64:
            raise ValueError("P-Box của PRESENT phải có chính xác 64 phần tử")
        return v

class PathRequest(BaseModel):
    sbox: List[int] = Field(..., description="Mảng cấu hình S-Box 16 phần tử")
    pbox: List[int] = Field(..., description="Mảng cấu hình P-Box 64 phần tử")
    rounds: int = Field(4, ge=1, le=31, description="Số vòng SPN")
    delta_in: int = Field(..., ge=1, le=18446744073709551615, description="Sai phân đầu vào 64-bit")
    global_limit: float = Field(35.0, description="Giới hạn trọng số nhánh (Cắt tỉa)")
    target_delta: Optional[int] = Field(None, description="Sai phân đầu ra mục tiêu (nếu có)")

    @field_validator('pbox')
    def validate_pbox(cls, v):
        if len(v) != 64:
            raise ValueError("P-Box của PRESENT phải có chính xác 64 phần tử")
        return v

class AttackRequest(BaseModel):
    num_samples: int = Field(..., gt=0, description="Số mẫu dữ liệu để tấn công")
    delta_p: int = Field(..., ge=1, le=18446744073709551615, description="Sai phân đầu vào 64-bit")
    secret_key: int = Field(..., ge=0, description="Khóa bí mật")
    target_sboxes: List[int] = Field(..., description="Danh sách S-Box mục tiêu")
    expected_delta_u: int = Field(..., ge=0, le=18446744073709551615, description="Sai phân đầu ra kỳ vọng")
    rounds: int = Field(4, ge=1, le=31, description="Số vòng cipher")

    @field_validator('target_sboxes')
    def validate_target_sboxes(cls, v):
        if not v:
            raise ValueError("target_sboxes không được rỗng")
        if any(not 0 <= item <= 15 for item in v):
            raise ValueError("target_sboxes phải nằm trong khoảng 0..15")
        return v


def _set_task(task_id: str, **updates: Any) -> None:
    with task_lock:
        task_store.setdefault(task_id, {}).update(updates)


def _run_attack_task(task_id: str, req: AttackRequest) -> None:
    _set_task(task_id, status="running")
    try:
        start_time = time.perf_counter()
        cipher = PRESENTCipher(rounds=req.rounds)
        generator = DataGenerator(cipher)
        dataset = generator.generate_pairs(req.num_samples, req.delta_p, req.secret_key)

        attacker = KeyRecovery()
        result = attacker.attack(
            C=dataset["C"],
            C_star=dataset["C_star"],
            target_sboxes=req.target_sboxes,
            expected_delta_u=req.expected_delta_u,
        )
        execution_time_ms = int((time.perf_counter() - start_time) * 1000)

        _set_task(
            task_id,
            status="completed",
            result={
                "best_candidate_hex": result["best_candidate_hex"],
                "top_candidate_hex": result["best_candidate_hex"],
                "best_score": result["best_score"],
                "num_samples": req.num_samples,
                "target_sboxes": req.target_sboxes,
                "rounds": req.rounds,
                "scores": result["scores"],
                "execution_time_ms": execution_time_ms,
            },
        )
    except Exception as exc:
        _set_task(task_id, status="failed", error=str(exc))


# ==========================================
# 3. API ENDPOINTS
# ==========================================


@app.get("/api/health", tags=["System"])
def health_check():
    return {"status": "ok"}

@app.post("/api/ddt", tags=["Analysis"])
def analyze_ddt(req: DDTRequest):
    """Tính toán ma trận DDT 16x16 từ S-Box."""
    try:
        analyzer = DDT_Analyzer(req.sbox)
        ddt_matrix = analyzer.compute()
        max_prob = analyzer.max_differential_prob(ddt_matrix)

        return {
            "status": "success",
            "ddt_matrix": ddt_matrix.tolist(),
            "max_prob_pairs": [max_prob]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate", tags=["Data"])
def generate_data(req: GenerateRequest):
    """Sinh dữ liệu và mã hóa qua mạng PRESENT 64-bit."""
    try:
        cipher = PRESENTCipher(
            sbox=np.array(req.sbox, dtype=np.uint8),
            pbox=np.array(req.pbox),
            rounds=4
        )

        # Sử dụng default_rng của NumPy để sinh an toàn số nguyên 64-bit
        rng = np.random.default_rng()
        plaintexts = rng.integers(0, 2**64, size=req.samples, dtype=np.uint64)
        plaintexts_star = np.bitwise_xor(plaintexts, np.uint64(req.delta_p))

        # Mã hóa toàn bộ batch
        ciphertexts = cipher.encrypt(plaintexts, req.key)
        ciphertexts_star = cipher.encrypt(plaintexts_star, req.key)

        return {
            "status": "success",
            "samples": req.samples,
            "data": {
                # Cần cast về int của Python vì JSON không hiểu np.uint64
                "plaintexts": [int(x) for x in plaintexts],
                "ciphertexts": [int(x) for x in ciphertexts],
                "plaintexts_star": [int(x) for x in plaintexts_star],
                "ciphertexts_star": [int(x) for x in ciphertexts_star]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/path", tags=["Attack Engine"])
def find_differential_path(req: PathRequest):
    """Chạy thuật toán Branch & Bound tìm đường vi phân tối ưu."""
    try:
        # Bước 1: Tính bảng DDT trước
        ddt_matrix = DDT_Analyzer(req.sbox).compute()
        
        # Bước 2: Khởi tạo PathFinder
        finder = PathFinder(
            ddt_matrix=ddt_matrix, 
            pbox=np.array(req.pbox), 
            rounds=req.rounds
        )
        
        # Bước 3: Tìm đường đi
        result = finder.find_best_path(
            delta_in=req.delta_in,
            global_limit=req.global_limit,
            target_delta=req.target_delta
        )
        
        # Bước 4: Convert numpy types to Python native types for JSON serialization
        if result.get("path"):
            result["path"] = [
                (int(delta), float(weight)) 
                for delta, weight in result["path"]
            ]
        result["best_weight"] = float(result["best_weight"])
        result["probability"] = float(result["probability"])
        
        return {
            "status": "success",
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/attack", tags=["Attack Engine"])
def start_attack(req: AttackRequest):
    task_id = uuid4().hex
    _set_task(task_id, status="queued")
    executor.submit(_run_attack_task, task_id, req)
    return {"status": "accepted", "task_id": task_id}


@app.get("/api/status/{task_id}", tags=["Attack Engine"])
def attack_status(task_id: str):
    with task_lock:
        task = task_store.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task không tồn tại")
    return task