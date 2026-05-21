from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import numpy as np

# Import các module lõi từ thư mục core
from core.ddt_analyzer import DDT_Analyzer
from core.cipher_engine import PRESENTCipher
from core.path_finder import PathFinder

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

# ==========================================
# 3. API ENDPOINTS
# ==========================================

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
        
        return {
            "status": "success",
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))