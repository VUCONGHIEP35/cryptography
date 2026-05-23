from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import uuid
import time

app = FastAPI(title="Cryptanalysis Core API")

# Database giả lập (In-memory) để lưu trạng thái tiến trình
# Trong thực tế Backend người ta sẽ dùng Redis, nhưng ở đây dùng Dict cho nhanh
task_db = {}

# Khai báo model nhận dữ liệu từ Frontend
class AttackRequest(BaseModel):
    num_samples: int
    target_sboxes: list[int]
    expected_delta_u: int

def background_attack_task(task_id: str, req: AttackRequest):
    """Tác vụ chạy ngầm không làm treo API"""
    try:
        task_db[task_id]["status"] = "processing"
        
        # 1. Gọi DataGenerator sinh dữ liệu (req.num_samples)
        # 2. Gọi KeyRecovery.attack(...) (Bản đa luồng vừa làm)
        
        # Giả lập thời gian chạy (Cậu sẽ thay bằng code gọi hàm thật)
        time.sleep(15) 
        
        # Giả sử đây là kết quả trả về từ lõi
        result = {
            "best_key": "0xabcd",
            "hits": 1245,
            "total_samples": req.num_samples
        }
        
        task_db[task_id]["status"] = "completed"
        task_db[task_id]["result"] = result
        
    except Exception as e:
        task_db[task_id]["status"] = "failed"
        task_db[task_id]["error"] = str(e)

@app.post("/api/attack")
async def start_attack(req: AttackRequest, background_tasks: BackgroundTasks):
    """Endpoint nhận lệnh và trả về Task ID ngay lập tức"""
    task_id = str(uuid.uuid4())
    task_db[task_id] = {"status": "queued", "result": None}
    
    # Quăng tác vụ nặng vào Background, giải phóng HTTP Request
    background_tasks.add_task(background_attack_task, task_id, req)
    
    return {"message": "Task started", "task_id": task_id}

@app.get("/api/status/{task_id}")
async def get_status(task_id: str):
    """Frontend (Streamlit) sẽ gọi endpoint này mỗi giây để lấy % tiến độ"""
    if task_id not in task_db:
        return {"error": "Task not found"}
    return task_db[task_id]