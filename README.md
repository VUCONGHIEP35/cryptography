# Cryptography - Copy

Project này gồm 3 phần chính:

- `core/`: logic thuật toán, cipher, DDT, path finding, key recovery
- `backend/`: FastAPI backend cung cấp API cho frontend
- `frontend/`: Streamlit UI

## Chạy nhanh bằng file .bat
Nếu bạn muốn khởi động nhanh backend và frontend, có sẵn các file `.bat` ở thư mục gốc dự án:

- Bấm đúp [run_all.bat](run_all.bat) để tự tạo `venv` nếu chưa có, cài dependencies và mở đồng thời backend + frontend.
- Bấm đúp [run_backend.bat](run_backend.bat) để tự kiểm tra `venv`, tự tạo lại nếu bị copy/hỏng và chạy backend.
- Bấm đúp [run_frontend.bat](run_frontend.bat) để tự kiểm tra `venv`, tự tạo lại nếu bị copy/hỏng và chạy frontend.

Lưu ý: nếu `venv` được copy từ máy khác, các file `.bat` sẽ tự xóa và tạo lại môi trường mới bằng Python 3 có sẵn trên máy hiện tại.

Các file `.bat` sẽ ưu tiên cài theo [requirements.lock.txt](requirements.lock.txt), rồi mới dùng [requirements.txt](requirements.txt) nếu file lock không có.

`run_all.bat` sẽ dùng `python` hoặc `py -3` để tạo lại môi trường khi chưa có `venv`.

## Yêu cầu

- Python 3 trên Windows, có `python` hoặc `py`
- Windows PowerShell

## Cách chạy chuẩn

Khuyến nghị: chỉ cần bấm đúp file `.bat`, script sẽ tự kiểm tra và tự dựng lại `venv` nếu môi trường cũ bị lỗi.

### 1) Mở thư mục dự án

```powershell
cd "c:\Users\admin\Desktop\cryptography - Copy"
```

### 2) Xóa `venv` cũ nếu đã có

Nếu bạn muốn làm sạch thủ công, xóa `venv` cũ:

```powershell
Remove-Item -Recurse -Force venv
```

### 3) Tạo lại `venv` từ đầu

Nếu lệnh `python` trên máy bạn hoạt động đúng:

```powershell
python -m venv venv
```

Nếu `python` không ổn định, dùng launcher `py` của Windows:

```powershell
py -3 -m venv venv
```

### 4) Kích hoạt `venv`

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
```

Nếu kích hoạt thành công, đầu dòng terminal sẽ hiện `(venv)`.

### 5) Cài đặt thư viện

Luôn cài bằng đúng interpreter đang hoạt động:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 6) Kiểm tra môi trường

```powershell
python -m pip check
python -m pip list
```

Nếu `pip check` không báo lỗi conflict thì môi trường đã ổn.

### 7) Chạy backend

Mở một terminal PowerShell khác, vào lại thư mục dự án nếu cần, rồi chạy:

```powershell
uvicorn backend.main:app --reload --port 8000
```

Backend chạy tại:

- `http://localhost:8000`
- Tài liệu API: `http://localhost:8000/docs`

### 8) Chạy frontend Streamlit

Mở thêm một terminal khác và chạy:

```powershell
streamlit run frontend/app.py
```

Frontend chạy tại:

- `http://localhost:8501`

### 9) Dùng giao diện

Trong Streamlit:

- Backend URL mặc định là `http://localhost:8000`
- Bấm các nút `DDT`, `Path`, `Attack`
- Frontend sẽ gọi backend qua API tương ứng

## Luồng hoạt động

### Backend

`backend/main.py` cung cấp các API chính:

- `GET /api/health`
- `POST /api/ddt`
- `POST /api/path`
- `POST /api/attack`
- `GET /api/status/{task_id}`

### Frontend

`frontend/app.py` là Streamlit UI và sẽ:

- lấy DDT từ backend
- lấy path từ backend
- gửi attack lên backend
- poll trạng thái bằng `task_id`

## Kiểm tra nhanh backend

```powershell
Invoke-RestMethod http://localhost:8000/api/health
```

 

## Lỗi thường gặp

### 1) Không kích hoạt được `venv`

Chạy lại:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
```

### 2) `python` bị trỏ sai hoặc báo lỗi đường dẫn Python cũ

Xóa `venv` và tạo lại từ đầu theo các bước trên. Đây là lỗi rất thường gặp nếu `venv` được copy từ máy khác.

### 3) Thiếu thư viện

Chạy lại:

```powershell
python -m pip install -r requirements.txt
```

### 4) Frontend không kết nối được backend

Kiểm tra:

- backend đã chạy chưa
- Backend URL trong Streamlit có đúng `http://localhost:8000` không
- port `8000` có bị app khác dùng không

### 5) Streamlit không mở được

Thử chạy:

```powershell
python -m streamlit run frontend/app.py
```

## Ghi chú

- Nếu backend restart, các task đang chạy có thể mất trạng thái nếu không lưu persistent storage.
- Cấu trúc hiện tại phù hợp cho mô hình frontend -> backend -> core.
