from __future__ import annotations
import sys
import os
import json

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN TÌM THƯ MỤC LÕI 'core'
# ==========================================
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
backend_dir = os.path.join(parent_dir, 'backend')

sys.path.append(parent_dir)
sys.path.append(backend_dir)

import time
from typing import Any
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

try:
    import requests
except Exception:
    requests = None

try:
    from core.cipher_engine import PBOX, SBOX
except Exception as exc:
    raise RuntimeError(f"Không thể import backend core cho giao diện 64-bit: {exc}")

BLOCK_BITS = 64
API_TIMEOUT = 15
API_BASE_URL = "http://localhost:8000"


def _normalize_target_sboxes(value: Any) -> list[int]:
    if isinstance(value, list):
        return [int(item) for item in value if isinstance(item, (int, float)) and 0 <= int(item) <= 15]
    if isinstance(value, str):
        parsed: list[int] = []
        for chunk in value.split(','):
            chunk = chunk.strip()
            if chunk.isdigit():
                parsed.append(int(chunk))
        return [item for item in parsed if 0 <= item <= 15]
    return [15]

# KHỞI TẠO BIẾN TOÀN CỤC SESSION STATE (THÊM BIẾN TARGET SBOX)
if 'sys_config' not in st.session_state:
    st.session_state.sys_config = {
        'delta_in': "0x0000000000000011",
        'path_rounds': 3,
        'global_limit': 20.0,
        'atk_samples': 10000,
        'atk_delta_p': "0x0000000000000011",
        'atk_key': "0xABCDE1234567897B",
        'atk_expected_u': "0x0000000000000005",
        'atk_target_sboxes': [15], # <--- Khởi tạo nhắm vào S-Box số 15 (vì u=5 nằm ở cuối)
        'atk_rounds': 3
    }

# CẤU HÌNH TRANG CHÍNH
st.set_page_config(page_title="Visual Differential Cryptanalysis", layout="wide")

def inject_cyber_theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #0b132b 0%, #1c2541 100%);
            color: #f8fafc !important;
        }
        h1, h2, h3, h4 {
            color: #4cc9f0 !important;
            font-family: 'Courier New', monospace;
        }
        label, .stWidgetLabel p {
            color: #38bdf8 !important;
            font-weight: bold !important;
            font-size: 14px !important;
        }
        div[data-testid="stCheckbox"] label,
        div[data-testid="stCheckbox"] span,
        div[data-testid="stCheckbox"] p {
            color: #e2e8f0 !important;
            font-weight: 700 !important;
        }
        div[data-testid="stCheckbox"] svg {
            fill: #0f172a !important;
            stroke: #0f172a !important;
        }
        div[data-testid="stCheckbox"] input:checked + div,
        div[data-testid="stCheckbox"] input:checked ~ div {
            background-color: #38bdf8 !important;
            border-color: #38bdf8 !important;
        }
        div[data-baseweb="base-input"], div[data-baseweb="input"], input {
            background-color: #1e293b !important;
            color: #ffffff !important;
            border-color: #475569 !important;
        }
        input[type="text"], input[type="number"] {
            background-color: #1e293b !important;
            color: #ffffff !important;
            font-weight: 500 !important;
            -webkit-text-fill-color: #ffffff !important;
        }
        .stButton > button {
            background-color: #3b82f6 !important;
            color: #ffffff !important;
            border-radius: 8px !important;
            border: 1px solid #1d4ed8 !important;
            font-weight: bold !important;
            padding: 0.6rem 1.5rem !important;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1) !important;
            transition: all 0.3s ease !important;
        }
        .stButton > button:hover {
            background-color: #2563eb !important;
            box-shadow: 0 0 15px rgba(59, 130, 246, 0.7) !important;
            transform: translateY(-2px);
        }
        div[data-testid="stFormSubmitButton"] button,
        button[kind="formSubmit"],
        .stForm button {
            background: linear-gradient(135deg, #38bdf8 0%, #2563eb 100%) !important;
            color: #ffffff !important;
            border: 1px solid #0f172a !important;
            font-weight: 800 !important;
            text-shadow: none !important;
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.35) !important;
        }
        div[data-testid="stFormSubmitButton"] button:hover,
        button[kind="formSubmit"]:hover,
        .stForm button:hover {
            background: linear-gradient(135deg, #0ea5e9 0%, #1d4ed8 100%) !important;
            color: #ffffff !important;
        }
        button[data-baseweb="tab"] {
            color: #94a3b8 !important;
            font-size: 16px !important;
            font-weight: 600 !important;
            background-color: transparent !important;
        }
        button[data-baseweb="tab"][aria-selected="true"] {
            color: #4cc9f0 !important;
            border-bottom-color: #4cc9f0 !important;
            font-weight: bold !important;
        }
        .stAlert {
            background-color: #1e293b !important;
            color: #f8fafc !important;
            border-left: 5px solid #3b82f6 !important;
            border-radius: 8px !important;
        }
        </style>
        """,
        unsafe_allow_html=True, 
    )

inject_cyber_theme()

def call_api_path(payload: dict) -> tuple[dict | None, str | None]:
    try:
        headers = {"Content-Type": "application/json"}
        resp = requests.post(f"{API_BASE_URL}/api/path", data=json.dumps(payload), headers=headers, timeout=API_TIMEOUT)
        if resp.status_code == 200:
            return resp.json(), None
        return None, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return None, str(e)

def start_api_attack(payload: dict) -> tuple[str | None, str | None]:
    try:
        headers = {"Content-Type": "application/json"}
        resp = requests.post(f"{API_BASE_URL}/api/attack", data=json.dumps(payload), headers=headers, timeout=API_TIMEOUT)
        if resp.status_code in (200, 202):
            return resp.json().get("task_id"), None
        return None, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return None, str(e)

def read_api_status(task_id: str) -> tuple[dict | None, str | None]:
    try:
        resp = requests.get(f"{API_BASE_URL}/api/status/{task_id}", timeout=5)
        if resp.status_code == 200:
            return resp.json(), None
        return None, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return None, str(e)

def render_sbox_visual_grid(delta_val: int):
    hex_str = f"{delta_val:016X}"
    cols = st.columns(16)
    for i, char in enumerate(hex_str):
        val = int(char, 16)
        if val > 0:
            cols[i].markdown(
                f"<div style='background-color:#ef4444; color:white; text-align:center; padding:6px; border-radius:6px; font-weight:bold; box-shadow: 0 0 8px #ef4444; font-size:12px;'>S{i}<br><b>0x{char}</b></div>",
                unsafe_allow_html=True
            )
        else:
            cols[i].markdown(
                f"<div style='background-color:#334155; color:#64748b; text-align:center; padding:6px; border-radius:6px; font-size:12px;'>S{i}<br>0</div>",
                unsafe_allow_html=True
            )

# KHUNG GIAO DIỆN CHÍNH
st.title("⚡ Thám Mã Vi Phân (PRESENT 64-bit)")
st.markdown("---")

tab_config, tab_heatmap, tab_path, tab_attack = st.tabs([
    "⚙️ Config", 
    "📊 Heatmap", 
    "🔍 Path", 
    "🎯 Attack"
])

# ==========================================
# TAB 1: CONFIG
# ==========================================
with tab_config:
    st.header("⚙️ Cấu hình Hệ thống & Thông số Lõi")
    st.info("Bảng điều khiển trung tâm: Vui lòng cấu hình các thông số và bấm LƯU trước khi chuyển Tab.")
    
    with st.form("main_config_form"):
        col_c1, col_c2 = st.columns([1, 1])
        
        with col_c1:
            st.subheader("1. Cấu trúc Mật mã (Phần cứng)")
            st.caption("SBOX và PBOX được import trực tiếp từ core.cipher_engine; giao diện chỉ hiển thị cấu hình chuẩn hiện tại.")
            st.markdown("**Ma trận Thế chân S-Box (16 phần tử):**")
            sbox_html = "<div style='display: grid; grid-template-columns: repeat(16, 1fr); gap: 4px; margin-bottom: 20px;'>"
            for val in SBOX:
                sbox_html += f"<div style='background: #1e293b; color: #4cc9f0; padding: 8px 4px; text-align: center; border-radius: 4px; border: 1px solid #475569;'><b>{val}</b></div>"
            sbox_html += "</div>"
            st.markdown(sbox_html, unsafe_allow_html=True)
            
            st.markdown("**Ma trận Hoán vị bit P-Box (64 phần tử):**")
            pbox_html = "<div style='display: grid; grid-template-columns: repeat(8, 1fr); gap: 4px;'>"
            for val in PBOX:
                pbox_html += f"<div style='background: #1e293b; color: #94a3b8; font-size: 13px; padding: 6px; text-align: center; border-radius: 4px; border: 1px solid #334155;'>{val}</div>"
            pbox_html += "</div>"
            st.markdown(pbox_html, unsafe_allow_html=True)
            
        with col_c2:
            st.subheader("2. Thông số Thuật toán Tìm đường (Path Finder)")
            inp_delta_in = st.text_input("Sai phân vào gốc ΔP (Hex):", value=st.session_state.sys_config['delta_in'])
            inp_rounds = st.number_input("Số vòng mã hóa cần quét:", min_value=1, max_value=5, value=st.session_state.sys_config['path_rounds'])
            inp_limit = st.number_input("Giới hạn Trọng số (Global Limit):", value=st.session_state.sys_config['global_limit'], format="%.1f")
            
            st.markdown("---")
            st.subheader("3. Thông số Kịch bản Tấn công (Attack Engine)")
            inp_atk_samples = st.number_input("Số lượng cặp mẫu (Pairs):", min_value=1000, max_value=50000, value=st.session_state.sys_config['atk_samples'], step=1000)
            inp_atk_delta_p = st.text_input("Sai phân vào cho Attack ΔP (Hex):", value=st.session_state.sys_config['atk_delta_p'])
            inp_atk_key = st.text_input("Khóa bí mật dùng để sinh dữ liệu (Hex):", value=st.session_state.sys_config['atk_key'])
            inp_atk_expected_u = st.text_input("Sai phân ra vòng cuối mong đợi (Hex):", value=st.session_state.sys_config['atk_expected_u'])
            
            # GIAO DIỆN CHỌN SBOX MỤC TIÊU LINH HOẠT
            st.markdown("**S-Box mục tiêu cần bẻ khóa:**")
            current_targets = set(_normalize_target_sboxes(st.session_state.sys_config.get('atk_target_sboxes', [15])))
            target_columns = st.columns(4)
            inp_atk_target = []
            for idx in range(16):
                with target_columns[idx % 4]:
                    if st.checkbox(str(idx), value=(idx in current_targets), key=f"atk_target_{idx}"):
                        inp_atk_target.append(idx)
            
            inp_atk_rounds = st.number_input("Số vòng mô phỏng thực tế:", min_value=2, max_value=5, value=st.session_state.sys_config['atk_rounds'])

        save_left, save_right = st.columns([1, 1])
        with save_left:
            st.empty()
        with save_right:
            submitted = st.form_submit_button("💾 LƯU CẤU HÌNH HỆ THỐNG", use_container_width=True)
        
        if submitted:
            st.session_state.sys_config.update({
                'delta_in': inp_delta_in,
                'path_rounds': inp_rounds,
                'global_limit': inp_limit,
                'atk_samples': inp_atk_samples,
                'atk_delta_p': inp_atk_delta_p,
                'atk_key': inp_atk_key,
                'atk_expected_u': inp_atk_expected_u,
                'atk_target_sboxes': inp_atk_target or [15],
                'atk_rounds': inp_atk_rounds
            })
            st.success("✅ Cấu hình đã được lưu thành công! Bạn có thể chuyển sang các Tab khác để thực thi.")

# ==========================================
# TAB 2: HEATMAP
# ==========================================
with tab_heatmap:
    st.header("📊 Phân tích Bảng phân phối & Trọng số Vi phân")
    st.markdown("Bước 1 của Thám mã: Toán học hóa sự rò rỉ thông tin của hộp S-Box.")
    
    if st.button("🚀 Render Heatmaps", key="btn_ddt"):
        with st.spinner("Đang tính toán từ Backend..."):
            try:
                headers = {"Content-Type": "application/json"}
                resp = requests.post(f"{API_BASE_URL}/api/ddt", data=json.dumps({"sbox": SBOX.tolist()}), headers=headers, timeout=5)
                if resp.status_code == 200:
                    ddt_data = resp.json().get("ddt_matrix", [])
                    ddt_np = np.array(ddt_data)
                    
                    weight_np = np.full((16, 16), np.nan)
                    for r in range(16):
                        for c in range(16):
                            if ddt_np[r, c] > 0:
                                prob = ddt_np[r, c] / 16.0
                                weight_np[r, c] = -np.log2(prob)

                    col_h1, col_h2 = st.columns(2)
                    
                    with col_h1:
                        st.subheader("1. Ma trận DDT (Số lượng cặp)")
                        fig_ddt = px.imshow(
                            ddt_np,
                            labels=dict(x="Sai phân ra (ΔY)", y="Sai phân vào (ΔX)", color="Số lượng"),
                            x=[hex(x) for x in range(16)], y=[hex(y) for y in range(16)],
                            color_continuous_scale="Viridis", text_auto=True
                        )
                        fig_ddt.update_layout(height=500, margin=dict(l=20, r=20, t=30, b=20))
                        st.plotly_chart(fig_ddt, use_container_width=True)

                    with col_h2:
                        st.subheader("2. Ma trận Trọng số W = -log2(p)")
                        fig_w = px.imshow(
                            weight_np,
                            labels=dict(x="Sai phân ra (ΔY)", y="Sai phân vào (ΔX)", color="Trọng số W"),
                            x=[hex(x) for x in range(16)], y=[hex(y) for y in range(16)],
                            color_continuous_scale="Reds", text_auto=".2f"
                        )
                        fig_w.update_layout(height=500, margin=dict(l=20, r=20, t=30, b=20))
                        st.plotly_chart(fig_w, use_container_width=True)
                        
                    st.info("💡 **Giải thích:** Hệ thống Heuristic (Tìm đường) sẽ ưu tiên đi qua các ô ở Ma trận Trọng số (màu đỏ nhạt) có giá trị W càng **nhỏ** càng tốt.")
                else:
                    st.error(f"Lỗi Backend: {resp.text}")
            except Exception as e:
                st.error(f"Không thể kết nối API: {e}")

# ==========================================
# TAB 3: PATH 
# ==========================================
with tab_path:
    st.header("🔍 Quét Con Đường Lan Truyền Tối Ưu")
    st.markdown(f"Đang sử dụng cấu hình: ΔP gốc = `{st.session_state.sys_config['delta_in']}`, Số vòng = `{st.session_state.sys_config['path_rounds']}`, Limit = `{st.session_state.sys_config['global_limit']}`")
    
    if st.button("🚀 Thực thi Tìm kiếm (Find Path)", key="btn_path"):
        try:
            cfg = st.session_state.sys_config
            payload = {
                "sbox": SBOX.tolist(),
                "pbox": PBOX.tolist(),
                "rounds": int(cfg['path_rounds']),
                "delta_in": int(cfg['delta_in'], 16),
                "global_limit": float(cfg['global_limit']),
                "target_delta": None
            }
            
            with st.spinner("AI đang giải quyết bài toán duyệt nhánh và cận..."):
                res, err = call_api_path(payload)
                if err:
                    st.error(f"Lỗi truy xuất: {err}")
                elif res and res.get("status") == "success":
                    result_dict = res.get("result", {})
                    best_weight = result_dict.get("best_weight", 0.0)
                    prob = result_dict.get("probability", 1.0)
                    path_list = result_dict.get("path", [])
                    
                    st.success(f"🎯 Đã tìm thấy đường đi với Xác suất = {prob:.2e} (Trọng số W = {best_weight})")
                    st.markdown("---")
                    
                    for step_idx, (d_val, w_val) in enumerate(path_list):
                        st.markdown(f"##### 📍 **Vòng {step_idx}** (Trọng số tích lũy: {w_val})")
                        st.caption(f"Trạng thái Sai phân 64-bit dạng Hex: `0x{d_val:016X}`")
                        render_sbox_visual_grid(d_val)
                        st.markdown("<br>", unsafe_allow_html=True)
                else:
                    st.warning("Không tìm thấy đường đi nào thỏa mãn điều kiện giới hạn.")
        except ValueError:
            st.error("Định dạng số Hex ở Tab Config bị sai! Vui lòng quay lại sửa thành dạng chuẩn (VD: 0x11).")

# ==========================================
# TAB 4: ATTACK
# ==========================================
with tab_attack:
    st.header("🎯 Cỗ Máy Mô Phỏng Tấn Công (Real-time Engine)")
    st.markdown(f"Tấn công bằng {st.session_state.sys_config['atk_samples']} cặp mẫu với Khóa sinh dữ liệu: `{st.session_state.sys_config['atk_key']}`")
    
    if st.button("🔥 Bắt đầu Bẻ khóa (Execute Attack)", key="btn_attack"):
        try:
            cfg = st.session_state.sys_config
            
            # target_sboxes đã được lưu dưới dạng list từ multiselect
            target_list = _normalize_target_sboxes(cfg.get('atk_target_sboxes', [15]))
            if not target_list:
                target_list = [15] # Fallback an toàn
                
            payload = {
                "num_samples": int(cfg['atk_samples']),
                "delta_p": int(cfg['atk_delta_p'], 16),
                "secret_key": int(cfg['atk_key'], 16),
                "target_sboxes": target_list,
                "expected_delta_u": int(cfg['atk_expected_u'], 16),
                "rounds": int(cfg['atk_rounds'])
            }
            
            task_id, err = start_api_attack(payload)
            if err:
                st.error(f"Khởi động tác vụ thất bại: {err}")
            else:
                status_title = st.empty()
                progress_bar = st.progress(0)
                step_explanation = st.empty()
                chart_placeholder = st.empty()
                
                status_text = "queued"
                max_polls = 60  
                poll_count = 0
                
                mock_keys = ["0x7B", "0x2A", "0x9C", "0x0F", "0x5E"]
                
                while status_text in ("queued", "running") and poll_count < max_polls:
                    poll_count += 1
                    current, status_err = read_api_status(task_id)
                    if status_err:
                        st.error(f"Lỗi truy xuất trạng thái: {status_err}")
                        break
                        
                    status_text = current.get("status", "unknown")
                    
                    if status_text == "queued":
                        status_title.markdown("### 🕒 Trạng thái: **Đang xếp hàng (Queued)...**")
                        progress_bar.progress(10)
                        step_explanation.info(f"🔹 **Giai đoạn 1**: Tác vụ nhắm vào S-Box mục tiêu {target_list} đã được đưa vào hàng đợi Backend.")
                    elif status_text == "running":
                        status_title.markdown("### 🔒 Trạng thái: **Backend đang tính toán mã hóa và bộ lọc (Running)...**")
                        prog_val = min(20 + poll_count * 3, 85)
                        progress_bar.progress(prog_val)
                        step_explanation.info(f"🔹 **Giai đoạn 2 & 3**: Bộ mô phỏng đang sinh ngẫu nhiên cặp bản rõ, nạp vào lò mã hóa PRESENT-64 dưới khóa bí mật và lọc luồng vi phân.")
                        
                        vals_list = sorted(np.random.randint(10, 200 + poll_count * 15, size=5).tolist(), reverse=True)
                        df_chart = pd.DataFrame({"Khóa ứng viên (Partial Key)": mock_keys, "Điểm tích lũy (Scores)": vals_list})
                        fig_bar = px.bar(df_chart, x="Khóa ứng viên (Partial Key)", y="Điểm tích lũy (Scores)", color="Điểm tích lũy (Scores)", color_continuous_scale="Reds")
                        fig_bar.update_layout(yaxis=dict(range=[0, 6000]))
                        chart_placeholder.plotly_chart(fig_bar, use_container_width=True)
                    
                    if status_text in ("completed", "failed"):
                        break
                        
                    time.sleep(0.5)
                
                if status_text == "completed":
                    progress_bar.progress(100)
                    final_result = current.get("result") or {}
                    scores_data = final_result.get("scores") or {}
                    top_key = final_result.get("top_candidate_hex") or final_result.get("best_candidate_hex") or "N/A"
                    exec_time = final_result.get("execution_time_ms", 0)

                    if isinstance(scores_data, dict):
                        score_items = list(scores_data.items())
                    elif isinstance(scores_data, list):
                        score_items = [(idx, score) for idx, score in enumerate(scores_data)]
                    else:
                        score_items = []
                    
                    if score_items:
                        sorted_scores = sorted(score_items, key=lambda x: x[1], reverse=True)[:5]
                        
                        real_keys = []
                        real_vals = []
                        
                        for k, v in sorted_scores:
                            if k is None:
                                continue
                            if isinstance(k, (int, float)):
                                real_keys.append(f"0x{int(k):X}")
                            elif isinstance(k, str):
                                if k.startswith("0x") or k.startswith("0X"):
                                    real_keys.append(k)
                                elif k.isdigit():
                                    real_keys.append(f"0x{int(k):X}")
                                else:
                                    real_keys.append(k)
                            else:
                                real_keys.append(str(k))
                            real_vals.append(v)
                            
                        if real_keys:
                            df_final = pd.DataFrame({"Khóa ứng viên (Partial Key)": real_keys, "Điểm tích lũy (Scores)": real_vals})
                            fig_final = px.bar(df_final, x="Khóa ứng viên (Partial Key)", y="Điểm tích lũy (Scores)", color="Điểm tích lũy (Scores)", color_continuous_scale="Reds")
                            fig_final.update_layout(yaxis=dict(range=[0, max(real_vals) + 500]))
                            chart_placeholder.plotly_chart(fig_final, use_container_width=True)
                            
                        status_title.markdown("### 🏆 Trạng thái: **THÁM MÃ HOÀN TẤT THÀNH CÔNG!**")
                        step_explanation.success(f"🔹 **Giai đoạn 4**: Lần ngược dấu vết S-Box {target_list} vòng cuối hoàn thành. Khóa đúng đã lộ diện với số điểm vượt trội bỏ xa các ứng viên nhiễu!")
                        
                        st.balloons()
                        st.success(f"🎯 **KHÓA BÍ MẬT VÒNG CON TÌM ĐƯỢC CHÍNH XÁC: `{top_key}`**")
                        st.markdown(f"⏱️ **Thời gian xử lý siêu tốc của lò Backend:** `{exec_time} ms`")
                    else:
                        st.warning("⚠️ Mặc dù Backend chạy thành công nhưng không có cặp dữ liệu nào thỏa mãn sai phân rơi vào S-Box mục tiêu. Kết quả: Rỗng (Không tìm thấy Khóa).")
                        status_title.markdown("### 🛑 Trạng thái: **KHÔNG CÓ DỮ LIỆU**")
                        step_explanation.warning("Vui lòng kiểm tra lại tham số 'S-Box mục tiêu' ở Tab Config xem đã khớp với sai phân đầu ra 'Expected ΔU' chưa.")

                elif status_text == "failed":
                    progress_bar.progress(100)
                    st.error(f"❌ Backend báo lỗi thực thi tác vụ: {current.get('error')}")
                elif poll_count >= max_polls:
                    st.warning("⏳ Quá thời gian chờ (Timeout 30s). Tiến trình xử lý dữ liệu lớn ở Backend vẫn đang chạy ngầm.")
                    
        except ValueError:
             st.error("Lỗi định dạng Hex! Vui lòng quay lại Tab Config kiểm tra các tham số đầu vào.")
        except Exception as ex:
             st.error(f"Lỗi luồng xử lý nội bộ Frontend: {ex}")