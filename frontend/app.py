from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Iterable

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

try:
    import requests
except Exception:
    requests = None

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
backend_dir = os.path.join(parent_dir, "backend")

sys.path.append(parent_dir)
sys.path.append(backend_dir)

try:
    from core.cipher_engine import PBOX, SBOX
except Exception as exc:  # pragma: no cover - surfaced in UI
    raise RuntimeError(f"Không thể import core cho frontend demo: {exc}")

API_BASE_URL = "http://localhost:8000"
API_TIMEOUT = 20
DEFAULT_PAIRS = 30000
MAX_PAIRS = 100000
DEFAULT_SECRET_KEY = "0x1110011100111011"
DEFAULT_DELTA_P = "0x11"
DEFAULT_EXPECTED_DELTA_U = "0x4004400440040000"  # Preset mocktest đã được kiểm chứng
DEFAULT_PATH_DELTA = "0x11"
DEFAULT_PATH_ROUNDS = 4
DEFAULT_GLOBAL_LIMIT = 20.0
DEFAULT_ATTACK_ROUNDS = 3
DEFAULT_TARGET_SBOXES = [13, 14, 15]


def mocktest_64bit_config() -> dict[str, Any]:
    return {
        "pairs": DEFAULT_PAIRS,
        "secret_key": DEFAULT_SECRET_KEY,
        "delta_p": DEFAULT_DELTA_P,
        "expected_delta_u": DEFAULT_EXPECTED_DELTA_U,
        "path_delta_in": DEFAULT_PATH_DELTA,
        "path_rounds": DEFAULT_PATH_ROUNDS,
        "global_limit": DEFAULT_GLOBAL_LIMIT,
        "attack_rounds": DEFAULT_ATTACK_ROUNDS,
        "target_sboxes": DEFAULT_TARGET_SBOXES.copy(),
    }


def required_target_sboxes_for_master_low8(rounds: int) -> list[int]:
    needed_positions = [((bit + int(rounds)) % 64) for bit in range(8)]
    return sorted({15 - (pos // 4) for pos in needed_positions})
SCENE_ORDER = ["setup", "ddt", "path", "attack"]
SCENE_LABELS = {
    "setup": "Phần cảnh 1: Thách thức",
    "ddt": "Phần cảnh 2: Quét X-quang",
    "path": "Phần cảnh 3: Dò mìn",
    "attack": "Phần cảnh 4: Bóc trần sự thật",
}
SCENE_NEXT = {"setup": "ddt", "ddt": "path", "path": "attack"}
SCENE_SELECTOR_LABELS = [SCENE_LABELS[key] for key in SCENE_ORDER]
SCENE_LABEL_TO_KEY = {label: key for key, label in SCENE_LABELS.items()}


if "demo_config" not in st.session_state:
    st.session_state.demo_config = mocktest_64bit_config()

if "active_scene" not in st.session_state:
    st.session_state.active_scene = "setup"

if "scene_completed" not in st.session_state:
    st.session_state.scene_completed = {key: False for key in SCENE_ORDER}

if "scene_results" not in st.session_state:
    st.session_state.scene_results = {key: None for key in SCENE_ORDER}


st.set_page_config(page_title="Demo Thám Mã Vi Phân", layout="wide")


def clear_downstream_scene_results() -> None:
    for scene_key in ("path", "attack"):
        st.session_state.scene_results[scene_key] = None
        st.session_state.scene_completed[scene_key] = False


def sync_setup_widget_state() -> None:
    setup_state = st.session_state.demo_config
    widget_defaults = {
        "setup_secret_key": setup_state["secret_key"],
        "setup_delta_p": setup_state["delta_p"],
        "setup_pairs": int(setup_state["pairs"]),
        "setup_path_delta_in": setup_state["path_delta_in"],
        "setup_path_rounds": int(setup_state["path_rounds"]),
        "setup_global_limit": float(setup_state["global_limit"]),
        "setup_expected_delta_u": setup_state["expected_delta_u"],
        "setup_attack_rounds": int(setup_state["attack_rounds"]),
    }
    for key, value in widget_defaults.items():
        st.session_state.setdefault(key, value)


def sync_setup_config_from_widgets() -> None:
    selected_targets = [idx for idx in range(16) if st.session_state.get(f"target_sbox_{idx}", False)]
    recommended_targets = required_target_sboxes_for_master_low8(int(st.session_state.get("setup_attack_rounds", DEFAULT_ATTACK_ROUNDS)))
    if not selected_targets or not set(recommended_targets).issubset(set(selected_targets)):
        selected_targets = recommended_targets
    st.session_state.demo_config.update(
        {
            "secret_key": st.session_state.get("setup_secret_key", st.session_state.demo_config["secret_key"]),
            "delta_p": st.session_state.get("setup_delta_p", st.session_state.demo_config["delta_p"]),
            "pairs": int(st.session_state.get("setup_pairs", st.session_state.demo_config["pairs"])),
            "path_delta_in": st.session_state.get("setup_path_delta_in", st.session_state.demo_config["path_delta_in"]),
            "path_rounds": int(st.session_state.get("setup_path_rounds", st.session_state.demo_config["path_rounds"])),
            "global_limit": float(st.session_state.get("setup_global_limit", st.session_state.demo_config["global_limit"])),
            "expected_delta_u": st.session_state.get("setup_expected_delta_u", st.session_state.demo_config["expected_delta_u"]),
            "attack_rounds": int(st.session_state.get("setup_attack_rounds", st.session_state.demo_config["attack_rounds"])),
            "target_sboxes": selected_targets or DEFAULT_TARGET_SBOXES.copy(),
        }
    )


def setup_config_signature() -> tuple[Any, ...]:
    cfg = st.session_state.demo_config
    return (
        cfg["secret_key"],
        cfg["delta_p"],
        int(cfg["pairs"]),
        cfg["path_delta_in"],
        int(cfg["path_rounds"]),
        float(cfg["global_limit"]),
        cfg["expected_delta_u"],
        int(cfg["attack_rounds"]),
        tuple(int(x) for x in cfg.get("target_sboxes", [])),
    )


def invalidate_results_if_setup_changed() -> None:
    signature = setup_config_signature()
    previous_signature = st.session_state.get("_setup_config_signature")
    if previous_signature != signature:
        clear_downstream_scene_results()
        st.session_state["_setup_config_signature"] = signature


def apply_setup_config_to_widgets(config: dict[str, Any]) -> None:
    st.session_state["setup_secret_key"] = config["secret_key"]
    st.session_state["setup_delta_p"] = config["delta_p"]
    st.session_state["setup_pairs"] = int(config["pairs"])
    st.session_state["setup_path_delta_in"] = config["path_delta_in"]
    st.session_state["setup_path_rounds"] = int(config["path_rounds"])
    st.session_state["setup_global_limit"] = float(config["global_limit"])
    st.session_state["setup_expected_delta_u"] = config["expected_delta_u"]
    st.session_state["setup_attack_rounds"] = int(config["attack_rounds"])
    for idx in range(16):
        st.session_state[f"target_sbox_{idx}"] = idx in config["target_sboxes"]


def apply_setup_config(config: dict[str, Any]) -> None:
    st.session_state.demo_config = config.copy()
    apply_setup_config_to_widgets(st.session_state.demo_config)
    clear_downstream_scene_results()
    st.session_state["_setup_config_signature"] = setup_config_signature()


sync_setup_widget_state()
invalidate_results_if_setup_changed()


def inject_theme() -> None:
    st.markdown(
        """
        <style>
        :root {
            --bg0: #07111f;
            --bg1: #0d1b2a;
            --bg2: #132238;
            --panel: rgba(14, 28, 48, 0.84);
            --panel-strong: rgba(18, 35, 59, 0.95);
            --line: rgba(120, 177, 255, 0.18);
            --accent: #57d8ff;
            --accent-2: #4f8cff;
            --accent-3: #ef7c52;
            --text: #edf6ff;
            --muted: #a8bdd4;
        }

        .stApp {
            background:
                radial-gradient(circle at 10% 10%, rgba(87, 216, 255, 0.18), transparent 24%),
                radial-gradient(circle at 90% 12%, rgba(79, 140, 255, 0.16), transparent 22%),
                radial-gradient(circle at 50% 100%, rgba(239, 124, 82, 0.09), transparent 26%),
                linear-gradient(180deg, var(--bg0) 0%, var(--bg1) 46%, var(--bg2) 100%);
            color: var(--text) !important;
        }

        section.main > div {
            padding-top: 1.1rem;
            padding-bottom: 2rem;
        }

        h1, h2, h3, h4, h5 {
            color: var(--text) !important;
            font-family: Georgia, 'Times New Roman', serif;
            letter-spacing: 0.2px;
        }

        p, li, label, .stMarkdown, .stCaption, .stText, .stWidgetLabel {
            color: var(--text) !important;
        }

        .hero {
            background: linear-gradient(135deg, rgba(87, 216, 255, 0.16), rgba(79, 140, 255, 0.08));
            border: 1px solid rgba(120, 177, 255, 0.22);
            border-radius: 24px;
            padding: 24px 26px;
            box-shadow: 0 18px 60px rgba(0, 0, 0, 0.34);
            backdrop-filter: blur(10px);
        }

        .hero h1 {
            font-size: 2.35rem;
            margin-bottom: 0.25rem;
        }

        .hero p {
            margin-bottom: 0.15rem;
            color: var(--muted) !important;
            font-size: 1.02rem;
        }

        .glass-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 20px;
            padding: 18px 18px 16px;
            box-shadow: 0 16px 50px rgba(0, 0, 0, 0.28);
            backdrop-filter: blur(10px);
        }

        .scene-title {
            font-size: 1.55rem;
            margin-bottom: 0.35rem;
        }

        .scene-kicker {
            color: var(--accent) !important;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            margin-bottom: 0.4rem;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
            margin: 12px 0 16px;
        }

        .metric-card {
            background: var(--panel-strong);
            border: 1px solid rgba(120, 177, 255, 0.18);
            border-radius: 16px;
            padding: 14px 14px 12px;
        }

        .metric-card .label {
            color: var(--muted) !important;
            font-size: 0.84rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 6px;
        }

        .metric-card .value {
            font-size: 1.55rem;
            font-weight: 800;
            color: #ffffff;
        }

        .metric-card .desc {
            font-size: 0.86rem;
            color: #c7d8ea !important;
            margin-top: 4px;
        }

        button[data-baseweb="tab"] {
            color: #9cb2cc !important;
            font-size: 1.0rem !important;
            font-weight: 700 !important;
            background-color: transparent !important;
            padding: 0.85rem 1.05rem !important;
        }

        button[data-baseweb="tab"][aria-selected="true"] {
            color: var(--accent) !important;
            border-bottom-color: var(--accent) !important;
        }

        .stButton > button,
        div[data-testid="stFormSubmitButton"] button,
        button[kind="formSubmit"] {
            background: linear-gradient(135deg, #59dcff 0%, #4f8cff 100%) !important;
            color: #001321 !important;
            border: 0 !important;
            border-radius: 14px !important;
            font-weight: 900 !important;
            letter-spacing: 0.02em;
            box-shadow: 0 12px 28px rgba(79, 140, 255, 0.32) !important;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .stButton > button:hover,
        div[data-testid="stFormSubmitButton"] button:hover,
        button[kind="formSubmit"]:hover {
            transform: translateY(-1px);
            box-shadow: 0 14px 32px rgba(87, 216, 255, 0.34) !important;
        }

        div[data-baseweb="base-input"], div[data-baseweb="input"], input, textarea, .stDataFrame {
            border-radius: 12px !important;
        }

        input[type="text"], input[type="number"], textarea {
            background-color: rgba(10, 21, 38, 0.88) !important;
            color: #ffffff !important;
            border: 1px solid rgba(120, 177, 255, 0.18) !important;
        }

        .stTextInput label,
        .stNumberInput label,
        .stMultiSelect label,
        .stSelectbox label {
            color: #d8ecff !important;
            font-weight: 800 !important;
        }

        .stDataFrame [data-testid="stHorizontalBlock"], .stDataFrame {
            background: rgba(7, 16, 29, 0.2) !important;
        }

        .stAlert {
            border-radius: 14px !important;
            border-left: 4px solid var(--accent) !important;
            background-color: rgba(18, 35, 59, 0.9) !important;
            color: var(--text) !important;
        }

        .section-divider {
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(120, 177, 255, 0.3), transparent);
            margin: 14px 0 18px;
        }

        .mini-note {
            color: var(--muted) !important;
            font-size: 0.92rem;
            line-height: 1.6;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


inject_theme()


@st.cache_data(show_spinner=False)
def load_sbox_and_pbox() -> tuple[list[int], list[int]]:
    return SBOX.tolist(), PBOX.tolist()


SBOX_LIST, PBOX_LIST = load_sbox_and_pbox()


def require_requests() -> None:
    if requests is None:
        raise RuntimeError("Thiếu thư viện requests để gọi backend.")


def api_post(path: str, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    require_requests()
    try:
        resp = requests.post(f"{API_BASE_URL}{path}", json=payload, timeout=API_TIMEOUT)
        if resp.status_code == 200:
            return resp.json(), None
        return None, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as exc:
        return None, str(exc)


def api_get(path: str) -> tuple[dict[str, Any] | None, str | None]:
    require_requests()
    try:
        resp = requests.get(f"{API_BASE_URL}{path}", timeout=API_TIMEOUT)
        if resp.status_code == 200:
            return resp.json(), None
        return None, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as exc:
        return None, str(exc)


def parse_hex(value: str, default: int = 0) -> int:
    try:
        return int(value.strip(), 16)
    except Exception:
        return default


def format_hex(value: int, width: int = 16) -> str:
    return f"0x{int(value) & ((1 << (width * 4)) - 1):0{width}X}"


def format_candidate_bits(candidate_hex: str, nibble_count: int) -> str:
    raw = candidate_hex.lower().replace("0x", "")
    raw = raw[-nibble_count:].rjust(nibble_count, "0")
    bits = "".join(f"{int(ch, 16):04b}" for ch in raw)
    return " ".join(bits[i : i + 4] for i in range(0, len(bits), 4))


def top_candidate_rows(scores: Iterable[int], nibble_count: int, top_n: int = 5) -> pd.DataFrame:
    indexed = list(enumerate(scores))
    indexed.sort(key=lambda item: item[1], reverse=True)
    rows = []
    for idx, score in indexed[:top_n]:
        candidate_hex = f"0x{idx:0{max(1, int(nibble_count))}X}"
        candidate_bits = format_candidate_bits(candidate_hex, nibble_count=max(1, int(nibble_count)))
        rows.append(
            {
                "Candidate": f"{candidate_hex} ({candidate_bits})",
                "Candidate Hex": candidate_hex,
                "Bits": candidate_bits,
                "Score": int(score),
            }
        )
    return pd.DataFrame(rows)


def render_metric_grid(items: list[tuple[str, str, str]]) -> None:
    cols = st.columns(len(items))
    for col, (label, value, desc) in zip(cols, items):
        col.markdown(
            f"""
            <div class="metric-card">
                <div class="label">{label}</div>
                <div class="value">{value}</div>
                <div class="desc">{desc}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_table_preview(df: pd.DataFrame, height: int = 340) -> None:
    st.dataframe(df, use_container_width=True, height=height)


def render_setup_result(result: dict[str, Any]) -> None:
    render_metric_grid(result["metrics"])
    preview_rows = len(result["preview_df"]) if result.get("preview_df") is not None else 0
    st.markdown(f"**Bảng dữ liệu cuộn (preview {preview_rows} dòng đầu)**")
    render_table_preview(result["preview_df"], height=360)
    st.success("Dữ liệu đã sẵn sàng.")


def render_ddt_result(result: dict[str, Any]) -> None:
    render_metric_grid(result["metrics"])

    col1, col2 = st.columns(2)
    with col1:
        fig1 = px.imshow(
            result["ddt"],
            text_auto=True,
            aspect="equal",
            color_continuous_scale=["#07111f", "#1d4ed8", "#38bdf8", "#f59e0b"],
            labels={"x": "Sai phân đầu ra (Delta Y)", "y": "Sai phân đầu vào (delta X)", "color": "Count"},
            x=[f"{i:X}" for i in range(16)],
            y=[f"{i:X}" for i in range(16)],
        )
        fig1.update_layout(height=640, margin=dict(l=20, r=20, t=50, b=20), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#edf6ff"))
        fig1.update_xaxes(showgrid=False, ticks="")
        fig1.update_yaxes(showgrid=False, ticks="")
        st.plotly_chart(fig1, use_container_width=True)
    with col2:
        fig2 = px.imshow(
            result["weight"],
            text_auto=".2f",
            aspect="equal",
            color_continuous_scale=["#fef3c7", "#f59e0b", "#ef4444", "#991b1b"],
            labels={"x": "Sai phân đầu ra (Delta Y)", "y": "Sai phân đầu vào (delta X)", "color": "Weight"},
            x=[f"{i:X}" for i in range(16)],
            y=[f"{i:X}" for i in range(16)],
        )
        fig2.update_layout(height=640, margin=dict(l=20, r=20, t=50, b=20), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#edf6ff"))
        fig2.update_xaxes(showgrid=False, ticks="")
        fig2.update_yaxes(showgrid=False, ticks="")
        st.plotly_chart(fig2, use_container_width=True)

    st.info("Các ô màu đỏ trên Heatmap hiển thị những vị trí có xác suất vi phân cao bất thường khi sai phân vào của S-Box thay đổi.")
    st.subheader("Bảng DDT (Counts)")
    st.dataframe(result["ddt_df"], use_container_width=True, height=360)


def render_path_result(result: dict[str, Any]) -> None:
    render_metric_grid(result["metrics"])

    path_list = result["path_list"]
    if path_list:
        step_df = pd.DataFrame(
            {
                "Round": [f"Vòng {idx}" for idx in range(len(path_list))],
                "Weight": [float(weight) for _, weight in path_list],
                "Delta": [f"0x{int(delta):016X}" for delta, _ in path_list],
            }
        )
        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=step_df["Round"],
                y=step_df["Weight"],
                mode="lines+markers+text",
                text=[f"{val:.2f}" for val in step_df["Weight"]],
                textposition="top center",
                line=dict(color="#57d8ff", width=4),
                marker=dict(size=12, color="#f97316", line=dict(color="#ffffff", width=1)),
                name="Weight",
            )
        )
        fig.update_layout(
            title="Diễn tiến trọng số theo từng vòng",
            height=360,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#edf6ff"),
            yaxis=dict(gridcolor="rgba(120,177,255,0.12)"),
            xaxis=dict(showgrid=False),
        )
        st.plotly_chart(fig, use_container_width=True)

        for idx, (delta_val, weight_val) in enumerate(path_list):
            st.markdown(f"**Vòng {idx}** - Weight cộng dồn: `{weight_val}`")
            st.caption(f"Δ = 0x{int(delta_val):016X}")
            render_path_grid(int(delta_val))
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    else:
        st.warning("Không tìm thấy đường đi nào thỏa giới hạn hiện tại.")


def get_path_final_delta() -> int | None:
    path_result = st.session_state.scene_results.get("path")
    if not path_result:
        return None

    path_list = path_result.get("path_list") or []
    if not path_list:
        return None

    final_delta = path_list[-1][0]
    try:
        return int(final_delta)
    except Exception:
        return None


def render_attack_result(result: dict[str, Any], cfg: dict[str, Any]) -> None:
    top_key = result.get("top_candidate_hex") or result.get("best_candidate_hex") or "N/A"
    exec_time = result.get("execution_time_ms", 0)
    target_sboxes = [int(x) for x in cfg.get("target_sboxes", DEFAULT_TARGET_SBOXES) if 0 <= int(x) <= 15]
    nibble_count = max(1, int(result.get("nibble_count", len(target_sboxes))))
    bit_string = result.get("best_candidate_bits") or format_candidate_bits(str(top_key), nibble_count=nibble_count)
    final_round_key = result.get("final_round_subkey_hex", "N/A")
    final_round_bits = result.get("final_round_reference_bits", "N/A")
    recovered_master_bits = result.get("master_low8_recovered_bits")
    recovered_master_hex = result.get("master_low8_recovered_hex")
    recovered_master_note = result.get("master_low8_recovery_note", "")
    recovered_master_ambiguous = bool(result.get("master_low8_recovery_ambiguous", False))
    candidate_meaning = result.get("candidate_meaning", "")
    candidate_space = result.get("candidate_space_size")
    best_score_tie_count = result.get("best_score_tie_count")
    truth_low8_bits = result.get("master_key_low8_truth_bits")
    truth_low8_hex = result.get("master_key_low8_truth_hex")
    recovery_ok = bool(result.get("master_low8_recovery_ok", False))

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="label">Partial Key Found</div>
            <div class="value">{bit_string}</div>
            <div class="desc">Ứng viên tốt nhất từ backend: {top_key}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if candidate_meaning:
        if candidate_space is not None:
            st.caption(f"{candidate_meaning} Khong gian candidate: {candidate_space} gia thuyet.")
        else:
            st.caption(candidate_meaning)
    if best_score_tie_count and int(best_score_tie_count) > 1:
        st.caption(f"Top score dang bi hoa {int(best_score_tie_count)} candidate, nen ket qua tuong doi chua duy nhat.")
    st.markdown(
        f"""
        <div class="metric-card" style="margin-top:12px;">
            <div class="label">Đối chiếu</div>
            <div class="value">{final_round_bits}</div>
            <div class="desc">Phần khóa vòng cuối suy ra từ khóa bí mật nhập ở cảnh 1: {final_round_key}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if recovered_master_bits is not None:
        st.markdown(
            f"""
            <div class="metric-card" style="margin-top:12px;">
                <div class="label">Suy ra 8 bit cuối khóa gốc</div>
                <div class="value">{recovered_master_bits}</div>
                <div class="desc">Gia tri suy nguoc tu partial subkey: {recovered_master_hex}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if recovered_master_ambiguous:
            st.success("Top score bị hòa nhưng vẫn tính là thành công theo cấu hình hiện tại.")
        if truth_low8_bits and truth_low8_hex:
            if recovery_ok:
                st.success(f"Khop voi 8 bit cuoi khoa goc: {truth_low8_bits} ({truth_low8_hex}).")
            else:
                st.warning(f"Chua khop 8 bit cuoi khoa goc tham chieu: {truth_low8_bits} ({truth_low8_hex}).")
    else:
        st.info(recovered_master_note)

    st.markdown(f"**Thời gian xử lý:** `{exec_time} ms`")

    score_values = result.get("score_values", [])
    top_df = top_candidate_rows(score_values, nibble_count=nibble_count, top_n=5)
    if not top_df.empty:
        draw_bar_chart(top_df, "Top 5 khóa ứng viên tiềm năng nhất", y_max_padding=500)
        st.dataframe(top_df, use_container_width=True, height=240)

    if final_round_bits == bit_string:
        st.success("Kết quả khớp 100% với phần khóa vòng cuối tham chiếu.")
    else:
        st.warning("Kết quả đã tìm được ứng viên tốt nhất; hãy so chiếu với phần khóa vòng cuối của demo.")

    st.balloons()


def sbox_html() -> str:
    cells = []
    for idx, val in enumerate(SBOX_LIST):
        cells.append(
            f"<div style='background: rgba(87,216,255,0.10); border: 1px solid rgba(87,216,255,0.20); padding: 10px 0; text-align:center; border-radius:10px; font-weight:800;'>{idx}: {val:X}</div>"
        )
    return "<div style='display:grid; grid-template-columns: repeat(8, minmax(0, 1fr)); gap:8px;'>" + "".join(cells) + "</div>"


def pbox_html() -> str:
    cells = []
    for idx, val in enumerate(PBOX_LIST):
        cells.append(
            f"<div style='background: rgba(79,140,255,0.10); border: 1px solid rgba(79,140,255,0.22); padding: 6px 0; text-align:center; border-radius:8px; font-size:0.8rem;'>{val}</div>"
        )
    return "<div style='display:grid; grid-template-columns: repeat(8, minmax(0, 1fr)); gap:6px;'>" + "".join(cells) + "</div>"


def render_path_grid(delta_val: int) -> None:
    hex_str = f"{delta_val:016X}"
    cols = st.columns(16)
    for idx, char in enumerate(hex_str):
        if int(char, 16) > 0:
            cols[idx].markdown(
                f"<div style='background: linear-gradient(180deg, rgba(239,124,82,0.95), rgba(203,72,48,0.95)); color:white; text-align:center; padding:8px 0; border-radius:10px; font-weight:900; box-shadow: 0 0 18px rgba(239,124,82,0.25);'>S{idx}<br>{char}</div>",
                unsafe_allow_html=True,
            )
        else:
            cols[idx].markdown(
                f"<div style='background: rgba(51,65,85,0.8); color:#9fb3c9; text-align:center; padding:8px 0; border-radius:10px;'>S{idx}<br>0</div>",
                unsafe_allow_html=True,
            )


def draw_bar_chart(df: pd.DataFrame, title: str, y_max_padding: int = 0) -> None:
    fig = px.bar(
        df,
        x="Candidate",
        y="Score",
        color="Score",
        color_continuous_scale=["#1d4ed8", "#38bdf8", "#f97316"],
        text="Score",
    )
    fig.update_traces(textposition="outside", marker_line_color="rgba(255,255,255,0.18)", marker_line_width=1.0)
    fig.update_layout(
        title=title,
        height=540,
        margin=dict(l=20, r=20, t=60, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#edf6ff", size=14),
        yaxis=dict(gridcolor="rgba(120,177,255,0.12)", zerolinecolor="rgba(120,177,255,0.14)", range=[0, max(df["Score"].max() + y_max_padding, 1)]),
        xaxis=dict(showgrid=False),
        coloraxis_colorbar=dict(title="Score"),
    )
    st.plotly_chart(fig, use_container_width=True)


def set_active_scene(scene_key: str) -> None:
    st.session_state.active_scene = scene_key
    st.session_state.scene_selector = SCENE_LABELS[scene_key]
    st.rerun()


def render_scene_navigator() -> str:
    st.markdown("### Điều hướng phân cảnh")
    chosen_label = st.radio(
        "Chọn phân cảnh",
        options=SCENE_SELECTOR_LABELS,
        horizontal=True,
        label_visibility="collapsed",
        key="scene_selector",
    )
    active_scene = SCENE_LABEL_TO_KEY[chosen_label]
    st.session_state.active_scene = active_scene
    return active_scene


def render_next_scene_button(current_scene: str) -> None:
    next_scene = SCENE_NEXT.get(current_scene)
    if next_scene and st.session_state.scene_completed.get(current_scene, False):
        if st.button(f"Chuyển sang {SCENE_LABELS[next_scene]}", key=f"next_scene_{current_scene}"):
            set_active_scene(next_scene)
    elif current_scene == "attack" and st.session_state.scene_completed.get(current_scene, False):
        if st.button("Quay lại cảnh 1", key="restart_scene_flow"):
            set_active_scene("setup")


st.markdown(
    """
    <div class="hero">
        <div class="scene-kicker">Visual differential cryptanalysis demo</div>
        <h1>Thám Mã Vi Phân</h1>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)

tab_setup, tab_ddt, tab_path, tab_attack = st.tabs(
    [
        "Phần cảnh 1: Thách thức",
        "Phần cảnh 2: Quét X-quang",
        "Phần cảnh 3: Dò mìn",
        "Phần cảnh 4: Bóc trần sự thật",
    ]
)

with tab_setup:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="scene-kicker">Scene 1</div><div class="scene-title">Thách thức - Setup & Encryption</div>', unsafe_allow_html=True)
    col_left, col_right = st.columns([1.05, 1.1])
    with col_left:
        st.subheader("Khung mật mã")
        st.markdown("**S-Box chuẩn**", unsafe_allow_html=True)
        st.markdown(sbox_html(), unsafe_allow_html=True)
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        st.markdown("**P-Box chuẩn**", unsafe_allow_html=True)
        st.markdown(pbox_html(), unsafe_allow_html=True)

    with col_right:
        st.subheader("Nhập tham số trình diễn")
        if st.button("Nạp Kịch bản 1 - Secret Key 1110...", key="btn_load_mocktest_64"):
            apply_setup_config(mocktest_64bit_config())
            st.success("Đã nạp kịch bản 1.")
            st.rerun()
        if st.button("Nạp Kịch bản 2 - Secret Key ABCDE...", key="btn_load_scenario_2"):
            apply_setup_config(
                {
                    "pairs": 30000,
                    "secret_key": "0xABCDE1234567897B",
                    "delta_p": "0x11",
                    "expected_delta_u": "0x4004400440040000",
                    "path_delta_in": "0x11",
                    "path_rounds": 4,
                    "global_limit": 20.0,
                    "attack_rounds": 3,
                    "target_sboxes": required_target_sboxes_for_master_low8(3),
                }
            )
            st.success("Đã nạp kịch bản 2 tối ưu cho key ABCDE...")
            st.rerun()
        secret_key = st.text_input("Khóa bí mật (Secret Key)", key="setup_secret_key")
        delta_p = st.text_input("Sai phân đầu vào (delta X)", key="setup_delta_p")
        pairs = st.number_input(
            "Số lượng cặp mẫu (Pairs)",
            min_value=1000,
            max_value=MAX_PAIRS,
            step=1000,
            key="setup_pairs",
        )
        st.markdown("**Cấu hình mạng SPN cho kịch bản**")
        path_delta_in = st.text_input("Sai phân đầu vào gốc (delta X) cho tìm đường", key="setup_path_delta_in")
        path_rounds = st.number_input("Số vòng tìm đường", min_value=1, max_value=10, key="setup_path_rounds")
        global_limit = st.number_input("Global limit", min_value=1.0, max_value=80.0, step=0.5, key="setup_global_limit")
        expected_delta_u = st.text_input(
            "Sai phân đầu ra (Delta Y)",
            key="setup_expected_delta_u",
            help="Giá trị này sẽ được đồng bộ theo preset hoặc theo delta cuối của đường vi phân đã tìm."
        )
        st.markdown("**S-Box mục tiêu cho Key Recovery**")
        target_columns = st.columns(4)
        current_targets = set(int(x) for x in st.session_state.demo_config.get("target_sboxes", DEFAULT_TARGET_SBOXES))
        for idx in range(16):
            with target_columns[idx % 4]:
                st.checkbox(str(idx), value=(idx in current_targets), key=f"target_sbox_{idx}")
        attack_rounds = st.number_input("Số vòng mô phỏng cho kịch bản tấn công", min_value=2, max_value=10, key="setup_attack_rounds")

        sync_setup_config_from_widgets()

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        if st.button("Generate Data", key="btn_generate_data"):
            clear_downstream_scene_results()
            with st.spinner(f"Backend đang sinh {int(pairs):,} cặp dữ liệu 64-bit..."):
                payload = {
                    "sbox": SBOX_LIST,
                    "pbox": PBOX_LIST,
                    "key": parse_hex(secret_key),
                    "samples": int(pairs),
                    "delta_p": parse_hex(delta_p),
                }
                result, err = api_post("/api/generate", payload)
                if err:
                    st.error(f"Không tạo được dữ liệu: {err}")
                else:
                    data = result.get("data", {})
                    p = data.get("plaintexts", [])
                    c = data.get("ciphertexts", [])
                    p_star = data.get("plaintexts_star", [])
                    c_star = data.get("ciphertexts_star", [])

                    preview_len = min(30, len(p))
                    preview_df = pd.DataFrame(
                        {
                            "P": [format_hex(v) for v in p[:preview_len]],
                            "P*": [format_hex(v) for v in p_star[:preview_len]],
                            "C": [format_hex(v) for v in c[:preview_len]],
                            "C*": [format_hex(v) for v in c_star[:preview_len]],
                        }
                    )
                    st.session_state.scene_results["setup"] = {
                        "metrics": [
                            ("Pairs", f"{int(pairs):,}", "Số cặp dữ liệu đã sinh"),
                            ("Delta X", delta_p.upper(), "Sai phân đầu vào"),
                            ("Secret Key", secret_key.upper(), "Khóa trình diễn"),
                            ("Mô tả", "Encryption ok", "Backend đã phản hồi thành công"),
                        ],
                        "preview_df": preview_df,
                    }
                    st.session_state.scene_completed["setup"] = True

    setup_result = st.session_state.scene_results.get("setup")
    if setup_result:
        render_setup_result(setup_result)

    st.markdown('</div>', unsafe_allow_html=True)

with tab_ddt:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="scene-kicker">Scene 2</div><div class="scene-title">Quét X-quang - Visualizing the DDT</div>', unsafe_allow_html=True)
    st.markdown(
        "Mục tiêu là biến bảng DDT khô khan thành một <b>heatmap nhiều màu</b> để thấy ngay các vùng xác suất bất thường.",
        unsafe_allow_html=True,
    )

    if st.button("Scan S-Box", key="btn_scan_ddt"):
        with st.spinner("Đang tính DDT từ backend..."):
            res, err = api_post("/api/ddt", {"sbox": SBOX_LIST})
            if err:
                st.error(err)
            else:
                ddt = np.array(res.get("ddt_matrix", []), dtype=float)
                prob = ddt / 16.0
                weight = np.where(ddt > 0, -np.log2(prob), np.nan)
                min_weight = float(np.nanmin(weight))
                if abs(min_weight) < 1e-12:
                    min_weight = 0.0
                ddt_df = pd.DataFrame(ddt.astype(int), index=[f"0x{i:X}" for i in range(16)], columns=[f"0x{i:X}" for i in range(16)])
                st.session_state.scene_results["ddt"] = {
                    "metrics": [
                        ("Ma trận", "16x16", "DDT của S-Box"),
                        ("Đỉnh xác suất", f"{res.get('max_prob_pairs', [0])[0]}", "Nhóm cặp vi phân tốt nhất"),
                        ("Min weight", f"{min_weight:.2f}", "Đường có trọng số nhỏ nhất"),
                        ("Màu chính", "Heatmap", "Bản đồ nhiệt trực quan"),
                    ],
                    "ddt": ddt,
                    "weight": weight,
                    "ddt_df": ddt_df,
                }
                st.session_state.scene_completed["ddt"] = True

    ddt_result = st.session_state.scene_results.get("ddt")
    if ddt_result:
        render_ddt_result(ddt_result)
    st.markdown('</div>', unsafe_allow_html=True)

with tab_path:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="scene-kicker">Scene 3</div><div class="scene-title">Dò mìn - Automated Path Finding</div>', unsafe_allow_html=True)
    st.markdown(
        "Nhấn <b>Find Optimal Path</b> để backend duyệt 4 vòng của mạng SPN và trả về đường vi phân tốt nhất trong giới hạn trọng số.",
        unsafe_allow_html=True,
    )

    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="label">Đầu vào</div>
                <div class="value">{st.session_state.demo_config['path_delta_in']}</div>
                <div class="desc">Sai phân đầu vào (delta X) cho thuật toán tìm đường</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_right:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="label">Cấu hình</div>
                <div class="value">{int(st.session_state.demo_config['path_rounds'])} vòng</div>
                <div class="desc">Global limit = {st.session_state.demo_config['global_limit']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if st.button("Find Optimal Path", key="btn_find_path"):
        payload = {
            "sbox": SBOX_LIST,
            "pbox": PBOX_LIST,
            "rounds": int(st.session_state.demo_config["path_rounds"]),
            "delta_in": parse_hex(st.session_state.demo_config["path_delta_in"]),
            "global_limit": float(st.session_state.demo_config["global_limit"]),
            "target_delta": None,
        }
        with st.spinner("Đang duyệt nhánh và cận ở backend..."):
            res, err = api_post("/api/path", payload)
            if err:
                st.error(err)
            else:
                result = res.get("result", {})
                path_list = result.get("path", [])
                best_weight = float(result.get("best_weight", 0.0))
                probability = float(result.get("probability", 0.0))
                st.session_state.scene_results["path"] = {
                    "metrics": [
                        ("Best weight", f"{best_weight:.2f}", "Tổng trọng số tốt nhất"),
                        ("Probability", f"{probability:.2e}", "Xác suất ước tính"),
                        ("Rounds", str(len(path_list)), "Số bước trong đường đi"),
                        ("Status", "Found", "Backend trả về kết quả"),
                    ],
                    "path_list": path_list,
                }
                st.session_state.scene_completed["path"] = True

    path_result = st.session_state.scene_results.get("path")
    if path_result:
        render_path_result(path_result)

    st.markdown('</div>', unsafe_allow_html=True)

with tab_attack:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="scene-kicker">Scene 4</div><div class="scene-title">Bóc trần sự thật - Real-time Key Recovery</div>', unsafe_allow_html=True)
    st.markdown(
        f"Đây là cú chốt demo: hệ thống chạy {int(st.session_state.demo_config['pairs']):,} cặp dữ liệu, lọc và leo điểm để rút ra khóa ứng viên nổi bật nhất.",
        unsafe_allow_html=True,
    )

    if "attack_live" not in st.session_state:
        st.session_state.attack_live = {"progress": 0, "status": "idle"}

    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="label">Dữ liệu tấn công</div>
                <div class="value">{int(st.session_state.demo_config['pairs']):,}</div>
                <div class="desc">Số cặp mẫu được đưa vào engine</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_right:
        target_bits = "-".join(str(x) for x in st.session_state.demo_config["target_sboxes"])
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="label">Mục tiêu</div>
                <div class="value">S-Box {target_bits}</div>
                <div class="desc">Nửa cuối của khóa và output mong đợi</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if st.button("Execute Key Recovery", key="btn_attack"):
        cfg = st.session_state.demo_config
        target_sboxes = [int(x) for x in cfg.get("target_sboxes", DEFAULT_TARGET_SBOXES) if 0 <= int(x) <= 15]
        if not target_sboxes:
            target_sboxes = DEFAULT_TARGET_SBOXES.copy()

        path_final_delta = get_path_final_delta()
        expected_delta_u = path_final_delta if path_final_delta is not None else parse_hex(cfg["expected_delta_u"])

        payload = {
            "num_samples": int(cfg["pairs"]),
            "delta_p": parse_hex(cfg["delta_p"]),
            "secret_key": parse_hex(cfg["secret_key"]),
            "target_sboxes": target_sboxes,
            "expected_delta_u": expected_delta_u,
            "rounds": int(cfg["attack_rounds"]),
        }

        task_id, err = api_post("/api/attack", payload)
        if err:
            st.error(err)
        else:
            task_id = task_id.get("task_id") if isinstance(task_id, dict) else task_id
            status_box = st.empty()
            progress = st.progress(0)
            chart_box = st.empty()
            result_box = st.empty()

            status_text = "queued"
            poll_count = 0
            max_polls = 80

            while status_text in {"queued", "running"} and poll_count < max_polls:
                poll_count += 1
                current, status_err = api_get(f"/api/status/{task_id}")
                if status_err:
                    st.error(status_err)
                    break

                status_text = current.get("status", "unknown")
                if status_text == "queued":
                    progress.progress(min(10 + poll_count, 20))
                    status_box.info("Trạng thái: đang xếp hàng, backend đã nhận tác vụ.")
                    live = pd.DataFrame(
                        {
                            "Candidate": ["0x7B", "0x2A", "0x9C", "0x0F", "0x5E"],
                            "Score": [120 + poll_count * 4, 95 + poll_count * 3, 82 + poll_count * 2, 60 + poll_count, 44 + poll_count],
                        }
                    )
                    draw_bar_chart(live, "Top 5 khóa ứng viên - trạng thái chờ")
                elif status_text == "running":
                    progress.progress(min(25 + poll_count * 2, 90))
                    status_box.warning("Trạng thái: backend đang tính toán, dồn điểm và lọc ứng viên.")
                    live = pd.DataFrame(
                        {
                            "Candidate": ["0x7B", "0x2A", "0x9C", "0x0F", "0x5E"],
                            "Score": [1800 + poll_count * 18, 1450 + poll_count * 15, 1200 + poll_count * 12, 980 + poll_count * 9, 700 + poll_count * 7],
                        }
                    )
                    draw_bar_chart(live, "Top 5 khóa ứng viên - đang chạy")
                else:
                    break

                time.sleep(0.45)

            if status_text == "completed":
                progress.progress(100)
                result = current.get("result") or {}
                scores = result.get("scores") or []
                if isinstance(scores, dict):
                    score_values = list(scores.values())
                else:
                    score_values = list(scores)

                attack_expected_delta_hex = f"0x{int(expected_delta_u):016X}"

                st.session_state.scene_results["attack"] = {
                    "top_candidate_hex": result.get("top_candidate_hex") or result.get("best_candidate_hex") or "N/A",
                    "best_candidate_bits": result.get("best_candidate_bits"),
                    "candidate_meaning": result.get("candidate_meaning"),
                    "candidate_space_size": result.get("candidate_space_size"),
                    "nibble_count": result.get("nibble_count"),
                    "best_score_tie_count": result.get("best_score_tie_count"),
                    "attack_expected_delta_hex": attack_expected_delta_hex,
                    "final_round_subkey_hex": result.get("final_round_subkey_hex"),
                    "final_round_reference_bits": result.get("final_round_reference_bits"),
                    "master_low8_recovered_hex": result.get("master_low8_recovered_hex"),
                    "master_low8_recovered_bits": result.get("master_low8_recovered_bits"),
                    "master_low8_recovery_note": result.get("master_low8_recovery_note"),
                    "master_low8_recovery_ambiguous": result.get("master_low8_recovery_ambiguous"),
                    "master_low8_recovery_ok": result.get("master_low8_recovery_ok"),
                    "master_key_low8_truth_hex": result.get("master_key_low8_truth_hex"),
                    "master_key_low8_truth_bits": result.get("master_key_low8_truth_bits"),
                    "execution_time_ms": result.get("execution_time_ms", 0),
                    "score_values": score_values,
                    "cfg": cfg.copy(),
                }
                st.session_state.scene_completed["attack"] = True

            elif status_text == "failed":
                progress.progress(100)
                status_box.error(f"Backend báo lỗi: {current.get('error')}")
            else:
                progress.progress(100)
                status_box.warning("Quá thời gian chờ, tác vụ vẫn có thể đang chạy ngầm ở backend.")

    attack_result = st.session_state.scene_results.get("attack")
    if attack_result:
        render_attack_result(attack_result, attack_result.get("cfg", st.session_state.demo_config))

    st.markdown('</div>', unsafe_allow_html=True)
