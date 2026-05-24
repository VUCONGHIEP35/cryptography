from __future__ import annotations

import time
from typing import Any

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from core.cipher_engine import PBOX, SBOX, PRESENTCipher
    from core.data_generator import DataGenerator
    from core.ddt_analyzer import DDT_Analyzer
    from core.key_recovery import KeyRecovery
    from core.path_finder import PathFinder
except Exception as exc:
    raise RuntimeError(f"Không thể import backend core cho giao diện 64-bit: {exc}")


BLOCK_BITS = 64
SBOX_SIZE = int(SBOX.size)

st.set_page_config(page_title="Bài tập nhóm cuối kỳ", layout="wide")


def inject_theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at top left, rgba(8, 74, 108, 0.27), transparent 34%),
                radial-gradient(circle at top right, rgba(227, 166, 78, 0.17), transparent 30%),
                linear-gradient(180deg, #06111a 0%, #081726 54%, #04090e 100%);
            color: #eef3f8;
        }
        .block-container { padding-top: 1.1rem; }
        .hero {
            border: 1px solid rgba(108, 191, 255, 0.22);
            border-radius: 20px;
            padding: 1.15rem 1.2rem;
            background: linear-gradient(135deg, rgba(9, 21, 34, 0.96), rgba(10, 31, 49, 0.90));
        }
        .card {
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 14px;
            padding: 0.8rem 1rem;
            background: rgba(255, 255, 255, 0.04);
        }
        .soft { color: #bed0df; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def parse_hex(value: str, width_bits: int) -> int:
    text = value.strip().lower().replace(" ", "")
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        return 0
    return int(text, 16) & ((1 << width_bits) - 1)


def parse_sbox_list(text: str) -> list[int]:
    cleaned = text.replace(" ", "")
    if not cleaned:
        return []
    out = [int(part) for part in cleaned.split(",") if part != ""]
    return [value for value in out if 0 <= value <= 15]


@st.cache_data(show_spinner=False)
def get_mock_ddt(seed: int = 64) -> np.ndarray:
    rng = np.random.default_rng(seed)
    matrix = rng.choice([0, 2, 4, 6, 8], size=(SBOX_SIZE, SBOX_SIZE), p=[0.47, 0.24, 0.15, 0.1, 0.04])
    matrix[0, 0] = SBOX_SIZE
    matrix[1, 3] = 8
    matrix[3, 1] = 8
    return matrix.astype(np.uint8)


@st.cache_data(show_spinner=False)
def get_live_ddt() -> tuple[np.ndarray, dict[str, Any]]:
    analyzer = DDT_Analyzer(SBOX)
    ddt = analyzer.compute()
    return ddt, analyzer.max_differential_prob(ddt)


def strongest_cell(ddt: np.ndarray) -> dict[str, Any]:
    masked = ddt.copy().astype(float)
    masked[0, 0] = 0
    dx, dy = np.unravel_index(masked.argmax(), masked.shape)
    return {
        "dx": int(dx),
        "dy": int(dy),
        "count": int(ddt[dx][dy]),
        "prob": round(int(ddt[dx][dy]) / ddt.shape[0], 4),
    }


def start_api_attack(api_base: str, payload: dict[str, Any]) -> tuple[str | None, str | None]:
    if requests is None:
        return None, "requests chưa được cài"
    try:
        res = requests.post(f"{api_base.rstrip('/')}/api/attack", json=payload, timeout=15)
        res.raise_for_status()
        body = res.json()
        return body.get("task_id"), None
    except Exception as exc:
        return None, str(exc)


def read_api_status(api_base: str, task_id: str) -> tuple[dict[str, Any] | None, str | None]:
    if requests is None:
        return None, "requests chưa được cài"
    try:
        res = requests.get(f"{api_base.rstrip('/')}/api/status/{task_id}", timeout=10)
        res.raise_for_status()
        return res.json(), None
    except Exception as exc:
        return None, str(exc)


def build_api_attack_payload(
    num_samples: int,
    delta_p: int,
    secret_key: int,
    target_sboxes: list[int],
    expected_u: int,
    rounds: int,
) -> dict[str, Any]:
    return {
        "num_samples": int(num_samples),
        "delta_p": int(delta_p),
        "secret_key": int(secret_key),
        "target_sboxes": target_sboxes,
        "expected_delta_u": int(expected_u),
        "rounds": int(rounds),
        "block_bits": BLOCK_BITS,
    }


def run_local_attack(num_samples: int, delta_p: int, secret_key: int, target_sboxes: list[int], expected_u: int, rounds: int) -> dict[str, Any]:
    cipher = PRESENTCipher(rounds=rounds)
    generator = DataGenerator(cipher)
    attacker = KeyRecovery()

    start = time.time()
    dataset = generator.generate_pairs(num_samples, delta_p, secret_key)
    gen_time = time.time() - start

    start = time.time()
    best_key, hits = attacker.attack(dataset, target_sboxes, expected_u)
    atk_time = time.time() - start

    return {
        "best_key": None if best_key is None else hex(int(best_key)),
        "hits": int(hits),
        "num_samples": int(num_samples),
        "data_time": round(gen_time, 4),
        "attack_time": round(atk_time, 4),
    }


def build_pbox_preview() -> pd.DataFrame:
    show_bits = list(range(0, 16)) + [63]
    return pd.DataFrame(
        {
            "Bit i": show_bits,
            "P(i)": [int(PBOX[i]) for i in show_bits],
        }
    )


inject_theme()

st.markdown(
    """
    <div class="hero">
      <h1 style="margin: 0.15rem 0 0.1rem 0;">Bài tập nhóm cuối kỳ</h1>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Cấu hình chạy")
    ddt_mode = st.radio("Nguồn DDT", ["Backend 64-bit", "Mock test"], index=0)
    attack_mode = st.radio("Luồng attack", ["Local core", "API /api/attack", "Mock test"], index=0)
    api_base_url = st.text_input("Backend URL", value="http://localhost:8000")
    st.caption("Local core: chạy trực tiếp bằng module trong core/.")
    st.caption("API /api/attack: gọi backend theo Backend URL.")
    st.caption("Mock test: dùng dữ liệu giả để test UI khi core hoặc backend chưa sẵn sàng.")


tab_cfg, tab_ddt, tab_path, tab_attack = st.tabs(["⚙️ Config 64-bit", "🔥 DDT", "🧭 Path", "⚔️ Attack"])


with tab_cfg:
    st.subheader("Thiết lập 64-bit")
    left, right = st.columns(2)

    with left:
        rounds = st.slider("Số vòng mã hóa", min_value=3, max_value=8, value=4)
        delta_p_text = st.text_input("ΔP 64-bit", value="0x0000000000000011")
        expected_u_text = st.text_input("Expected ΔU 64-bit", value="0x0900090000000900")
        target_sboxes_text = st.text_input("Target S-Boxes (vd: 1,5,13)", value="1,5,13")
        num_samples = st.number_input("Số mẫu", min_value=1000, max_value=2_000_000, value=100_000, step=1000)
        secret_key_text = st.text_input("Secret key demo 80-bit", value="0x1A2B3C4D5E6F7A8B9C0D")

    with right:
        st.markdown('<div class="card"><span class="soft">Giao diện 64-bit này tích hợp trực tiếp với lõi backend của dự án và có mock fallback.</span></div>', unsafe_allow_html=True)
        st.write("**S-Box PRESENT**")
        sbox_df = pd.DataFrame([SBOX.tolist()], columns=[f"{i:X}" for i in range(SBOX_SIZE)], index=["Output"])
        st.table(sbox_df)
        st.write("**P-Box preview**")
        st.dataframe(build_pbox_preview(), use_container_width=True, hide_index=True)

    if st.button("Lưu cấu hình 64-bit"):
        st.session_state["a3_rounds"] = int(rounds)
        st.session_state["a3_delta_p"] = delta_p_text
        st.session_state["a3_expected_u"] = expected_u_text
        st.session_state["a3_target_sboxes"] = target_sboxes_text
        st.session_state["a3_num_samples"] = int(num_samples)
        st.session_state["a3_secret_key"] = secret_key_text
        st.success("Đã lưu cấu hình cho app3.")


with tab_ddt:
    st.subheader("Heatmap DDT")
    if st.button("Tính DDT 64-bit"):
        ddt = None
        best = None
        source = ""

        if ddt_mode == "Backend 64-bit":
            try:
                ddt, best = get_live_ddt()
                source = "core.ddt_analyzer"
            except Exception as exc:
                st.warning(f"Không đọc được backend nội bộ: {exc}")

        if ddt is None:
            ddt = get_mock_ddt()
            best = strongest_cell(ddt)
            source = "mock test"

        labels = [f"{i:X}" for i in range(ddt.shape[0])]
        ddt_df = pd.DataFrame(ddt, index=labels, columns=labels)

        left, right = st.columns(2)
        with left:
            fig = px.imshow(
                ddt_df,
                labels={"x": "ΔY", "y": "ΔX", "color": "Count"},
                color_continuous_scale=["#081a28", "#1a5a79", "#4cc9f0", "#ffb703"],
                template="plotly_dark",
            )
            fig.update_layout(title=f"Nguồn: {source}")
            st.plotly_chart(fig, use_container_width=True)

        with right:
            st.dataframe(ddt_df, use_container_width=True)
            st.success(f"Ô mạnh nhất: ΔX=0x{best['dx']:X} | ΔY=0x{best['dy']:X} | count={best['count']} | prob={best['prob']}")


with tab_path:
    st.subheader("PathFinder từ backend")
    if st.button("Quét đường đi vi phân"):
        rounds = int(st.session_state.get("a3_rounds", 4))
        delta_p = parse_hex(st.session_state.get("a3_delta_p", "0x0000000000000011"), 64)

        try:
            ddt = DDT_Analyzer(SBOX).compute()
            radar = PathFinder(ddt, PBOX, rounds=max(1, rounds - 1))
            result = radar.find_best_path(delta_p)
            if result.get("path") is None:
                st.warning("Không tìm thấy đường đi phù hợp.")
            else:
                st.success(f"Best weight: {result['best_weight']} | probability: {result['probability']}")
                rows = []
                for idx, node in enumerate(result["path"], start=1):
                    rows.append({"Round": idx, "Delta": hex(int(node[0])), "Weight": float(node[1])})
                st.dataframe(pd.DataFrame(rows), use_container_width=True)
        except Exception as exc:
            st.error(f"Lỗi PathFinder: {exc}")


with tab_attack:
    st.subheader("Attack 64-bit")

    if st.button("Chạy attack 64-bit"):
        rounds = int(st.session_state.get("a3_rounds", 4))
        delta_p = parse_hex(st.session_state.get("a3_delta_p", "0x0000000000000011"), 64)
        expected_u = parse_hex(st.session_state.get("a3_expected_u", "0x0900090000000900"), 64)
        target_sboxes = parse_sbox_list(st.session_state.get("a3_target_sboxes", "1,5,13"))
        num_samples = int(st.session_state.get("a3_num_samples", 100000))
        secret_key = parse_hex(st.session_state.get("a3_secret_key", "0x1A2B3C4D5E6F7A8B9C0D"), 80)

        if attack_mode == "Local core":
            try:
                with st.spinner("Đang chạy DataGenerator + KeyRecovery..."):
                    result = run_local_attack(num_samples, delta_p, secret_key, target_sboxes, expected_u, rounds)
                st.success("Attack local hoàn tất.")
                st.json(result)
            except Exception as exc:
                st.warning(f"Attack local lỗi, chuyển qua mock: {exc}")

        elif attack_mode == "API /api/attack":
            payload = build_api_attack_payload(num_samples, delta_p, secret_key, target_sboxes, expected_u, rounds)
            task_id, err = start_api_attack(api_base_url, payload)
            if err:
                st.warning(f"Không gọi được API, chuyển sang mock: {err}")
            else:
                progress = st.progress(0)
                status_box = st.empty()
                done = False
                for step in range(1, 91):
                    progress.progress(step / 90)
                    current, status_err = read_api_status(api_base_url, task_id)
                    if status_err:
                        status_box.warning(f"Lỗi đọc status: {status_err}")
                        break

                    status_text = current.get("status", "unknown")
                    status_box.info(f"Task {task_id} | status: {status_text}")
                    if status_text in ("completed", "failed"):
                        done = True
                        if status_text == "completed":
                            st.success("Attack hoàn tất từ backend API")
                            st.json(current.get("result", {}))
                        else:
                            st.error(f"Task failed: {current.get('error', 'unknown')}")
                        break
                    time.sleep(0.5)

                if not done:
                    st.warning("Task chưa kết thúc trong thời gian chờ của frontend. Bạn có thể bấm lại để kiểm tra tiếp.")
                    st.code(task_id)
                    st.caption("Dùng lại task_id này để query tiếp endpoint /api/status/{task_id} nếu cần.")
                st.stop()

        # Mock fallback
        progress = st.progress(0)
        log_box = st.empty()
        chart_box = st.empty()

        candidates = ["0x4F1A", "0xA1C3", "0x22DD", "0x8B7E", "0x1C90"]
        scores = [4, 5, 3, 5, 2]

        for idx in range(1, 121):
            progress.progress(idx / 120)
            if idx in (1, 30, 60, 90):
                log_box.code(f"Mock attack step {idx} | target_sboxes={target_sboxes} | expected_u={hex(expected_u)}")

            if idx % 12 == 0:
                scores = [value + (idx % 8) for value in scores]
                scores[0] += 7
                df = pd.DataFrame({"Candidate": candidates, "Score": scores}).sort_values(by="Score", ascending=True)
                fig_bar = px.bar(df, x="Score", y="Candidate", orientation="h", template="plotly_dark")
                chart_box.plotly_chart(fig_bar, use_container_width=True)
            time.sleep(0.01)

        st.success(f"Mock result: best key candidate = {candidates[0]}")
