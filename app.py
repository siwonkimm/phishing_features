"""악성 URL 구조 분석 대시보드 (산업데이터시각화 개인 프로젝트)

질문: 악성 URL은 정상 URL과 구조가 어떻게 다르고,
      악성 URL 안에서는 어떤 유형(IP형 / 도메인형 / 서비스 악용)이 많은가?

실행: streamlit run app.py
데이터는 preprocess.py 가 만든 data/ 폴더의 파일을 읽습니다.
"""
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ─────────────────────────────────────────────
# 0. 설정 · 출처 (※ 제출 전에 링크를 직접 확인해서 채워 넣으세요)
# ─────────────────────────────────────────────
SOURCE_1 = "Kaggle ‘Malicious URLs dataset’ (malicious_phish.csv) — 링크: [여기에 Kaggle 페이지 URL 기입]"
SOURCE_2 = "phishing_features.csv — 출처: [여기에 다운로드 출처 기입]"
AUTHOR = "(이름)"

BASE = Path(__file__).resolve().parent  # app.py 가 있는 폴더 기준으로 data/ 를 찾음

st.set_page_config(page_title="악성 URL 구조 분석", page_icon="🔎", layout="wide")

TYPE_KO = {"benign": "정상", "defacement": "웹변조", "phishing": "피싱", "malware": "악성코드"}
TYPE_ORDER = ["정상", "웹변조", "피싱", "악성코드"]
COLORS = {"정상": "#5B8DEF", "웹변조": "#F5A623", "피싱": "#EF6B6B", "악성코드": "#3CB98A"}
GREEN, BLUE, GRAY = "#2EAD78", "#3B82F6", "#EEF1F5"
FONT = "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Noto Sans KR, sans-serif"

FEATURES = {
    "url_length": "URL 길이",
    "num_digits": "숫자 개수",
    "num_dots": "점(.) 개수",
    "num_hyphens": "하이픈(-) 개수",
    "num_slashes": "경로 깊이",
    "num_params": "파라미터 수",
}

SHORT = {"url_length": "길이", "num_digits": "숫자", "num_dots": "점", "num_hyphens": "하이픈", "num_slashes": "경로 깊이", "num_params": "파라미터"}

# ─────────────────────────────────────────────
# 1. 스타일 (카드형 디자인)
# ─────────────────────────────────────────────
st.markdown(
    """
<style>
@import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.css');
.stApp {font-family:'Pretendard Variable',Pretendard,'Apple SD Gothic Neo','Noto Sans KR',sans-serif; background:#EEF1F6;}
#MainMenu, footer {visibility:hidden;}
header[data-testid="stHeader"] {background:transparent;}
.block-container {padding-top:1.6rem; max-width:1400px;}

/* 사이드바 */
section[data-testid="stSidebar"] {background:#FFFFFF; border-right:1px solid #E6E9EF;}
.brand {font-size:1.55rem; font-weight:800; color:#2EAD78; letter-spacing:-0.5px; margin:.2rem 0 0;}
.brand-sub {font-size:.8rem; color:#9AA3AF; margin-bottom:1.2rem;}
[class*="st-key-nav_"] button, [class*="st-key-navon_"] button {
  width:100%; justify-content:flex-start; border:0; border-radius:10px;
  padding:.55rem .8rem; background:transparent; box-shadow:none;
  transition:background .2s ease, transform .2s ease;}
[class*="st-key-nav_"] button p, [class*="st-key-navon_"] button p {
  text-align:left; font-weight:600; font-size:.95rem; color:#4B5563;}
[class*="st-key-nav_"] button:hover {background:#F3F5F8;}
[class*="st-key-nav_"] button:hover, [class*="st-key-navon_"] button:hover {transform:translateX(3px);}
[class*="st-key-navon_"] button {background:#E6F6EE;}
[class*="st-key-navon_"] button p {color:#1F9D68;}

/* 카드 */
[class*="st-key-card"] {background:#FFFFFF; border-radius:18px; padding:20px 22px;
  box-shadow:0 1px 3px rgba(16,24,40,.06); height:100%;
  animation:cardIn .55s cubic-bezier(.22,.61,.36,1) both;
  transition:transform .25s ease, box-shadow .25s ease;}
[class*="st-key-card"]:hover {
  transform:translateY(-3px);
  box-shadow:0 10px 24px rgba(16,24,40,.10);}
[class*="st-key-card"]:nth-of-type(2n) {animation-delay:.09s;}
[class*="st-key-card"] [data-testid="stMarkdownContainer"] {
  color:#374151;
  font-size:.92rem;
  line-height:1.75;
}
[class*="st-key-card"] [data-testid="stMarkdownContainer"] p,
[class*="st-key-card"] [data-testid="stMarkdownContainer"] li {
  color:#374151;
  font-size:.92rem;
  line-height:1.75;
  opacity:1;
}
[class*="st-key-card"] [data-testid="stMarkdownContainer"] strong {
  color:#1F2937;
  font-weight:800;
}
.st-key-card_dash_e, .st-key-card_dash_f, .st-key-card_dash_g {min-height:330px;}
.ch {display:flex; align-items:center; gap:10px; margin-bottom:.5rem;
  animation:fadeSlide .45s ease both;}
.ci {width:30px; height:30px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:1rem;
  animation:iconPop .5s cubic-bezier(.34,1.56,.64,1) both;}
.ct {font-size:1.08rem; font-weight:700; color:#1F2937; line-height:1.2;}
.cs {font-size:.76rem; color:#9AA3AF; margin-top:2px;}

/* 공지 바 */
.notice {background:#FFFFFF; border-radius:14px; padding:16px 22px; display:flex; gap:18px;
  align-items:center; box-shadow:0 1px 3px rgba(16,24,40,.06); font-size:.92rem; color:#374151;}
.notice b {color:#1F2937; white-space:nowrap;}
.notice span.r {margin-left:auto; color:#B0B7C3; font-size:.82rem; white-space:nowrap;}

/* 수치 타일 */
.tiles {display:grid; gap:10px;}
.tiles2 {grid-template-columns:repeat(2,1fr);} .tiles4 {grid-template-columns:repeat(4,1fr);}
.tile {background:#F5F7FA; border-radius:12px; padding:14px 16px;
  animation:fadeSlide .45s ease both;
  transition:transform .2s ease, background .2s ease;}
.tile:hover {background:#EEF3FA; transform:translateY(-2px);}
.stPlotlyChart {animation:fadeSlide .55s .05s ease both;}
.tl {font-size:.78rem; color:#6B7280; margin-bottom:6px;}
.tv {font-size:1.45rem; font-weight:700; color:#374151; letter-spacing:-0.5px;}
.dot {display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px;}

/* 리스트 행 */
.row {display:flex; justify-content:space-between; padding:12px 2px; border-bottom:1px solid #EEF0F3;
  font-size:.92rem; color:#374151;}
.row:last-child {border-bottom:0;}
.row b {color:#1F2937;} .row i {color:#9AA3AF; font-style:normal;}

.pt {font-size:1.3rem; font-weight:800; color:#1F2937; margin:.2rem 0 .2rem;
  animation:fadeSlide .45s ease both;}
.pts {font-size:.85rem; color:#9AA3AF; margin-bottom:1rem;
  animation:fadeSlide .45s .08s ease both;}
.foot {font-size:.75rem; color:#9AA3AF; margin-top:1.2rem;}

@keyframes cardIn {
  from {opacity:0; transform:translateY(14px) scale(.985);}
  to {opacity:1; transform:translateY(0) scale(1);}
}
@keyframes fadeSlide {
  from {opacity:0; transform:translateY(8px);}
  to {opacity:1; transform:translateY(0);}
}
@keyframes iconPop {
  0% {opacity:0; transform:scale(.65) rotate(-8deg);}
  70% {transform:scale(1.08) rotate(2deg);}
  100% {opacity:1; transform:scale(1) rotate(0);}
}

@media (prefers-reduced-motion: reduce) {
  [class*="st-key-card"], .ch, .ci, .pt, .pts, .tile, .stPlotlyChart,
  [class*="st-key-nav_"] button, [class*="st-key-navon_"] button {
    animation:none !important;
    transition:none !important;
  }
}
</style>
""",
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────
# 2. 데이터 불러오기 (한 번만 읽고 캐시)
# ─────────────────────────────────────────────
@st.cache_data
def load_main():
    df = pd.read_parquet(BASE / "data" / "phish_features.parquet")
    df["유형"] = df["type"].map(TYPE_KO)
    return df


@st.cache_data
def load_inner():
    return pd.read_parquet(BASE / "data" / "phish_inner.parquet")


@st.cache_data
def load_samples():
    s = pd.read_csv(BASE / "data" / "sample_urls.csv")
    s["유형"] = s["type"].map(TYPE_KO)
    return s


main_df, inner_df, samples = load_main(), load_inner(), load_samples()


# ─────────────────────────────────────────────
# 3. 화면 조각 함수
# ─────────────────────────────────────────────
def rgba(hex_color, a):
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{a})"


def head(icon, title, sub="", tone="green"):
    bg = {"green": "#E3F6EC", "blue": "#E4EEFF", "orange": "#FFF1DD", "red": "#FDE8E8"}[tone]
    st.markdown(
        f'<div class="ch"><span class="ci" style="background:{bg}">{icon}</span>'
        f'<div><div class="ct">{title}</div><div class="cs">{sub}</div></div></div>',
        unsafe_allow_html=True,
    )


def tiles(items, cols=2):
    cells = "".join(
        f'<div class="tile"><div class="tl">{l}</div><div class="tv">{v}</div></div>' for l, v in items
    )
    st.markdown(f'<div class="tiles tiles{cols}">{cells}</div>', unsafe_allow_html=True)


def rows(items):
    html = "".join(f'<div class="row"><span>{a}</span><b>{b}</b></div>' for a, b in items)
    st.markdown(html, unsafe_allow_html=True)


def dot(color, text):
    return f'<span class="dot" style="background:{color}"></span>{text}'


def base_layout(fig, h=300, legend=True):
    fig.update_layout(
        height=h, margin=dict(l=4, r=4, t=10, b=4),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT, color="#4B5563", size=12),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.0, xanchor="left", x=0, title_text=""),
    )
    fig.update_xaxes(showgrid=False, linecolor="#E5E7EB", zeroline=False)
    fig.update_yaxes(gridcolor="#EEF0F3", zeroline=False, automargin=True, title_standoff=8)
    fig.update_xaxes(automargin=True)
    return fig


def show(fig):
    st.plotly_chart(fig, width="stretch", theme=None, config={"displayModeBar": False})


def donut(values, colors, labels, top, bottom, bottom_color, h=230):
    fig = go.Figure(go.Pie(
        values=values, labels=labels, hole=0.74, sort=False, direction="clockwise",
        marker=dict(colors=colors, line=dict(color="#FFFFFF", width=2)),
        textinfo="none", hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>"))
    fig.update_layout(
        height=h, margin=dict(l=0, r=0, t=0, b=0), showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)", font=dict(family=FONT),
        annotations=[
            dict(x=0.5, y=0.60, showarrow=False, text=top, font=dict(size=13, color="#6B7280")),
            dict(x=0.5, y=0.43, showarrow=False, text=f"<b>{bottom}</b>", font=dict(size=28, color=bottom_color)),
        ])
    show(fig)


def area_dist(df, feat_key, order, h=300):
    """선택한 특징의 값 분포를 유형별 면적 그래프(유형 내 %)로 그린다."""
    hi = max(int(np.ceil(df[feat_key].quantile(0.995))), 1)
    bins = np.arange(0, hi + 2) if hi <= 40 else np.linspace(0, hi, 41)
    fig = go.Figure()
    for t in order:
        v = df.loc[df["유형"] == t, feat_key]
        v = v[v <= hi]
        cnt, edges = np.histogram(v, bins=bins)
        fig.add_trace(go.Scatter(
            x=edges[:-1], y=cnt / max(len(v), 1) * 100, name=t, mode="lines",
            line=dict(color=COLORS[t], width=2.5, shape="spline", smoothing=0.6),
            fill="tozeroy", fillcolor=rgba(COLORS[t], 0.12),
            hovertemplate=f"{t}<br>{FEATURES[feat_key]} %{{x}}: %{{y:.1f}}%<extra></extra>"))
    base_layout(fig, h)
    fig.update_layout(xaxis_title=FEATURES[feat_key], yaxis_title="유형 내 비율(%)")
    show(fig)
    return hi


def hbar(labels, values, color, h=300):
    fig = go.Figure(go.Bar(
        x=values[::-1], y=labels[::-1], orientation="h", marker_color=color,
        text=[f"{v:,}" for v in values[::-1]], textposition="outside", cliponaxis=False,
        hovertemplate="%{y}: %{x:,}<extra></extra>"))
    base_layout(fig, h, legend=False)
    fig.update_yaxes(showgrid=False)
    fig.update_xaxes(showgrid=True, gridcolor="#EEF0F3", range=[0, max(values) * 1.22])
    show(fig)


def footer():
    st.markdown(f'<div class="foot">출처 ① {SOURCE_1}<br>출처 ② {SOURCE_2}</div>', unsafe_allow_html=True)


def page_title(t, s):
    st.markdown(f'<div class="pt">{t}</div><div class="pts">{s}</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────
# 4. 사이드바 메뉴
# ─────────────────────────────────────────────
PAGES = [("대시보드", "📊"), ("정상 vs 악성", "🔀"), ("악성 URL 안쪽", "🔍"), ("결론과 한계", "📝")]
st.session_state.setdefault("page", "대시보드")

with st.sidebar:
    st.markdown('<div class="brand">URL·SCAN</div><div class="brand-sub">악성 URL 구조 분석</div>',
                unsafe_allow_html=True)
    for i, (name, icon) in enumerate(PAGES):
        active = st.session_state["page"] == name
        if st.button(f"{icon}  {name}", key=f"{'navon' if active else 'nav'}_{i}"):
            st.session_state["page"] = name
            st.rerun()
    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("📌 데이터 출처·집계 기준"):
        st.markdown(
            f"""
**데이터**
- ① {SOURCE_1}
- ② {SOURCE_2}
- 두 데이터는 출처가 달라 **합치지 않고** 따로 분석합니다.

**집계 기준**
- ① 원본 651,191건 → 라벨이 서로 다른 같은 URL 6건 제외, 같은 URL 중복 제거 → **{len(main_df):,}건**
- ① URL 특징은 원본 URL 문자열에서 직접 계산
- ② 정상 라벨 820건은 경로 없는 유명 도메인 위주라 비교에 부적합해 제외 → 악성 **{len(inner_df):,}건**
- ② TLD는 도메인형에서만 직접 계산 (원본 `tld`는 IP 마지막 숫자가 섞여 있음)
- 분포 그래프의 비율은 각 유형 안에서의 비율(%)
"""
        )

page = st.session_state["page"]

# 자주 쓰는 집계
n_main = len(main_df)
ip_rate = inner_df["has_ip"].mean() * 100
ip_https = inner_df.loc[inner_df.has_ip == 1, "has_https"].mean() * 100
dm_https = inner_df.loc[inner_df.has_ip == 0, "has_https"].mean() * 100

# ─────────────────────────────────────────────
# 5. 페이지: 대시보드 (요약)
# ─────────────────────────────────────────────
if page == "대시보드":
    n1, n2 = st.columns(2)
    n1.markdown(
        '<div class="notice"><b>질문</b><span>악성 URL은 정상 URL과 구조가 어떻게 다른가?</span></div>',
        unsafe_allow_html=True)
    n2.markdown(
        f'<div class="notice"><b>데이터</b><span>① {n_main:,}건 · ② 악성 {len(inner_df):,}건</span>'
        '<span class="r">중복 제거 후</span></div>', unsafe_allow_html=True)
    st.write("")

    a, b = st.columns(2)
    counts = main_df["유형"].value_counts().reindex(TYPE_ORDER)
    with a:
        with st.container(key="card_dash_a"):
            head("🧩", "URL 유형 구성", "① 정상 + 악성 3유형 · 표본 구성", "green")
            c1, c2 = st.columns([1, 1.15])
            with c1:
                donut(counts.values, [COLORS[t] for t in TYPE_ORDER], TYPE_ORDER,
                      "전체 URL", f"{n_main / 10000:.1f}만", "#374151")
            with c2:
                tiles([(dot(COLORS[t], t), f"{counts[t]:,}") for t in TYPE_ORDER])
    with b:
        with st.container(key="card_dash_b"):
            head("🌐", "악성 URL 형태", "② 악성 URL 기준 · IP 직접 접속 vs 도메인", "blue")
            c1, c2 = st.columns([1, 1.15])
            with c1:
                donut([ip_rate, 100 - ip_rate], [BLUE, GRAY], ["IP 직접 접속형", "도메인형"],
                      "IP 직접 접속", f"{ip_rate:.1f}%", BLUE)
            with c2:
                tiles([
                    ("IP형 건수", f"{int(inner_df.has_ip.sum()):,}"),
                    ("도메인 건수", f"{int((1 - inner_df.has_ip).sum()):,}"),
                    ("IP형 https", f"{ip_https:.1f}%"),
                    ("도메인 https", f"{dm_https:.1f}%"),
                ])
    st.write("")

    a, b = st.columns([1.35, 1])
    with a:
        with st.container(key="card_dash_c"):
            head("📈", "유형별 URL 특징 분포", "특징을 고르면 그래프가 바뀝니다 · 유형 내 비율(%)", "blue")
            feat = st.segmented_control(
                "특징", list(FEATURES), default="url_length", format_func=lambda k: SHORT[k],
                label_visibility="collapsed", key="dash_feat") or "url_length"
            hi = area_dist(main_df, feat, TYPE_ORDER, h=290)
            st.caption(f"상위 0.5%({hi} 초과)는 그래프에서 제외했습니다.")
    with b:
        with st.container(key="card_dash_d"):
            head("🔗", "자주 나온 도메인", "② 도메인형 악성 URL · 건수 상위", "orange")
            hn = inner_df[inner_df.has_ip == 0]["hostname"].value_counts().head(7)
            rows([(h, f"{v:,}") for h, v in hn.items()])
            st.caption("서비스 전체가 악성이라는 뜻이 아니라, 그 서비스의 개별 링크가 악성으로 수집된 것입니다.")
    st.write("")

    a, b, c = st.columns([1, 1, 1.2])
    sc = main_df["scheme"].value_counts(normalize=True) * 100
    ipx = inner_df[(inner_df.has_ip == 1) & inner_df.ext.notna()]["ext"].value_counts().head(5)
    with a:
        with st.container(key="card_dash_e"):
            head("🔒", "주소 앞부분 구성", "① 전체 URL 기준", "green")
            rows([(k, f"{sc.get(k, 0):.1f}%") for k in ["http", "https", "없음"]])
    with b:
        with st.container(key="card_dash_f"):
            head("📦", "IP형이 가리키는 파일", "② 확장자 상위 5", "red")
            rows([(f".{k}", f"{v:,}건") for k, v in ipx.items()])
    with c:
        with st.container(key="card_dash_g"):
            head("⚠️", "읽을 때 주의", "자세한 내용은 ‘결론과 한계’", "orange")
            rows([("수집 출처 차이", "스킴 비교 주의"), ("표본 구성", "실제 비율 아님"),
                  ("시간 정보", "없음")])
    footer()

# ─────────────────────────────────────────────
# 6. 페이지: 정상 vs 악성
# ─────────────────────────────────────────────
elif page == "정상 vs 악성":
    page_title("정상 vs 악성 · 유형별 비교", f"① malicious_phish · 중복 제거 후 {n_main:,}건")

    with st.container(key="card_p1_filter"):
        head("🎛️", "조건 선택", "바꾸면 아래 숫자와 모든 그래프가 함께 바뀝니다", "blue")
        c1, c2, c3 = st.columns([2, 1.4, 1.6])
        sel_types = c1.multiselect("보고 싶은 유형", TYPE_ORDER, default=TYPE_ORDER)
        feat_key = c2.selectbox("비교할 URL 특징", list(FEATURES), format_func=lambda k: FEATURES[k])
        max_len = c3.slider("URL 길이 상한 (글자 수)", 50, 500, 300, step=10,
                            help="이 길이를 넘는 URL은 이상치로 보고 제외합니다.")

    df = main_df[main_df["유형"].isin(sel_types)]
    n_before = len(df)
    df = df[df["url_length"] <= max_len]
    n_cut = n_before - len(df)
    st.write("")

    if df.empty:
        st.warning("조건에 맞는 데이터가 없습니다. 유형을 하나 이상 선택해 주세요.")
    else:
        order = [t for t in TYPE_ORDER if t in sel_types]
        tiles([
            ("선택한 URL 수", f"{len(df):,}"),
            (f"{FEATURES[feat_key]} 평균", f"{df[feat_key].mean():.1f}"),
            (f"{FEATURES[feat_key]} 중앙값", f"{df[feat_key].median():.0f}"),
            ("IP 주소 직접 접속", f"{df['has_ip'].mean() * 100:.1f}%"),
        ], cols=4)
        st.caption(f"길이 {max_len}자 초과 {n_cut:,}건 제외 (선택 유형의 {n_cut / max(n_before, 1) * 100:.2f}%)")

        a, b = st.columns(2)
        with a:
            with st.container(key="card_p1_a"):
                head("🧩", "유형별 URL 수", "표본 구성", "green")
                cnt = df["유형"].value_counts().reindex(order)
                fig = go.Figure(go.Bar(
                    x=order, y=cnt.values, marker_color=[COLORS[t] for t in order],
                    text=[f"{v / cnt.sum() * 100:.1f}%" for v in cnt.values], textposition="outside",
                    hovertemplate="%{x}: %{y:,}<extra></extra>"))
                base_layout(fig, 300, legend=False)
                fig.update_layout(yaxis_title="URL 수")
                show(fig)
                st.caption("정상이 가장 많은 것은 이 데이터의 표본 구성일 뿐, 실제 인터넷의 악성 비율이 아닙니다.")
        with b:
            with st.container(key="card_p1_b"):
                head("📈", f"{FEATURES[feat_key]} 분포", "유형 내 비율(%)", "blue")
                hi = area_dist(df, feat_key, order, h=300)
                st.caption(f"상위 0.5%({hi} 초과)는 그래프에서 제외했습니다.")
        st.write("")

        a, b = st.columns(2)
        with a:
            with st.container(key="card_p1_c"):
                head("📊", f"유형별 {FEATURES[feat_key]} 평균", "선택한 특징 기준", "orange")
                avg = df.groupby("유형")[feat_key].mean().reindex(order)
                fig = go.Figure(go.Bar(
                    x=order, y=avg.values, marker_color=[COLORS[t] for t in order],
                    text=[f"{v:.1f}" for v in avg.values], textposition="outside",
                    hovertemplate="%{x}: %{y:.2f}<extra></extra>"))
                base_layout(fig, 300, legend=False)
                fig.update_layout(yaxis_title="평균")
                show(fig)
        with b:
            with st.container(key="card_p1_d"):
                head("🔒", "주소 앞부분(http/https/없음) 구성", "유형 내 비율(%)", "red")
                sc2 = pd.crosstab(df["유형"], df["scheme"], normalize="index").reindex(order) * 100
                fig = go.Figure()
                for k, col in [("http", "#EF6B6B"), ("https", "#3CB98A"), ("없음", "#CBD2DC")]:
                    if k in sc2:
                        fig.add_trace(go.Bar(x=order, y=sc2[k].values, name=k, marker_color=col,
                                             hovertemplate=f"{k}: %{{y:.1f}}%<extra></extra>"))
                base_layout(fig, 300)
                fig.update_layout(barmode="stack", yaxis_title="유형 내 비율(%)")
                show(fig)
                st.caption("⚠ 정상은 대부분 ‘없음’, 웹변조는 100% http입니다. 실제 위협의 특성이라기보다 "
                           "**유형별로 데이터를 수집한 출처가 달라서 생긴 차이**일 수 있어, 이것만으로 악성 여부를 판단하면 안 됩니다.")

        with st.expander("예시 URL 보기 (유형별 무작위 표본)"):
            show_t = st.selectbox("유형", order, key="sample_type")
            st.dataframe(samples[samples["유형"] == show_t][["url"]].head(15),
                         width="stretch", hide_index=True)
    footer()

# ─────────────────────────────────────────────
# 7. 페이지: 악성 URL 안쪽
# ─────────────────────────────────────────────
elif page == "악성 URL 안쪽":
    page_title("악성 URL 안쪽 들여다보기", f"② phishing_features 의 악성 URL {len(inner_df):,}건 · 정상 비교 없음")

    with st.container(key="card_p2_filter"):
        head("🎛️", "조건 선택", "바꾸면 아래 숫자와 모든 그래프가 함께 바뀝니다", "blue")
        c1, c2, c3 = st.columns([1.6, 1.3, 1.5])
        kind = c1.radio("URL 형태", ["전체", "IP 직접 접속형", "도메인형"], horizontal=True)
        proto = c2.radio("접속 방식", ["전체", "https", "http"], horizontal=True)
        top_n = c3.slider("상위 몇 개까지 볼까요", 5, 20, 10)

    base = inner_df
    if proto == "https":
        base = base[base["has_https"] == 1]
    elif proto == "http":
        base = base[base["has_https"] == 0]
    sub = base
    if kind == "IP 직접 접속형":
        sub = base[base["has_ip"] == 1]
    elif kind == "도메인형":
        sub = base[base["has_ip"] == 0]
    st.write("")

    if sub.empty:
        st.warning("조건에 맞는 데이터가 없습니다.")
    else:
        tiles([
            ("선택한 URL 수", f"{len(sub):,}"),
            ("https 비율", f"{sub['has_https'].mean() * 100:.1f}%"),
            ("숫자 개수 평균", f"{sub['digits_count'].mean():.1f}"),
            ("엔트로피 평균", f"{sub['entropy'].mean():.2f}"),
        ], cols=4)
        st.caption("엔트로피: URL 글자 구성의 불규칙한 정도. 클수록 무작위에 가깝습니다.")

        dom = sub[sub["has_ip"] == 0]
        a, b = st.columns(2)
        with a:
            with st.container(key="card_p2_a"):
                head("🌐", "악성 URL의 두 가지 형태", "접속 방식 조건만 반영", "blue")
                g = base["has_ip"].map({1: "IP 직접 접속형", 0: "도메인형"}).value_counts()
                fig = go.Figure(go.Bar(
                    x=g.index, y=g.values, marker_color=["#3B82F6" if i.startswith("IP") else "#93B8F7" for i in g.index],
                    text=[f"{v / g.sum() * 100:.1f}%" for v in g.values], textposition="outside",
                    hovertemplate="%{x}: %{y:,}<extra></extra>"))
                base_layout(fig, 300, legend=False)
                fig.update_layout(yaxis_title="URL 수")
                show(fig)
        with b:
            with st.container(key="card_p2_b"):
                head("📦", f"URL 끝 파일 확장자 상위 {top_n}", "선택한 형태 기준", "red")
                ext = sub["ext"].dropna().value_counts().head(top_n)
                if ext.empty:
                    st.info("확장자가 있는 URL이 없습니다.")
                else:
                    hbar([f".{e}" for e in ext.index], [int(v) for v in ext.values], "#F5A623")
                st.caption(f"확장자가 없는 URL은 {sub['ext'].isna().mean() * 100:.1f}%이며 이 그래프에서 제외했습니다.")
        st.write("")

        a, b = st.columns(2)
        with a:
            with st.container(key="card_p2_c"):
                head("🏷️", f"도메인형의 TLD 상위 {top_n}", "IP형에는 TLD가 없음", "green")
                if dom.empty:
                    st.info("IP 직접 접속형에는 TLD가 없어 ‘도메인형’ 또는 ‘전체’를 선택하면 표시됩니다.")
                else:
                    tld = dom["tld"].value_counts().head(top_n)
                    hbar(list(tld.index), [int(v) for v in tld.values], "#5B8DEF")
                    st.caption("TLD 건수는 많이 쓰인 정도이지, TLD 자체가 위험하다는 뜻은 아닙니다.")
        with b:
            with st.container(key="card_p2_d"):
                head("🔗", f"자주 나온 도메인 상위 {top_n}", "공유·단축 서비스 등", "orange")
                if dom.empty:
                    st.info("IP 직접 접속형에는 도메인이 없어 ‘도메인형’ 또는 ‘전체’를 선택하면 표시됩니다.")
                else:
                    hn = dom["hostname"].value_counts().head(top_n)
                    hbar(list(hn.index), [int(v) for v in hn.values], "#3CB98A")
                    st.caption("서비스 전체가 악성이라는 뜻이 아니라, 그 서비스의 개별 링크가 악성으로 수집된 것입니다.")
    footer()

# ─────────────────────────────────────────────
# 8. 페이지: 결론과 한계 (숫자는 데이터에서 직접 계산)
# ─────────────────────────────────────────────
else:
    page_title("결론과 한계", "숫자는 모두 데이터에서 직접 계산한 값입니다")
    m = main_df.groupby("유형")[["url_length", "num_digits", "num_params", "has_ip"]].mean()
    exe_set = {"exe", "sh", "scr", "lnk", "zip"}
    ipx = inner_df[(inner_df.has_ip == 1) & inner_df.ext.notna()]
    ip_file_share = ipx["ext"].isin(exe_set).mean() * 100

    a, b = st.columns(2)
    with a:
        with st.container(key="card_p3_a"):
            head("✅", "결론", "", "green")
            st.markdown(
                f"""
1. **유형마다 URL 모양이 다릅니다.** 숫자 개수 평균은 악성코드 {m.loc['악성코드', 'num_digits']:.1f}개로
   정상({m.loc['정상', 'num_digits']:.1f}), 웹변조({m.loc['웹변조', 'num_digits']:.1f}),
   피싱({m.loc['피싱', 'num_digits']:.1f})보다 많고, IP 주소 직접 접속 비율도
   악성코드 {m.loc['악성코드', 'has_ip'] * 100:.0f}%로 두드러집니다.
2. **웹변조 URL은 길고 파라미터가 많습니다.** 평균 길이 {m.loc['웹변조', 'url_length']:.0f}자,
   파라미터 {m.loc['웹변조', 'num_params']:.1f}개. 피싱은 평균 {m.loc['피싱', 'url_length']:.0f}자로 비교적 짧습니다.
3. **악성 URL 안쪽(②)은 크게 두 형태입니다.** 전체의 {ip_rate:.1f}%가 IP 직접 접속형이고,
   이 중 https는 {ip_https:.1f}%뿐인 반면 도메인형은 {dm_https:.1f}%가 https입니다.
   파일 확장자가 보이는 IP형 URL의 {ip_file_share:.0f}%가 실행·압축 파일 계열(exe, sh, scr, lnk, zip)입니다.
4. 도메인형에서는 공유·단축 서비스(문서 공유, QR·단축 링크 등)가 상위에 나타납니다.
"""
            )
    with b:
        with st.container(key="card_p3_b"):
            head("⚠️", "한계 (해석할 때 주의할 점)", "", "orange")
            st.markdown(
                """
- **수집 출처 차이:** 주소 앞부분(http/https/없음) 구성이 유형별로 극단적으로 달라, 실제 위협의 특성보다
  데이터를 모은 방식의 차이가 반영됐을 수 있습니다.
- **표본 구성 ≠ 실제 비율:** 정상 URL이 많은 것은 표본 구성이며, 실제 인터넷의 악성 비율이 아닙니다.
- **시간 정보 없음:** 언제 수집된 URL인지 알 수 없어 시기별 변화나 최신 경향은 말할 수 없습니다.
- **구조만으로 악성 판정 불가:** 평균이 다르다는 것이지 특정 구조가 곧 악성이라는 뜻이 아닙니다. 분포가 겹치는 구간이 큽니다.
- **두 데이터는 합치지 않음:** 출처와 라벨 기준이 달라(46건만 겹침) 하나의 표로 합치지 않았고, ②는 악성 URL만 있어 정상과 비교할 수 없습니다.
- **라벨 의미:** ②의 악성 URL은 실행·압축 파일을 가리키는 IP형이 많아, 이름과 달리 피싱보다 악성코드 유포 URL이 섞여 있을 가능성이 있습니다(출처 확인 필요).
"""
            )
    st.markdown(f'<div class="foot">제작: {AUTHOR} · 사용 AI: Claude — 데이터 전처리와 대시보드 코드 초안 작성에 사용, 결과는 직접 확인</div>',
                unsafe_allow_html=True)
    footer()
