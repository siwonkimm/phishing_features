"""악성 URL 구조 분석 대시보드 (산업데이터시각화 개인 프로젝트)

질문: 악성 URL은 정상 URL과 구조가 어떻게 다르고,
      악성 URL 안에서는 어떤 유형(IP형 / 도메인형 / 서비스 악용)이 많은가?

실행: streamlit run app.py
데이터는 preprocess.py 가 만든 data/ 폴더의 파일을 읽습니다.
"""
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

# ─────────────────────────────────────────────
# 0. 기본 설정 · 출처 (※ 제출 전에 링크를 직접 확인해서 채워 넣으세요)
# ─────────────────────────────────────────────
SOURCE_1 = "Kaggle ‘Malicious URLs dataset’ (malicious_phish.csv) — 링크: [여기에 Kaggle 페이지 URL 기입]"
SOURCE_2 = "phishing_features.csv — 출처: [여기에 다운로드 출처 기입]"

# app.py가 있는 폴더 기준으로 data/ 를 찾음 (저장소 안 어느 폴더에 둬도 동작)
BASE = Path(__file__).resolve().parent

st.set_page_config(page_title="악성 URL 구조 분석", page_icon="🔎", layout="wide")

TYPE_KO = {"benign": "정상", "defacement": "웹변조", "phishing": "피싱", "malware": "악성코드"}
TYPE_ORDER = ["정상", "웹변조", "피싱", "악성코드"]
COLORS = {"정상": "#4C78A8", "웹변조": "#F58518", "피싱": "#E45756", "악성코드": "#72B7B2"}

FEATURES = {
    "url_length": "URL 길이(글자 수)",
    "num_digits": "숫자 개수",
    "num_dots": "점(.) 개수",
    "num_hyphens": "하이픈(-) 개수",
    "num_slashes": "경로 깊이(/ 개수)",
    "num_params": "파라미터 개수",
}


# ─────────────────────────────────────────────
# 1. 데이터 불러오기 (한 번만 읽고 캐시)
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


main_df = load_main()
inner_df = load_inner()
samples = load_samples()

# ─────────────────────────────────────────────
# 2. 제목 · 질문 · 출처
# ─────────────────────────────────────────────
st.title("🔎 악성 URL은 정상 URL과 구조가 어떻게 다른가?")
st.markdown(
    "**질문** 악성 URL은 정상 URL과 구조가 어떻게 다르고, "
    "악성 URL 안에서는 어떤 유형(IP 직접 접속 / 도메인 / 공유·단축 서비스 악용)이 많은가?"
)

with st.expander("📌 데이터 출처와 집계 기준 (먼저 읽어 주세요)", expanded=False):
    st.markdown(
        f"""
**데이터**
- ① {SOURCE_1}
- ② {SOURCE_2}
- 두 데이터는 출처가 달라 **합치지 않고** 탭 ①·②에서 따로 분석합니다.

**집계 기준**
- ① 원본 {651191:,}건 → 라벨이 서로 다른 같은 URL 6건 제외, 완전히 같은 URL 중복 제거 → **{len(main_df):,}건**
- ① URL 특징(길이, 숫자·점·하이픈 개수 등)은 원본 URL 문자열에서 직접 계산
- ② 정상 라벨 820건은 경로가 없는 유명 도메인 위주(`google.com` 등)라 정상 비교에 부적합하여 제외 → 악성 **{len(inner_df):,}건**만 사용
- ② TLD는 도메인형 URL에서만 직접 계산 (원본 `tld` 컬럼은 IP 주소 마지막 숫자가 섞여 있어 사용하지 않음)
- 모든 비율은 선택한 조건 안에서의 비율이며, 분포 그래프는 유형 내 비율(%)입니다.
"""
    )

tab1, tab2, tab3 = st.tabs(["① 정상 vs 악성 (유형별 비교)", "② 악성 URL 안쪽 들여다보기", "③ 결론과 한계"])

# ─────────────────────────────────────────────
# 3. 탭 ① 정상 vs 악성
# ─────────────────────────────────────────────
with tab1:
    st.caption(f"데이터: ① malicious_phish (중복 제거 후 {len(main_df):,}건)")

    c1, c2, c3 = st.columns([2, 2, 2])
    with c1:
        sel_types = st.multiselect("보고 싶은 유형", TYPE_ORDER, default=TYPE_ORDER)
    with c2:
        feat_key = st.selectbox(
            "비교할 URL 특징", list(FEATURES), format_func=lambda k: FEATURES[k]
        )
    with c3:
        max_len = st.slider("URL 길이 상한 (글자 수)", 50, 500, 300, step=10,
                            help="이 길이를 넘는 URL은 이상치로 보고 제외합니다.")

    df = main_df[main_df["유형"].isin(sel_types)]
    n_before = len(df)
    df = df[df["url_length"] <= max_len]
    n_cut = n_before - len(df)

    if df.empty:
        st.warning("조건에 맞는 데이터가 없습니다. 유형을 하나 이상 선택해 주세요.")
    else:
        st.caption(
            f"길이 {max_len}자 초과 {n_cut:,}건 제외 "
            f"(선택 유형의 {n_cut / max(n_before, 1) * 100:.2f}%)"
        )
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("선택한 URL 수", f"{len(df):,}")
        k2.metric(f"{FEATURES[feat_key]} 평균", f"{df[feat_key].mean():.1f}")
        k3.metric(f"{FEATURES[feat_key]} 중앙값", f"{df[feat_key].median():.0f}")
        k4.metric("IP 주소 직접 접속 비율", f"{df['has_ip'].mean() * 100:.1f}%")

        order = [t for t in TYPE_ORDER if t in sel_types]

        # 차트 1: 유형별 건수
        left, right = st.columns(2)
        with left:
            cnt = df["유형"].value_counts().reindex(order).reset_index()
            cnt.columns = ["유형", "건수"]
            cnt["비율"] = cnt["건수"] / cnt["건수"].sum() * 100
            fig = px.bar(cnt, x="유형", y="건수", color="유형", color_discrete_map=COLORS,
                         text=cnt["비율"].map("{:.1f}%".format),
                         title="① 유형별 URL 수 (표본 구성)")
            fig.update_layout(showlegend=False, yaxis_title="URL 수")
            st.plotly_chart(fig, width="stretch")
            st.caption("※ 정상이 가장 많은 것은 이 데이터의 표본 구성일 뿐, 실제 인터넷의 악성 비율이 아닙니다.")

        # 차트 2: 선택한 특징의 분포 (유형별)
        with right:
            hi = max(int(np.ceil(df[feat_key].quantile(0.995))), 1)
            bins = np.arange(0, hi + 2) if hi <= 40 else np.linspace(0, hi, 41)
            rows = []
            for t in order:
                v = df.loc[df["유형"] == t, feat_key]
                v = v[v <= hi]
                h, edges = np.histogram(v, bins=bins)
                rows.append(pd.DataFrame({
                    "값": edges[:-1], "비율(%)": h / max(len(v), 1) * 100, "유형": t}))
            dist = pd.concat(rows)
            fig = px.line(dist, x="값", y="비율(%)", color="유형", color_discrete_map=COLORS,
                          title=f"② {FEATURES[feat_key]} 분포 (유형 내 비율)")
            fig.update_layout(xaxis_title=FEATURES[feat_key], yaxis_title="유형 내 비율(%)")
            st.plotly_chart(fig, width="stretch")
            st.caption(f"※ 상위 0.5%({hi} 초과)는 그래프에서 제외했습니다.")

        # 차트 3: IP 직접 접속 비율 / 평균 비교
        left, right = st.columns(2)
        with left:
            avg = df.groupby("유형")[feat_key].mean().reindex(order).reset_index()
            avg.columns = ["유형", "평균"]
            fig = px.bar(avg, x="유형", y="평균", color="유형", color_discrete_map=COLORS,
                         text=avg["평균"].map("{:.1f}".format),
                         title=f"③ 유형별 {FEATURES[feat_key]} 평균")
            fig.update_layout(showlegend=False, yaxis_title="평균")
            st.plotly_chart(fig, width="stretch")

        # 차트 4: 스킴 구성
        with right:
            sc = pd.crosstab(df["유형"], df["scheme"], normalize="index").reindex(order) * 100
            sc = sc.reset_index().melt(id_vars="유형", var_name="스킴", value_name="비율(%)")
            fig = px.bar(sc, x="유형", y="비율(%)", color="스킴", barmode="stack",
                         color_discrete_map={"http": "#E45756", "https": "#54A24B", "없음": "#BAB0AC"},
                         title="④ 주소 앞부분(http/https/없음) 구성")
            fig.update_layout(yaxis_title="유형 내 비율(%)")
            st.plotly_chart(fig, width="stretch")
            st.caption("⚠ 정상 URL은 대부분 ‘없음’, 웹변조는 100% http 입니다. 실제 위협의 특성이라기보다 "
                       "**유형별로 데이터를 수집한 출처가 달라서 생긴 차이**일 수 있어, 이것만으로 악성 여부를 판단하면 안 됩니다.")

        with st.expander("예시 URL 보기 (유형별 무작위 표본)"):
            show_t = st.selectbox("유형", order, key="sample_type")
            st.dataframe(samples[samples["유형"] == show_t][["url"]].head(15),
                         width="stretch", hide_index=True)

# ─────────────────────────────────────────────
# 4. 탭 ② 악성 URL 안쪽
# ─────────────────────────────────────────────
with tab2:
    st.caption(f"데이터: ② phishing_features 의 악성 URL {len(inner_df):,}건 (정상 비교 없음)")

    c1, c2, c3 = st.columns(3)
    with c1:
        kind = st.radio("URL 형태", ["전체", "IP 직접 접속형", "도메인형"], horizontal=True)
    with c2:
        proto = st.radio("접속 방식", ["전체", "https", "http"], horizontal=True)
    with c3:
        top_n = st.slider("상위 몇 개까지 볼까요", 5, 20, 10)

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

    if sub.empty:
        st.warning("조건에 맞는 데이터가 없습니다.")
    else:
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("선택한 URL 수", f"{len(sub):,}")
        k2.metric("https 비율", f"{sub['has_https'].mean() * 100:.1f}%")
        k3.metric("숫자 개수 평균", f"{sub['digits_count'].mean():.1f}")
        k4.metric("엔트로피 평균", f"{sub['entropy'].mean():.2f}",
                  help="URL 글자 구성의 불규칙한 정도. 클수록 무작위에 가까움")

        left, right = st.columns(2)

        # 차트 5: IP형 vs 도메인형
        with left:
            g = base["has_ip"].map({1: "IP 직접 접속형", 0: "도메인형"}).value_counts().reset_index()
            g.columns = ["형태", "건수"]
            g["비율"] = g["건수"] / g["건수"].sum() * 100
            fig = px.bar(g, x="형태", y="건수", color="형태",
                         color_discrete_map={"IP 직접 접속형": "#E45756", "도메인형": "#4C78A8"},
                         text=g["비율"].map("{:.1f}%".format),
                         title="⑤ 악성 URL의 두 가지 형태")
            fig.update_layout(showlegend=False, yaxis_title="URL 수")
            st.plotly_chart(fig, width="stretch")

        # 차트 6: 파일 확장자
        with right:
            ext = sub["ext"].dropna().value_counts().head(top_n).reset_index()
            ext.columns = ["확장자", "건수"]
            no_ext = sub["ext"].isna().mean() * 100
            fig = px.bar(ext.iloc[::-1], x="건수", y="확장자", orientation="h",
                         title=f"⑥ URL 끝 파일 확장자 상위 {top_n}")
            fig.update_traces(marker_color="#F58518")
            st.plotly_chart(fig, width="stretch")
            st.caption(f"※ 확장자가 없는 URL은 {no_ext:.1f}%이며 이 그래프에서 제외했습니다.")

        left, right = st.columns(2)
        dom = sub[sub["has_ip"] == 0]

        # 차트 7: TLD
        with left:
            if dom.empty:
                st.info("IP 직접 접속형에는 TLD가 없어 도메인형을 선택하면 표시됩니다.")
            else:
                tld = dom["tld"].value_counts().head(top_n).reset_index()
                tld.columns = ["TLD", "건수"]
                fig = px.bar(tld.iloc[::-1], x="건수", y="TLD", orientation="h",
                             title=f"⑦ 도메인형 악성 URL의 TLD 상위 {top_n}")
                fig.update_traces(marker_color="#4C78A8")
                st.plotly_chart(fig, width="stretch")
                st.caption("※ TLD 건수는 많이 쓰인 정도이지, TLD 자체가 위험하다는 뜻은 아닙니다.")

        # 차트 8: 도메인(서비스) 상위
        with right:
            if dom.empty:
                st.info("IP 직접 접속형에는 도메인이 없어 도메인형을 선택하면 표시됩니다.")
            else:
                hn = dom["hostname"].value_counts().head(top_n).reset_index()
                hn.columns = ["도메인", "건수"]
                fig = px.bar(hn.iloc[::-1], x="건수", y="도메인", orientation="h",
                             title=f"⑧ 자주 등장하는 도메인 상위 {top_n}")
                fig.update_traces(marker_color="#72B7B2")
                st.plotly_chart(fig, width="stretch")
                st.caption("※ 공유·단축 서비스가 많이 보이지만, 서비스 전체가 악성이라는 뜻이 아니라 "
                           "그 서비스를 통한 개별 링크가 악성으로 수집된 것입니다.")

# ─────────────────────────────────────────────
# 5. 탭 ③ 결론과 한계 (숫자는 데이터에서 직접 계산)
# ─────────────────────────────────────────────
with tab3:
    m = main_df.groupby("유형")[["url_length", "num_digits", "num_params", "has_ip"]].mean()
    ip_rate = inner_df["has_ip"].mean() * 100
    ip_https = inner_df.loc[inner_df.has_ip == 1, "has_https"].mean() * 100
    dm_https = inner_df.loc[inner_df.has_ip == 0, "has_https"].mean() * 100
    exe_set = {"exe", "sh", "scr", "lnk", "zip"}
    ipx = inner_df[(inner_df.has_ip == 1) & inner_df.ext.notna()]
    ip_file_share = ipx["ext"].isin(exe_set).mean() * 100

    st.subheader("결론")
    st.markdown(
        f"""
1. **유형마다 URL 모양이 다릅니다.** 숫자 개수 평균은 악성코드 {m.loc['악성코드', 'num_digits']:.1f}개로
   정상({m.loc['정상', 'num_digits']:.1f}), 웹변조({m.loc['웹변조', 'num_digits']:.1f}),
   피싱({m.loc['피싱', 'num_digits']:.1f})보다 많고, IP 주소로 직접 접속하는 비율도
   악성코드 {m.loc['악성코드', 'has_ip'] * 100:.0f}%로 두드러집니다.
2. **웹변조 URL은 길고 파라미터가 많습니다.** 평균 길이 {m.loc['웹변조', 'url_length']:.0f}자,
   파라미터 {m.loc['웹변조', 'num_params']:.1f}개로 다른 유형보다 큽니다. 반면 피싱은
   평균 {m.loc['피싱', 'url_length']:.0f}자로 비교적 짧습니다.
3. **악성 URL 안쪽(②)은 크게 두 형태입니다.** 전체의 {ip_rate:.1f}%가 IP 직접 접속형이고,
   이 중 https는 {ip_https:.1f}%에 불과한 반면 도메인형은 {dm_https:.1f}%가 https입니다.
   파일 확장자가 보이는 IP형 URL의 {ip_file_share:.0f}%가 실행·압축 파일 계열
   (exe, sh, scr, lnk, zip)입니다.
4. 도메인형에서는 공유·단축 서비스(문서 공유, QR·단축 링크 등)가 상위에 나타납니다.
"""
    )

    st.subheader("한계 (해석할 때 주의할 점)")
    st.markdown(
        """
- **수집 출처 차이:** 주소 앞부분(http/https/없음) 구성이 유형별로 극단적으로 달라, 실제 위협의 특성보다
  데이터를 모은 방식의 차이가 반영됐을 수 있습니다.
- **표본 구성 ≠ 실제 비율:** 정상 URL이 많은 것은 표본 구성이며, 실제 인터넷의 악성 비율이 아닙니다.
- **시간 정보 없음:** 언제 수집된 URL인지 알 수 없어 시기별 변화나 최신 경향은 말할 수 없습니다.
- **구조만으로 악성 판정 불가:** 평균이 다르다는 것이지, 특정 구조가 곧 악성이라는 뜻이 아닙니다.
  분포가 겹치는 구간이 큽니다.
- **두 데이터는 합치지 않음:** 출처와 라벨 기준이 달라(46건만 겹침) 하나의 표로 합치지 않았고,
  ②는 악성 URL만 있어 정상과의 비교가 불가능합니다.
- **라벨 의미:** ②의 악성 URL은 실행·압축 파일을 가리키는 IP형이 많아, 이름과 달리 피싱보다
  악성코드 유포 URL이 섞여 있을 가능성이 있습니다(출처 확인 필요).
"""
    )
    st.caption("제작: (이름) · 사용 AI: Claude — 데이터 전처리와 대시보드 코드 초안 작성에 사용, 결과는 직접 확인")
