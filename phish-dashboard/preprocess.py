"""원본 CSV -> 대시보드용 가벼운 파일(data/)로 만드는 전처리 스크립트.
실행: python preprocess.py   (raw/ 폴더에 원본 두 파일이 있어야 함)
"""
import pandas as pd

# ---------- 1) malicious_phish.csv (Kaggle) ----------
m = pd.read_csv("raw/malicious_phish.csv")
n_raw = len(m)

# 같은 URL에 서로 다른 라벨이 붙은 경우는 라벨을 믿을 수 없어 제외
conflict = m.groupby("url")["type"].nunique()
conflict_urls = conflict[conflict > 1].index
m = m[~m["url"].isin(conflict_urls)]
# 완전히 같은 URL(중복)은 1개만 남김
m = m.drop_duplicates("url").reset_index(drop=True)

u = m["url"]
scheme = u.str.extract(r"^(https?)://", expand=False).fillna("없음")
rest = u.str.replace(r"^https?://", "", regex=True)      # 스킴 제거
host = rest.str.split("/", n=1).str[0]
path = rest.str.split("/", n=1).str[1].fillna("")

feat = pd.DataFrame({
    "type": m["type"],
    "url_length": u.str.len(),
    "num_dots": u.str.count(r"\."),
    "num_digits": u.str.count(r"\d"),
    "num_hyphens": u.str.count("-"),
    "num_slashes": path.str.count("/"),                    # 경로 깊이
    "num_params": u.str.count("&") + u.str.contains(r"\?").astype(int),
    "has_ip": host.str.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$").astype(int),
    "scheme": scheme,
})
feat.to_parquet("data/phish_features.parquet", index=False)

# 예시 URL (유형별 150개) - 화면 표시용
sample = m.groupby("type", group_keys=False).sample(150, random_state=42)
sample.to_csv("data/sample_urls.csv", index=False)

# 전처리 기록
with open("data/prep_log.txt", "w", encoding="utf-8") as f:
    f.write(f"원본 행 수: {n_raw}\n라벨 충돌 URL 수: {len(conflict_urls)}\n"
            f"중복 제거 후 행 수: {len(m)}\n")
print(open("data/prep_log.txt", encoding="utf-8").read())

# ---------- 2) phishing_features.csv ----------
p = pd.read_csv("raw/phishing_features.csv")
p = p[p["label"] == 1].copy()          # 정상(820개)은 유명 도메인 목록이라 비교에서 제외
u = p["url"]
rest = u.str.replace(r"^https?://", "", regex=True)
host = rest.str.split("/", n=1).str[0]
path = rest.str.split("/", n=1).str[1].fillna("")
hostname = host.str.replace(r":\d+$", "", regex=True)

out = pd.DataFrame({
    "url_length": p["url_length"],
    "has_https": p["has_https"],
    "has_ip": p["has_ip"],
    "digits_count": p["digits_count"],
    "entropy": p["entropy"],
    "hostname": hostname,
})
# TLD는 도메인형 URL에서만 직접 계산 (원본 tld 컬럼은 IP 마지막 숫자가 섞여 있음)
out["tld"] = hostname.str.rsplit(".", n=1).str[-1].where(out["has_ip"] == 0)
# 경로 끝 파일 확장자 (예: sh, exe)
last = path.str.split("?").str[0].str.rsplit("/", n=1).str[-1]
out["ext"] = last.str.extract(r"\.([A-Za-z0-9]{1,5})$", expand=False).str.lower()
out.to_parquet("data/phish_inner.parquet", index=False)
print("phish_inner:", out.shape)
