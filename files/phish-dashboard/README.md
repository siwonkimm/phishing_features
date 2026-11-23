# 악성 URL 구조 분석 대시보드

산업데이터시각화 2026-2 개인 프로젝트.

**질문** 악성 URL은 정상 URL과 구조가 어떻게 다르고, 악성 URL 안에서는 어떤 유형이 많은가?

## 데이터 출처
- Kaggle "Malicious URLs dataset" (malicious_phish.csv): [링크 기입]
- phishing_features.csv: [출처 기입]

## 실행
```
pip install -r requirements.txt
python preprocess.py   # raw/ 폴더에 원본 CSV 두 개 필요 (저장소에는 포함하지 않음)
streamlit run app.py
```
`data/` 폴더의 전처리 결과가 저장소에 들어 있어 배포 시에는 `preprocess.py`를 다시 돌릴 필요가 없습니다.
