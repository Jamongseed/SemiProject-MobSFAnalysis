# mobsf_static.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

from mobsf_api import (
    MOBSF_URL,
    MOBSF_KEY,
    upload_apk_with_filename,
    scan_apk,
    download_pdf,
)

OUT_DIR = Path("./output")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# APK 리스트는 그대로 사용
TARGET_APKS = [
    Path("./smali-decrypted/sample.apk"),
    Path("./smali-decrypted/pgsHZz.apk"),
    Path("./smali-decrypted/sample_signed_decrypted.apk"),
    Path("./smali-decrypted/pgsHZz_signed_decrypted.apk"),
]


def mobsf_upload_and_scan(apk_path: Path):
    """APK 파일 업로드, 스캔, PDF 다운로드 (공통 mobsf_api 사용)"""
    print(f"파일 업로드중 {apk_path.name} ...")

    r = upload_apk_with_filename(apk_path, server=MOBSF_URL, apikey=MOBSF_KEY)
    j = r.json()
    file_hash = j.get("hash")
    file_name = j.get("file_name", apk_path.name)

    print(f"분석중 {file_name} ...")
    scan_apk(file_name, file_hash, server=MOBSF_URL, apikey=MOBSF_KEY)

    base_name = f"{apk_path.stem}_report"
    pdf_path = OUT_DIR / f"{base_name}.pdf"

    print(f"PDF 생성중 {pdf_path.name} ...")
    download_pdf(file_hash, pdf_path, server=MOBSF_URL, apikey=MOBSF_KEY)

    print(f"PDF 생성완료!: {pdf_path}")
    return apk_path.name, "OK"


def run_static_analysis(target_apks=None):
    if target_apks is None:
        target_apks = TARGET_APKS

    print("\n===== MobSF 정적 분석 시작 =====")

    with ProcessPoolExecutor(max_workers=len(target_apks)) as executor:
        futures = {
            executor.submit(mobsf_upload_and_scan, apk): apk
            for apk in target_apks if apk.exists()
        }

        for future in as_completed(futures):
            apk_name, result = future.result()
            print(f"[결과] {apk_name}: {result}")

    print("\n===== MobSF 정적 분석 완료 =====")


if __name__ == "__main__":
    try:
        # 필요하다면 여기에서 code.py(→ apk_pipeline) 먼저 실행
        from apk_pipeline import run_apk_pipeline

        run_apk_pipeline()
        run_static_analysis()
    except Exception as e:
        print(e)
        sys.exit(1)
