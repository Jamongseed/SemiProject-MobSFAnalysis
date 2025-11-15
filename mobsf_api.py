# mobsf_api.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from pathlib import Path
from typing import Optional
import requests

# ▶ 공통 기본값 (원하면 .env / 환경변수로 빼도 됨)
MOBSF_URL = "http://127.0.0.1:8000"
MOBSF_KEY = "8627ee69f5b9839624697459793d105754c939b0cba5ce31370fa2ea4c85d3e8"

def ts():
    return time.strftime("[%H:%M:%S]")

def http(
    path: str,
    method: str = "POST",
    *,
    server: str = MOBSF_URL,
    apikey: str = MOBSF_KEY,
    **kw
) -> requests.Response:
    """
    MobSF와 HTTP 통신. dynamic_driver / static 분석에서 공통 사용.
    """
    url = f"{server.rstrip('/')}{path}"
    headers = kw.pop("headers", {})
    headers["Authorization"] = apikey

    print(f"{ts()}[MobSF] {method} {url}")
    if "files" in kw:
        print(f"{ts()}[MobSF] files={list(kw['files'].keys())}")
    if "data" in kw:
        print(f"{ts()}[MobSF] data={kw['data']}")

    r = requests.request(method, url, headers=headers, timeout=120, **kw)
    print(f"{ts()}[MobSF] -> {r.status_code} {r.text[:400]}")
    r.raise_for_status()
    return r

def upload_apk_with_filename(
    apk_path: Path,
    *,
    server: str = MOBSF_URL,
    apikey: str = MOBSF_KEY,
):
    """
    APK 업로드만 담당. hash, file_name은 호출한 쪽에서 r.json()으로 꺼내 사용.
    """
    p = Path(apk_path)
    if not p.exists():
        raise SystemExit(f"APK 파일을 찾을 수 없음: {apk_path}")

    size = p.stat().st_size
    print(f"{ts()}[MobSF] UPLOAD begin: path={p}, size={size}")
    filename = p.name if p.suffix.lower() == ".apk" else "artifact.apk"
    mime = "application/vnd.android.package-archive"
    print(f"{ts()}[MobSF] filename={filename}, mime={mime}")

    with open(p, "rb") as f:
        files = {"file": (filename, f, mime)}
        return http("/api/v1/upload", server=server, apikey=apikey,
                    files=files, data={"scan_type": "apk"})

def scan_apk(
    file_name: str,
    file_hash: str,
    *,
    server: str = MOBSF_URL,
    apikey: str = MOBSF_KEY,
):
    """
    정적 스캔 시작.
    """
    return http("/api/v1/scan", server=server, apikey=apikey,
                data={"scan_type": "apk", "file_name": file_name, "hash": file_hash})

def download_pdf(
    file_hash: str,
    out_path: Path,
    *,
    server: str = MOBSF_URL,
    apikey: str = MOBSF_KEY,
):
    """
    정적 PDF 리포트 다운로드.
    """
    r = http("/api/v1/download_pdf", server=server, apikey=apikey,
             data={"hash": file_hash, "scan_type": "apk"}, stream=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    print(f"{ts()}[MobSF] PDF saved → {out_path}")
    return out_path
