#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import shutil
from pathlib import Path

from mobsf_api import http, upload_apk_with_filename
from family_malware1 import run_vt_report

BASE_DIR = Path(__file__).parent

# MobSF 서버는 고정
SERVER = "http://127.0.0.1:8000"
DEFAULT_APIKEY = "4a592aa733bc68bca8ebae4bc9f005afe4b4c4bc9e569b84a8ded338319cd446"          # 필요하면 여기다 API 키를 박아두고, 입력 없이 쓰면 됨
DEFAULT_OUTDIR = "output"

FRIDA_HOST = "192.168.56.101:27042"
FRIDA_SCRIPT = BASE_DIR / "bypass.js"
FRIDA_MODE = "attach"

def run_static_analysis_single(apk_path: Path, apikey: str, outdir: str = DEFAULT_OUTDIR):
    """
    단일 APK에 대해 MobSF 정적 분석 + PDF 보고서 다운로드.
    """
    server = SERVER
    out_dir = Path(outdir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[STATIC] APK 업로드 중: {apk_path}")

    # mobsf_api 시그니처에 맞게: apk_path만 위치 인자로, server/apikey는 키워드 인자로
    res = upload_apk_with_filename(apk_path, server=server, apikey=apikey)
    j = res.json()
    file_hash = j.get("hash")
    file_name = j.get("file_name", apk_path.name)

    if not file_hash:
        print("[STATIC] MobSF 응답에 hash가 없습니다. 업로드 실패?")
        return

    print(f"[STATIC] 정적 분석 시작: file_name={file_name}, hash={file_hash}")

    http(
        "/api/v1/scan",
        server=server,
        apikey=apikey,
        data={"scan_type": "apk", "file_name": file_name, "hash": file_hash},
    )

    base_name = f"{apk_path.stem}_report"
    pdf_path = out_dir / f"{base_name}.pdf"
    print(f"[STATIC] PDF 보고서 생성 중: {pdf_path.name}")

    r_pdf = http(
        "/api/v1/download_pdf",
        server=server,
        apikey=apikey,
        data={"hash": file_hash, "scan_type": "apk"},
        stream=True,
    )

    with open(pdf_path, "wb") as f:
        for chunk in r_pdf.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    print(f"[STATIC] PDF 보고서 생성 완료 → {pdf_path}")


def run_static_pipeline(apk_input: Path, apikey: str):
    """
    1) 입력 APK를 (main.py와 같은 폴더)에 sample.apk 로 복사
    2) apk_pipeline.py / code.py 를 찾아서, 항상 '루트(lastone)'를 cwd로 실행
    3) ./smali-decrypted 안에 생성된 APK들에 대해 정적분석
    """
    script_dir = Path(__file__).parent.resolve()
    workspace = script_dir / "smali-decrypted"
    workspace.mkdir(parents=True, exist_ok=True)

    # 1) 입력 APK → 루트의 sample.apk 로 복사 (같은 파일이면 복사 생략)
    sample_apk_root = script_dir / "sample.apk"

    if apk_input.resolve() != sample_apk_root.resolve():
        print(f"\n[PIPE] 입력 APK를 루트로 복사:")
        print(f"      {apk_input}  ->  {sample_apk_root}")
        shutil.copy2(apk_input, sample_apk_root)
    else:
        print(f"\n[PIPE] 입력 APK가 이미 루트 sample.apk 입니다. 복사 생략.")

    # 2) 파이프라인 스크립트 탐색
    #    (1) 루트/apk_pipeline.py
    #    (2) smali-decrypted/apk_pipeline.py
    candidates = [
        script_dir / "apk_pipeline.py",
        workspace / "apk_pipeline.py",
    ]

    apk_pipeline = None
    for path in candidates:
        if path.exists():
            apk_pipeline = path
            break

    if not apk_pipeline:
        print("[PIPE][ERROR] apk_pipeline.py 를 찾을 수 없습니다.")
        for path in candidates:
            print(f"  - {path}")
        return

    cmd = [sys.executable, str(apk_pipeline)]
    cwd_for_pipeline = script_dir  # 항상 프로젝트 루트에서 실행

    print(f"\n[PIPE] apk 파이프라인 실행:")
    print(" ", " ".join(cmd), f"(cwd={cwd_for_pipeline})")

    try:
        subprocess.run(cmd, check=True, cwd=str(cwd_for_pipeline))
    except subprocess.CalledProcessError as e:
        print(f"[PIPE][ERROR] 파이프라인 실행 중 오류 (exit={e.returncode}): {e}")
        return
    except Exception as e:
        print(f"[PIPE][ERROR] 예기치 못한 오류: {e}")
        return

    print("\n[PIPE] 파이프라인 실행 완료. 정적분석 대상 APK를 수집합니다.")

    # 3) 정적분석 대상 목록
    target_apks = [
        workspace / "sample.apk",
        workspace / "pgsHZz.apk",
        workspace / "sample_signed_decrypted.apk",
        workspace / "pgsHZz_signed_decrypted.apk",
    ]

    for apk in target_apks:
        if apk.exists():
            run_static_analysis_single(apk, apikey, outdir=DEFAULT_OUTDIR)
        else:
            print(f"[STATIC][SKIP] 대상 APK 없음: {apk}")


def run_dynamic_analysis(apk_path: Path, apikey: str):
    """
    mobsf_dynamic_driver.py 를 서브프로세스로 실행해서 동적 분석 수행.
    - 메인 시나리오: scenario_sample.yaml (고정)
    - 설치 시나리오: scenario_keys.yaml (고정, 없으면 생략)
    """
    server = SERVER
    script_dir = Path(__file__).parent.resolve()

    # 1) 디바이스만 입력 받기
    device = input(
        "\n[DYNC] ADB 디바이스 ID (예: 127.0.0.1:5555, 비우면 127.0.0.1:5555): "
    ).strip()
    if not device:
        device = "127.0.0.1:5555"

    # 2) 시나리오 경로 고정
    scenario = script_dir / "scenario_sample.yaml"
    scenario_install = script_dir / "scenario_keys.yaml"

    if not scenario.exists():
        print(f"[DYNC][ERROR] 메인 시나리오 파일을 찾을 수 없습니다: {scenario}")
        print("  - scenario_keys.yaml 파일이 main.py와 같은 폴더에 있어야 합니다.")
        return

    if not scenario_install.exists():
        print(f"[DYNC] 설치 시나리오 파일이 없습니다(생략): {scenario_install}")
        scenario_install = None
    else:
        print(f"[DYNC] 설치 시나리오 사용: {scenario_install}")

    dyn_driver = script_dir / "mobsf_dynamic_driver.py"

    if not dyn_driver.exists():
        print(f"[DYNC][ERROR] mobsf_dynamic_driver.py 파일을 찾을 수 없습니다: {dyn_driver}")
        return

    cmd = [
        sys.executable,
        str(dyn_driver),
        "--server", server,
        "--apikey", apikey,
        "--device", device,
        "--apk", str(apk_path),
        "--scenario", str(scenario),
        "--outdir", DEFAULT_OUTDIR,
    ]

    if scenario_install:
        cmd += ["--scenario-install", str(scenario_install)]

    if FRIDA_SCRIPT.exists():
        print(f"[DYNC] Frida 사용: host={FRIDA_HOST}, script={FRIDA_SCRIPT}, mode={FRIDA_MODE}")
        cmd += [
            "--frida-host", FRIDA_HOST,
            "--frida-script", str(FRIDA_SCRIPT),
            "--frida-mode", FRIDA_MODE,
        ]
    else:
        print(f"[DYNC][WARN] Frida 스크립트(bypass.js)를 찾을 수 없습니다: {FRIDA_SCRIPT}")
        
    print(f"\n[DYNC] 동적 분석 실행 명령:")
    print(" ", " ".join(cmd))

    try:
        subprocess.run(cmd, check=True)
        print("\n[DYNC] 동적 분석이 정상 종료되었습니다.")
    except subprocess.CalledProcessError as e:
        print(f"\n[DYNC] 동적 분석 실행 중 오류 발생: {e}")
    except Exception as e:
        print(f"\n[DYNC] 예기치 못한 오류: {e}")


def main():
    print("=== MobSF 메인 드라이버 ===")

    # 1) APK 경로 입력
    apk_input = input("분석할 APK 파일 경로를 입력하세요: ").strip()
    if not apk_input:
        print("APK 경로가 비어 있습니다. 종료합니다.")
        sys.exit(1)

    apk_path = Path(apk_input).expanduser().resolve()
    if not apk_path.exists():
        print(f"APK 파일을 찾을 수 없습니다: {apk_path}")
        sys.exit(1)

    # 서버는 고정, API 키만 입력
    print(f"MobSF 서버 URL: {SERVER} (고정)")
    apikey = input("MobSF API KEY (엔터 시 DEFAULT_APIKEY 사용): ").strip() or DEFAULT_APIKEY

    if not apikey:
        print("API KEY가 필요합니다. main.py 상단의 DEFAULT_APIKEY를 채우거나, 여기서 입력하세요.")
        sys.exit(1)

    # 2) 정적/동적 선택
    while True:
        mode = input("\n정적분석(S) / 동적분석(D)을 선택하세요 (S/D): ").strip().upper()
        if mode in ("S", "D"):
            break
        print("S 또는 D만 입력 가능합니다.")

    # 3) S → 파이프라인(복호화/우회/재서명) + 멀티 정적분석
    if mode == "S":
        run_static_pipeline(apk_path, apikey)
        use_vt = input("\n[옵션] VirusTotal 추가 정적 인텔리전스 분석도 수행할까요? (Y/n): ").strip().lower()
        if use_vt in ("", "y", "yes"):
            print("\n[VT] 선택된 APK에 대해 VirusTotal 인텔리전스를 조회합니다...")
            try:
                run_vt_report(target_apk_path=apk_path)
            except Exception as e:
                print(f"[VT] 분석 중 오류 발생: {e}")


    # 4) D → 입력 APK에 대해 동적 분석만
    else:
        run_dynamic_analysis(apk_path, apikey)


if __name__ == "__main__":
    main()
