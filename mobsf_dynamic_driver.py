#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, time, zipfile, shutil, subprocess, argparse, pathlib, shlex, re
from datetime import datetime
import requests

try:
    import yaml
except Exception:
    yaml = None

from mobsf_api import upload_apk_with_filename

# ---------------- Utils ----------------
def ts(): return time.strftime("[%H:%M:%S]")

def run(cmd, check=True, capture=False, text=True, quiet=False):
    if not quiet:
        print(f"{ts()}$ {' '.join(cmd)}")

    if capture:
        p = subprocess.run(
            cmd,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=text,
        )
        out = (p.stdout or "").strip()
        if out and not quiet:
            for line in out.splitlines():
                print(line)
        return out
    else:
        if quiet:
            return subprocess.run(
                cmd,
                check=check,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=text,
            )
        else:
            return subprocess.run(cmd, check=check, text=text)

def adb(device, args, **kw):
    return run(["adb", "-s", device] + args, **kw)

    
def adb(device, args, **kw):
    return run(["adb", "-s", device] + args, **kw)


def ensure_dir(p: pathlib.Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def ensure_adb_connected(device, retries=3, delay=1.0):
    for i in range(retries):
        try:
            out = run(["adb", "-s", device, "get-state"], check=False, capture=True)
            if (out or "").strip() == "device":
                return True
        except Exception:
            pass
        if ":" in device:
            run(["adb", "connect", device], check=False, capture=True)
        time.sleep(delay)
    return False

def http(server, path, apikey, method="POST", **kw):
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

# ---------------- UI helpers ----------------
KEYMAP = {
    "TAB": "61", "ENTER": "66", "BACK": "4",
    "DPAD_CENTER": "23", "DPAD_DOWN": "20", "DPAD_UP": "19",
    "DPAD_LEFT": "21", "DPAD_RIGHT": "22",
    "HOME": "3", "APP_SWITCH": "187", "POWER": "26", "MENU": "82",
}

def wake_and_unlock(device):
    adb(device, ["shell", "input", "keyevent", "224"], check=False)  # SCREEN_ON
    time.sleep(0.4)
    adb(device, ["shell", "input", "keyevent", KEYMAP["MENU"]], check=False)
    time.sleep(0.2)
    adb(device, ["shell", "input", "keyevent", KEYMAP["HOME"]], check=False)
    time.sleep(0.3)

def start_logcat(device, outfile):
    try: adb(device, ["logcat", "-c"], check=False)
    except Exception: pass
    f = open(outfile, "w", encoding="utf-8", errors="ignore")
    p = subprocess.Popen(["adb", "-s", device, "logcat", "-v", "time"],
                         stdout=f, stderr=subprocess.STDOUT)
    return p, f

def stop_logcat(proc, fp):
    try:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(2)
            except Exception: proc.kill()
    finally:
        try: fp.flush(); fp.close()
        except Exception: pass

def top_activity(device):
    try:
        out = adb(
            device,
            ["shell", "dumpsys", "activity", "activities"],
            capture=True,
            check=False,
            quiet=True,
        )
    except Exception:
        return ""

    if not out:
        return ""

    cur = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("topResumedActivity:"):
            cur = s.split()[-1]
            break
        if " realActivity=" in s:
            ix = s.find("realActivity=")
            if ix >= 0:
                cur = s[ix + len("realActivity="):].strip()
                break
    return cur

def wait_activity(device, target, timeout=12.0, poll=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        cur = top_activity(device)
        if target in cur:
            print(f"{ts()}[UI] target reached → {cur}")
            return True
        time.sleep(poll)
    print(f"{ts()}[UI] wait_activity timeout. last={top_activity(device)}")
    return False

def start_activity(device, component, wait_done=True):
    adb(device, ["shell", "am", "start", "-W", "-n", component], check=False)
    if wait_done:
        wait_activity(device, component, timeout=10.0)

def send_keys(device, keys, delay=0.25, quiet=False, log_keys=True):
    for k in keys:
        code = KEYMAP.get(k.upper())
        if not code:
            raise SystemExit(f"정의되지 않은 key: {k} (허용: {list(KEYMAP.keys())})")
        if log_keys:
            print(f"{ts()}[KEY] {k} → {code}")
        adb(device, ["shell", "input", "keyevent", code], check=False, quiet=quiet)
        time.sleep(delay)


# ---------------- Scenario ----------------
def parse_scenario(path):
    p = pathlib.Path(path)
    raw = p.read_text(encoding="utf-8")
    if yaml:
        try: return yaml.safe_load(raw)
        except Exception: pass
    return json.loads(raw)

def normalize_scenario(spec):
    return {
        "launch_activity": spec.get("launch_activity"),
        "post_launch_sleep": float(spec.get("post_launch_sleep", 0.0)),
        "steps": list(spec.get("steps", [])),
    }

def exec_step(device, step, quiet=False, log_keys=True):
    # 1) 단순 대기
    if "wait_ms" in step:
        ms = float(step.get("wait_ms", 0))
        if ms > 0:
            if not quiet:
                print(f"{ts()}[STEP] wait_ms {ms}ms")
            time.sleep(ms / 1000.0)
        return

    if "sleep" in step:
        secs = float(step["sleep"])
        if not quiet:
            print(f"{ts()}[STEP] sleep {secs}s")
        time.sleep(secs)
        return

    # 2) activity 대기
    if "wait_activity" in step:
        ok = wait_activity(device, step["wait_activity"],
                           timeout=float(step.get("timeout", 12.0)))
        if not ok and not quiet:
            print(f"{ts()}[WARN] wait_activity 실패: {step['wait_activity']}")
        return

    # 3) 키 입력
    if "keys" in step:
        delay = float(step.get("delay", 0.25))
        send_keys(device, step["keys"], delay=delay, quiet=quiet, log_keys=log_keys)
        return

    # 4) Activity 시작
    if "launch_activity" in step:
        comp = step["launch_activity"]
        start_activity(device, comp, wait_done=True)
        return

    if "start_activity" in step:
        comp = step["start_activity"]
        if isinstance(comp, dict):
            comp = comp.get("component")
        if not comp:
            if not quiet:
                print(f"{ts()}[WARN] start_activity: component 누락")
            return
        start_activity(device, comp, wait_done=True)
        return

    # 5) VIEW intent
    if "start_view" in step:
        item = step["start_view"]
        uri = item.get("uri") if isinstance(item, dict) else str(item)
        if not uri:
            if not quiet:
                print(f"{ts()}[WARN] start_view: uri 누락")
            return
        adb(device, ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                     "-d", uri], check=False, quiet=quiet)
        return

    # 6) raw adb
    if "adb" in step:
        cmds = step["adb"]
        cmds = [cmds] if isinstance(cmds, str) else cmds
        for line in cmds:
            if not line.strip():
                continue
            parts = shlex.split(line)
            if parts[:2] == ["adb", "shell"]:
                adb(device, parts[2:], check=False, quiet=quiet)
            elif parts and parts[0] == "adb":
                adb(device, parts[1:], check=False, quiet=quiet)
            else:
                adb(device, ["shell"] + parts, check=False, quiet=quiet)
        return

    if not quiet:
        print(f"{ts()}[WARN] 알 수 없는 step: {step}")


# ---------------- MobSF helpers ----------------
def pm_clear(device, pkg):
    try:
        print(f"{ts()}[APP] pm clear {pkg}")
        adb(device, ["shell","pm","clear", pkg], check=False)
    except Exception: pass

def mobsf_activity_test(server, apikey, app_hash, mode="exported"):
    # mode: "exported" or "activity"
    return http(server, "/api/v1/android/activity", apikey,
                data={"hash": app_hash, "test": mode}).json()

def mobsf_start_activity(server, apikey, app_hash, component):
    # component 예: "com.ldjSxw.heBbQd/.IntroActivity"
    return http(server, "/api/v1/android/start_activity", apikey,
                data={"hash": app_hash, "activity": component}).json()

def mobsf_tls_tests(server, apikey, app_hash):
    return http(server, "/api/v1/android/tls_tests", apikey,
                data={"hash": app_hash}).json()

# ---------------- Proxy helpers ----------------
PROXY_CHECK_CMDS = [
    ["shell","settings","get","global","http_proxy"],
    ["shell","settings","get","global","global_http_proxy_host"],
    ["shell","settings","get","global","global_http_proxy_port"],
    ["shell","getprop","http.proxy"],
    ["shell","getprop","https.proxy"],
]

def log_proxy_state(device, prefix="[PROXY]"):
    print(f"{ts()}{prefix} --- proxy state ---")
    for c in PROXY_CHECK_CMDS:
        try:
            out = adb(device, c, capture=True).strip()
        except Exception:
            out = "(error)"
        print(f"{ts()}{prefix} {' '.join(c[1:]):<45} => {out or '(empty)'}")

def set_os_proxy(device, host, port):
    cmds = [
        ["shell","settings","put","global","http_proxy", f"{host}:{port}"],
        ["shell","settings","put","global","global_http_proxy_host", host],
        ["shell","settings","put","global","global_http_proxy_port", str(port)],
        ["shell","setprop","http.proxy", f"{host}:{port}"],
        ["shell","setprop","https.proxy", f"{host}:{port}"],
    ]
    for c in cmds: adb(device, c, check=False)
    log_proxy_state(device, prefix="[PROXY after set]")

def unset_os_proxy(device):
    ensure_adb_connected(device)
    cmds = [
        ["shell","settings","delete","global","http_proxy"],
        ["shell","settings","put","global","global_http_proxy_host",""],
        ["shell","settings","put","global","global_http_proxy_port","0"],
        ["shell","settings","put","system","http_proxy",""],
        ["shell","setprop","http.proxy",""],
        ["shell","setprop","https.proxy",""],
    ]
    for c in cmds: adb(device, c, check=False)
    log_proxy_state(device, prefix="[PROXY after unset]")

# ---------------- Frida helpers ----------------
def frida_attach(host, pid, script, log_path=None):
    args = ["frida", "-H", host, "-p", str(pid), "-l", script, "-q"]
    if log_path:
        args += ["-o", log_path]
    print(f"{ts()}$ {' '.join(args)}")
    return subprocess.Popen(args, stdin=subprocess.PIPE)

def frida_spawn(host, package, script, log_path=None):
    args = ["frida", "-H", host, "-f", package, "-l", script]
    if log_path:
        args += ["-o", log_path]
    print(f"{ts()}$ {' '.join(args)}")
    p = subprocess.Popen(args, stdin=subprocess.PIPE, text=True)
    try:
        time.sleep(0.6)
        p.stdin.write("%resume\n"); p.stdin.flush()
    except Exception:
        pass
    return p

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="MobSF dynamic driver with install+main scenarios")
    ap.add_argument("--server", required=True)
    ap.add_argument("--apikey", required=True)
    ap.add_argument("--device", required=True)
    ap.add_argument("--apk", required=True)
    ap.add_argument("--scenario", required=True, help="메인 시나리오 YAML/JSON")
    ap.add_argument("--scenario-install", default=None, help="설치/권한 처리용 시나리오(YAML/JSON)")
    ap.add_argument("--post-install-wait", type=float, default=2.0, help="설치 시나리오 종료 후 대기(초)")
    ap.add_argument("--outdir", default="output")
    ap.add_argument("--tail-secs", type=float, default=5.0)
    # Frida
    ap.add_argument("--frida-host", default=None)
    ap.add_argument("--frida-script", default=None)
    ap.add_argument("--frida-log", default="frida.log")
    ap.add_argument("--frida-mode", choices=["attach","spawn"], default="spawn")
    ap.add_argument("--package", default=None)
    # Proxy control
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--keep-proxy", action="store_true")
    ap.add_argument("--force-proxy", default=None, help="HOST:PORT")
    # Misc
    ap.add_argument("--clear-data", action="store_true")
    args = ap.parse_args()

    server, apikey, device = args.server, args.apikey, args.device
    apk_path = str(pathlib.Path(args.apk).resolve())
    scen_main = normalize_scenario(parse_scenario(args.scenario))
    scen_install = normalize_scenario(parse_scenario(args.scenario_install)) if args.scenario_install else None

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = ensure_dir(pathlib.Path(args.outdir) / f"run_{stamp}")
    logcat_file = outdir / "logcat.txt"
    dyn_json = outdir / "dynamic_report.json"

    print(f"{ts()} START with: server={server}, device={device}")
    print(f"{ts()} output → {outdir}")

    lc_proc, lc_fp = start_logcat(device, str(logcat_file))
    frida_proc = None

    try:
        wake_and_unlock(device)

        # 1) 업로드/정적
        try:
            r = upload_apk_with_filename(
                pathlib.Path(apk_path),
                server=server,
                apikey=apikey,
            )
        except requests.HTTPError as e:
            msg = e.response.text if e.response is not None else ""
            if "File format not Supported" in msg:
                with open(apk_path, "rb") as f:
                    files = {"file": ("sample.apk", f, "application/octet-stream")}
                    r = http(server, "/api/v1/upload", apikey, files=files, data={"scan_type":"apk"})
            else:
                raise
        j = r.json()
        app_hash = j.get("hash") or j.get("md5")
        if not app_hash:
            raise SystemExit("MobSF 업로드 응답에 hash 없음")

        scan_meta = http(server, "/api/v1/scan", apikey, data={"hash": app_hash}).json()
        pkg = args.package or scan_meta.get("package_name") or ""
        if not pkg:
            raise SystemExit("패키지명을 찾을 수 없습니다. --package 를 지정하세요.")

        if args.clear_data:
            pm_clear(device, pkg)

        # 3) 프록시
        if args.no_proxy:
            print(f"{ts()}[PROXY] NO-PROXY mode")
            unset_os_proxy(device)
        else:
            if args.force_proxy:
                m = re.match(r"^([^:]+):(\d+)$", args.force_proxy.strip())
                if not m:
                    raise SystemExit("--force-proxy 형식은 HOST:PORT")
                host, port = m.group(1), int(m.group(2))
                print(f"{ts()}[PROXY] FORCE set OS proxy to {host}:{port}")
                set_os_proxy(device, host, port)
            else:
                try:
                    http(server, "/api/v1/android/mobsfy", apikey, data={"identifier": device})
                except Exception as e:
                    print(f"{ts()}[MobSF] /android/mobsfy 스킵: {e}")
                try:
                    http(server, "/api/v1/android/global_proxy", apikey, data={"action": "set"})
                except Exception as e:
                    print(f"{ts()}[MobSF] /android/global_proxy 스킵: {e}")
                log_proxy_state(device, prefix="[PROXY after MobSF]")

        # 2) 동적 시작(설치 트래픽까지 캡처하려면 여기서 시작)
        http(server, "/api/v1/dynamic/start_analysis", apikey, data={"hash": app_hash})

        # 4) Frida (옵션)
        if args.frida_host and args.frida_script:
            if args.frida_mode == "spawn":
                frida_proc = frida_spawn(args.frida_host, pkg, args.frida_script, args.frida_log)
                time.sleep(float(scen_install.get("post_launch_sleep", 0.8) if scen_install else scen_main.get("post_launch_sleep", 0.8)))
            else:
                first_launch = (scen_install or {}).get("launch_activity") or scen_main.get("launch_activity")
                if first_launch:
                    print(f"{ts()}[STEP] launch → {first_launch}")
                    start_activity(device, first_launch, wait_done=True)
                    time.sleep(float(scen_install.get("post_launch_sleep", 0.8) if scen_install else scen_main.get("post_launch_sleep", 0.8)))
                pid = adb(device, ["shell","pidof","-s", pkg], capture=True).strip()
                if not pid and scen_main.get("launch_activity"):
                    start_activity(device, scen_main["launch_activity"], wait_done=True)
                    time.sleep(0.8)
                    pid = adb(device, ["shell","pidof","-s", pkg], capture=True).strip()
                if pid:
                    print(f"{ts()}[FRIDA] attach pid={pid}")
                    frida_proc = frida_attach(args.frida_host, pid, args.frida_script, args.frida_log)

        # 5) 설치 시나리오 (있으면 먼저)
        if scen_install:
            if scen_install.get("launch_activity"):
                print(f"{ts()}[INSTALL] launch → {scen_install['launch_activity']}")
                start_activity(device, scen_install["launch_activity"], wait_done=True)
                if scen_install.get("post_launch_sleep", 0):
                    time.sleep(float(scen_install["post_launch_sleep"]))

            for i, step in enumerate(scen_install.get("steps", []), 1):
                print(f"{ts()}[INSTALL STEP {i}]")
                exec_step(device, step, quiet=True, log_keys=False)

            if args.post_install_wait > 0:
                print(f"{ts()}[INSTALL] post-install wait {args.post_install_wait}s")
                time.sleep(args.post_install_wait)

        # 6) 메인 시나리오
        print(f"{ts()} ==== RUN MAIN SCENARIO ====")
        if scen_main.get("launch_activity"):
            print(f"{ts()}[STEP] launch → {scen_main['launch_activity']}")
            start_activity(device, scen_main["launch_activity"], wait_done=True)
            if scen_main.get("post_launch_sleep", 0):
                time.sleep(float(scen_main["post_launch_sleep"]))
        for i, step in enumerate(scen_main.get("steps", []), 1):
            print(f"{ts()}[STEP {i}] {step}")
            exec_step(device, step)

        # MobSF 부가 점검(동적 종료/리포트 수집 전에)
        try:
            print(f"{ts()} === MobSF exported activity sweep ===")
            r = mobsf_activity_test(server, apikey, app_hash, "exported")
            print(f"{ts()}[MobSF] activity(exported) → {r}")
        except Exception as e:
            print(f"{ts()}[MobSF] activity(exported) 실패: {e}")
        
        try:
            print(f"{ts()} === MobSF TLS tests ===")
            tls = mobsf_tls_tests(server, apikey, app_hash)
            print(f"{ts()}[MobSF] tls_tests → {tls.get('tls_tests')}")
            (outdir / "tls_tests.json").write_text(
                json.dumps(tls, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            print(f"{ts()} saved → {outdir/'tls_tests.json'}")
        except Exception as e:
            print(f"{ts()}[MobSF] tls_tests 실패: {e}")
        
        # 7) tail
        if args.tail_secs > 0:
            print(f"{ts()} tail wait {args.tail_secs}s...")
            time.sleep(args.tail_secs)

        # 8) 리포트/아티팩트(프록시 해제 전에)
        try:
            rj = http(server, "/api/v1/dynamic/report_json", apikey, data={"hash": app_hash})
            dyn_json.write_text(rj.text, encoding="utf-8")
            print(f"{ts()} saved → {dyn_json}")
        except Exception as e:
            print(f"{ts()}[MobSF] dynamic/report_json 실패: {e}")

        def fetch_dyn_file(server, apikey, h, mob_name, save_as, outdir):
            try:
                r = http(server, "/api/v1/dynamic/download", apikey,
                         data={"hash": h, "file": mob_name})
                p = pathlib.Path(outdir) / save_as
                p.write_bytes(r.content)
                print(f"{ts()} saved → {p}  (src={mob_name})")
                return True
            except Exception as e:
                print(f"{ts()}[MISS] {mob_name} → {e}")
                return False

        def fetch_first(server, apikey, h, names, save_as, outdir):
            for nm in names:
                if fetch_dyn_file(server, apikey, h, nm, save_as, outdir):
                    return True
            return False

        got = False
        got |= fetch_first(server, apikey, app_hash,
                           [f"{app_hash}-web_traffic.txt",
                            f"{app_hash}-web-traffic.txt",
                            "web_traffic.txt", "web-traffic.txt"],
                           "web_traffic.txt", outdir)

        fetch_first(server, apikey, app_hash,
                    [f"{app_hash}-logcat.txt", "logcat.txt"],
                    "device_logcat.txt", outdir)

        fetch_first(server, apikey, app_hash,
                    [f"{app_hash}-app_data.tar", "app_data.tar"],
                    "app_data.tar", outdir)

        if not got:
            print(f"{ts()}[MobSF] web_traffic 미수집 → 우회/핀/직접소켓 가능성")

        # 9) 동적 종료
        try:
            http(server, "/api/v1/dynamic/stop_analysis", apikey, data={"hash": app_hash})
        except Exception as e:
            print(f"{ts()}[MobSF] stop_analysis 스킵: {e}")
        time.sleep(0.6)

        # 10) 프록시 해제
        if args.no_proxy:
            pass
        elif args.keep_proxy:
            print(f"{ts()}[PROXY] keep-proxy requested: 프록시 해제하지 않음")
            log_proxy_state(device, prefix="[PROXY kept]")
        else:
            try:
                ensure_adb_connected(device)
                http(server, "/api/v1/android/global_proxy", apikey, data={"action": "unset"})
            except Exception as e:
                print(f"{ts()}[MobSF] global_proxy unset 실패 → OS에서 직접 해제: {e}")
            unset_os_proxy(device)

    finally:
        try:
            if frida_proc:
                try:
                    if getattr(frida_proc, "stdin", None):
                        frida_proc.stdin.close()
                except Exception:
                    pass
                if frida_proc.poll() is None:
                    frida_proc.terminate()
                    try: frida_proc.wait(2)
                    except Exception: frida_proc.kill()
        except Exception:
            pass
        stop_logcat(lc_proc, lc_fp)

        time.sleep(0.2)

        print(f"{ts()} logcat saved at: {logcat_file}")

if __name__ == "__main__":
    main()
