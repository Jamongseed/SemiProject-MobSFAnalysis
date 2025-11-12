# pip install pycryptodomex==3.23.0
import subprocess
import re
import os
import shutil
import logging
import functools
import inspect
import secrets
from typing import List, Dict
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(module)s:%(lineno)d - %(levelname)s - %(message)s - %(funcName)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

DEFAULT_CLEAR_PATH = "clear_path"

KEY = b"dbcdcfghijklmaop"
PASSWORD = "goormthon"

CODE_PATH = "./smali-decrypted/"
KEYSTORE_PATH = CODE_PATH + "dev.keystore"

APKTOOL_JAR = CODE_PATH + "apktool.jar"
BAKSMALI_JAR = CODE_PATH + "baksmali-3.0.9-fat.jar"
SMALI_JAR = CODE_PATH + "smali-3.0.9-fat.jar"

SAMPLE_APK = "sample.apk"
NESTED_APK = "pgsHZz.apk"

SMALI_SAMPLE_FILE = "com\\ldjSxw\\heBbQd\\a\\b.smali"
SMALI_NESTED_FILE = "com\\bosetn\\oct16m\\kits\\Kit.smali"

SMALI_FILE_PATHS = [SMALI_SAMPLE_FILE, SMALI_NESTED_FILE]

KILL_CLASSES_DEX = "kill-classes.dex"

DECRYPTED = "decrypted"
CRYPTED = "crypted"
SMALI = "smali"
BYPASS = "bypass"
SIGNED = "signed"
APK = ".apk"
ASSETS = "ASSETS"
CLASSES_DEX = "classes.dex"

class Config:
    def __init__(self, apk):
        apk_name = Path(apk).stem
        self.base_dir = Path(CODE_PATH)
        # sample.apk
        self.apk = self.apk_name_factory([apk_name])
        # sample_signed_decrypted.apk
        self.signed_decrypted_apk = self.apk_name_factory([apk_name, SIGNED, DECRYPTED])
        # sample_signed_bypass_decrypted.apk
        self.signed_bypass_decrypted_apk = self.apk_name_factory([apk_name, SIGNED, BYPASS, DECRYPTED])
        # sample_signed_bypass_crypted.apk
        self.signed_bypass_crypted_apk = self.apk_name_factory([apk_name, SIGNED, BYPASS, CRYPTED])
        

        # sample_smali
        self.smali_dir = self.name_factory([apk_name, SMALI])

        # sapmle
        self.apk_dir = CODE_PATH + apk_name
        # sample_decrypted
        self.decrypted_dir = CODE_PATH + self.name_factory([apk_name, DECRYPTED]) 
        # sample_bypass_decrypted
        self.bypass_decrypted_dir = CODE_PATH + self.name_factory([apk_name, BYPASS, DECRYPTED])
        # sample_bypass_crypted
        self.bypass_crypted_dir = CODE_PATH + self.name_factory([apk_name, BYPASS, CRYPTED])
        
        self.dex_files: Dict[str, Dict[str, str]] = {}

    
    def get_dir_apk_list(self):
        return [
            (self.decrypted_dir, self.signed_decrypted_apk),
            (self.bypass_decrypted_dir, self.signed_bypass_decrypted_apk),
            (self.bypass_crypted_dir, self.signed_bypass_crypted_apk)
        ]

    
    def register_dex(self, dex_file: str):
        if dex_file == CLASSES_DEX:
            logging.info(f"DEX 파일 예외 : classes.dex은 등록하지 않습니다.")
            return
        # kill-classes
        dex_name = Path(dex_file).stem

        if dex_name in self.dex_files:
            logging.warning(f"DEX 파일 중복 : '{dex_name}'는(은) 이미 등록되었습니다. 덮어씁니다.")

        names_for_dex = {
            # kill-classes.dex
            "origin": dex_file,
            # decrypted-kill-classes.dex
            "decrypted": DECRYPTED + "-" + dex_file,
            # bypass-decrypted-kill-classes.dex
            "bypass-decrypted": BYPASS + "-" + DECRYPTED + "-" + dex_file,
            # bypass-crypted-kill-classes.dex
            "bypass-crypted": BYPASS + "-" + CRYPTED + "-" + dex_file
        }

        self.dex_files[dex_name] = names_for_dex
        logging.info(f"DEX 파일 등록됨: {dex_name}")


    def apk_name_factory(self, strs):
        return self.name_factory(strs) + APK

    
    def name_factory(self, strs: List[str]):
        return '_'.join(strs)


def clear_path(func):
    try:
        sig = inspect.signature(func)
    except ValueError:
        return func
    
    exists_clear_path = False

    for k, _ in sig.parameters.items():
        if k.find(DEFAULT_CLEAR_PATH) != -1:
            exists_clear_path = True

    if not exists_clear_path:
        return func
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        path_to_clear = None
        try:
            bound_args = sig.bind(*args, **kwargs)
            for k, _ in sig.parameters.items():
                if k.find(DEFAULT_CLEAR_PATH) != -1:
                    path_to_clear = bound_args.arguments.get(k)
        except TypeError as e:
            logging.warning(f"데코레이터 에러 : clear_path {func.__name__} 인자 바인딩에 실패했습니다.")

        if not path_to_clear:
            return func(*args, **kwargs)
        
        if Path(path_to_clear).is_dir():
            del_dir(path_to_clear)
        else:
            del_file(path_to_clear)

        return func(*args, **kwargs)
    return wrapper



def del_dir(dir: str):
    if (d := Path(dir)) and d.exists() and d.is_dir():
        shutil.rmtree(d)
        logging.info(f"디렉터리 삭제 : {d} 디렉터리를 삭제했습니다.")
    else:
        logging.debug(f"삭제 건너뜀 : {d} 디렉터리를 찾을 수 없습니다.")


def del_file(file: str):
    if (f := Path(file)) and f.exists():
        f.unlink()
        logging.info(f"파일 삭제 : {f} 파일을 삭제했습니다.")
    else:
        logging.debug(f"삭제 건너뜀 : {f} 파일을 찾을 수 없습니다.")


def win_call(commands: List[str]):
    try:
        result = subprocess.run(
            commands,
            creationflags=subprocess.CREATE_NO_WINDOW,
            capture_output=True,
            check=True,
            text=True,
            encoding='utf-8'
        )

        logging.info(result.stdout)
        logging.info(f"명령어 실행 완료 : {" ".join(commands)}")
    except subprocess.CalledProcessError as e:
        logging.warning(f"명령어 출력 : {' '.join(commands)} 명령어 실행 경고 : {e.stdout}")
        logging.critical(f"명령어 에러 출력 : {' '.join(commands)} 명령어 실행 에러 : {e.stderr}")
        raise e
    except Exception as e:
        logging.critical(f"명령어 에러 출력 : {" ".join(commands)} 명령어 실행 에러 : {e}")
        raise e


# apk 디컴파일 dex_clear_path 디렉터리로 추출
@clear_path
def decompile_apk_dex(apk: str, decrypted_clear_path: str):
    win_call(["java", "-jar", APKTOOL_JAR, "d", apk, "-s", 
        "-o", decrypted_clear_path, "-f"])
    logging.info(f"디컴파일 완료 : {apk} -> {decrypted_clear_path}")
    return decrypted_clear_path


# dex1 파일 복호화 후 dex2_clear_path 파일로 저장
@clear_path
def decrypt_dex(dex1: Path, dex2_clear_path: Path):
    with open(dex1, "rb") as f:
        crypted_dex_data = f.read()

    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(crypted_dex_data), AES.block_size)

    # dex2_clear_path 파일 생성
    if decrypted_data.startswith(b'dex\n'):
        with open(dex2_clear_path, "wb") as f:
            f.write(decrypted_data)
            logging.info(f"DEX 복호화 완료 : {dex1} -> {dex2_clear_path}")

        return dex2_clear_path
    else:
        logging.critical(f"DEX 복호화 실패 : {dex1} -> {dex2_clear_path} : {decrypted_data}가 dex로 시작하지 않습니다.")
        raise IOError


# dex 파일을 smali_clear_path 디렉터리로 디어셈블
@clear_path
def deassemble_dex_smali(dex: str, smali_dir_clear_path: str):
    win_call(["java", "-jar", BAKSMALI_JAR, "d", dex, "-o", smali_dir_clear_path])
    logging.info(f"디어셈블 완료 : {dex} -> {smali_dir_clear_path}")
    return smali_dir_clear_path
    

# 복호화된 smali 파일 수정, 저장(우회 로직 특화)
def modify_smali_bypass(smali: Path):
    method_signatures = [
        r"\.method public static k\(Landroid\/content\/Context;\)Z",
        r"\.method public static t0\(Landroid\/content\/Context;\)Z"
    ]
    
    method_end = r"\.end method"

    for method_signature in method_signatures:
        pattern = re.compile(f"({method_signature})(.*?)({method_end})", re.DOTALL)

        new_body_lines = [
            "    .registers 2",
            "    .param p0, \"context\"    # Landroid/content/Context;",
            "",
            "    const/4 v0, 0x0",
            "    return v0"
        ]
        replacement_body = "\n".join(new_body_lines)

        with open(smali, 'r', encoding='utf-8') as f:
            content = f.read()

        replacement_string = f"\\1\n{replacement_body}\n\\3"

        modified_content, count = pattern.subn(replacement_string, content)

        if count > 0:
            with open(smali, 'w', encoding="utf-8") as f:
                f.write(modified_content)
            logging.info(f"SMALI 수정 완료 : {smali}의 {method_signature} 시그니처에 해당하는 우회 로직을 수정 했습니다.")
            return smali
        else:
            logging.info(f"SMALI 수정 생략 : {smali} 파일에 {method_signature} 시그니처에 해당하는 수정할 로직이 없습니다. 다음 시그니처를 탐색합니다.")
            continue
    
    logging.critical(f"SMALI 수정 실패 : {smali} 파일에서 method_signature: {method_signature}, method_end: {method_end}와 매치되는 텍스트를 찾지 못했습니다.")
    raise FileNotFoundError


# smali_dir 디렉터리를 dex_clear_path로 어셈블
@clear_path
def assemble_smali_dex(smali_dir: str, dex_file_clear_path: str):
    win_call(["java", "-jar", SMALI_JAR, "a", smali_dir, 
    "-o", dex_file_clear_path])
    logging.info(f"DEX 생성 완료 : {smali_dir} 수정 후 {dex_file_clear_path} 어셈블 하였습니다.")
    return dex_file_clear_path


# dex를 암호화
def encrypt_dex_file(dex_file):
    with open(dex_file, "rb") as f:
        decrypted_dex_data = f.read()

    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(decrypted_dex_data, AES.block_size))


# encrypted_data 바이너리를 dex_clear_path 파일로 생성
@clear_path
def create_crypted_bypassed_dex_file(encrypted_data: bytes, dex_file_clear_path: Path):
    if not encrypted_data.startswith(b"dex\n"):
        with open(dex_file_clear_path, "wb") as f:
            f.write(encrypted_data)
            logging.info(f"DEX 암호화 완료 : {dex_file_clear_path} 파일을 생성했습니다.")
        return dex_file_clear_path
    else:
        logging.critical(f"DEX 암호화 실패 : 암호화 된 {encrypted_data[:20]} 데이터를 DEX 파일로 생성을 실패했습니다.")
        raise IOError


# dir 주소를 apk 컴파일
def compile_dex_to_apk(dir: str, apk: str):
    win_call(["java", "-jar", APKTOOL_JAR, "b", dir, "-o", apk])
    logging.info(f"APK 컴파일 완료 : {dir} -> {apk}")
    return apk


# 키 생성
@clear_path
def create_keystore(password: str, keystore_clear_path: str):
    win_call(["keytool", "-genkey", "-v", "-keystore", keystore_clear_path, "-alias", "dev",
          "-keyalg", "RSA", "-keysize", "2048", "-storepass", password, "-keypass", password,
          "-dname", "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown"])
    logging.info(f"KEYSTORE 생성 완료 : {keystore_clear_path}")
    return keystore_clear_path


# apk 서명
@clear_path
def sign_apk(keystore: str, password: str, compiled_apk: str, signed_apk_clear_path: str):
    win_call(["jarsigner", "-keystore", keystore, "-storepass", password,
              "-signedjar", signed_apk_clear_path, compiled_apk, "dev"])
    logging.info(f"APK 서명 완료 : keystore : {keystore}, before apk : {compiled_apk}, signed apk : {signed_apk_clear_path}")
    return signed_apk_clear_path


def run_apk_jobs(sc: Config):
    #   d. sample 디렉터리를 sample_decrypted, sample_bypass_decrypted, sample_bypass_crypted
    #      이름으로 각각 복사
    source_dir = Path(sc.apk_dir)
    target_dirs = [
        sc.decrypted_dir, sc.bypass_decrypted_dir, sc.bypass_crypted_dir
    ]

    if not source_dir.is_dir():
        logging.critical(f"복사할 원본 디렉터리 '{source_dir}'를 찾을 수 없습니다")
        raise FileNotFoundError
    else:
        logging.info(f"디렉터리 복사 : {source_dir} -> {target_dirs}")

        for dest_name in target_dirs:
            dest_path = Path(dest_name)

            if dest_path.exists():
                shutil.rmtree(dest_path)
            shutil.copytree(source_dir, dest_path)
            logging.info(f"복사 완료 : {dest_path}")

    #   e. 반복문으로 dex 파일 찾아서 각각 암복호화
    # 2. dex 복호화(AES ECB, KEY=dbcdcfghijklmaop, IV 없음)
    for dex in list(Path(sc.decrypted_dir).glob("*.dex")):
        
        if dex.name == CLASSES_DEX:
            continue
        
        sc.register_dex(dex.name)

    #   a. sample_decrypted 디렉터리에서 작업
    #   b. 암호화 된 kill-classes.dex를 복호화
    #   c. decrypted-kill-classes.dex 이름으로 저장, kill-classes.dex삭제
        dex_dict = sc.dex_files[dex.stem]
        decrypted_dir = Path(sc.decrypted_dir)
        origin_dex = decrypted_dir / dex_dict["origin"]
        new_dex = decrypted_dir / dex_dict["decrypted"]
        decrypted_dex = decrypt_dex(origin_dex, dex2_clear_path=new_dex)
        del_file(str(origin_dex))

        # 우회 로직 수정이 필요없는 경우 smali 파일을 수정할 필요가 없고
        # bypass_decrypted 파일에 복호화 된 dex 파일만 저장하면 된다.
        # bypass_decrypted 디렉터리에 암호화 된 기존 파일은 삭제한다.
        if dex.name != KILL_CLASSES_DEX:
            bypass_decrypted_dir = Path(sc.bypass_decrypted_dir)
            bypass_decrypted_dex = bypass_decrypted_dir / dex_dict["bypass-decrypted"]
            shutil.copy2(decrypted_dex, bypass_decrypted_dex)
            logging.info(f"복사 완료 : {decrypted_dex} -> {bypass_decrypted_dex}")

            origin_dex = bypass_decrypted_dir / dex_dict["origin"]
            del_file(str(origin_dex))
            continue

    # 3. dex를 smail로 디어셈블
    #   a. decrypted-kill-classes.dex를 smail로 디어셈블
        smali_dir = decrypted_dir / sc.smali_dir
        deassemble_dex_smali(str(decrypted_dex),
                                            smali_dir_clear_path=str(smali_dir))

    # 4. smali 우회 로직 수정
        smali_file_path = None
        for path in SMALI_FILE_PATHS:
            if (Path(smali_dir) / path).exists():
                smali_file_path = Path(smali_dir) / path
                break
        if not smali_file_path:
            logging.critical(f"SMALI 경로 에러 : {smali_dir}에서 smali 경로를 찾을 수 없습니다.")
            raise FileNotFoundError
        
        modify_smali_bypass(smali_file_path)

    # 5. bypass-decrypted-kill-classes.dex 제작
    #   a. sample_smali → dex로 어셈블
        bypass_decrypted_dex = decrypted_dir / dex_dict["bypass-decrypted"]
        assemble_smali_dex(str(smali_dir),
            dex_file_clear_path=str(bypass_decrypted_dex))
        
    #   c. sample_bypass_decrypted 디렉터리로 이동, kill-classes.dex삭제
        bypass_decrypted_dir = Path(sc.bypass_decrypted_dir)
        origin_dex = bypass_decrypted_dir / dex_dict["origin"]

        del_file(str(origin_dex))
    #      bypass-decrypted-kill-classes.dex를 저장
        shutil.move(bypass_decrypted_dex, bypass_decrypted_dir)
        logging.info(f"파일 이동 완료 : {bypass_decrypted_dex} -> {bypass_decrypted_dir}")

    # 6. 우회 된 dex 파일을 암호화하여 저장
    #   a. bypass-decrypted-kill-classes.dex를 암호화
        bypass_decrypted_dex = bypass_decrypted_dir / dex_dict["bypass-decrypted"]
        encrypted_data = encrypt_dex_file(Path(bypass_decrypted_dex))

    #   b. sample_bypass_crypted 디렉터리에 kill-classes.dex삭제
        bypass_crypted_dir = Path(sc.bypass_crypted_dir)
        origin_dex = bypass_crypted_dir / dex_dict["origin"]
        del_file(str(origin_dex))

    #      sample_bypass_crypted 디렉터리에 bypass-crypted-kill-classes.dex로 저장
        bypass_crypted_dex = bypass_crypted_dir / dex_dict["bypass-crypted"]
        create_crypted_bypassed_dex_file(
            encrypted_data, dex_file_clear_path=bypass_crypted_dex)
        logging.info(f"DEX 생성 완료 : {bypass_crypted_dex} 생성을 완료했습니다.")


def compile_sign_apk(keystore, dir: str, base_dir: Path, apk: str):
    compile_apk_path = base_dir / Path(secrets.token_hex(4) + apk)
    logging.info(f"APK 컴파일 시작 : {dir} 프로젝트를 APK 컴파일을 시작했습니다.")
    compiled_apk = compile_dex_to_apk(dir, str(compile_apk_path))
    logging.info(f"파일 생성 완료 : {compiled_apk}를 임시 생성했습니다.")

    signed_apk = base_dir / apk
    sign_apk(keystore, PASSWORD, compiled_apk, signed_apk_clear_path=str(signed_apk))

    del_file(compiled_apk)
    logging.info(f"파일 삭제 완료 : 임시 생성 된 {compiled_apk}를 삭제하였습니다.")
    logging.info(f"파일 생성 완료 : {apk} ")

if __name__ == "__main__":
    try:
        # sample.apk 현재 디렉터리로 복사
        shutil.copy2(Path(SAMPLE_APK), Path(CODE_PATH) / SAMPLE_APK)

        sc = Config(SAMPLE_APK)
        
        # 1. dex 추출 디컴파일
        #   a. sample.apk → sample(암호화 디렉터리)
        decompiled_dex_dir_path = decompile_apk_dex(str(sc.base_dir / sc.apk),
                                                    decrypted_clear_path=sc.apk_dir)
        #   c. assets 디렉터리에 있는 nested_apk를 프로젝트 디렉터리로 이동
        source_apk = Path(sc.apk_dir) / ASSETS / NESTED_APK
        dest_apk = sc.base_dir / source_apk.name

        if source_apk.exists():
            shutil.move(source_apk, dest_apk)
            logging.info(f"파일 이동 완료: '{source_apk}' -> '{dest_apk}'")
        else:
            logging.critical(f"파일 에러 : {source_apk} nested apk를 찾을 수 없습니다")
            raise FileNotFoundError

        run_apk_jobs(sc)
        
        keystore = create_keystore(PASSWORD, keystore_clear_path=KEYSTORE_PATH)

        # 9. nested apk 각각 컴파일 후 assets 디렉터리 이동
        #   a. pgsHZz_decrypted, pgsHZz_bypass_decrypted, pgsHZz_bypass_crypted를 apk로 컴파일 → 키 서명
        nest_sc = Config(NESTED_APK)

        decompile_apk_dex(str(nest_sc.base_dir / nest_sc.apk), decrypted_clear_path=nest_sc.apk_dir)

        run_apk_jobs(nest_sc)
        
        for dir, apk in nest_sc.get_dir_apk_list():
            compile_sign_apk(keystore, dir, nest_sc.base_dir, apk)
            d = None

        #   b. 우회 유무, 암복호화 상태 맞춰서 원래 있던 디렉터리의 assets 디렉터리로 이동
            if BYPASS in apk and DECRYPTED in apk:
                d = sc.bypass_decrypted_dir
            elif BYPASS in apk and CRYPTED in apk:
                d = sc.bypass_crypted_dir
            elif DECRYPTED in apk:
                d = sc.decrypted_dir
            else:
                logging.critical(f"APK 이름 에러 : {dir} {apk} 파일이 assets 디렉터리로 이동하지 않았습니다.")
                raise FileNotFoundError
        
            sorce = sc.base_dir / apk
            dest = Path(d) / ASSETS / NESTED_APK
            shutil.copy2(sorce, dest)
            logging.info(f"APK 복사 완료 : {sorce}을 {dest}로 복사했습니다.")
            
        # 10. 전체 수정된 디렉터리를 apk 컴파일, 키 제작, 서명
        #   a. sample_decrypted, sample_bypass_decrypted, sample_bypass_crypted
        for dir, apk in sc.get_dir_apk_list():
            compile_sign_apk(keystore, dir, sc.base_dir, apk)
    except Exception as e:
        print(e)
        exit()
