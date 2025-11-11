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
    format='%(asctime)s %(module)s:%(lineno)d - %(funcName)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

DEFAULT_CLEAR_PATH = "clear_path"

KEY = b"dbcdcfghijklmaop"
PASSWORD = "goormthon"
KEYSTORE = "dev.keystore"

APKTOOL_JAR = "apktool.jar"
BAKSMALI_JAR = "baksmali-3.0.9-fat.jar"
SMALI_JAR = "smali-3.0.9-fat.jar"

SAMPLE_APK = "sample.apk"
SAMPLE_BYPASS_CRYPTED_APK = "sample_bypass_crypted.apk"
SAMPLE_SIGNED_CRYPTED_APK = "sample_signed_crypted.apk"

SAMPLE_DEX_DIR = "sample-dex"

SMALI_SAMPLE_FILE = "com\\ldjSxw\\heBbQd\\a\\b.smali"
SMALI_NESTED_FILE = "com\\bosetn\\oct16m\\kits\\Kit.smali"

SMALI_FILE_PATHS = [SMALI_SAMPLE_FILE, SMALI_NESTED_FILE]

SMALI_DECRYPTED_SAMPLE_DIR = "smail-decrypted-sample"

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
        self.base_dir = Path(".")
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
        self.apk_dir = apk_name
        # sample_decrypted
        self.decrypted_dir = self.name_factory([apk_name, DECRYPTED]) 
        # sample_bypass_decrypted
        self.bypass_decrypted_dir = self.name_factory([apk_name, BYPASS, DECRYPTED])
        # sample_bypass_crypted
        self.bypass_crypted_dir = self.name_factory([apk_name, BYPASS, CRYPTED])
        
        self.dex_files: Dict[str, Dict[str, str]] = {}

    
    def get_dir_apk_list(self):
        return [
            (self.decrypted_dir, self.signed_decrypted_apk),
            (self.bypass_decrypted_dir, self.signed_bypass_decrypted_apk),
            (self.bypass_crypted_dir, self.signed_bypass_crypted_apk)
        ]

    
    def register_dex(self, dex_file: str):
        if dex_file == CLASSES_DEX:
            logging.info("classes.dex은 등록하지 않음")
            return
        # kill-classes
        dex_name = Path(dex_file).stem

        if dex_name in self.dex_files:
            logging.warning(f"'{dex_name}'는(은) 이미 등록되었습니다. 덮어씁니다.")

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
            logging.warning(f"clear_path {func.__name__} 인자 바인딩 실패")

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
        logging.info(f"{d} 삭제")
    else:
        logging.debug(f"{d} 디렉터리를 찾을 수 없습니다.")


def del_file(file: str):
    if (f := Path(file)) and f.exists():
        f.unlink()
        logging.info(f"{f} 삭제")
    else:
        logging.debug(f"{f} 파일을 찾을 수 없습니다.")


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
        logging.warning(f"{" ".join(commands)} 명령어 실행 경고 : {e.stdout}")
        logging.critical(f"{" ".join(commands)} 명령어 실행 에러 : {e.stderr}")
        raise e
    except Exception as e:
        logging.critical(f"{" ".join(commands)} 명령어 실행 에러 : {e}")
        raise e


# apk 디컴파일 dex_clear_path 디렉터리로 추출
@clear_path
def decompile_apk_dex(apk: str, decrypted_clear_path: str):
    win_call(["java", "-jar", APKTOOL_JAR, "d", apk, "-s", 
        "-o", decrypted_clear_path, "-f"])
    logging.info(f"{apk}를 {decrypted_clear_path}에 디컴파일")
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
            logging.info(f"{dex2_clear_path} 파일 생성")

        return dex2_clear_path


# dex 파일을 smali_clear_path 디렉터리로 디어셈블
@clear_path
def deassemble_dex_smali(dex: str, smali_dir_clear_path: str):
    win_call(["java", "-jar", BAKSMALI_JAR, "d", dex, "-o", smali_dir_clear_path])
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
            return smali
        else:
            continue
    
    logging.critical(f"method_signature: {method_signature}, method_end: {method_end}와 매치되는 텍스트를 찾지 못했습니다.")
    raise FileNotFoundError


# smali_dir 디렉터리를 dex_clear_path로 어셈블
@clear_path
def assemble_smali_dex(smali_dir: str, dex_file_clear_path: str):
    win_call(["java", "-jar", SMALI_JAR, "a", smali_dir, 
    "-o", dex_file_clear_path])
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
            logging.info(f"{dex_file_clear_path} 파일 생성")
        return dex_file_clear_path
    return None


# dir 주소를 apk 컴파일
def compile_dex_to_apk(dir, apk):
    win_call(["java", "-jar", APKTOOL_JAR, "b", dir, "-o", apk])
    return apk


# 키 생성
@clear_path
def create_keystore(password: str, keystore_clear_path: str):
    win_call(["keytool", "-genkey", "-v", "-keystore", keystore_clear_path, "-alias", "dev",
          "-keyalg", "RSA", "-keysize", "2048", "-storepass", password, "-keypass", password,
          "-dname", "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown"])
    return keystore_clear_path


# apk 서명
@clear_path
def sign_apk(keystore, password, compiled_apk, signed_apk_clear_path):
    win_call(["jarsigner", "-verbose", "-keystore", keystore, "-storepass", password,
              "-signedjar", signed_apk_clear_path, compiled_apk, "dev"])
    return signed_apk_clear_path


def run_apk_jobs(sc: Config):
    #   d. sample 디렉터리를 sample_decrypted, sample_bypass_decrypted, sample_bypass_crypted
    #      이름으로 각각 복제
    source_dir = Path(sc.apk_dir)
    target_dirs = [
        sc.decrypted_dir, sc.bypass_decrypted_dir, sc.bypass_crypted_dir
    ]

    if not source_dir.is_dir():
        logging.error(f"복사할 원본 디렉터리 '{source_dir}'를 찾을 수 없습니다")
        raise FileNotFoundError
    else:
        logging.info(f"'{source_dir}'를 다음 대상 폴더로 복제합니다: {target_dirs}")

        for dest_name in target_dirs:
            dest_path = Path(dest_name)

            if dest_path.exists():
                shutil.rmtree(dest_path)
            shutil.copytree(source_dir, dest_path)
            logging.info(f"'{dest_path}' 복제 완료.")

    #   e. 반복문으로 dex 파일 찾아서 각각 암복호화
    # 2. dex 복호화(AES ECB, KEY=dbcdcfghijklmaop, IV 없음)
    for dex in list(Path(sc.decrypted_dir).glob("*.dex")):
        
        if dex.name == CLASSES_DEX or dex.name != KILL_CLASSES_DEX:
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
            logging.critical(f"{smali_dir}에서 smali 경로를 찾을 수 없습니다.")
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


def compile_sign_apk(keystore, dir, apk):
    random = secrets.token_hex(4)
    compiled_apk = compile_dex_to_apk(dir, random + apk)
    logging.info(f"{compiled_apk} 임시 생성")
    sign_apk(keystore, PASSWORD, compiled_apk, signed_apk_clear_path=apk)
    del_file(compiled_apk)
    logging.info(f"임시 생성 된 {compiled_apk} 삭제")
    logging.info(f"{apk} 생성 완료")

if __name__ == "__main__":
    try:
        sc = Config("sample.apk")
        
        # 1. dex 추출 디컴파일
        #   a. sample.apk → sample(암호화 디렉터리)
        decompiled_dex_dir_path = decompile_apk_dex(sc.apk,
                                                    decrypted_clear_path=sc.apk_dir)
        #   c. assets 디렉터리에 있는 nested_apk를 프로젝트 디렉터리로 이동
        source_apk = Path(sc.apk_dir) / ASSETS / "pgsHZz.apk"
        dest_apk = sc.base_dir / source_apk.name

        if source_apk.exists():
            shutil.move(source_apk, dest_apk)
            logging.info(f"파일 이동 완료: '{source_apk}' -> '{dest_apk}'")
        else:
            logging.error(f"nested apk를 찾을 수 없습니다: {source_apk}")
            raise FileNotFoundError

        run_apk_jobs(sc)
        
        keystore = create_keystore(PASSWORD, keystore_clear_path=KEYSTORE)

        # 9. nested apk 각각 컴파일 후 assets 디렉터리 이동
        #   a. pgsHZz_decrypted, pgsHZz_bypass_decrypted, pgsHZz_bypass_crypted를 apk로 컴파일 → 키 서명
        nest_sc = Config("pgsHZz.apk")

        decompile_apk_dex(nest_sc.apk, decrypted_clear_path=nest_sc.apk_dir)

        run_apk_jobs(nest_sc)
        
        for dir, apk in nest_sc.get_dir_apk_list():
            compile_sign_apk(keystore, dir, apk)
            dest = Path()

        #   b. 우회 유무, 암복호화 상태 맞춰서 원래 있던 디렉터리의 assets 디렉터리로 이동
            if BYPASS in apk and DECRYPTED in apk:
                dest = Path(sc.bypass_decrypted_dir)
            elif BYPASS in apk and CRYPTED in apk:
                dest = Path(sc.bypass_crypted_dir)
            elif DECRYPTED in apk:
                dest = Path(sc.decrypted_dir)
            else:
                logging.error(f"{dir} {apk} 파일이 assets 디렉터리로 이동하지 않았습니다.")
                raise IOError
        
            shutil.copy2(apk, dest / ASSETS / "pgsHZz.apk")
            logging.info(f"{apk}을 {dest}로 이동 완료")
            
        # 10. 전체 수정된 디렉터리를 apk 컴파일, 키 제작, 서명
        #   a. sample_decrypted, sample_bypass_decrypted, sample_bypass_crypted
        for dir, apk in sc.get_dir_apk_list():
            compile_sign_apk(keystore, dir, apk)
    except Exception as e:
        print(e)
        exit()