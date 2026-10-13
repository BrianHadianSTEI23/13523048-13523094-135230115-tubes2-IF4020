import shutil
import subprocess
import sys
from pathlib import Path

NATIVE_DIR = Path(__file__).resolve().parent / "src" / "native"
SOURCE = NATIVE_DIR / "oatside_sha.c"


def library_name() -> str:
    if sys.platform.startswith("win"):
        return "oatside_sha.dll"
    if sys.platform == "darwin":
        return "liboatside_sha.dylib"
    return "liboatside_sha.so"


def main() -> int:
    target = NATIVE_DIR / library_name()
    for compiler in ("gcc", "clang", "cc"):
        if shutil.which(compiler):
            command = [compiler, "-O3", "-shared", "-o", str(target), str(SOURCE)]
            if not sys.platform.startswith("win"):
                command.insert(2, "-fPIC")
            break
    else:
        if shutil.which("cl"):
            command = ["cl", "/O2", "/LD", str(SOURCE), f"/Fe:{target}"]
        else:
            print("fail bang", file=sys.stderr)
            return 1
    print(" ".join(command))
    result = subprocess.run(command)
    if result.returncode == 0:
        print(f"Built {target}")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
