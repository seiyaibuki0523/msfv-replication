#!/usr/bin/env python3
"""Smoke test for the container PoC sandbox — hand-crafted recipes, no LLM.

Validates: container execution, --network none, sanitizer oracle (C++),
marker oracle (Python), nonzero_exit oracle, and the safe-case (triggered=False).
Run after the cevanex/poc-sandbox image is built.
"""
import os
import sys
from pathlib import Path

FROZEN = Path(os.environ.get("MSFV_FROZEN", Path(__file__).resolve().parent.parent))  # this frozen-code tree
sys.path.insert(0, str(FROZEN / "src" / "main"))
sys.path.insert(0, str(FROZEN / "src"))

from core.analysis.poc_sandbox import PocSandbox, SandboxConfig  # noqa: E402

UUID = "PWNED_7f3a9c2b"

CASES = [
    # 1. C++ heap-buffer-overflow → ASan must fire → triggered True
    ("cpp-overflow", {
        "files": [{"name": "poc.cpp", "content": (
            "#include <cstring>\n#include <cstdlib>\n"
            "int main(){ char* b=(char*)malloc(8);"
            " strcpy(b, \"AAAAAAAAAAAAAAAAAAAAAAAA\"); return b[0]; }\n"
        )}],
        "build_cmd": "g++ -fsanitize=address,undefined -g -o poc poc.cpp",
        "run_cmd": "./poc",
        "trigger_on": "sanitizer_report",
        "assert_marker": "",
        "poc_method": "cpp-asan",
    }, True),

    # 2. C++ safe program → ASan clean → triggered False
    ("cpp-safe", {
        "files": [{"name": "poc.cpp", "content": (
            "#include <cstdio>\nint main(){ int x=41; printf(\"%d\\n\", x+1); return 0; }\n"
        )}],
        "build_cmd": "g++ -fsanitize=address,undefined -g -o poc poc.cpp",
        "run_cmd": "./poc",
        "trigger_on": "sanitizer_report",
        "assert_marker": "",
        "poc_method": "cpp-asan",
    }, False),

    # 3. Python command-injection → benign marker via os.system → triggered True
    ("py-cmdinj", {
        "files": [{"name": "poc.py", "content": (
            "import os\n"
            "def run(user_input):\n"
            "    os.system('echo ' + user_input)  # vulnerable: shell concat\n"
            f"run('{UUID}')\n"
        )}],
        "build_cmd": "",
        "run_cmd": "python3 poc.py",
        "trigger_on": "marker",
        "assert_marker": UUID,
        "poc_method": "pytest",
    }, True),

    # 4. Python nonzero_exit assert → triggered True
    ("py-assert", {
        "files": [{"name": "poc.py", "content": (
            "def vuln(a,b):\n    return a - b  # should have been a+b\n"
            "assert vuln(2,2)==4, 'exploit: wrong result'\n"
        )}],
        "build_cmd": "",
        "run_cmd": "python3 poc.py",
        "trigger_on": "nonzero_exit",
        "assert_marker": "",
        "poc_method": "pytest",
    }, True),

    # 5. C++ that does not compile → poc_compile False (no ground truth)
    ("cpp-broken", {
        "files": [{"name": "poc.cpp", "content": "int main(){ this is not c++ }\n"}],
        "build_cmd": "g++ -fsanitize=address -o poc poc.cpp",
        "run_cmd": "./poc",
        "trigger_on": "sanitizer_report",
        "assert_marker": "",
        "poc_method": "cpp-asan",
    }, None),
]


def main():
    sb = PocSandbox(SandboxConfig(timeout_seconds=60))
    if not sb.is_available():
        print("✗ sandbox not available (docker daemon / image missing)")
        return 1
    print("✓ sandbox available\n")
    passed = 0
    for name, recipe, expect_trigger in CASES:
        v = sb.run_recipe(recipe)
        got = v.get("poc_triggers_bug")
        compiled = v.get("poc_compile")
        ok = (got is expect_trigger) if expect_trigger is not None \
            else (compiled is False)
        passed += ok
        flag = "✓" if ok else "✗"
        print(f"{flag} {name:14s} compile={compiled} triggered={got} "
              f"conf={v.get('ground_truth_confidence')} "
              f"method={v.get('poc_method')}"
              + (f" err={v.get('error')[:60]}" if v.get('error') else ""))
    print(f"\n{passed}/{len(CASES)} cases passed")
    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
