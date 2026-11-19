"""
Deterministic 4-Gate Patch Validator:
  Gate 1: Clean compile under AddressSanitizer + UndefinedBehaviorSanitizer
  Gate 2: 3/3 deterministic PoV replay (original crash must be mitigated)
  Gate 3: 10 functional unit tests + AST structural edit-class guard
  Gate 4: 5,000-execution bounded re-fuzz with 0 sanitizer crashes
"""
import os
import shutil
import subprocess
import tempfile
from typing import Dict

from crs.ast_guard import check_patch_ast_guard


def _compiler() -> str:
    return shutil.which("clang") or shutil.which("gcc") or "gcc"


def compile_and_replay_pov(
    source_c_path: str,
    header_dir: str,
    standalone_harness: str,
    pov_path: str,
    replays: int = 3,
) -> Dict:
    cc = _compiler()
    build_base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".build_tmp")
    os.makedirs(build_base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=build_base) as tmp:
        bin_path = os.path.join(tmp, "runner_asan")
        cmd = [
            cc,
            "-O1",
            "-g",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            f"-I{header_dir}",
            source_c_path,
            standalone_harness,
            "-o",
            bin_path,
        ]
        comp = subprocess.run(cmd, capture_output=True, text=True)
        if comp.returncode != 0:
            return {"compiled": False, "error": comp.stderr, "crashes": 0, "replays": replays}

        crashes = 0
        last_stderr = ""
        for _ in range(replays):
            run = subprocess.run([bin_path, pov_path], capture_output=True, text=True)
            if run.returncode != 0 and ("AddressSanitizer" in run.stderr or "ERROR:" in run.stderr):
                crashes += 1
                last_stderr = run.stderr
        return {
            "compiled": True,
            "compiler": os.path.basename(cc),
            "crashes": crashes,
            "replays": replays,
            "asan_excerpt": "\n".join(last_stderr.splitlines()[:8]) if last_stderr else "",
        }


def run_four_gates(
    original_c_path: str,
    patched_c_text: str,
    header_dir: str,
    standalone_harness: str,
    functional_test_c: str,
    pov_path: str,
    refuzz_iters: int = 5000,
) -> Dict:
    cc = _compiler()
    original_c_text = open(original_c_path, encoding="utf-8").read()
    results = {
        "gate1_compile": False,
        "gate2_pov_mitigated": False,
        "gate3_tests_and_ast": False,
        "gate4_bounded_refuzz": False,
        "all_passed": False,
        "details": {},
    }

    build_base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".build_tmp")
    os.makedirs(build_base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=build_base) as tmp:
        patched_c_path = os.path.join(tmp, "edge_mqtt_parser.c")
        with open(patched_c_path, "w", encoding="utf-8") as f:
            f.write(patched_c_text)

        # Gate 1: Compile under ASan + UBSan
        runner_bin = os.path.join(tmp, "runner_asan")
        g1 = subprocess.run(
            [
                cc,
                "-O1",
                "-g",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                f"-I{header_dir}",
                patched_c_path,
                standalone_harness,
                "-o",
                runner_bin,
            ],
            capture_output=True,
            text=True,
        )
        results["gate1_compile"] = g1.returncode == 0
        results["details"]["gate1"] = "PASS (compiled cleanly with ASan+UBSan)" if g1.returncode == 0 else g1.stderr[:300]
        if not results["gate1_compile"]:
            return results

        # Gate 2: 3/3 PoV Replay must NOT crash
        pov_crashes = 0
        for _ in range(3):
            r = subprocess.run([runner_bin, pov_path], capture_output=True, text=True)
            if "AddressSanitizer" in r.stderr or "UndefinedBehaviorSanitizer" in r.stderr:
                pov_crashes += 1
        results["gate2_pov_mitigated"] = pov_crashes == 0
        results["details"]["gate2"] = f"PASS (0/3 ASan crashes)" if pov_crashes == 0 else f"FAIL ({pov_crashes}/3 crashes)"

        # Gate 3: AST Guard + 10 Functional Tests
        ast_ok, ast_msg = check_patch_ast_guard(original_c_text, patched_c_text)
        test_bin = os.path.join(tmp, "test_func")
        tc = subprocess.run(
            [
                cc,
                "-O1",
                "-g",
                "-fsanitize=address,undefined",
                f"-I{header_dir}",
                patched_c_path,
                functional_test_c,
                "-o",
                test_bin,
            ],
            capture_output=True,
            text=True,
        )
        tests_ok = False
        test_msg = tc.stderr[:200]
        if tc.returncode == 0:
            tr = subprocess.run([test_bin], capture_output=True, text=True)
            tests_ok = tr.returncode == 0
            test_msg = (tr.stdout.strip() or tr.stderr.strip())[:200]

        results["gate3_tests_and_ast"] = ast_ok and tests_ok
        results["details"]["gate3"] = f"AST: {ast_msg} | Tests: {test_msg}"
        if not results["gate3_tests_and_ast"]:
            return results

        # Gate 4: 5,000-Execution Bounded Re-Fuzz
        rf = subprocess.run([runner_bin, "--refuzz", str(refuzz_iters)], capture_output=True, text=True)
        rf_ok = rf.returncode == 0 and "AddressSanitizer" not in rf.stderr and "UndefinedBehaviorSanitizer" not in rf.stderr
        results["gate4_bounded_refuzz"] = rf_ok
        results["details"]["gate4"] = (
            f"PASS ({refuzz_iters:,} bounded re-fuzz execs, 0 crashes)"
            if rf_ok
            else f"FAIL during re-fuzz: {rf.stderr[:200]}"
        )

        results["all_passed"] = all(
            [
                results["gate1_compile"],
                results["gate2_pov_mitigated"],
                results["gate3_tests_and_ast"],
                results["gate4_bounded_refuzz"],
            ]
        )
    return results
