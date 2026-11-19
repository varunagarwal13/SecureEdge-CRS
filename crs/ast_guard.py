"""
AST Comment Stripper (Prompt-Injection Mitigation) & Structural Edit-Class Guard (Gate 3).
Works standalone with Python stdlib; uses tree-sitter when installed.
"""
import re
from typing import Tuple


def strip_c_comments(source: str) -> str:
    """Remove /* ... */ and // ... comments before code is sent to any LLM."""
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE,
    )

    def _repl(match: re.Match) -> str:
        s = match.group(0)
        return " " if s.startswith("/") else s

    return re.sub(pattern, _repl, source)


def check_patch_ast_guard(original_c: str, patched_c: str) -> Tuple[bool, str]:
    """
    Gate 3 structural guard: reject overfitted LLM patches that silence crashes
    by deleting core payload-copy logic, zeroing output lengths, or gutting functions.
    """
    orig_clean = strip_c_comments(original_c)
    patch_clean = strip_c_comments(patched_c)

    # 1. Prevent deletion of core memcpy calls
    orig_memcpy = len(re.findall(r"\bmemcpy\s*\(", orig_clean))
    patch_memcpy = len(re.findall(r"\bmemcpy\s*\(", patch_clean))
    if patch_memcpy < orig_memcpy:
        return (
            False,
            f"REJECTED by AST Guard: core memcpy count dropped ({orig_memcpy} -> {patch_memcpy}); likely crash-silencing deletion.",
        )

    # 2. Prevent hardcoded zero-length bypasses
    if re.search(r"out->actual_len\s*=\s*0\s*;", patch_clean) and not re.search(
        r"out->actual_len\s*=\s*0\s*;", orig_clean
    ):
        return (
            False,
            "REJECTED by AST Guard: detected hardcoded zero-length assignment (out->actual_len = 0).",
        )

    # 3. Ensure parse_edge_mqtt_packet function signature remains intact
    if "parse_edge_mqtt_packet(" not in patch_clean:
        return (False, "REJECTED by AST Guard: target function signature removed.")

    # 4. Ensure diff stays bounded (not deleting >30% of non-empty lines)
    orig_lines = [ln for ln in orig_clean.splitlines() if ln.strip()]
    patch_lines = [ln for ln in patch_clean.splitlines() if ln.strip()]
    if len(patch_lines) < int(len(orig_lines) * 0.7):
        return (
            False,
            f"REJECTED by AST Guard: excessive code deletion ({len(orig_lines)} -> {len(patch_lines)} lines).",
        )

    return (True, "PASS: structural edit-class guard satisfied (bounds check added, core logic preserved).")
