#!/usr/bin/env python3
"""
SecureEdge-CRS Phase 1 Vertical Slice Demo:
  1. Target Intake + AST Comment Stripping (mitigates prompt injection in C comments)
  2. 12s Stagnation Breaker -> AGX2 Header + XOR-CRC Seed Synthesis
  3. 3/3 Deterministic ASan PoV Confirmation (L3_DEMONSTRATED_POV)
  4. Naive Overfit Candidate -> REJECTED by Gate 3 (AST Guard + 10 Functional Tests)
  5. Valid Bounds-Checked Candidate -> PASSES all 4/4 Deterministic Gates (incl. 5,000 re-fuzz)
  6. Exports SHA-256 Hash-Chained Audit Log + Adaption DPO Preference Pair JSONL
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from crs.ast_guard import strip_c_comments
from crs.audit_dpo import AuditChain, export_dpo_pair
from crs.crc_seed_agent import synthesize_stagnation_seed
from crs.four_gate_validator import compile_and_replay_pov, run_four_gates


def apply_overfit_patch(src: str) -> str:
    old = """    uint8_t alloc_size = (uint8_t)(payload_len + 16);
    uint8_t *scratch = (uint8_t *)malloc(alloc_size);
    if (!scratch) {
        return -6;
    }

    memcpy(scratch, data + 8 + topic_len, payload_len);

    size_t copy_out = payload_len < AGX2_MAX_PAYLOAD ? payload_len : AGX2_MAX_PAYLOAD;
    memcpy(out->payload, scratch, copy_out);
    out->actual_len = (uint16_t)copy_out;

    free(scratch);"""
    new = """    /* Naive LLM overfit: skip payload copy to silence crash */
    out->actual_len = 0;"""
    assert old in src
    return src.replace(old, new)


def apply_valid_patch(src: str) -> str:
    old = """    uint8_t alloc_size = (uint8_t)(payload_len + 16);
    uint8_t *scratch = (uint8_t *)malloc(alloc_size);
    if (!scratch) {
        return -6;
    }

    memcpy(scratch, data + 8 + topic_len, payload_len);

    size_t copy_out = payload_len < AGX2_MAX_PAYLOAD ? payload_len : AGX2_MAX_PAYLOAD;
    memcpy(out->payload, scratch, copy_out);
    out->actual_len = (uint16_t)copy_out;"""
    new = """    if (payload_len > AGX2_MAX_PAYLOAD) {
        return -7;
    }
    size_t alloc_size = (size_t)payload_len + 16;
    uint8_t *scratch = (uint8_t *)malloc(alloc_size);
    if (!scratch) {
        return -6;
    }

    memcpy(scratch, data + 8 + topic_len, payload_len);

    size_t copy_out = (size_t)payload_len;
    memcpy(out->payload, scratch, copy_out);
    out->actual_len = (uint16_t)copy_out;"""
    assert old in src
    return src.replace(old, new)


def main() -> int:
    target_c = os.path.join(REPO_ROOT, "targets", "edge_mqtt_parser.c")
    header_dir = os.path.join(REPO_ROOT, "targets")
    standalone_harness = os.path.join(REPO_ROOT, "targets", "harness_standalone.c")
    functional_test_c = os.path.join(REPO_ROOT, "targets", "test_functional.c")
    out_dir = os.path.join(REPO_ROOT, "outputs")
    os.makedirs(out_dir, exist_ok=True)

    audit = AuditChain(os.path.join(out_dir, "audit_chain.jsonl"))
    print("=" * 72)
    print("SecureEdge-CRS | AgenticX 2.0 Phase 1 Vertical Slice Demo")
    print("=" * 72)

    # Step 1: Intake & AST Comment Stripping
    raw_src = open(target_c, encoding="utf-8").read()
    stripped_src = strip_c_comments(raw_src)
    injected_present = "SYSTEM OVERRIDE" in raw_src
    injected_removed = "SYSTEM OVERRIDE" not in stripped_src
    print(f"[1/6] AST Comment Stripper: prompt-injection comment detected={injected_present}, stripped={injected_removed}")
    audit.append("intake_ast_strip", {"target": "targets/edge_mqtt_parser.c", "injection_stripped": injected_removed})

    # Step 2: 12s Stagnation Breaker -> CRC-Validated AGX2 Seed
    seed_res = synthesize_stagnation_seed(stripped_src, stall_seconds=12)
    pov_path = os.path.join(out_dir, "pov_agx2_seed.bin")
    with open(pov_path, "wb") as f:
        f.write(seed_res["seed_bytes"])
    print(f"[2/6] Stagnation Seed Agent ({seed_res['mode']}): {seed_res['validation_msg']}")
    audit.append("stagnation_seed_synth", {"mode": seed_res["mode"], "crc_valid": seed_res["crc_valid"], "bytes": len(seed_res["seed_bytes"])})

    # Step 3: 3/3 Deterministic PoV Confirmation (L3)
    pov = compile_and_replay_pov(target_c, header_dir, standalone_harness, pov_path, replays=3)
    assert pov["compiled"] and pov["crashes"] == 3, f"Expected 3/3 ASan crash, got: {pov}"
    print(f"[3/6] Evidence Lattice -> L3_DEMONSTRATED_POV ({pov['crashes']}/3 deterministic ASan crashes via {pov['compiler']})")
    for line in pov["asan_excerpt"].splitlines()[:3]:
        print(f"      {line}")
    audit.append("pov_confirmed_l3", {"replays": "3/3", "cwe": "CWE-190->CWE-787", "compiler": pov["compiler"]})

    # Step 4: Overfit Candidate -> Rejected by Gate 3
    overfit_c = apply_overfit_patch(raw_src)
    overfit_res = run_four_gates(target_c, overfit_c, header_dir, standalone_harness, functional_test_c, pov_path)
    assert not overfit_res["all_passed"], "Overfit patch must be rejected!"
    print(f"[4/6] Candidate A (Overfit Deletion): BLOCKED -> {overfit_res['details']['gate3']}")
    audit.append("patch_candidate_rejected", {"candidate": "overfit_deletion", "gate3": overfit_res["details"]["gate3"]})

    # Step 5: Valid Bounds-Checked Candidate -> Passes 4/4 Gates
    valid_c = apply_valid_patch(raw_src)
    valid_res = run_four_gates(target_c, valid_c, header_dir, standalone_harness, functional_test_c, pov_path, refuzz_iters=5000)
    assert valid_res["all_passed"], f"Valid patch failed: {valid_res}"
    print("[5/6] Candidate B (Bounds-Checked Fix): PASSED 4/4 GATES")
    for k in ("gate1", "gate2", "gate3", "gate4"):
        print(f"      {k.upper()}: {valid_res['details'][k]}")
    audit.append("patch_candidate_passed_4gates", {"candidate": "bounds_checked_fix", "gates": valid_res["details"]})

    # Step 6: Export Adaption-Ready DPO Preference Pair JSONL
    chosen_diff = open(os.path.join(REPO_ROOT, "patches", "candidate_valid.diff"), encoding="utf-8").read()
    rejected_diff = open(os.path.join(REPO_ROOT, "patches", "candidate_overfit.diff"), encoding="utf-8").read()
    dpo_path = os.path.join(out_dir, "dpo_preference_pairs.jsonl")
    export_dpo_pair(
        path=dpo_path,
        finding_id="F-108",
        target_file="targets/edge_mqtt_parser.c",
        cwe="CWE-190 -> CWE-787",
        prompt_context="Fix heap-buffer-overflow caused by 8-bit integer truncation in parse_edge_mqtt_packet.",
        chosen_diff=chosen_diff,
        rejected_diff=rejected_diff,
        chosen_gates=valid_res,
        rejected_gates=overfit_res,
    )
    print(f"[6/6] Provenance Exported:")
    print(f"      Audit chain : outputs/audit_chain.jsonl (head={audit.prev_hash[:16]}...)")
    print(f"      DPO pairs   : outputs/dpo_preference_pairs.jsonl (chosen=Candidate B, rejected=Candidate A)")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
