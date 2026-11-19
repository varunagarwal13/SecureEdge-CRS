# SecureEdge-CRS — AgenticX 2.0 (Phase 1 Working PoC)

# **Team** 

**Varun agarwal**

**Aayush pachchigar**
#
**Track 1 — Software (Agentic AI)** · Future Tech Summit ’26 · AIRC, Woxsen University  
**No Bug Goes Unproven:** Every finding ships with its evidence tier (L1–L3), a 3× deterministic Proof-of-Vulnerability (PoV), and a patch verified by four deterministic gates — plus Adaption-ready DPO preference pairs.

## What Works Live in This Phase 1 PoC

Run one command (`make demo` or `python3 scripts/run_vertical_slice.py`) to execute the end-to-end vertical slice on `targets/edge_mqtt_parser.c`:

1. **AST Comment Stripper (`crs/ast_guard.py`):** Strips an embedded prompt-injection C comment (`SYSTEM OVERRIDE`) before any source reaches an LLM.
2. **Stagnation Breaker & CRC Validator (`crs/crc_seed_agent.py`):** Synthesizes a valid `AGX2` magic-byte header + XOR-CRC seed that unlocks the parser's `CWE-190 -> CWE-787` integer-truncation heap overflow.
3. **3× Deterministic ASan PoV (`crs/four_gate_validator.py`):** Compiles with `-fsanitize=address,undefined` and reproduces the real AddressSanitizer `heap-buffer-overflow` 3/3 times (`L3_DEMONSTRATED_POV`).
4. **Overfit Patch Rejection (Gate 3):** Blocks `patches/candidate_overfit.diff` (a naive LLM patch that deletes `memcpy` and zeroes `actual_len`) via both the structural AST edit guard and the 10-test functional suite (`targets/test_functional.c`).
5. **4-Gate Verified Repair:** Validates `patches/candidate_valid.diff` across all 4 deterministic gates:
   - **Gate 1:** Clean compilation under ASan + UBSan
   - **Gate 2:** 3/3 original PoV mitigated (0 crashes)
   - **Gate 3:** 10/10 functional tests + AST structural edit guard pass
   - **Gate 4:** 5,000-execution bounded re-fuzz with 0 sanitizer crashes
6. **Provenance & Adaption Continual-Learning Export (`crs/audit_dpo.py`):** Emits an append-only SHA-256 hash-chained log (`outputs/audit_chain.jsonl`) and a `(chosen, rejected)` DPO preference pair (`outputs/dpo_preference_pairs.jsonl`).

## Quickstart

```bash
# Requires gcc (or clang) with AddressSanitizer + Python 3.10+
python3 scripts/run_vertical_slice.py
```

Optional native LLVM libFuzzer run (when `clang` is installed):
```bash
make fuzz
```
## Verification Output

<img width="1917" height="940" alt="DEMO" src="https://github.com/user-attachments/assets/8b32fdad-a761-4d82-b985-7091a9e8ba92" />


## Phase 2 Onsite Roadmap (Dec 8–9, 2026)

- Dual-ISA worker dispatch (Docker `x86_64` + Arduino UNO Q `ARM64` with external INA219 power + Linux `thermal_zone` telemetry)
- Warm-start LinUCB scheduler routing by unique PoVs/Wh (`<= 78 °C`)
- Live Adaption Labs API integration for seed synthesis, ReAct patching, and continual-learning DPO updates
