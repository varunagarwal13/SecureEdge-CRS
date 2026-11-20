# SecureEdge-CRS — AgenticX 2.0 (Phase 1 Working PoC)

SecureEdge-CRS is an autonomous AI system that finds memory bugs in edge/IoT firmware, proves they are real by triggering them, and generates verified patches without breaking existing code.

# **Team** 

**Varun Agarwal**

**Samyak Jain** 

**Anish Sinha**

**Aayush Pachchigar**
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



## Phase 2 Onsite Roadmap (Dec 8–9, 2026 · Woxsen University)

Phase 1 proves the deterministic verification core (`make demo` — AST guard, CRC seed unlock, 3× ASan PoV, 4-gate repair, SHA-256 audit chain, and DPO export). For the Phase 2 live onsite build and jury demo, we extend this vertical slice into the full 3-tier system:

* **Live Multi-Agent Control Plane (Track 1 Core):** FastAPI orchestrator + LangGraph 3-agent loop (*Triage*, *12 s Stagnation Seed Breaker*, and *ReAct Patcher*) with 6 s worker leases and resumable campaign state.
* **Adaption Labs Continual-Learning Loop (Dual-Mode):** Feed 4-gate-verified `(chosen, rejected)` pairs from `outputs/dpo_preference_pairs.jsonl` into **Adaption** (`adaptionlabs.ai` / AutoScientist DPO loop) to iteratively improve first-pass 4-gate repair accuracy and reduce overfit deletions — with local `Qwen2.5-Coder` (`--network=none`) as the air-gapped offline fallback.
* **Heterogeneous Dual-ISA Workers & Telemetry:** Parallel fuzzing across `x86_64` Docker (`AFL++`/`libFuzzer`) and **Arduino UNO Q (`ARM64` ABI target)** with live `INA219` power + Linux `thermal_zone` 2 s heartbeats, LED matrix PoV alerts, cross-ISA DWARF deduplication, and warm-start **LinUCB** scheduling (`Δcoverage / Wh`, hard thermal cap `≤ 78 °C`).
* **3-Target Live Jury Demo (45 s Loop):**
  1. Dead-code Semgrep alert held at `L1` (zero false alarm)
  2. `edge_mqtt_parser.c` 12 s coverage stall broken by LLM-synthesized `AGX2` + CRC seed → `CWE-190 → CWE-787` PoV flashed on UNO Q
  3. ARM64-only `unsigned char` ABI bug caught exclusively on `aarch64`
  4. Overfit deletion patch blocked by Gate 3 (AST guard + 10 tests) → valid patch passes `4/4` gates, stages human-reviewed PR, and logs a new Adaption DPO pair
* **Live Next.js Telemetry & Dossier UI:** Real-time coverage curve, UNO Q °C/W/RSS gauges, 4-gate status badges, and verifiable SHA-256 patch dossier.
