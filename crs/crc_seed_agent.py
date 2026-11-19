"""
12-Second Stagnation Breaker & Deterministic AGX2 XOR-CRC Seed Validator.
When coverage plateaus on magic-byte headers / checksums, proposes a structured
AGX2 seed and validates its XOR-CRC deterministically before injecting into the corpus.
"""
import os
from typing import Dict, Tuple


def compute_agx2_crc(data: bytes) -> int:
    crc = 0x5A
    for b in data:
        crc ^= b
    return crc


def validate_agx2_seed(seed: bytes) -> Tuple[bool, str]:
    if len(seed) < 9:
        return False, "Seed too short (< 9 bytes)"
    if seed[:4] != b"AGX2":
        return False, f"Invalid magic header: {seed[:4]!r}"
    expected = compute_agx2_crc(seed[:-1])
    if seed[-1] != expected:
        return False, f"CRC mismatch: got 0x{seed[-1]:02x}, expected 0x{expected:02x}"
    return True, f"Valid AGX2 seed ({len(seed)} bytes, CRC=0x{expected:02x})"


def synthesize_stagnation_seed(stripped_source: str, stall_seconds: int = 12) -> Dict:
    """
    Synthesizes a candidate seed that satisfies AGX2 header + XOR-CRC + integer-wrap
    boundary (payload_len = 244 -> uint8_t(244 + 16) = 4 bytes allocated).
    Set ADAPTION_API_KEY in Phase 2 to route through Adaption Labs API.
    """
    mode = "adaption_api" if os.environ.get("ADAPTION_API_KEY") else "deterministic_offline_poc"

    topic = b"edge/plc01"
    payload_len = 244  # Triggers uint8_t(244 + 16) == 4 byte allocation -> heap OOB write
    payload = b"A" * payload_len

    header = (
        b"AGX2"
        + bytes([1, len(topic), (payload_len >> 8) & 0xFF, payload_len & 0xFF])
    )
    body = header + topic + payload
    crc = compute_agx2_crc(body)
    seed = body + bytes([crc])

    ok, msg = validate_agx2_seed(seed)
    return {
        "mode": mode,
        "stall_seconds": stall_seconds,
        "prompt_source_len": len(stripped_source),
        "seed_bytes": seed,
        "crc_valid": ok,
        "validation_msg": msg,
    }
