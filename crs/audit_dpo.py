"""
Append-Only SHA-256 Hash-Chained Audit Log & Adaption-Ready DPO Preference Pair Exporter.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict


class AuditChain:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.prev_hash = "0" * 64
        if os.path.exists(path):
            os.remove(path)

    def append(self, stage: str, payload: Dict[str, Any]) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "prev_hash": self.prev_hash,
            "payload": payload,
        }
        raw = json.dumps(entry, sort_keys=True).encode("utf-8")
        curr_hash = hashlib.sha256(raw).hexdigest()
        entry["sha256"] = curr_hash
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self.prev_hash = curr_hash
        return curr_hash


def export_dpo_pair(
    path: str,
    finding_id: str,
    target_file: str,
    cwe: str,
    prompt_context: str,
    chosen_diff: str,
    rejected_diff: str,
    chosen_gates: Dict[str, Any],
    rejected_gates: Dict[str, Any],
) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    record = {
        "finding_id": finding_id,
        "target": target_file,
        "cwe": cwe,
        "prompt": prompt_context,
        "chosen": chosen_diff,
        "rejected": rejected_diff,
        "provenance": {
            "chosen_all_4_gates": chosen_gates["all_passed"],
            "rejected_failure_reason": rejected_gates["details"].get("gate3", ""),
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
