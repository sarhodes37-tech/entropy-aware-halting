import time
import os
import json
from epistemicos.audit import TamperEvidentAuditTrail

def setup_file():
    log_path = "logs/test_tail2.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    with open(log_path, "wb") as f:
        for i in range(10):
            entry = {"entry_hash": f"hash_{i}", "data": "A" * 1024}
            f.write((json.dumps(entry) + "\n").encode("utf-8"))

        # Last entry has a 50KB payload
        entry = {"entry_hash": "hash_last", "data": "B" * 50000}
        f.write((json.dumps(entry) + "\n").encode("utf-8"))

def benchmark(audit_trail):
    start = time.time()
    for _ in range(100):
        # Force re-read
        audit_trail.last_hash = None
        h = audit_trail._get_last_hash()
    end = time.time()
    return h, end - start

if __name__ == "__main__":
    setup_file()
    audit_trail = TamperEvidentAuditTrail("logs/test_tail2.jsonl")

    h, t = benchmark(audit_trail)
    print(f"Original last_hash: {h}")
    print(f"Original Time (100 reads): {t:.6f} seconds")
