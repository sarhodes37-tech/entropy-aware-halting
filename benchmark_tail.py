import time
import os
import json
from epistemicos.audit import TamperEvidentAuditTrail

def setup_file():
    log_path = "logs/test_tail.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    # Create a file with a very long last line (e.g., large payload snippet)
    with open(log_path, "wb") as f:
        for i in range(10):
            entry = {"entry_hash": f"hash_{i}", "data": "A" * 1024}
            f.write((json.dumps(entry) + "\n").encode("utf-8"))

        # Last entry has a 50KB payload
        entry = {"entry_hash": "hash_last", "data": "B" * 50000}
        f.write((json.dumps(entry) + "\n").encode("utf-8"))

def benchmark():
    setup_file()
    audit_trail = TamperEvidentAuditTrail("logs/test_tail.jsonl")

    # Measure time to get last hash when it's not cached
    start = time.time()
    last_hash = audit_trail._get_last_hash()
    end = time.time()

    print(f"last_hash: {last_hash}")
    print(f"Time: {end - start:.6f} seconds")

if __name__ == "__main__":
    benchmark()
