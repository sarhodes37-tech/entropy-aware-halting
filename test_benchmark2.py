import time
import os
import json
from epistemicos.audit import TamperEvidentAuditTrail

def benchmark_tail_efficiency():
    log_path = "logs/test_tail_eff.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    # Write a file with a large last line (e.g. 500KB)
    with open(log_path, "wb") as f:
        for i in range(10):
            entry = {"entry_hash": f"hash_{i}", "data": "A" * 1024}
            f.write((json.dumps(entry) + "\n").encode("utf-8"))

        entry = {"entry_hash": "hash_last", "data": "B" * 500000}
        f.write((json.dumps(entry) + "\n").encode("utf-8"))

    # The issue: `while pointer > 0 and len(lines) < 2:`
    # It reads chunks backwards but OVERWRITES `lines` with `chunk.split(b"\n")`.
    # This means if the last line is 500KB, it will loop 500 times, reading 1KB chunks.
    # At each loop, it splits the 1KB chunk. Unless the 1KB chunk happens to contain a newline
    # (which it won't until we reach the start of the last line), it will keep looping.
    # This loop is O(L^2) where L is the length of the line in chunks?
    # No, it's just O(L) iterations, but `f.seek()` and `f.read()` are called 500 times.
    # What's worse, since it overwrites `lines`, it throws away the actual end of the line!
    # And then it returns genesis_hash because JSON decode fails!
    # AND if it returns genesis_hash, it SETS `self.last_hash = self.genesis_hash`!

    audit_trail = TamperEvidentAuditTrail(log_path)

    # To benchmark the read, we can force it to do this
    start = time.time()
    for _ in range(100):
        audit_trail.last_hash = None
        audit_trail._get_last_hash()
    end = time.time()
    print(f"Time taken: {end - start:.4f}s")
    print(f"Resulting last hash: {audit_trail.last_hash}")

benchmark_tail_efficiency()
