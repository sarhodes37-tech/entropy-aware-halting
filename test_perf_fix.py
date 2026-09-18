import time
import os
import json
from epistemicos.audit import TamperEvidentAuditTrail

def setup_file():
    log_path = "logs/test_tail_eff2.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    with open(log_path, "wb") as f:
        for i in range(10):
            entry = {"entry_hash": f"hash_{i}", "data": "A" * 1024}
            f.write((json.dumps(entry) + "\n").encode("utf-8"))

        # Last entry has a 500KB payload
        entry = {"entry_hash": "hash_last", "data": "B" * 500000}
        f.write((json.dumps(entry) + "\n").encode("utf-8"))

def benchmark():
    setup_file()
    log_path = "logs/test_tail_eff2.jsonl"
    audit_trail = TamperEvidentAuditTrail(log_path)

    start = time.time()
    for _ in range(100):
        audit_trail.last_hash = None
        audit_trail._get_last_hash()
    end = time.time()
    print(f"Time taken (buggy): {end - start:.4f}s")

    # Now let's test the fix logic
    start = time.time()
    for _ in range(100):
        # Implement fixed logic here
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pointer = f.tell()
            buffer_size = 65536

            # Efficient backwards file read for last non-empty line
            accumulated = []
            newline_count = 0

            while pointer > 0 and newline_count < 2:
                read_size = min(buffer_size, pointer)
                pointer -= read_size
                f.seek(pointer)
                chunk = f.read(read_size)
                accumulated.append(chunk)
                newline_count += chunk.count(b"\n")

            last_line = b""
            if accumulated:
                lines = b"".join(reversed(accumulated)).split(b"\n")
                for line in reversed(lines):
                    if line.strip():
                        last_line = line
                        break

    end = time.time()
    print(f"Time taken (fixed skeleton): {end - start:.4f}s")

benchmark()
