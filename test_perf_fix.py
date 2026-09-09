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
            buffer_size = 1024

            # Efficient backwards file read for last non-empty line
            accumulated = []
            last_line = b""

            while pointer > 0:
                read_size = min(buffer_size, pointer)
                pointer -= read_size
                f.seek(pointer)
                chunk = f.read(read_size)

                # Split chunk by newline
                lines = chunk.split(b"\n")

                if len(lines) > 1:
                    # We found a newline!
                    # The last line is the rest of this chunk (lines[-1]) + accumulated
                    accumulated.insert(0, lines[-1])

                    # Also, the previous line might be lines[-2]
                    # But actually we just need the LAST non-empty line.

                    # We can join and check
                    # However, to avoid complexity, we can just prepend lines[-1]
                    # to accumulated.
                    # Actually, if we just want the last line:
                    break
                else:
                    accumulated.insert(0, chunk)

            # Actually, the simplest approach to reading the last line is:
            # chunk.split(b"\n")
            pass

    end = time.time()
    print(f"Time taken (fixed skeleton): {end - start:.4f}s")

benchmark()
