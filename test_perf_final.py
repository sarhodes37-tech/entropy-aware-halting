import time
import os
import json
from epistemicos.audit import TamperEvidentAuditTrail

def setup_file():
    log_path = "logs/test_tail_eff3.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    with open(log_path, "wb") as f:
        for i in range(10):
            entry = {"entry_hash": f"hash_{i}", "data": "A" * 1024}
            f.write((json.dumps(entry) + "\n").encode("utf-8"))

        # Last entry has a 1MB payload
        entry = {"entry_hash": "hash_last", "data": "B" * 1000000}
        f.write((json.dumps(entry) + "\n").encode("utf-8"))

def benchmark():
    setup_file()
    log_path = "logs/test_tail_eff3.jsonl"

    audit_trail = TamperEvidentAuditTrail(log_path)

    # Buggy baseline
    start = time.time()
    for _ in range(100):
        audit_trail.last_hash = None
        audit_trail._get_last_hash()
    end = time.time()
    baseline = end - start
    print(f"Time taken (buggy): {baseline:.4f}s")
    print(f"Result (buggy): {audit_trail.last_hash}")

    # Now let's test the fix logic
    start = time.time()
    for _ in range(100):
        # Implement fixed logic here
        last_hash = None
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pointer = f.tell()
            buffer_size = 1024

            accumulated = []
            line_str = None

            while pointer > 0:
                read_size = min(buffer_size, pointer)
                pointer -= read_size
                f.seek(pointer)
                chunk = f.read(read_size)

                lines = chunk.split(b"\n")

                if len(lines) > 1:
                    last_part = lines[-1] + b"".join(accumulated)
                    if last_part.strip():
                        line_str = last_part.strip().decode("utf-8")
                        break

                    found = False
                    for i in range(len(lines) - 2, 0, -1):
                        if lines[i].strip():
                            line_str = lines[i].strip().decode("utf-8")
                            found = True
                            break
                    if found:
                        break

                    accumulated = [lines[0]]
                else:
                    accumulated.insert(0, chunk)

            if line_str is None:
                full_data = b"".join(accumulated)
                if full_data.strip():
                    line_str = full_data.strip().decode("utf-8")

            if line_str:
                try:
                    last_entry = json.loads(line_str)
                    last_hash = last_entry.get("entry_hash", "genesis")
                except Exception:
                    pass

    end = time.time()
    optimized = end - start
    print(f"Time taken (fixed): {optimized:.4f}s")
    print(f"Result (fixed): {last_hash}")

    if baseline > 0:
        improvement = (baseline - optimized) / baseline * 100
        print(f"Improvement: {improvement:.2f}%")

benchmark()
