import time
import os
import json
from epistemicos.audit import TamperEvidentAuditTrail

# Ensure log file exists for benchmark
log_path = "logs/epistemic_audit_benchmark.jsonl"
if not os.path.exists(log_path):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w") as f:
        for i in range(100):
            f.write(json.dumps({"entry_hash": f"hash_{i}", "data": "A"*1000}) + "\n")

audit_trail = TamperEvidentAuditTrail(log_file_path=log_path)
start = time.time()
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
        buffer_size = 65536
        accumulated = []

        while pointer > 0:
            read_size = min(buffer_size, pointer)
            pointer -= read_size
            f.seek(pointer)
            chunk = f.read(read_size)
            accumulated.append(chunk)

            if chunk.count(b'\n') >= 2:
                break

        if accumulated:
            combined = b"".join(reversed(accumulated))
            lines = combined.split(b"\n")

            for line in reversed(lines):
                line_str = line.strip().decode("utf-8")
                if line_str:
                    try:
                        last_entry = json.loads(line_str)
                        last_hash = last_entry.get("entry_hash", "genesis")
                        break
                    except json.JSONDecodeError:
                        continue
end = time.time()
print(f"Time taken (fixed): {end - start:.4f}s")
print(f"Result (fixed): {last_hash}")
