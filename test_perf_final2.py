import time
import os
import json

def setup_file():
    log_path = "logs/test_tail_eff4.jsonl"
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
    log_path = "logs/test_tail_eff4.jsonl"

    # We will test two fixed logic approaches

    # Approach 1: The correct iterative loop
    start = time.time()
    for _ in range(100):
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
    optimized1 = end - start
    print(f"Time taken (Approach 1 - 1KB buffer): {optimized1:.4f}s")

    # Approach 2: Using 64KB buffer for faster reads
    start = time.time()
    for _ in range(100):
        last_hash = None
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pointer = f.tell()
            buffer_size = 65536

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
    optimized2 = end - start
    print(f"Time taken (Approach 2 - 64KB buffer): {optimized2:.4f}s")

benchmark()
