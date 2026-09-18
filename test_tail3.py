import os
import json

log_path = "logs/test_tail2.jsonl"
buffer_size = 1024

try:
    with open(log_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pointer = f.tell()
        lines = []

        # Current implementation
        while pointer > 0 and len(lines) < 2:
            read_size = min(buffer_size, pointer)
            pointer -= read_size
            f.seek(pointer)
            chunk = f.read(read_size)
            lines = chunk.split(b"\n")
            print(f"pointer={pointer}, len(lines)={len(lines)}")
            # WAIT! lines gets overwritten on every loop iteration instead of prepended/accumulated!
            # If the last line is very large (> 1024 bytes), it will just read chunks of it and lines will be length 1.
            # But since it resets `lines = chunk.split(b"\n")`, it will loop until it finds a newline in the chunk.
            # It throws away previous chunks! This means it will only see a fragment of the last line!
            # Wait, if `len(lines) < 2`, it keeps looping. If it hits a newline, `len(lines)` becomes >= 2.
            # But the `chunk` is only the current 1024 bytes.
            # If `lines = chunk.split(b"\n")`, the line is split, but it ignores the data from previous reads (closer to EOF).
            # Then when the loop exits, it only has the lines from the LAST read chunk! Which is a middle fragment of the line!
            # Then it tries to decode and json.loads it. This will fail with JSONDecodeError!
except Exception as e:
    print("Exception", e)
