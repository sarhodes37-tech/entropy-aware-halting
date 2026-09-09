import os
import json
import traceback

log_path = "logs/test_tail2.jsonl"
buffer_size = 1024

try:
    with open(log_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pointer = f.tell()
        lines = []

        while pointer > 0 and len(lines) < 2:
            read_size = min(buffer_size, pointer)
            pointer -= read_size
            f.seek(pointer)
            chunk = f.read(read_size)
            lines = chunk.split(b"\n")
            # print(f"chunk: {chunk[:20]} ... {chunk[-20:]}")

        for line in reversed(lines):
            line_str = line.strip().decode("utf-8")
            if line_str:
                print(f"Trying to decode: {line_str[:50]}...")
                last_entry = json.loads(line_str)
                print("SUCCESS")
except Exception as e:
    traceback.print_exc()
