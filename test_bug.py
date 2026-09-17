import json
import os

with open("logs/test_tail_eff.jsonl", "rb") as f:
    f.seek(0, os.SEEK_END)
    pointer = f.tell()
    buffer_size = 1024
    lines = []

    while pointer > 0 and len(lines) < 2:
        read_size = min(buffer_size, pointer)
        pointer -= read_size
        f.seek(pointer)
        chunk = f.read(read_size)
        lines = chunk.split(b"\n")

    for line in reversed(lines):
        line_str = line.strip().decode("utf-8")
        if line_str:
            try:
                last_entry = json.loads(line_str)
                print("Parsed successfully:", last_entry["entry_hash"])
            except Exception as e:
                print("Failed to parse:", e)
