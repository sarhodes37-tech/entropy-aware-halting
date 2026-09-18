import os
import json

def get_last_line(log_path):
    with open(log_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pointer = f.tell()
        buffer_size = 1024

        if pointer == 0:
            return None

        accumulated = []

        while pointer > 0:
            read_size = min(buffer_size, pointer)
            pointer -= read_size
            f.seek(pointer)
            chunk = f.read(read_size)

            # Split by newline
            lines = chunk.split(b"\n")

            if len(lines) > 1:
                # We found at least one newline

                # Check the part after the last newline first
                last_part = lines[-1] + b"".join(accumulated)
                if last_part.strip():
                    return last_part.strip()

                # If it's empty, check the previous lines in this chunk
                for i in range(len(lines) - 2, 0, -1):
                    if lines[i].strip():
                        return lines[i].strip()

                # If all lines in this chunk were empty, the first part (lines[0])
                # becomes the new accumulated, because it's incomplete (no newline before it)
                accumulated = [lines[0]]
            else:
                # No newline, accumulate
                accumulated.insert(0, chunk)

        # End of file
        full = b"".join(accumulated)
        if full.strip():
            return full.strip()

        return None

def test():
    log_path = "logs/test_tail_eff2.jsonl"
    line = get_last_line(log_path)
    if line:
        print("Found line of length:", len(line))
        entry = json.loads(line.decode("utf-8"))
        print("Hash:", entry.get("entry_hash"))
    else:
        print("No line found")

test()
