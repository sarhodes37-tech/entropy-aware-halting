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

            lines = chunk.split(b"\n")

            if len(lines) > 1:
                # We found at least one newline
                # lines[-1] goes with accumulated
                last_part = lines[-1] + b"".join(accumulated)
                if last_part.strip():
                    return last_part.strip()

                # Check other lines from right to left
                for line in reversed(lines[:-1]):
                    if line.strip():
                        return line.strip()

                # If we get here, all lines were empty.
                accumulated = []
            else:
                # No newline
                accumulated.insert(0, chunk)

        # End of file
        full_data = b"".join(accumulated)
        if full_data.strip():
            return full_data.strip()

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
