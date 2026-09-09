import os
import json

def get_last_line(log_path):
    with open(log_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pointer = f.tell()
        buffer_size = 8192  # Increased buffer size for efficiency

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
                # The last part of the chunk joins with whatever we've accumulated
                last_part = lines[-1]
                current_line = last_part + b"".join(accumulated)

                if current_line.strip():
                    return current_line.strip()

                # If current_line was empty, maybe one of the other lines in the chunk is non-empty
                for line in reversed(lines[:-1]):
                    if line.strip():
                        return line.strip()

                # If all lines in this chunk were empty, reset accumulated and continue
                accumulated = []
            else:
                # No newline in this chunk, prepend it to accumulated
                accumulated.insert(0, chunk)

        # If we get here, no newline was found in the whole file
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
