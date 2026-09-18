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

            # Find the last newline in this chunk
            idx = chunk.rfind(b"\n")

            if idx != -1:
                # We found a newline. The part after the newline goes with accumulated
                last_part = chunk[idx+1:] + b"".join(accumulated)
                if last_part.strip():
                    return last_part.strip()

                # If it's empty, we must keep looking in this chunk, but this gets complicated.
                # The easiest robust way is to just read line by line from the end.
                # Actually, wait: we can split by b"\n"

                lines = chunk.split(b"\n")

                # lines[-1] + accumulated is what we just checked
                # If we get here, it was empty.
                for line in reversed(lines[:-1]):
                    if line.strip():
                        return line.strip()

                # If all were empty
                accumulated = []
            else:
                # No newline, accumulate
                accumulated.insert(0, chunk)

        # If we exit the loop, there was no newline in the entire file
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
