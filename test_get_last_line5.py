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

            idx = chunk.rfind(b"\n")

            if idx != -1:
                # We found a newline. The part after the newline goes with accumulated
                # BUT if we want to return the line, we must make sure we have the WHOLE line.
                # If we return `chunk[idx+1:] + accumulated`, that is the remainder of the file after the last newline.
                # What if the line before it is the one we want?
                # Actually, `chunk[idx+1:] + b"".join(accumulated)` is EXACTLY the last line of the file!
                # (Assuming the file doesn't end with a newline, or if it does, this part is empty, and we need the line before it)

                last_part = chunk[idx+1:] + b"".join(accumulated)

                if last_part.strip():
                    return last_part.strip()

                # If the last part is empty (e.g. file ended with \n), we need to keep going!
                # We can update accumulated to just the part BEFORE the newline
                accumulated = [chunk[:idx]]

                # We can't just return here, we have to loop!
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
