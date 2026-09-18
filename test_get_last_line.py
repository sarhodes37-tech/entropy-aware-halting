import os
import json

def get_last_line(log_path):
    with open(log_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pointer = f.tell()
        buffer_size = 1024

        # If the file is empty, return None
        if pointer == 0:
            return None

        accumulated = []

        while pointer > 0:
            read_size = min(buffer_size, pointer)
            pointer -= read_size
            f.seek(pointer)
            chunk = f.read(read_size)

            # Find the last newline character in this chunk
            newline_pos = chunk.rfind(b"\n")

            if newline_pos != -1:
                # We found a newline.
                # If we've already accumulated some data, or if there's data after the newline
                # Then the last line is the remainder of this chunk after the newline + accumulated
                last_part = chunk[newline_pos + 1:]

                # Check if this combined line is non-empty
                # Note: If the file ends with a newline, the first time we see \n it's at the very end
                # (or we accumulated an empty string). We want to find the last *non-empty* line.

                # Let's accumulate everything from the newline to the end of the chunk
                current_line = last_part + b"".join(accumulated)

                if current_line.strip():
                    return current_line.strip()

                # If it's empty (e.g. trailing newlines), we keep searching backward
                # But we have to handle the data BEFORE the newline in this chunk!
                # We can just split the chunk and look at it backward.

            accumulated.insert(0, chunk)

        # If we reach here, we've read the whole file without finding a newline (or only finding empty lines)
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
