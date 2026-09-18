import time
import os
import json

def get_last_line(log_path):
    with open(log_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pointer = f.tell()
        buffer_size = 65536
        accumulated = []

        while pointer > 0:
            read_size = min(buffer_size, pointer)
            pointer -= read_size
            f.seek(pointer)
            chunk = f.read(read_size)

            lines = chunk.split(b"\n")
            if len(lines) > 1:
                last_part = lines[-1] + b"".join(accumulated)
                if last_part.strip():
                    return last_part.strip().decode("utf-8")

                for i in range(len(lines) - 2, 0, -1):
                    if lines[i].strip():
                        return lines[i].strip().decode("utf-8")
                accumulated = [lines[0]]
            else:
                accumulated.insert(0, chunk)

        full = b"".join(accumulated)
        if full.strip():
            return full.strip().decode("utf-8")
    return None
