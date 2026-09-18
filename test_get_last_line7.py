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

                # Check the part after the last newline first
                last_part = lines[-1] + b"".join(accumulated)
                if last_part.strip():
                    return last_part.strip()

                # Check the previous lines in this chunk
                for i in range(len(lines) - 2, 0, -1):
                    if lines[i].strip():
                        return lines[i].strip()

                # If all lines after the first one are empty,
                # the first line (lines[0]) is incomplete and becomes the new accumulated
                accumulated = [lines[0]]
            else:
                # No newline in this chunk, prepend it to accumulated
                accumulated.insert(0, chunk)

        # If we reach here, we've read the whole file without finding any more newlines
        full_data = b"".join(accumulated)
        if full_data.strip():
            return full_data.strip()

        return None

def test_cases():
    import tempfile

    cases = [
        b"",
        b"\n\n",
        b"hello",
        b"hello\n",
        b"hello\n\n",
        b"hello\nworld",
        b"hello\nworld\n",
        b"hello\n" + b"world" * 1000,
        b"hello\n" + b"world\n" * 1000,
    ]

    for case in cases:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(case)
            path = f.name

        line = get_last_line(path)

        # Expected
        expected = None
        for l in reversed(case.split(b"\n")):
            if l.strip():
                expected = l.strip()
                break

        if line != expected:
            print(f"FAILED on case {case[:50]}: expected {expected}, got {line}")
        else:
            print(f"Passed on case length {len(case)}")

        os.remove(path)

test_cases()
