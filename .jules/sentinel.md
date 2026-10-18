## 2025-10-18 - Avoid Raw String Injections in `re.sub` Replacement Arguments
**Vulnerability:** Passing untrusted or arbitrary raw string values directly as the second argument (`repl`) to `re.sub()` allows regex backreference evaluation (e.g. `\1`, `\g<0>`), causing string corruption or `bad escape` exceptions if the raw string contains backslashes or capture reference syntax.
**Learning:** Python's `re.sub(pattern, repl, string)` parses replacement string syntax in `repl` unless a replacement callable function is passed.
**Prevention:** Always pass a replacement callable (e.g. `lambda _: raw_val`) when performing literal string replacements with `re.sub()` where the replacement value could contain arbitrary text or backslashes.
