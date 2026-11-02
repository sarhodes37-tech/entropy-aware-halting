## 2025-10-18 - Avoid Raw String Injections in `re.sub` Replacement Arguments
**Vulnerability:** Passing untrusted or arbitrary raw string values directly as the second argument (`repl`) to `re.sub()` allows regex backreference evaluation (e.g. `\1`, `\g<0>`), causing string corruption or `bad escape` exceptions if the raw string contains backslashes or capture reference syntax.
**Learning:** Python's `re.sub(pattern, repl, string)` parses replacement string syntax in `repl` unless a replacement callable function is passed.
**Prevention:** Always pass a replacement callable (e.g. `lambda _: raw_val`) when performing literal string replacements with `re.sub()` where the replacement value could contain arbitrary text or backslashes.

## 2026-10-19 - Iterative Unquoting Before HTTP Path Validation
**Vulnerability:** Checking raw URL paths for directory traversal sequences (like `..`) before URL unquoting allows attackers to bypass traversal filters using single (`%2e%2e`) or double (`%252e%252e`) percent-encoding.
**Learning:** HTTP servers must decode/unquote URL-encoded path components iteratively until stable prior to evaluating path traversal rules or joining paths.
**Prevention:** Always iteratively `unquote()` HTTP request paths before checking for `..`, `\`, or `\x00`, and enforce `Path.relative_to` checks against the static root directory.

## 2026-10-20 - Synchronize Multi-Provider Credential Patterns Across Detection & Audit Layers
**Vulnerability:** Audit log redaction (`REGEX_SK`) and outbound privacy sanitization (`_API_KEY_REGEX`) supported OpenAI, GitHub, GitLab, AWS, Hugging Face, and Slack tokens, but lacked full prefix matching for Anthropic API and Admin keys (`sk-ant-api03-...`, `sk-ant-admin01-...`), capturing only internal substrings and producing malformed double prefixes (`sk-sk-[REDACTED]`) while leaving the `sk-` prefix unredacted in detection spans.
**Learning:** When multi-provider LLM adapters (e.g. OpenAI and Anthropic) are supported across the architecture, credential pattern sets must cover the complete documented credential format including provider-specific prefixes (`sk-ant-(?:api|admin)...`), maintaining synchronized parity across both prompt boundary inspection (`SensitiveDataDetector`) and audit trail sanitization (`TamperEvidentAuditTrail`).
**Prevention:** Always verify that API key regexes match complete token boundaries including provider prefixes (`sk-ant-api`, `sk-ant-admin`, `sk-`, `hf_`, etc.), preventing partial span capture or duplicate replacement artifacts, and enforce pattern parity across modules with automated regression tests.
