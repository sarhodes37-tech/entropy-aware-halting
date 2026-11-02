## 2025-10-18 - Avoid Raw String Injections in `re.sub` Replacement Arguments
**Vulnerability:** Passing untrusted or arbitrary raw string values directly as the second argument (`repl`) to `re.sub()` allows regex backreference evaluation (e.g. `\1`, `\g<0>`), causing string corruption or `bad escape` exceptions if the raw string contains backslashes or capture reference syntax.
**Learning:** Python's `re.sub(pattern, repl, string)` parses replacement string syntax in `repl` unless a replacement callable function is passed.
**Prevention:** Always pass a replacement callable (e.g. `lambda _: raw_val`) when performing literal string replacements with `re.sub()` where the replacement value could contain arbitrary text or backslashes.

## 2026-10-19 - Iterative Unquoting Before HTTP Path Validation
**Vulnerability:** Checking raw URL paths for directory traversal sequences (like `..`) before URL unquoting allows attackers to bypass traversal filters using single (`%2e%2e`) or double (`%252e%252e`) percent-encoding.
**Learning:** HTTP servers must decode/unquote URL-encoded path components iteratively until stable prior to evaluating path traversal rules or joining paths.
**Prevention:** Always iteratively `unquote()` HTTP request paths before checking for `..`, `\`, or `\x00`, and enforce `Path.relative_to` checks against the static root directory.

## 2026-10-20 - Synchronize Multi-Provider Credential Patterns Across Detection & Audit Layers
**Vulnerability:** While documented Anthropic credentials (`sk-ant-api03-...`, `sk-ant-admin01-...`) were mathematically matched by the existing generic `sk-[a-zA-Z0-9_\-]{20,}` pattern with identical span and redaction behavior, adding explicit provider-specific recognition (`sk-ant-(?:api|admin)[a-zA-Z0-9_\-]{20,}`) serves as defense-in-depth, explicit format documentation, and regression protection rather than fixing a demonstrated leakage vulnerability.
**Learning:** When multi-provider LLM adapters (e.g. OpenAI and Anthropic) are integrated, making credential formats explicit in regex patterns improves maintainability, domain clarity, and targeted test coverage across prompt inspection (`SensitiveDataDetector`) and audit logging (`TamperEvidentAuditTrail`) without altering baseline redaction behavior.
**Prevention:** Maintain strict pattern parity across detection and audit layers, pair provider-specific token alternatives with comprehensive test suites (covering complete spans, redaction, non-rehydration, and near-misses), and perform empirical differential verification before classifying format updates as vulnerability fixes.

## 2026-11-02 - Suppress BaseHTTPRequestHandler Runtime Version Disclosure in Server Header
**Vulnerability:** Python's standard `http.server.BaseHTTPRequestHandler.version_string()` concatenates `server_version + ' ' + sys_version`, emitting headers like `Server: BaseHTTP/0.6 Python/3.12.13`. This leaks internal server implementation details and exact runtime minor/patch versions to external clients across both successful and error responses.
**Learning:** Setting `sys_version = ""` alone still leaves a trailing space (`"ServerName "`) because `version_string()` unconditionally joins with `' '`. Fully neutralizing runtime banner disclosures requires overriding `version_string(self)` to return the clean generic token directly alongside setting `server_version` and empty `sys_version`.
**Prevention:** In standard-library HTTP servers, always explicitly define `server_version`, set `sys_version = ""`, and override `version_string(self)` to return a constant, non-disclosing identifier.

## 2026-11-03 - Enforce Fail-Closed Validation on Security Revocation Registries
**Vulnerability:** Returning `False` from revocation query functions (such as `is_revoked(None) -> False`) when passed malformed, empty, or non-string identifiers creates an authorization-friendly answer where callers interpret `False` as "approval is valid and unrevoked", converting invalid input into an authorization pass.
**Learning:** For security-sensitive revocation registries, invalid, missing, or malformed identifiers must never be converted into evidence that an authorization token is safe to use.
**Prevention:** Always fail closed by raising `ValueError` (or equivalent exception) when revocation check methods receive `None`, non-string, or empty/whitespace-only identifiers, ensuring callers cannot mistakenly proceed as if the identifier were unrevoked.
