## 2024-05-24 - Recursive Generator Expressions vs Iterative DFS in Python
**Learning:** In Python, deeply nested recursive generator expressions like `max((func(x) for x in obj))` create significant performance bottlenecks due to generator instantiation and function call overhead on every level of nesting. They also risk `RecursionError` on large data structures.
**Action:** Replace deep recursive generator aggregations with stack-based iterative Depth-First Search (DFS) patterns to reduce runtime overhead and protect against recursion limits.

## 2024-05-18 - Optimize Scheduler all() Evaluation
**Learning:** Using list comprehensions inside an `all()` function call forces Python to evaluate every item and allocate memory for the full list before checking conditions. This negates `all()`'s short-circuiting ability and wastes CPU/memory, particularly on larger iterables or sliding windows.
**Action:** When passing a comprehension into `all()` or `any()`, always omit the square brackets to use a generator expression instead. This prevents list allocation overhead and takes full advantage of early loop termination (short-circuiting).

## 2025-05-18 - Consolidating Static Word/Entity Dictionary Regexes
**Learning:** In Python, iterating over a list of N individual compiled word-boundary regex patterns (`[re.compile(r"\b" + name + r"\b") for name in dictionary]`) causes N separate regex engine invocations over the target text per detection call.
**Action:** Consolidate static word/entity sets into a single compiled regex pattern with alternation (`re.compile(r"\b(?:" + "|".join(escaped_words) + r")\b")`) to perform a single pass over text, significantly reducing detection latency (~8.4x speedup for dictionary matching).

## 2026-03-31 - Fast-Path Trigger Character & Length Short-Circuiting for Regular Expression Sanitizers
**Learning:** In Python, unconditionally executing multiple compiled regex substitutions (`.sub()`) across string fields in recursive data structures introduces significant CPU overhead even when trigger patterns (like '@', '=', 'bearer', digits) are not present. Using lightweight substring checks (`"@" in s`, `"=" in s`, `len(s) < N`, `re.search(r"\d", s)`) before triggering regex execution yields ~3.6x speedup for string sanitization and ~2.3x overall speedup for log/receipt data sanitization without introducing fragile pattern coupling.
**Action:** Before running complex or multiple `.sub()` operations in hot traversal paths, add fast substring or length guards to short-circuit regex engine invocation when trigger characters are absent.
