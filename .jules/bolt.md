## 2024-05-24 - Recursive Generator Expressions vs Iterative DFS in Python
**Learning:** In Python, deeply nested recursive generator expressions like `max((func(x) for x in obj))` create significant performance bottlenecks due to generator instantiation and function call overhead on every level of nesting. They also risk `RecursionError` on large data structures.
**Action:** Replace deep recursive generator aggregations with stack-based iterative Depth-First Search (DFS) patterns to reduce runtime overhead and protect against recursion limits.

## 2024-05-18 - Optimize Scheduler all() Evaluation
**Learning:** Using list comprehensions inside an `all()` function call forces Python to evaluate every item and allocate memory for the full list before checking conditions. This negates `all()`'s short-circuiting ability and wastes CPU/memory, particularly on larger iterables or sliding windows.
**Action:** When passing a comprehension into `all()` or `any()`, always omit the square brackets to use a generator expression instead. This prevents list allocation overhead and takes full advantage of early loop termination (short-circuiting).
