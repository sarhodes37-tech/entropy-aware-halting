## 2024-05-24 - Recursive Generator Expressions vs Iterative DFS in Python
**Learning:** In Python, deeply nested recursive generator expressions like `max((func(x) for x in obj))` create significant performance bottlenecks due to generator instantiation and function call overhead on every level of nesting. They also risk `RecursionError` on large data structures.
**Action:** Replace deep recursive generator aggregations with stack-based iterative Depth-First Search (DFS) patterns to reduce runtime overhead and protect against recursion limits.
