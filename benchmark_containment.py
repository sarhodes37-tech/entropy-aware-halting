import timeit

setup = """
from epistemicos.containment import ContainmentGuard
"""

stmt = """
cg = ContainmentGuard()
"""

n = 10000
t = timeit.timeit(stmt, setup=setup, number=n)
print(f"Baseline for {n} instantiations: {t} seconds")
