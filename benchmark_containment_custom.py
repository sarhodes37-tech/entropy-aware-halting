import timeit

setup = """
from epistemicos.containment import ContainmentGuard
"""

stmt = """
cg = ContainmentGuard(custom_forbidden_commands=["sudo ", "rm -f "])
"""

n = 10000
t = timeit.timeit(stmt, setup=setup, number=n)
print(f"Baseline custom for {n} instantiations: {t} seconds")
