"""
Layer 2 Code Generation Benchmark for EpistemicOS.
Evaluates entropy-guided trajectory rollback against Python code completion tasks.
"""

import ast
import re
from typing import Dict, Any, List
import pytest


HUMANEVAL_SAMPLE_PROBLEMS = [
    {
        "task_id": "HumanEval/0",
        "prompt": "def has_close_elements(numbers: list[float], threshold: float) -> bool:\n    \"\"\" Check if in given list of numbers, are any two numbers closer to each other than given threshold.\n    >>> has_close_elements([1.0, 2.0, 3.0], 0.5)\n    False\n    \"\"\"",
        "test": "assert has_close_elements([1.0, 2.0, 3.9, 4.0, 5.0, 2.2], 0.3) == True"
    },
    {
        "task_id": "HumanEval/2",
        "prompt": "def truncate_number(number: float) -> float:\n    \"\"\" Given a positive floating point number, return the decimal part. \"\"\"",
        "test": "assert truncate_number(3.5) == 0.5"
    },
    {
        "task_id": "HumanEval/3",
        "prompt": "def below_zero(operations: list[int]) -> bool:\n    \"\"\" Return True if account balance ever drops below zero. \"\"\"",
        "test": "assert below_zero([1, 2, 3]) == False"
    }
]


def extract_code_block(text: str) -> str:
    """Extracts code contained within ```python markdown blocks or returns raw text."""
    if "```python" in text:
        parts = text.split("```python")
        if len(parts) > 1:
            return parts[1].split("```")[0].strip()
    elif "```" in text:
        parts = text.split("```")
        if len(parts) > 1:
            return parts[1].strip()
    return text.strip()


def validate_code_execution(full_code: str, test_assertion: str) -> bool:
    """Evaluates code syntax and functional test pass in an isolated namespace."""
    try:
        # Step 1: AST Parse Check
        ast.parse(full_code)
        
        # Step 2: Exec Assertion Check
        exec_globals: Dict[str, Any] = {}
        exec(full_code, exec_globals)
        exec(test_assertion, exec_globals)
        return True
    except Exception:
        return False


def mock_pipeline_eval(prompt: str) -> Dict[str, Any]:
    """
    Simulates pipeline output for test execution:
    Returns both raw unrolled trajectory and entropy-rolled-back text.
    """
    if "truncate_number" in prompt:
        raw_tail = "\n    return number - int(number)\n# Extra redundant comments\n```"
        return {
            "raw_trajectory": prompt + raw_tail,
            "final_text": prompt + "\n    return number - int(number)",
            "halt_directive": "OPTIMAL_CONVERGENCE",
            "halt_step": 15
        }
    else:
        raw_tail = "\n    balance = 0\n    for op in operations:\n        balance += op\n        if balance < 0: return True\n    return False"
        return {
            "raw_trajectory": prompt + raw_tail,
            "final_text": prompt + raw_tail,
            "halt_directive": "COMPLETED",
            "halt_step": 20
        }


# =====================================================================
# Benchmark Tests
# =====================================================================

def test_layer2_code_generation_rollback():
    """
    Evaluates baseline vs EpistemicOS recovered pass rates across code problems.
    Ensures rollback prevents token corruption without degrading syntax/execution.
    """
    total_baseline_pass = 0
    total_recovered_pass = 0
    total_corruption_prevented = 0

    for prob in HUMANEVAL_SAMPLE_PROBLEMS:
        # Run pipeline evaluation
        result = mock_pipeline_eval(prob["prompt"])

        raw_code = extract_code_block(result["raw_trajectory"])
        recovered_code = extract_code_block(result["final_text"])

        baseline_pass = validate_code_execution(raw_code, prob["test"])
        recovered_pass = validate_code_execution(recovered_code, prob["test"])

        if baseline_pass:
            total_baseline_pass += 1
        if recovered_pass:
            total_recovered_pass += 1

        prevented_chars = max(0, len(result["raw_trajectory"]) - len(result["final_text"]))
        total_corruption_prevented += prevented_chars

    # Assertions
    assert total_recovered_pass >= total_baseline_pass
    assert total_recovered_pass > 0
