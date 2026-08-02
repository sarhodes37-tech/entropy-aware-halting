import pytest
from epistemicos.telemetry import (
    ASTAnalyzer,
    calculate_entropy_differential,
    calculate_structural_risk_index,
    ResourceProfiler
)

def test_ast_analyzer_risk():
    analyzer = ASTAnalyzer()
    code = "x = 1\nfor i in range(10):\n    print(i)"
    
    assert analyzer.passes_static_ast(code) is True
    risk_score = analyzer.compute_aggregate_ast_risk(code)
    assert risk_score > 0.0

def test_structural_risk_index_calculation():
    # dH positive surge, omega weight, AST node delta
    sri = calculate_structural_risk_index(dH_pos=1.5, omega=3.5, dA=4)
    # 1.5 * 3.5 * 4 = 21.0
    assert sri == 21.0

def test_resource_profiler_fallback():
    # Running on CPU/mock environment should safely execute without throwing errors
    with ResourceProfiler(device="cpu", token_count=10) as profiler:
        total = sum(range(1000))
        
    telemetry = profiler.get_telemetry()
    assert telemetry.tokens_processed == 10
    assert telemetry.wall_clock_ms >= 0.0
