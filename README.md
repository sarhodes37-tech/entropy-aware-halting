# EpistemicOS: Deterministic Halting & Security Middleware for LLMs
EpistemicOS is a low-latency security middleware designed to enforce deterministic halting and strict sandbox boundaries on Large Language Model (LLM) outputs. It intercepts structural collapse, N-gram loops, epistemic hallucinations, and unauthorized tool-calling vectors before they can execute within a broader system.
Think of standard LLM safety filters like a bouncer checking every single patron's ID one by one—a high-latency bottleneck. EpistemicOS operates more like a thermodynamic sensor. It detects the sudden statistical pressure drop of an anomalous token stream in O(1) time and drops the blast doors instantly, only applying heavier regex and AST parsing to stable, baseline traffic.
## 📊 Empirical Validation & Benchmarks

### Benchmark Reproduction
To run and reproduce the full empirical benchmark suite, 6-baseline comparison, threshold ablations, and generate machine-readable results (`results/ablation_table.json`, `results/per_case_results.json`, and `results/ablation_summary.md`):

```bash
python3 -m benchmarks.run_full_benchmark
```

For detailed experimental methodology and limitations, see [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## 🏗 Core Architecture
EpistemicOS routes the token stream through sequential hard gates to guarantee deterministic containment.
### 1. Optimized Entropy Gate (Statistical Sandbox)
Calculates Shannon Entropy and tracks token variance using a rolling 64-token window.
It utilizes a streaming Z-score calculation to detect massive spikes in epistemic uncertainty:
> **Note:** A standard deviation floor (\sigma \ge 0.05) is strictly enforced to prevent mathematical paradoxes where benign micro-fluctuations in highly confident token streams trigger artificial Z-score explosions.
> 
### 2. Optimized Permission Gate (Contract Bounding)
A Just-In-Time (JIT) pre-compiled regex and AST evaluation gate. It restricts LLM actions to a predefined array of allowed tool calls and intercepts unsafe system command injections (e.g., sudo, rm -rf, exec).

## 🔒 Security Hardening & Trust Boundaries

### Fail-Safe Model Loading Defaults
EpistemicOS enforces `trust_remote_code=False` by default across both `epistemicos.utils.get_model_and_tokenizer` and the public API wrapper `epistemicos.get_model_and_tokenizer`. Custom remote code execution requires explicit opt-in (`trust_remote_code=True`). For production and security-sensitive deployments, pinning model artifacts with immutable commit SHAs (e.g. `revision="4a2b9f..."`) is strongly encouraged to prevent supply-chain tampering.

### Trusted Authorization Scope Boundary
`PermissionGate` strictly isolates authorization scope resolution. Request-supplied or agent-controlled `scope` parameters in unauthenticated payloads are never treated as authoritative permissions. Authoritative scope must be injected via trusted gate configuration or authenticated context (`trusted_scope`). If trusted scope is missing, malformed, or ambiguous, protected actions fail closed.
### 3. Tamper-Evident Audit Trail
All intercepted violations are logged cryptographically. The orchestrator records the trigger condition, the gate that threw the flag, and the execution latency, ensuring transparent and immutable security audits.
## 🚀 Quickstart & Installation
EpistemicOS is built entirely on the Python standard library to ensure maximum execution speed and zero dependency bloat.
**Requirements:**
 * Python 3.8+
**1. Clone the repository:**
```bash
git clone https://github.com/sarhodes37-tech/entropy-aware-halting.git
cd entropy-aware-halting

```
**2. Install dependencies (Optional dev/testing tools):**
```bash
pip install -r requirements.txt

```
**3. Run the Benchmark:**
Execute the test harness to run the orchestrator against the dataset_rhodes.jsonl adversarial vector.
```bash
python3 test_rhodes_bench.py

```
**4. Run the Integration Suite:**
To execute the full test suite against your local environment:
```bash
pytest tests/integration/test_pipeline_gamma.py -v

```
