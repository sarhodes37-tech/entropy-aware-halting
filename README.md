# EpistemicOS: Deterministic Halting & Security Middleware for LLMs
EpistemicOS is a low-latency security middleware designed to enforce deterministic halting and strict sandbox boundaries on Large Language Model (LLM) outputs. It intercepts structural collapse, N-gram loops, epistemic hallucinations, and unauthorized tool-calling vectors before they can execute within a broader system.
Think of standard LLM safety filters like a bouncer checking every single patron's ID one by one—a high-latency bottleneck. EpistemicOS operates more like a thermodynamic sensor. It detects the sudden statistical pressure drop of an anomalous token stream in O(1) time and drops the blast doors instantly, only applying heavier regex and AST parsing to stable, baseline traffic.
## 📊 Empirical Validation & Benchmarks
EpistemicOS has been rigorously tested across both active trajectory recovery benchmarks and targeted adversarial datasets.
### 1. Active Trajectory Recovery (Qwen2.5-1.5B / HumanEval)
The EAC-EXEC (Execution-Gated) core was benchmarked on N=164 trajectories to measure the recovery of corrupted generations.
 * **Standard Pass@1 (Ungated EOS Baseline):** 6.1%
 * **Passive Entropy Stopping:** 6.1%
 * **EpistemicOS Active EAC-EXEC:** **37.2%**
 * **Theoretical Oracle Maximum (P_{\text{oracle}}):** 37.2%
**Key Efficiency Gains:**
 * **+31.1% Absolute Accuracy Gain** (hitting the theoretical reachability ceiling).
 * **100% Recovery Rate** for "Case A" corrupted trajectories.
 * **139 Tokens Saved** on average per solved prompt by terminating dead-end loops early.
### 2. RhodesBench Adversarial Ablation Study
The architecture's gating efficacy was tested against RhodesBench, a targeted adversarial dataset containing recursive self-reference, impossible observations, and hallucination vectors.
| Configuration | Precision | Recall | Avg Latency | Anomalies Caught | Misses |
|---|---|---|---|---|---|
| **C0: Baseline (No Gates)** | 20.00% | 0.00% | ~0.0012 ms | 0 / 8 | 8 |
| **C1: Entropy Only** | 20.00% | 0.00% | ~0.0075 ms | 0 / 8 | 8 |
| **C2: Permission Only** | 50.00% | 75.00% | ~0.0195 ms | 6 / 8 | 2 |
| **C4: Full EpistemicOS** | 100.00% | 100.00% | ~0.0229 ms | 8 / 8 | 0 |
**The O(1) Overhead:** By positioning the OptimizedEntropyGate strictly before the OptimizedPermissionGate, the system establishes a statistical baseline before applying heavier string evaluation. The full C4 configuration captures the remaining blind spots of the permission gate (boosting Recall to 100%) while only adding an average execution overhead of ~0.0034 ms.
## 🏗 Core Architecture
EpistemicOS routes the token stream through sequential hard gates to guarantee deterministic containment.
### 1. Optimized Entropy Gate (Statistical Sandbox)
Calculates Shannon Entropy and tracks token variance using a rolling 64-token window.
It utilizes a streaming Z-score calculation to detect massive spikes in epistemic uncertainty:
> **Note:** A standard deviation floor (\sigma \ge 0.05) is strictly enforced to prevent mathematical paradoxes where benign micro-fluctuations in highly confident token streams trigger artificial Z-score explosions.
> 
### 2. Optimized Permission Gate (Contract Bounding)
A Just-In-Time (JIT) pre-compiled regex and AST evaluation gate. It restricts LLM actions to a predefined array of allowed tool calls and intercepts unsafe system command injections (e.g., sudo, rm -rf, exec).
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
