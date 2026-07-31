EpistemicOS: Deterministic Halting & Security Middleware for LLMs

​EpistemicOS is a low-latency security middleware designed to enforce deterministic halting and strict sandbox boundaries on Large Language Model (LLM) outputs. It intercepts structural collapse, N-gram loops, epistemic hallucinations, and unauthorized tool-calling vectors before they can be executed by the broader system.

​Think of standard LLM safety filters like a bouncer checking every single patron's ID one by one—a high-latency bottleneck. EpistemicOS operates more like a thermodynamic sensor. It detects the sudden statistical pressure drop of an anomalous token stream in O(1) time and drops the blast doors instantly, only applying heavier regex parsing to stable, baseline traffic.

​Performance: RhodesBench Ablation Study

​The architecture's efficacy was tested against RhodesBench, a targeted adversarial dataset containing recursive self-reference, impossible observations, and hallucination vectors.
​The ablation data below demonstrates that deploying the full gate sequence not only yields a 100% interception rate but actually reduces average processing latency compared to running the permission gate alone.

Configuration
Precision
Recall
Avg Latency
Anomalies Caught (True Positives)
False Commits (Misses)

C0: Baseline (No Gates)
20.00%
0.00%
~0.0004 ms
0 / 8
8

C1: Entropy Only
33.33%
50.00%
~0.0053 ms
4 / 8
4

C2: Permission Only
50.00%
75.00%
~0.0170 ms
6 / 8
2

C4: Full EpistemicOS
100.00%
100.00%
~0.0106 ms
8 / 8
0


The Latency Short-Circuit

​The C4 configuration (0.0106 ms) executes faster than C2 (0.0170 ms). Because the O(1) OptimizedEntropyGate sits strictly before the heavier regex evaluation of the OptimizedPermissionGate, it acts as a short-circuit. When the entropy gate flags an epistemic collapse, the execution halts immediately, bypassing string evaluation entirely and optimizing compute overhead.


​Core Architecture

​EpistemicOS routes the token stream through two sequential hard gates.

​1. Optimized Entropy Gate (Statistical Sandbox)

​Calculates Shannon Entropy and tracks token variance using a 64-token rolling window.

H(X) = -\sum_{i} P(x_i) \log_2 P(x_i)

It utilizes a streaming Z-score calculation to detect massive spikes in uncertainty:

Z = \frac{\vert{}H(X) - \mu\vert{}}{\max(\sigma, 0.05)}

Note: A standard deviation floor (\sigma \ge 0.05) is strictly enforced to prevent mathematical paradoxes where benign micro-fluctuations in highly confident token streams trigger artificial Z-score explosions.

2. Optimized Permission Gate (Contract Bounding)

​A Just-In-Time (JIT) pre-compiled regex evaluation gate. It restricts LLM actions to a predefined array of allowed tool calls and intercepts unsafe system command injections (e.g., sudo, rm -rf, exec).

​3. Tamper-Evident Audit Trail

​All intercepted violations are logged cryptographically. The orchestrator records the trigger condition, the gate that threw the flag, and the execution latency, ensuring transparent and immutable security audits.


​Quickstart

​1. Clone the repository:

git clone https://github.com/sarhodes37-tech/entropy-aware-halting.git
cd entropy-aware-halting

2. Run the Benchmark:

Execute the test harness to run the orchestrator against the dataset_rhodes.jsonl adversarial vectors.

python3 test_rhodes_bench.py


Installation

EpistemicOS is built entirely on the Python standard library to ensure maximum execution speed and zero dependency bloat.

**Requirements:**
- Python 3.8+

**Setup:**

git clone [https://github.com/sarhodes37-tech/entropy-aware-halting.git](https://github.com/sarhodes37-tech/entropy-aware-halting.git)
cd entropy-aware-halting
pip install -r requirements.txt  # Installs dev/testing tools (optional)


