import json
import torch
import pandas as pd
from extractor import TraceExtractor
from kernel import EpistemicKernel
from controller import EpistemicController
from metrics import ASTAnalyzer

print("[+] INITIALIZING IFEVAL JSON BENCHMARK FOR TINYLLAMA...")

# 1. Initialize Components
# Using TinyLlama or any small model available in the environment
MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
extractor = TraceExtractor(model_name=MODEL_NAME)
ast_analyzer = ASTAnalyzer()

# Tuned Kernel for small models: tighter patience, lower threshold for faster intervention
kernel = EpistemicKernel(gamma=0.95, patience=1, lam=2.5, window_k=10)
controller = EpistemicController(k_persistence=2, threshold=0.45)
# Note: Assuming controller is already trained, or we mock it for the intervention test
controller.is_trained = True

# 2. Strict IFEval JSON Dataset (Mocked for immediate testing)
ifeval_json_prompts = [
    "Extract the company 'Acme Corp' and revenue '500' into a JSON object with keys 'company' and 'revenue'. Output ONLY valid JSON and nothing else.",
    "Format the following as JSON: Name is John, Age is 30. Use keys 'name' and 'age'. Do not add any conversational text.",
    "Create a JSON object for a car with make 'Toyota' and model 'Camry'. Strictly JSON output required.",
    "Convert this to JSON: status is active, id is 99. Use 'status' and 'id' as keys. End your response immediately after the JSON.",
    "Output a JSON object with 'temperature' set to 72 and 'condition' set to 'sunny'. No markdown, no explanations."
]

def strict_json_grader(text: str) -> bool:
    """Strictly attempts to parse the string as JSON. Fails on any trailing text."""
    try:
        # Strip only leading/trailing whitespace, do not strip trailing conversational text
        # If the model added "Here is your JSON:", loads will fail.
        parsed = json.loads(text.strip())
        return isinstance(parsed, dict)
    except json.JSONDecodeError:
        return False

def run_trajectory(prompt: str, apply_intervention: bool = False):
    """Generates trajectory and optionally applies EpistemicOS halting."""
    trace_steps = extractor.extract_trajectory(prompt, max_new_tokens=150)

    ast_history = []
    entropy_history = []
    prev_entropy = None
    final_text = ""
    halt_step = None

    for step_data in trace_steps:
        current_entropy = step_data["entropy"]
        clean_prefix = step_data["clean_prefix"]
        final_text = clean_prefix

        is_valid_ast = ast_analyzer.passes_static_ast(clean_prefix)
        ast_history.append(is_valid_ast)
        entropy_history.append(current_entropy)

        if apply_intervention:
            nri, tau_t, probe_triggered, halt_execution = kernel.step(
                h_current=current_entropy,
                h_previous=prev_entropy,
                omega=1.0,
                dA=ast_analyzer.count_ast_nodes(clean_prefix)
            )

            # If entropy spikes above dynamic envelope, halt immediately
            if probe_triggered or halt_execution:
                halt_step = step_data["step"]
                break

        prev_entropy = current_entropy

    return final_text, halt_step, len(trace_steps)

# 3. Execution Loop
results = []
print("\n[+] Running A/B Test: Baseline vs. EpistemicOS Intervention...")

for i, prompt in enumerate(ifeval_json_prompts):
    print(f"\n--- Sample {i+1}/{len(ifeval_json_prompts)} ---")

    # Run Baseline
    base_text, _, base_tokens = run_trajectory(prompt, apply_intervention=False)
    base_pass = strict_json_grader(base_text)

    # Run EpistemicOS
    kernel = EpistemicKernel(gamma=0.95, patience=1, lam=2.5, window_k=10) # Reset state
    ep_text, halt_step, ep_tokens = run_trajectory(prompt, apply_intervention=True)
    ep_pass = strict_json_grader(ep_text)

    tokens_saved = base_tokens - (halt_step if halt_step else ep_tokens)

    print(f"Baseline Output (length {len(base_text)}): {base_text.replace(chr(10), ' ')[:60]}...")
    print(f"Epistemic Output (length {len(ep_text)}): {ep_text.replace(chr(10), ' ')[:60]}...")

    if not base_pass and ep_pass:
        print(f"-> [!] INTERVENTION SUCCESS: Saved from parse failure at step {halt_step}. Saved {tokens_saved} tokens.")

    results.append({
        "sample": i + 1,
        "baseline_pass": base_pass,
        "epistemic_pass": ep_pass,
        "halt_step": halt_step,
        "tokens_saved": max(0, tokens_saved)
    })

# 4. Final Reporting
df = pd.DataFrame(results)
base_accuracy = df['baseline_pass'].mean() * 100
ep_accuracy = df['epistemic_pass'].mean() * 100
total_saved = df['tokens_saved'].sum()
rescued = df[(df['baseline_pass'] == False) & (df['epistemic_pass'] == True)].shape[0]

print("\n" + "="*50)
print(" EPISTEMICOS IFEVAL (JSON) INTERVENTION RESULTS")
print("="*50)
print(f" Total Samples Evaluated:    {len(ifeval_json_prompts)}")
print(f" Baseline Pass@1:            {base_accuracy:.1f}%")
print(f" Rollback Engine Pass@1:     {ep_accuracy:.1f}%")
print(f" Absolute Accuracy Delta:    +{ep_accuracy - base_accuracy:.1f}%")
print(f" Total Trajectories Rescued: {rescued}")
print(f" Compute Waste Prevented:    {total_saved} tokens")
print("="*50)