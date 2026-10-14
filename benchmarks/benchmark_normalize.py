import time
from epistemicos.semantic_uncertainty import ExactAndNormalizedResolver, SemanticUncertaintyEstimator

def main():
    resolver = ExactAndNormalizedResolver()
    sample_texts = [
        "This request is not unauthorized and should be processed immediately.",
        "The document is not invalid according to section 4.",
        "Statement 1 is not false, but statement 2 is not correct.",
        "Access was not denied for user admin.",
        "It is not impossible to complete this task on time.",
        "The output is not incorrect.",
        "Regular text without any double negation patterns here.",
        "Another sentence checking USD $100 and non-alphanumeric punctuation!!!"
    ] * 10000  # 80,000 texts

    # Warmup
    for text in sample_texts[:1000]:
        _ = resolver._normalize(text)

    # Multiple runs to measure mean and distribution
    normalize_times = []
    rounds = 5
    for r in range(rounds):
        t0 = time.perf_counter()
        for text in sample_texts:
            _ = resolver._normalize(text)
        t1 = time.perf_counter()
        normalize_times.append(t1 - t0)

    mean_norm = sum(normalize_times) / rounds
    min_norm = min(normalize_times)
    max_norm = max(normalize_times)
    print(f"Measured _normalize ({len(sample_texts)} calls x {rounds} rounds):")
    print(f"  Mean: {mean_norm:.4f} s ({mean_norm / len(sample_texts) * 1e6:.2f} µs/op)")
    print(f"  Min:  {min_norm:.4f} s | Max: {max_norm:.4f} s")

    estimator = SemanticUncertaintyEstimator(resolver=resolver)
    candidates = [
        "This request is not unauthorized.",
        "This request is authorized.",
        "Access is not denied.",
        "Access is approved.",
        "It is not false that the transaction succeeded.",
        "The transaction succeeded.",
    ] * 5

    estimate_runs = 50
    estimate_times = []
    for r in range(rounds):
        t0 = time.perf_counter()
        for _ in range(estimate_runs):
            _ = estimator.estimate(candidates)
        t1 = time.perf_counter()
        estimate_times.append(t1 - t0)

    mean_est = sum(estimate_times) / rounds
    min_est = min(estimate_times)
    max_est = max(estimate_times)
    print(f"\nMeasured estimate ({estimate_runs} runs x {rounds} rounds):")
    print(f"  Mean: {mean_est:.4f} s ({mean_est / estimate_runs * 1e3:.2f} ms/op)")
    print(f"  Min:  {min_est:.4f} s | Max: {max_est:.4f} s")

if __name__ == "__main__":
    main()
