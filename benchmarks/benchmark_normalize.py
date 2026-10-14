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

    start_time = time.perf_counter()
    for text in sample_texts:
        _ = resolver._normalize(text)
    end_time = time.perf_counter()

    elapsed = end_time - start_time
    print(f"Baseline _normalize ({len(sample_texts)} calls): {elapsed:.4f} seconds ({elapsed / len(sample_texts) * 1e6:.2f} µs/op)")

    estimator = SemanticUncertaintyEstimator(resolver=resolver)
    candidates = [
        "This request is not unauthorized.",
        "This request is authorized.",
        "Access is not denied.",
        "Access is approved.",
        "It is not false that the transaction succeeded.",
        "The transaction succeeded.",
    ] * 5

    start_time = time.perf_counter()
    for _ in range(200):
        _ = estimator.estimate(candidates)
    end_time = time.perf_counter()

    elapsed_est = end_time - start_time
    print(f"Baseline estimate (200 runs): {elapsed_est:.4f} seconds ({elapsed_est / 200 * 1e3:.2f} ms/op)")

if __name__ == "__main__":
    main()
