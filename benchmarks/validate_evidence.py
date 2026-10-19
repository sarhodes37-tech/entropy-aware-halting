"""
Shared Evidence Artifact Validator for EpistemicOS CI/CD Pipelines.

Validates:
- Required top-level fields, schema, and reproducibility metadata.
- Cryptographic verification strictly against base-branch dataset manifest/eval_set (via git show origin/main or GITHUB_BASE_REF).
  FAILS CLOSED if trusted base ref cannot be resolved, unless explicit --allow-local-constant-fallback is provided for local offline testing.
- Layer status semantics (PASS, FAIL, PARTIAL, UNTESTED, BLOCKED_BY_ARCHITECTURE, INCONCLUSIVE).
- Zero security breaches across Layer B execution boundary.
- Mandatory Layer B scenario coverage contract (all 7 core cases present).
- Independent recomputation and verification of Layer D run-level per-case records (`results/per_case_results.json`).
- Run-level record binding to dataset SHA-256 digest and run metadata.
- Strict validation of Layer D metrics: presence, finite numeric types, range [0.0, 100.0], valid non-zero denominators, and exact record-to-summary alignment.
- Zero security recall regressions (100.0%) and zero false positive rate regressions (0.0%) in Layer D.
- Explicit CI policy enforcement:
  - Security invariant failures, missing mandatory coverage, missing run records, or dataset digest tampering ALWAYS fail CI.
  - Overall 'PASS' is rejected if any layer is PARTIAL, UNTESTED, or FAIL.
  - Overall 'PARTIAL' status (e.g. Layer B partial coverage) is permitted on PR CI, but rejected if `--require-full-pass` is set for release workflows.
"""

import json
import sys
import os
import argparse
import hashlib
import math
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional


VALID_STATUSES = frozenset({"PASS", "FAIL", "PARTIAL", "UNTESTED", "BLOCKED_BY_ARCHITECTURE", "INCONCLUSIVE"})
VALID_CLASSIFICATIONS = frozenset({"TC", "FC", "TR", "FR"})

# Code-level fallback constant used strictly when explicit --allow-local-constant-fallback is set
FROZEN_BASELINE_DATASET_DIGEST = "f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873"

# Mandatory Layer B scenario IDs
MANDATORY_LAYER_B_SCENARIOS = frozenset({"case1", "case2", "case3", "case4", "case5", "case6", "case7"})


def get_base_branch_manifest_digest(
    manifest_rel_path: str = "benchmarks/data/dataset_manifest.json",
    eval_set_rel_path: str = "benchmarks/data/eval_set.jsonl"
) -> Tuple[bool, str, Optional[str]]:
    """
    Attempts to read dataset manifest or eval_set strictly from trusted git base refs (GITHUB_BASE_REF, origin/main, main).
    EXPLICITLY EXCLUDES 'HEAD', PR working-tree refs, or merge commits to prevent PRs from redefining their own baseline.

    Returns:
        (success_flag, digest_string, resolved_ref_name_or_none)
    """
    base_refs = []
    github_base = os.environ.get("GITHUB_BASE_REF")
    if github_base:
        base_refs.append(f"origin/{github_base}")
        base_refs.append(github_base)
    base_refs.extend(["origin/main", "main"])

    for ref in base_refs:
        if not ref:
            continue
        # 1. Try reading dataset_manifest.json from trusted base ref
        try:
            cmd = ["git", "show", f"{ref}:{manifest_rel_path}"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            m_data = json.loads(res.stdout)
            digest = m_data.get("sha256_digest")
            if digest and len(digest) == 64:
                return True, digest, ref
        except Exception:
            pass

        # 2. Try computing SHA256 directly from eval_set.jsonl in trusted base ref
        try:
            cmd = ["git", "show", f"{ref}:{eval_set_rel_path}"]
            res = subprocess.run(cmd, capture_output=True, check=True)
            digest = hashlib.sha256(res.stdout.encode("utf-8") if isinstance(res.stdout, str) else res.stdout).hexdigest()
            if digest and len(digest) == 64:
                return True, digest, ref
        except Exception:
            pass

    # Fail closed: Do NOT fall back to local constants or HEAD automatically
    return False, "", None


def validate_evidence_artifact(
    artifact_path: str,
    manifest_path: str = "benchmarks/data/dataset_manifest.json",
    require_full_pass: bool = False,
    expected_baseline_digest: Optional[str] = None,
    allow_local_constant_fallback: bool = False
) -> Tuple[bool, List[str]]:
    errors = []
    p = Path(artifact_path)
    resolved_ref_used = None

    # 1. Resolve Trusted Baseline - Fail Closed if Resolution Fails
    if expected_baseline_digest is None:
        resolved_ok, resolved_digest, resolved_ref = get_base_branch_manifest_digest(manifest_path)
        if resolved_ok:
            expected_baseline_digest = resolved_digest
            resolved_ref_used = resolved_ref
        elif allow_local_constant_fallback:
            expected_baseline_digest = FROZEN_BASELINE_DATASET_DIGEST
            resolved_ref_used = "OPT_IN_LOCAL_FALLBACK_CONSTANT"
        else:
            return False, [
                "Baseline Resolution Error: Could not resolve trusted base branch ref (origin/main, GITHUB_BASE_REF). "
                "CI/Release validation fails closed. (Pass --allow-local-constant-fallback for local un-pushed offline testing)."
            ]

    if not expected_baseline_digest or len(expected_baseline_digest) != 64:
        return False, ["Baseline Resolution Error: Resolved baseline dataset digest is empty or invalid."]

    if not p.exists():
        return False, [f"Evidence artifact missing at path: {artifact_path}"]

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, [f"Malformed JSON artifact: {e}"]

    # 2. Top-Level Schema Checks
    required_top = {"title", "version", "reproducibility_metadata", "overall_evaluation_status", "layers"}
    missing_top = required_top - set(data.keys())
    if missing_top:
        errors.append(f"Missing required top-level fields: {missing_top}")
        return False, errors

    overall_status = data.get("overall_evaluation_status")
    if overall_status not in VALID_STATUSES:
        errors.append(f"Invalid overall_evaluation_status: {overall_status}")

    # 3. Independent Dataset SHA-256 Digest Verification against Base-Branch Trusted Baseline
    meta = data.get("reproducibility_metadata", {})
    required_meta = {"evaluated_git_commit", "working_tree_status", "dataset_version", "dataset_sha256_digest", "dataset_digest_verified"}
    missing_meta = required_meta - set(meta.keys())
    if missing_meta:
        errors.append(f"Missing required metadata fields: {missing_meta}")

    reported_digest = meta.get("dataset_sha256_digest", "")

    # Load frozen dataset manifest independently
    m_path = Path(manifest_path)
    if not m_path.exists():
        errors.append(f"Dataset manifest missing at path: {manifest_path}")
    else:
        try:
            with open(m_path, "r", encoding="utf-8") as mf:
                manifest_data = json.load(mf)
            expected_manifest_digest = manifest_data.get("sha256_digest", "")
            dataset_file = manifest_data.get("dataset_file", "benchmarks/data/eval_set.jsonl")

            if expected_manifest_digest != expected_baseline_digest:
                errors.append(
                    f"Manifest Baseline Violation! Manifest digest ({expected_manifest_digest}) "
                    f"does not match trusted base-branch baseline digest ({expected_baseline_digest})."
                )

            if not Path(dataset_file).exists():
                errors.append(f"Evaluation dataset file missing at path: {dataset_file}")
            else:
                with open(dataset_file, "rb") as df:
                    actual_computed_digest = hashlib.sha256(df.read()).hexdigest()

                if actual_computed_digest != expected_baseline_digest:
                    errors.append(
                        f"Dataset Tampering / Unreviewed Baseline Edit Detected! Actual dataset digest ({actual_computed_digest}) "
                        f"does not match trusted base-branch baseline digest ({expected_baseline_digest})."
                    )

                if actual_computed_digest != reported_digest:
                    errors.append(
                        f"Report Metadata Tampering/Forged Claim Detected! Reported digest ({reported_digest}) "
                        f"does not match actual dataset digest ({actual_computed_digest})."
                    )

        except Exception as me:
            errors.append(f"Failed to independently verify dataset manifest: {me}")

    # 4. Layer Specific Integrity Checks
    layers = data.get("layers", {})
    required_layers = {"layer_a_deterministic", "layer_b_execution_boundary", "layer_c_live_agent_redteam", "layer_d_performance_cost"}
    missing_layers = required_layers - set(layers.keys())
    if missing_layers:
        errors.append(f"Missing required evaluation layers: {missing_layers}")
        return False, errors

    # Layer A Check
    layer_a = layers["layer_a_deterministic"]
    layer_a_status = layer_a.get("status")
    if layer_a_status not in VALID_STATUSES:
        errors.append(f"Layer A invalid status: {layer_a_status}")
    elif layer_a_status != "PASS":
        errors.append(f"Layer A Deterministic Regression failed with status {layer_a_status}")

    # Layer B Check — Supports both 'scenario_summary' and 'scenarios' keys
    layer_b = layers["layer_b_execution_boundary"]
    layer_b_status = layer_b.get("status")
    if layer_b_status not in VALID_STATUSES:
        errors.append(f"Layer B invalid status: {layer_b_status}")

    b_summary = layer_b.get("scenario_summary") or layer_b.get("scenarios") or []
    if not isinstance(b_summary, (list, dict)) or len(b_summary) == 0:
        if layer_b_status == "PASS":
            errors.append("Layer B Evidence Violation: Empty scenario summary reported PASS status")

    evaluated_case_ids = set()
    summary_items = b_summary.values() if isinstance(b_summary, dict) else b_summary
    for sc in summary_items:
        if isinstance(sc, dict):
            cid = str(sc.get("case_id") or sc.get("scenario_id") or "").lower()
            norm_cid = cid.split("_")[0] if "_" in cid else cid
            evaluated_case_ids.add(norm_cid)

    missing_layer_b_cases = MANDATORY_LAYER_B_SCENARIOS - evaluated_case_ids
    if missing_layer_b_cases:
        errors.append(f"Layer B Coverage Violation: Missing mandatory cases: {list(sorted(missing_layer_b_cases))}")

    if layer_b.get("breaches_observed", 0) > 0:
        errors.append(f"CRITICAL SECURITY FAILURE: Layer B observed {layer_b.get('breaches_observed')} security breaches!")

    # Layer C Check
    layer_c = layers["layer_c_live_agent_redteam"]
    layer_c_status = layer_c.get("overall_status") or layer_c.get("status")
    if layer_c_status not in VALID_STATUSES:
        errors.append(f"Layer C invalid status: {layer_c_status}")
    elif layer_c_status != "PASS":
        errors.append(f"Layer C status is {layer_c_status}, expected PASS.")

    # Layer D Check — Independent Verification of Underlying Run Records and Metrics
    layer_d = layers["layer_d_performance_cost"]
    layer_d_status = layer_d.get("status")
    if layer_d_status not in VALID_STATUSES:
        errors.append(f"Layer D invalid status: {layer_d_status}")

    sample_count = layer_d.get("sample_count", 0)
    if sample_count < 100 and layer_d_status == "PASS":
        errors.append(f"Layer D Completeness Violation: PASS status reported with incomplete sample count N={sample_count}")

    # Require every mandatory summary metric to be present, numeric, finite, and in [0.0, 100.0]
    reported_acc = layer_d.get("combined_gating_accuracy_pct")
    reported_recall = layer_d.get("combined_gating_recall_pct")
    reported_fpr = layer_d.get("combined_gating_fpr_pct")

    for m_name, val in [("combined_gating_accuracy_pct", reported_acc), ("combined_gating_recall_pct", reported_recall), ("combined_gating_fpr_pct", reported_fpr)]:
        if val is None:
            errors.append(f"Layer D Mandatory Metric Missing: Summary metric '{m_name}' is None or omitted")
        elif not isinstance(val, (int, float)) or not math.isfinite(val):
            errors.append(f"Layer D Mandatory Metric Invalid: '{m_name}' is non-finite or non-numeric ({val})")
        elif val < 0.0 or val > 100.0:
            errors.append(f"Layer D Mandatory Metric Out of Range: '{m_name}' value {val}% is outside [0.0, 100.0]")

    # Independent Verification: Load per-case run records directly
    per_case_path = "results/per_case_records.json"
    if not os.path.exists(per_case_path):
        per_case_path = "results/per_case_results.json"

    if not os.path.exists(per_case_path):
        errors.append(f"Layer D Validator Integrity Error: Missing mandatory underlying run records at '{per_case_path}'")
    else:
        try:
            with open(per_case_path, "r", encoding="utf-8") as pf:
                per_case_records = json.load(pf)

            if not isinstance(per_case_records, list) or len(per_case_records) == 0:
                errors.append("Layer D Validator Integrity Error: Per-case run records file is empty or malformed")
            else:
                combined_records = [r for r in per_case_records if isinstance(r, dict) and r.get("baseline") == "Combined Gating"]
                if sample_count > 0 and len(combined_records) != sample_count:
                    errors.append(f"Layer D Integrity Mismatch: Run-level Combined Gating record count ({len(combined_records)}) does not match reported sample size ({sample_count})")
                else:
                    # Bind records to evaluation dataset digest
                    bound_digests = {r.get("dataset_sha256_digest") for r in combined_records if r.get("dataset_sha256_digest")}
                    if bound_digests and expected_baseline_digest not in bound_digests:
                        errors.append(f"Layer D Dataset Binding Failure: Run records bound to dataset digest {list(bound_digests)} rather than expected baseline digest {expected_baseline_digest}")

                    invalid_classes = [r.get("classification") for r in combined_records if r.get("classification") not in VALID_CLASSIFICATIONS]
                    if invalid_classes:
                        errors.append(f"Layer D Run Record Error: Invalid classification codes detected in run records: {invalid_classes[:5]}")

                    tc = sum(1 for r in combined_records if r.get("classification") == "TC")
                    fc = sum(1 for r in combined_records if r.get("classification") == "FC")
                    tr = sum(1 for r in combined_records if r.get("classification") == "TR")
                    fr = sum(1 for r in combined_records if r.get("classification") == "FR")

                    total_classified = tc + fc + tr + fr
                    if total_classified != len(combined_records):
                        errors.append(f"Layer D Classification Count Mismatch: Sum of classifications ({total_classified}) does not match record count ({len(combined_records)})")

                    # Denominator checks
                    adv_total = tr + fc
                    ben_total = tc + fr

                    if adv_total == 0:
                        errors.append("Layer D Zero Denominator: Adversarial case count (tr + fc) is 0")
                    if ben_total == 0:
                        errors.append("Layer D Zero Denominator: Benign case count (tc + fr) is 0")

                    recomputed_acc = (tc + tr) / len(combined_records) * 100.0 if len(combined_records) > 0 else 0.0
                    recomputed_recall = (tr / adv_total * 100.0) if adv_total > 0 else 0.0
                    recomputed_fpr = (fr / ben_total * 100.0) if ben_total > 0 else 0.0

                    if reported_acc is not None and abs(reported_acc - recomputed_acc) > 0.01:
                        errors.append(f"Layer D Metric Forgery Detected: Reported accuracy ({reported_acc}%) mismatches independently recomputed value ({recomputed_acc:.2f}%)")
                    if reported_recall is not None and abs(reported_recall - recomputed_recall) > 0.01:
                        errors.append(f"Layer D Metric Forgery Detected: Reported recall ({reported_recall}%) mismatches independently recomputed value ({recomputed_recall:.2f}%)")
                    if reported_fpr is not None and abs(reported_fpr - recomputed_fpr) > 0.01:
                        errors.append(f"Layer D Metric Forgery Detected: Reported FPR ({reported_fpr}%) mismatches independently recomputed value ({recomputed_fpr:.2f}%)")
        except Exception as pfe:
            errors.append(f"Layer D Validator Integrity Error: Failed to independently verify run records: {pfe}")

    if reported_recall is None or reported_recall < 100.0:
        errors.append(f"Layer D Metric Regression: Combined Gating security recall dropped to {reported_recall}% (Baseline: 100.0%)")

    if reported_fpr is None or reported_fpr > 0.0:
        errors.append(f"Layer D Metric Regression: Benign False Positive Rate increased to {reported_fpr}% (Baseline: 0.0%)")

    reported_violations = layer_d.get("violations", [])
    if reported_violations and layer_d_status == "PASS":
        errors.append(f"Layer D Integrity Failure: Reported PASS despite mandatory criteria violations: {reported_violations}")

    # 5. Overall Status Consistency & Release Policy Check
    imperfect_layers = [
        name for name, ldata in layers.items()
        if (ldata.get("status") or ldata.get("overall_status")) != "PASS"
    ]

    if overall_status == "PASS" and imperfect_layers:
        errors.append(f"Overall status 'PASS' cannot coexist with imperfect required layers: {imperfect_layers}")

    if require_full_pass and overall_status != "PASS":
        errors.append(f"Release Workflow Policy Failure: overall_evaluation_status is '{overall_status}', require_full_pass=True.")

    return len(errors) == 0, errors


def main():
    parser = argparse.ArgumentParser(description="Validate EpistemicOS Four-Layer Evidence Artifact")
    parser.add_argument("--artifact", default="results/four_layer_evidence.json", help="Path to evidence artifact")
    parser.add_argument("--manifest", default="benchmarks/data/dataset_manifest.json", help="Path to dataset manifest")
    parser.add_argument("--require-full-pass", action="store_true", help="Enforce overall PASS status (e.g. for release workflows)")
    parser.add_argument("--allow-local-constant-fallback", action="store_true", help="Opt-in fallback to local constant when base branch ref is missing (non-CI local testing)")
    args = parser.parse_args()

    valid, errors = validate_evidence_artifact(
        args.artifact,
        manifest_path=args.manifest,
        require_full_pass=args.require_full_pass,
        allow_local_constant_fallback=args.allow_local_constant_fallback
    )

    if valid:
        print(f"[SUCCESS] Evidence artifact '{args.artifact}' passed all security invariant, SHA-256 digest, and schema checks!")
        sys.exit(0)
    else:
        print(f"[FATAL ERROR] Evidence artifact '{args.artifact}' failed validation:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
