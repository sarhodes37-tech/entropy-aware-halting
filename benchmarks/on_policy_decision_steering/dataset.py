"""Dataset loading, validation, and cryptographic digest manifest verification."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from benchmarks.on_policy_decision_steering.models import Candidate, DatasetManifest, Scenario


def compute_dataset_digest(file_path: str) -> str:
    """Compute SHA-256 digest over the exact byte contents of a dataset file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_scenarios(file_path: str, partition: Optional[str] = None) -> List[Scenario]:
    """
    Load and validate scenarios from JSON dataset file.

    Args:
        file_path: Path to dataset JSON file.
        partition: Optional partition filter ("dev" or "held_out").

    Returns:
        List of validated Scenario objects.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_scenarios = data.get("scenarios", [])
    scenarios: List[Scenario] = []
    seen_scenario_ids = set()

    for item in raw_scenarios:
        scenario = Scenario.from_dict(item)

        # Validation checks
        if scenario.scenario_id in seen_scenario_ids:
            raise ValueError(f"Duplicate scenario ID found in dataset: {scenario.scenario_id}")
        seen_scenario_ids.add(scenario.scenario_id)

        if not scenario.candidates:
            raise ValueError(f"Scenario {scenario.scenario_id} has no candidate options.")

        # Candidate ID uniqueness check within scenario
        candidate_ids = [c.candidate_id for c in scenario.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError(f"Scenario {scenario.scenario_id} contains duplicate candidate IDs.")

        if scenario.partition not in ("dev", "held_out"):
            raise ValueError(f"Scenario {scenario.scenario_id} has invalid partition: {scenario.partition}")

        # Filter by partition if requested
        if partition is not None:
            if partition not in ("dev", "held_out"):
                raise ValueError(f"Invalid partition filter: {partition}. Must be 'dev' or 'held_out'.")
            if scenario.partition != partition:
                continue

        scenarios.append(scenario)

    return scenarios


def generate_manifest(file_path: str, dataset_version: str = "v1.0.0-smoke") -> DatasetManifest:
    """Generate DatasetManifest for a dataset file."""
    digest = compute_dataset_digest(file_path)
    all_scenarios = load_scenarios(file_path, partition=None)
    dev_count = len([s for s in all_scenarios if s.partition == "dev"])
    held_out_count = len([s for s in all_scenarios if s.partition == "held_out"])

    return DatasetManifest(
        dataset_version=dataset_version,
        dataset_path=str(file_path),
        sha256_digest=digest,
        total_scenarios=len(all_scenarios),
        dev_scenarios=dev_count,
        held_out_scenarios=held_out_count,
    )


def verify_dataset_manifest(file_path: str, expected_manifest: DatasetManifest) -> bool:
    """
    Verify a dataset file against an expected manifest.
    Checks SHA-256 digest match and scenario counts.
    """
    actual_manifest = generate_manifest(file_path, dataset_version=expected_manifest.dataset_version)
    if actual_manifest.sha256_digest != expected_manifest.sha256_digest:
        return False
    if actual_manifest.total_scenarios != expected_manifest.total_scenarios:
        return False
    if actual_manifest.dev_scenarios != expected_manifest.dev_scenarios:
        return False
    if actual_manifest.held_out_scenarios != expected_manifest.held_out_scenarios:
        return False
    return True
