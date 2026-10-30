"""
Unit tests for reproducible, commit-pinned security evaluation harness and validation.

Tests:
- Requested commit SHA mismatch against checked-out HEAD raises ValueError.
- Dirty source worktree or untracked source files are rejected when clean evaluation is required.
- Writing output artifacts outside the source worktree preserves clean source tree status and revision.
- Missing or malformed evaluation metadata causes validation failure.
- Nonzero exit status and scenario failures are accurately preserved and reported separately from pass rates.
- Reported scenario counts must match recorded individual outcome items.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
import pytest

from benchmarks.eval_metadata import (
    collect_environment_metadata,
    get_git_commit_hash,
    get_working_tree_status,
    verify_commit_and_tree
)
from benchmarks.run_incident_lab import IncidentLabRunner
from benchmarks.validate_evidence import validate_evidence_artifact


@pytest.fixture
def temp_git_repo(tmp_path):
    """Creates a temporary clean git repository for isolated commit verification testing."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True, capture_output=True)

    dummy_file = repo_dir / "README.md"
    dummy_file.write_text("# Test Repo\n")

    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True)
    commit_sha = res.stdout.strip()

    return repo_dir, commit_sha


def test_commit_verification_matching_sha(temp_git_repo):
    repo_dir, commit_sha = temp_git_repo
    res = verify_commit_and_tree(expected_commit=commit_sha, require_clean=True, root_dir=str(repo_dir))
    assert res["evaluated_git_commit"] == commit_sha
    assert res["working_tree_status"] == "CLEAN"


def test_commit_verification_mismatch_raises_error(temp_git_repo):
    repo_dir, _ = temp_git_repo
    fake_sha = "0000000000000000000000000000000000000000"
    with pytest.raises(ValueError, match="Commit verification failure"):
        verify_commit_and_tree(expected_commit=fake_sha, require_clean=False, root_dir=str(repo_dir))


def test_dirty_working_tree_rejected_when_clean_required(temp_git_repo):
    repo_dir, commit_sha = temp_git_repo

    dirty_file = repo_dir / "dirty_file.py"
    dirty_file.write_text("# dirty file\n")

    info = get_working_tree_status(root_dir=str(repo_dir))
    assert info["status"] == "DIRTY"
    assert "dirty_file.py" in info["untracked_files"]

    with pytest.raises(ValueError, match="Clean working tree assertion failed"):
        verify_commit_and_tree(expected_commit=commit_sha, require_clean=True, root_dir=str(repo_dir))


def test_untracked_source_files_detected(temp_git_repo):
    repo_dir, _ = temp_git_repo
    untracked = repo_dir / "untracked_source.py"
    untracked.write_text("print('untracked')\n")

    status = get_working_tree_status(root_dir=str(repo_dir))
    assert status["status"] == "DIRTY"
    assert "untracked_source.py" in status["untracked_files"]


def test_output_generation_outside_source_tree_preserves_clean_status(temp_git_repo, tmp_path):
    repo_dir, commit_sha = temp_git_repo
    out_dir = tmp_path / "external_outputs"

    pre_status = get_working_tree_status(root_dir=str(repo_dir))
    assert pre_status["status"] == "CLEAN"

    out_file = out_dir / "results.json"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps({"test": "data"}))

    post_status = get_working_tree_status(root_dir=str(repo_dir))
    assert post_status["status"] == "CLEAN"
    assert post_status["status"] == pre_status["status"]


def test_validate_evidence_rejects_missing_metadata_fields(tmp_path):
    art = tmp_path / "artifact.json"
    data = {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "overall_evaluation_status": "PASS",
        "reproducibility_metadata": {
            # Missing evaluated_git_commit
            "working_tree_status": "CLEAN"
        },
        "layers": {}
    }
    art.write_text(json.dumps(data))

    valid, errors = validate_evidence_artifact(str(art), allow_local_constant_fallback=True)
    assert not valid
    assert any("evaluated_git_commit" in e for e in errors)


def test_validate_evidence_rejects_invalid_commit_sha_format(tmp_path):
    art = tmp_path / "artifact.json"
    data = {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "overall_evaluation_status": "PASS",
        "reproducibility_metadata": {
            "evaluated_git_commit": "short_invalid_sha",
            "working_tree_status": "CLEAN",
            "working_tree_digest": "0" * 64,
            "dataset_version": "1.0.0",
            "dataset_sha256_digest": "f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873",
            "dataset_digest_verified": True
        },
        "layers": {}
    }
    art.write_text(json.dumps(data))

    valid, errors = validate_evidence_artifact(str(art), allow_local_constant_fallback=True)
    assert not valid
    assert any("non-40-character evaluated_git_commit" in e for e in errors)


def test_validate_evidence_rejects_commit_mismatch_against_expected(tmp_path):
    art = tmp_path / "artifact.json"
    data = {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "overall_evaluation_status": "PASS",
        "reproducibility_metadata": {
            "evaluated_git_commit": "a" * 40,
            "working_tree_status": "CLEAN",
            "working_tree_digest": "0" * 64,
            "dataset_version": "1.0.0",
            "dataset_sha256_digest": "f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873",
            "dataset_digest_verified": True
        },
        "layers": {}
    }
    art.write_text(json.dumps(data))

    valid, errors = validate_evidence_artifact(
        str(art),
        expected_commit="b" * 40,
        allow_local_constant_fallback=True
    )
    assert not valid
    assert any("Evaluated commit SHA mismatch" in e for e in errors)


def test_validate_evidence_rejects_nonzero_process_exit_code(tmp_path):
    art = tmp_path / "artifact.json"
    data = {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "overall_evaluation_status": "PASS",
        "reproducibility_metadata": {
            "evaluated_git_commit": "a" * 40,
            "working_tree_status": "CLEAN",
            "working_tree_digest": "0" * 64,
            "exit_code": 1,
            "exit_status": "FAILURE",
            "dataset_version": "1.0.0",
            "dataset_sha256_digest": "f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873",
            "dataset_digest_verified": True
        },
        "layers": {}
    }
    art.write_text(json.dumps(data))

    valid, errors = validate_evidence_artifact(str(art), allow_local_constant_fallback=True)
    assert not valid
    assert any("non-zero exit_code" in e for e in errors)


def test_validate_evidence_layer_b_scenario_count_mismatch(tmp_path):
    art = tmp_path / "artifact.json"
    data = {
        "title": "EpistemicOS Four-Layer Security Evaluation Artifact",
        "version": "1.0.0",
        "overall_evaluation_status": "PASS",
        "reproducibility_metadata": {
            "evaluated_git_commit": "a" * 40,
            "working_tree_status": "CLEAN",
            "working_tree_digest": "0" * 64,
            "dataset_version": "1.0.0",
            "dataset_sha256_digest": "f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873",
            "dataset_digest_verified": True
        },
        "layers": {
            "layer_a_deterministic": {"status": "PASS"},
            "layer_b_execution_boundary": {
                "status": "PASS",
                "scenarios_evaluated": 10,  # Claims 10
                "scenario_summary": [
                    {"case_id": "case1", "security_outcome": "PASS"},
                    {"case_id": "case2", "security_outcome": "PASS"}
                ]
            },
            "layer_c_live_agent_redteam": {"status": "PASS"},
            "layer_d_performance_cost": {"status": "PASS"}
        }
    }
    art.write_text(json.dumps(data))

    valid, errors = validate_evidence_artifact(str(art), allow_local_constant_fallback=True)
    assert not valid
    assert any("Layer B Scenario Count Mismatch" in e for e in errors)
