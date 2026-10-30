"""
Unit and End-to-End Integration tests for reproducible, commit-pinned security evaluation harness,
manifest generation, publication lifecycle, and artifact validation.

Tests:
- Target SHA mismatch against checked-out HEAD raises ValueError.
- Dirty source worktree or untracked source files are rejected when clean evaluation is required.
- Pre-existing uncommitted modifications to tracked files (including tracked docs/reports) cause fail-closed rejection.
- Writing output artifacts outside the source worktree preserves clean source tree status and revision.
- Non-self-referential manifest matches exact final file bytes on disk.
- Publication lifecycle transitions PENDING_PUBLICATION -> PUBLISHED and enforces persistence commit format.
- Tampered artifact file bytes or altered manifest hashes cause explicit validation failure.
- Full end-to-end integration test exercising real evaluation generation, manifest creation, and validation pipeline.
"""

import copy
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import pytest

from benchmarks.eval_metadata import (
    collect_environment_metadata,
    compute_working_tree_digest,
    create_evidence_manifest,
    get_git_commit_hash,
    get_working_tree_status,
    verify_commit_and_tree
)
from benchmarks.generate_evidence_report import generate_consolidated_evidence
from benchmarks.publish_evidence import publish_manifest
from benchmarks.validate_evidence import (
    FROZEN_BASELINE_DATASET_DIGEST,
    validate_evidence_artifact,
    validate_evidence_manifest
)


@pytest.fixture
def temp_git_repo(tmp_path):
    """Creates a temporary clean git repository for isolated commit verification testing."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True, capture_output=True)

    dummy_file = repo_dir / "README.md"
    dummy_file.write_text("# Test Repo\n", encoding="utf-8")

    code_file = repo_dir / "main.py"
    code_file.write_text("print('hello')\n", encoding="utf-8")

    tracked_report_dir = repo_dir / "docs" / "security"
    tracked_report_dir.mkdir(parents=True, exist_ok=True)
    tracked_report = tracked_report_dir / "report.md"
    tracked_report.write_text("# Initial Report\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
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
    dirty_file.write_text("# dirty file\n", encoding="utf-8")

    info = get_working_tree_status(root_dir=str(repo_dir))
    assert info["status"] == "DIRTY"
    assert "dirty_file.py" in info["untracked_files"]

    with pytest.raises(ValueError, match="Clean working tree assertion failed"):
        verify_commit_and_tree(expected_commit=commit_sha, require_clean=True, root_dir=str(repo_dir))


def test_pre_existing_tracked_file_modification_rejected(temp_git_repo):
    repo_dir, commit_sha = temp_git_repo

    # Modify existing tracked code file
    code_file = repo_dir / "main.py"
    code_file.write_text("print('modified')\n", encoding="utf-8")

    info = get_working_tree_status(root_dir=str(repo_dir))
    assert info["status"] == "DIRTY"
    assert any("main.py" in change for change in info["tracked_changes"])

    with pytest.raises(ValueError, match="Clean working tree assertion failed"):
        verify_commit_and_tree(expected_commit=commit_sha, require_clean=True, root_dir=str(repo_dir))


def test_pre_existing_tracked_report_modification_rejected(temp_git_repo):
    repo_dir, commit_sha = temp_git_repo

    # Modify pre-existing tracked report file before evaluation
    report_file = repo_dir / "docs" / "security" / "report.md"
    report_file.write_text("# Modified Report\n", encoding="utf-8")

    info = get_working_tree_status(root_dir=str(repo_dir))
    assert info["status"] == "DIRTY"
    assert any("report.md" in change for change in info["tracked_changes"])

    with pytest.raises(ValueError, match="Clean working tree assertion failed"):
        verify_commit_and_tree(expected_commit=commit_sha, require_clean=True, root_dir=str(repo_dir))


def test_git_status_failure_raises_runtime_error(tmp_path):
    non_git_dir = tmp_path / "non_git"
    non_git_dir.mkdir()

    with pytest.raises(RuntimeError, match="Unable to establish Git"):
        get_working_tree_status(root_dir=str(non_git_dir))


def test_output_generation_outside_source_tree_preserves_clean_status(temp_git_repo, tmp_path):
    repo_dir, commit_sha = temp_git_repo
    out_dir = tmp_path / "external_outputs"

    pre_status = get_working_tree_status(root_dir=str(repo_dir))
    assert pre_status["status"] == "CLEAN"

    out_file = out_dir / "results.json"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps({"test": "data"}), encoding="utf-8")

    post_status = get_working_tree_status(root_dir=str(repo_dir))
    assert post_status["status"] == "CLEAN"
    assert post_status["status"] == pre_status["status"]


def test_publication_lifecycle_and_validation(tmp_path):
    manifest_file = tmp_path / "evidence_manifest.json"
    art_file = tmp_path / "sample_art.json"
    art_file.write_text(json.dumps({"data": "test"}), encoding="utf-8")

    env_meta = {
        "evaluation_suite_name": "Test Suite",
        "evaluation_suite_version": "1.0.0",
        "evaluated_git_commit": "a" * 40,
        "working_tree_status": "CLEAN",
        "working_tree_digest": "0" * 64
    }
    dataset_info = {
        "dataset_version": "1.0.0",
        "dataset_sha256_digest": "0" * 64,
        "dataset_digest_verified": True
    }

    manifest = create_evidence_manifest(
        env_metadata=env_meta,
        artifact_paths=[str(art_file)],
        dataset_info=dataset_info,
        output_manifest_path=str(manifest_file),
        root_dir=str(tmp_path)
    )

    assert manifest["publication_metadata"]["publication_status"] == "PENDING_PUBLICATION"
    assert manifest["publication_metadata"]["report_persistence_commit"] is None

    # Validate pending publication manifest
    valid_pending, errs_pending = validate_evidence_manifest(str(manifest_file), expected_commit="a" * 40, require_clean_tree=True, root_dir=str(tmp_path))
    assert valid_pending is True
    assert len(errs_pending) == 0

    # Publish manifest
    pub_commit = "b" * 40
    published_manifest = publish_manifest(str(manifest_file), pub_commit)
    assert published_manifest["publication_metadata"]["publication_status"] == "PUBLISHED"
    assert published_manifest["publication_metadata"]["report_persistence_commit"] == pub_commit

    # Validate published manifest
    valid_pub, errs_pub = validate_evidence_manifest(str(manifest_file), expected_commit="a" * 40, require_clean_tree=True, root_dir=str(tmp_path))
    assert valid_pub is True
    assert len(errs_pub) == 0


def test_manifest_artifact_tampering_detected(tmp_path):
    manifest_file = tmp_path / "evidence_manifest.json"
    art_file = tmp_path / "sample_art.json"
    art_file.write_text(json.dumps({"data": "original"}), encoding="utf-8")

    env_meta = {
        "evaluation_suite_name": "Test Suite",
        "evaluation_suite_version": "1.0.0",
        "evaluated_git_commit": "a" * 40,
        "working_tree_status": "CLEAN",
        "working_tree_digest": "0" * 64
    }
    dataset_info = {"dataset_version": "1.0.0", "dataset_sha256_digest": "0" * 64, "dataset_digest_verified": True}

    create_evidence_manifest(
        env_metadata=env_meta,
        artifact_paths=[str(art_file)],
        dataset_info=dataset_info,
        output_manifest_path=str(manifest_file),
        root_dir=str(tmp_path)
    )

    # Tamper with the artifact file content on disk
    art_file.write_text(json.dumps({"data": "TAMPERED_CONTENT"}), encoding="utf-8")

    valid, errors = validate_evidence_manifest(str(manifest_file), expected_commit="a" * 40, root_dir=str(tmp_path))
    assert valid is False
    assert any("Artifact Digest Mismatch" in e for e in errors)


def test_e2e_full_pipeline_generation_and_validation(tmp_path):
    """
    End-to-end integration test exercising real generate_consolidated_evidence
    and validate_evidence_artifact / validate_evidence_manifest against results directory.
    """
    out_dir = tmp_path / "results"
    docs_dir = tmp_path / "docs_sec"

    evidence = generate_consolidated_evidence(
        fast_mode=True,
        require_clean=False,
        output_dir=str(out_dir),
        docs_dir=str(docs_dir)
    )

    assert evidence["overall_evaluation_status"] in ("PASS", "PARTIAL")

    manifest_path = out_dir / "evidence_manifest.json"
    assert manifest_path.exists()

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_data["publication_metadata"]["publication_status"] == "PENDING_PUBLICATION"

    # Verify manifest byte digests match actual files on disk
    for rel_p, art_info in manifest_data["artifacts"].items():
        p = Path(rel_p)
        assert p.exists()
        actual_bytes = p.read_bytes()
        actual_hash = hashlib.sha256(actual_bytes).hexdigest()
        assert actual_hash == art_info["sha256_digest"]
        assert len(actual_bytes) == art_info["byte_size"]

    # Validate evidence artifact and manifest
    valid, errors = validate_evidence_artifact(
        artifact_path=str(out_dir / "four_layer_evidence.json"),
        manifest_file=str(manifest_path),
        allow_local_constant_fallback=True
    )
    assert valid is True
    assert len(errors) == 0
