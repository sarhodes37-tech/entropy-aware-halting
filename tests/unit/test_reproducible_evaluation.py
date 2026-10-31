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
import sys
import tempfile
from pathlib import Path
import pytest

from benchmarks.eval_metadata import (
    PROJECT_ROOT,
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


@pytest.fixture
def full_cloned_repo(tmp_path):
    """Clones the current working repository into an isolated temporary folder for E2E CLI tests."""
    import shutil
    repo_dir = tmp_path / "full_repo"
    subprocess.run(["git", "clone", PROJECT_ROOT, str(repo_dir)], check=True, capture_output=True)

    # Sync uncommitted working tree files into cloned repo
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "tmp", "results", "logs", ".pytest_cache", ".venv", "env")]
        rel_dir = os.path.relpath(root, PROJECT_ROOT)
        target_dir = repo_dir / rel_dir if rel_dir != "." else repo_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        for f in files:
            if f in ("coverage.xml", ".coverage"):
                continue
            shutil.copy2(os.path.join(root, f), target_dir / f)

    # Copy pre-existing benchmark artifacts if present to support fast_mode tests
    target_res = repo_dir / "results"
    target_res.mkdir(parents=True, exist_ok=True)
    src_res = Path(PROJECT_ROOT) / "results"
    if src_res.exists():
        for fname in ("ablation_table.json", "per_case_results.json", "incident_lab_results.json"):
            s_file = src_res / fname
            if s_file.exists():
                shutil.copy2(s_file, target_res / fname)

    subprocess.run(["git", "config", "user.name", "CI User"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "ci@example.com"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "--allow-empty", "-m", "Test worktree sync"], cwd=repo_dir, check=True, capture_output=True)

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

    # Create and track an EVIDENCE_OUTPUT_FILE
    report_file = repo_dir / "docs" / "security" / "four_layer_evidence_report.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text("# Tracked Initial Report\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Track report"], cwd=repo_dir, check=True, capture_output=True)

    new_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True).stdout.strip()

    # Pre-existing modification to tracked report file BEFORE evaluation starts
    report_file.write_text("# Pre-existing Modification\n", encoding="utf-8")

    # With allow_output_files=False (pre-run check), this MUST fail as dirty
    info = get_working_tree_status(root_dir=str(repo_dir), allow_output_files=False)
    assert info["status"] == "DIRTY"
    assert any("four_layer_evidence_report.md" in change for change in info["tracked_changes"])

    with pytest.raises(ValueError, match="Clean working tree assertion failed"):
        verify_commit_and_tree(expected_commit=new_sha, require_clean=True, root_dir=str(repo_dir), allow_output_files=False)


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

    # Create all required mandatory files
    files = []
    from benchmarks.validate_evidence import MANDATORY_MANIFEST_ARTIFACTS
    for rel_p in MANDATORY_MANIFEST_ARTIFACTS:
        fp = tmp_path / rel_p
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(json.dumps({"content": rel_p}), encoding="utf-8")
        files.append(rel_p)

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
        artifact_paths=files,
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


def test_manifest_generation_fails_closed_when_mandatory_artifact_missing(tmp_path):
    manifest_file = tmp_path / "evidence_manifest.json"
    env_meta = {
        "evaluation_suite_name": "Test Suite",
        "evaluation_suite_version": "1.0.0",
        "evaluated_git_commit": "a" * 40,
        "working_tree_status": "CLEAN",
        "working_tree_digest": "0" * 64
    }
    dataset_info = {"dataset_version": "1.0.0", "dataset_sha256_digest": "0" * 64, "dataset_digest_verified": True}

    # Attempt to create manifest pointing to non-existent artifact file
    missing_art = str(tmp_path / "missing_report.json")
    with pytest.raises(FileNotFoundError, match="Mandatory evidence artifact missing on disk"):
        create_evidence_manifest(
            env_metadata=env_meta,
            artifact_paths=[missing_art],
            dataset_info=dataset_info,
            output_manifest_path=str(manifest_file),
            root_dir=str(tmp_path)
        )


def test_manifest_validation_enforces_mandatory_artifact_set(tmp_path):
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
    dataset_info = {"dataset_version": "1.0.0", "dataset_sha256_digest": "0" * 64, "dataset_digest_verified": True}

    # Manually write manifest lacking mandatory artifacts
    manifest_data = {
        "manifest_version": "1.0.0",
        "created_at_utc": "2026-10-30T00:00:00Z",
        "reproducibility_metadata": env_meta,
        "dataset_metadata": dataset_info,
        "publication_metadata": {
            "publication_status": "PENDING_PUBLICATION",
            "report_persistence_commit": None,
            "published_at_utc": None
        },
        "artifacts": {
            str(art_file): {
                "sha256_digest": hashlib.sha256(art_file.read_bytes()).hexdigest(),
                "byte_size": len(art_file.read_bytes())
            }
        }
    }
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    valid, errors = validate_evidence_manifest(str(manifest_file), expected_commit="a" * 40, root_dir=str(tmp_path))
    assert valid is False
    assert any("Missing required evidence artifact declarations" in e for e in errors)


def test_manifest_artifact_tampering_detected(tmp_path):
    manifest_file = tmp_path / "evidence_manifest.json"

    # Create mock required files
    files = {}
    from benchmarks.validate_evidence import MANDATORY_MANIFEST_ARTIFACTS
    for rel_p in MANDATORY_MANIFEST_ARTIFACTS:
        fp = tmp_path / rel_p
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(json.dumps({"content": rel_p}), encoding="utf-8")
        files[rel_p] = fp

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
        artifact_paths=list(files.keys()),
        dataset_info=dataset_info,
        output_manifest_path=str(manifest_file),
        root_dir=str(tmp_path)
    )

    # Tamper with one artifact file content on disk
    first_key = list(files.keys())[0]
    files[first_key].write_text(json.dumps({"data": "TAMPERED_CONTENT"}), encoding="utf-8")

    valid, errors = validate_evidence_manifest(str(manifest_file), expected_commit="a" * 40, root_dir=str(tmp_path))
    assert valid is False
    assert any("Artifact Digest Mismatch" in e for e in errors)


def test_subprocess_cli_integration_evaluation_and_validation(full_cloned_repo, tmp_path):
    """
    Subprocess-level CLI integration test covering commit pinning, clean-tree enforcement,
    report generation, and manifest validation end-to-end.
    """
    repo_dir, commit_sha = full_cloned_repo

    # 1. Run generate_evidence_report via subprocess with --commit and --require-clean
    gen_cmd = [
        sys.executable, "-m", "benchmarks.generate_evidence_report",
        "--fast",
        "--commit", commit_sha,
        "--require-clean",
        "--output-dir", "results",
        "--docs-dir", "docs/security"
    ]
    env = os.environ.copy()
    site_pkgs = os.popen("python -c 'import site; print(site.getsitepackages()[0])'").read().strip()
    env["PYTHONPATH"] = f"{repo_dir}{os.pathsep}{PROJECT_ROOT}{os.pathsep}{site_pkgs}"

    res_gen = subprocess.run(gen_cmd, cwd=repo_dir, capture_output=True, text=True, env=env)
    assert res_gen.returncode == 0, f"Report generation CLI failed!\nSTDOUT: {res_gen.stdout}\nSTDERR: {res_gen.stderr}"

    manifest_p = repo_dir / "results" / "evidence_manifest.json"
    evidence_p = repo_dir / "results" / "four_layer_evidence.json"
    assert manifest_p.exists()
    assert evidence_p.exists()

    # 2. Run validate_evidence via subprocess with --manifest-file and --require-clean-tree
    val_cmd = [
        sys.executable, "-m", "benchmarks.validate_evidence",
        "--artifact", str(evidence_p),
        "--manifest-file", str(manifest_p),
        "--expected-commit", commit_sha,
        "--require-clean-tree",
        "--allow-local-constant-fallback"
    ]
    res_val = subprocess.run(val_cmd, cwd=repo_dir, capture_output=True, text=True, env=env)
    assert res_val.returncode == 0, f"Validator CLI failed!\nSTDOUT: {res_val.stdout}\nSTDERR: {res_val.stderr}"


def test_e2e_full_pipeline_generation_and_validation(full_cloned_repo, tmp_path):
    """
    End-to-end integration test exercising real generate_consolidated_evidence
    and validate_evidence_artifact / validate_evidence_manifest against results directory in a clean repo.
    """
    repo_dir, commit_sha = full_cloned_repo
    out_dir = repo_dir / "results"
    docs_dir = repo_dir / "docs" / "security"

    orig_cwd = os.getcwd()
    os.chdir(repo_dir)
    try:
        evidence = generate_consolidated_evidence(
            fast_mode=True,
            expected_commit=commit_sha,
            require_clean=True,
            output_dir="results",
            docs_dir="docs/security"
        )

        assert evidence["overall_evaluation_status"] in ("PASS", "PARTIAL")

        manifest_path = out_dir / "evidence_manifest.json"
        assert manifest_path.exists()

        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest_data["publication_metadata"]["publication_status"] == "PENDING_PUBLICATION"

        # Verify manifest byte digests match actual files on disk
        for rel_p, art_info in manifest_data["artifacts"].items():
            p = repo_dir / rel_p
            assert p.exists()
            actual_bytes = p.read_bytes()
            actual_hash = hashlib.sha256(actual_bytes).hexdigest()
            assert actual_hash == art_info["sha256_digest"]
            assert len(actual_bytes) == art_info["byte_size"]

        # Validate evidence artifact and manifest
        valid, errors = validate_evidence_artifact(
            artifact_path=str(out_dir / "four_layer_evidence.json"),
            manifest_file=str(manifest_path),
            expected_commit=commit_sha,
            require_clean_tree=True,
            allow_local_constant_fallback=True,
            per_case_filepath=str(out_dir / "per_case_results.json")
        )
        assert valid is True, f"Validation failed with errors: {errors}"
        assert len(errors) == 0
    finally:
        os.chdir(orig_cwd)
