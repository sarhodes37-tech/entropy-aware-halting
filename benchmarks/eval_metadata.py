"""
Evaluation Metadata & Commit Verification Module for EpistemicOS.

Provides unified commit verification, working-tree status checking,
environmental provenance metadata capture, and non-self-referential
evidence manifest creation for security benchmark runners.
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Untracked output/test prefixes and files ignored during source tree cleanliness checks
IGNORED_UNTRACKED_PREFIXES = ("logs/", "tmp/", ".git/", "__pycache__", ".pytest_cache", "results/")
IGNORED_UNTRACKED_FILES = ("coverage.xml", ".coverage")


def get_git_commit_hash(root_dir: Optional[str] = None) -> str:
    cwd = root_dir or PROJECT_ROOT
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=cwd
        )
        return res.stdout.strip()
    except Exception as e:
        raise RuntimeError(f"Unable to establish Git commit hash: {e}") from e


def get_working_tree_status(root_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Inspects source working tree status via `git status --porcelain=v1 -uall`.
    Any pre-existing modification to tracked files in Git (M, D, R, etc.) causes dirty status.
    Untracked files inside transient runtime/test directories are excluded.
    Returns dict with overall status ('CLEAN' / 'DIRTY'), list of tracked changes,
    and list of untracked files.
    """
    cwd = root_dir or PROJECT_ROOT

    try:
        res = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            capture_output=True,
            text=True,
            check=True,
            cwd=cwd
        )
        lines = [line.rstrip("\r\n") for line in res.stdout.split("\n") if line.strip()]
    except Exception as e:
        raise RuntimeError(f"Unable to establish Git working-tree status: {e}") from e

    tracked_changes = []
    untracked_files = []

    for line in lines:
        if len(line) < 4:
            continue
        status_code = line[:2]
        rel_path_str = line[3:].strip()

        if " -> " in rel_path_str:
            rel_path_str = rel_path_str.split(" -> ")[-1].strip()

        if rel_path_str.startswith('"') and rel_path_str.endswith('"'):
            rel_path_str = rel_path_str[1:-1]

        norm_path = Path(rel_path_str).as_posix()

        if status_code == "??" or status_code.strip() == "A":
            if any(norm_path.startswith(prefix) or f"/{prefix}" in norm_path for prefix in IGNORED_UNTRACKED_PREFIXES):
                continue
            if norm_path in IGNORED_UNTRACKED_FILES:
                continue
            untracked_files.append(norm_path)
        else:
            # ANY modification, deletion, or rename on ANY tracked file makes the source working tree dirty!
            tracked_changes.append(f"{status_code} {norm_path}")

    is_dirty = len(tracked_changes) > 0 or len(untracked_files) > 0
    return {
        "status": "DIRTY" if is_dirty else "CLEAN",
        "tracked_changes": tracked_changes,
        "untracked_files": untracked_files
    }


def compute_working_tree_digest(root_dir: Optional[str] = None) -> str:
    """
    Computes a full 64-character SHA-256 digest covering all relevant tracked and untracked source inputs.
    """
    base = Path(root_dir) if root_dir else Path(PROJECT_ROOT)
    hasher = hashlib.sha256()

    commit_sha = get_git_commit_hash(str(base))
    hasher.update(f"COMMIT:{commit_sha}\n".encode("utf-8"))

    try:
        res = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            capture_output=True,
            text=True,
            check=True,
            cwd=str(base)
        )
        lines = [line.rstrip("\r\n") for line in res.stdout.split("\n") if line.strip()]
    except Exception as e:
        raise RuntimeError(f"Unable to compute Git working-tree digest: {e}") from e

    inventory: List[Tuple[str, str, Path]] = []
    for line in lines:
        if len(line) < 4:
            continue
        status_code = line[:2]
        rel_path_str = line[3:].strip()

        if " -> " in rel_path_str:
            rel_path_str = rel_path_str.split(" -> ")[-1].strip()

        if rel_path_str.startswith('"') and rel_path_str.endswith('"'):
            rel_path_str = rel_path_str[1:-1]

        norm_path = Path(rel_path_str).as_posix()

        if status_code == "??" or status_code.strip() == "A":
            if any(norm_path.startswith(prefix) or f"/{prefix}" in norm_path for prefix in IGNORED_UNTRACKED_PREFIXES):
                continue
            if norm_path in IGNORED_UNTRACKED_FILES:
                continue

        full_path = base / rel_path_str
        inventory.append((norm_path, status_code, full_path))

    inventory.sort(key=lambda x: x[0])

    for norm_path, status_code, full_path in inventory:
        hasher.update(f"PATH:{norm_path}:STATUS:{status_code}\n".encode("utf-8"))

        if full_path.is_symlink():
            try:
                target = os.readlink(full_path)
                hasher.update(f"SYMLINK:{target}\n".encode("utf-8"))
            except Exception:
                hasher.update(b"SYMLINK_ERROR\n")
        elif not full_path.exists():
            hasher.update(b"STATUS:DELETED\n")
        elif full_path.is_dir():
            try:
                sub_res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=str(full_path))
                sub_sha = sub_res.stdout.strip()
                hasher.update(f"SUBMODULE:{sub_sha}\n".encode("utf-8"))
            except Exception:
                hasher.update(b"DIRECTORY\n")
        elif full_path.is_file():
            try:
                content = full_path.read_bytes()
                hasher.update(f"SIZE:{len(content)}\n".encode("utf-8"))
                hasher.update(content)
                hasher.update(b"\n")
            except Exception:
                hasher.update(b"READ_ERROR\n")

    return hasher.hexdigest()


def get_lockfile_digest(root_dir: Optional[str] = None) -> str:
    base = Path(root_dir or PROJECT_ROOT)
    for lfile in ["requirements-full-lock.txt", "requirements-test-lock.txt", "requirements.txt"]:
        lp = base / lfile
        if lp.exists():
            try:
                return hashlib.sha256(lp.read_bytes()).hexdigest()
            except Exception:
                pass
    return "UNKNOWN_LOCKFILE_DIGEST"


def verify_commit_and_tree(
    expected_commit: Optional[str] = None,
    require_clean: bool = False,
    root_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verifies that checked-out HEAD matches expected_commit (if supplied)
    and checks working tree status. Fails closed (raises ValueError) on mismatch
    or if require_clean=True and working tree is DIRTY.
    """
    cwd = root_dir or PROJECT_ROOT
    current_head = get_git_commit_hash(cwd)

    if expected_commit:
        expected_clean = expected_commit.strip()
        try:
            res = subprocess.run(
                ["git", "rev-parse", expected_clean],
                capture_output=True,
                text=True,
                check=True,
                cwd=cwd
            )
            resolved_expected = res.stdout.strip()
        except Exception as e:
            raise ValueError(f"Commit verification failure: Could not resolve requested commit '{expected_commit}': {e}") from e

        if current_head.lower() != resolved_expected.lower():
            raise ValueError(
                f"Commit verification failure: Checked-out HEAD ({current_head}) "
                f"does not match requested commit ({expected_commit} -> {resolved_expected})."
            )

    tree_info = get_working_tree_status(cwd)
    tree_digest = compute_working_tree_digest(cwd)

    if require_clean and tree_info["status"] != "CLEAN":
        tracked_str = ", ".join(tree_info["tracked_changes"][:5])
        untracked_str = ", ".join(tree_info["untracked_files"][:5])
        raise ValueError(
            f"Clean working tree assertion failed! The evaluated source tree contains uncommitted changes. "
            f"Tracked: [{tracked_str}], Untracked: [{untracked_str}]. Refusing to label evaluation reproducible."
        )

    return {
        "evaluated_git_commit": current_head,
        "working_tree_status": tree_info["status"],
        "working_tree_digest": tree_digest,
        "uncommitted_tracked_changes_count": len(tree_info["tracked_changes"]),
        "uncommitted_untracked_files_count": len(tree_info["untracked_files"]),
        "tracked_changes_sample": tree_info["tracked_changes"][:5],
        "untracked_files_sample": tree_info["untracked_files"][:5]
    }


def collect_environment_metadata(
    suite_name: str,
    suite_version: str,
    expected_commit: Optional[str] = None,
    require_clean: bool = False,
    execution_command: Optional[str] = None,
    root_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Collects complete environmental and reproducibility metadata for an evaluation run.
    """
    verification = verify_commit_and_tree(expected_commit=expected_commit, require_clean=require_clean, root_dir=root_dir)
    cmd = execution_command or " ".join(sys.argv)
    is_ci = os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") == "true"
    env_type = "CI" if is_ci else "LOCAL"

    return {
        "evaluation_suite_name": suite_name,
        "evaluation_suite_version": suite_version,
        "evaluated_git_commit": verification["evaluated_git_commit"],
        "working_tree_status": verification["working_tree_status"],
        "working_tree_digest": verification["working_tree_digest"],
        "uncommitted_tracked_changes": verification["uncommitted_tracked_changes_count"],
        "uncommitted_untracked_files": verification["uncommitted_untracked_files_count"],
        "evaluation_command": cmd,
        "python_version": platform.python_version(),
        "operating_system": platform.platform(),
        "execution_environment_type": env_type,
        "lockfile_sha256_digest": get_lockfile_digest(root_dir),
        "start_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


def create_evidence_manifest(
    env_metadata: Dict[str, Any],
    artifact_paths: List[str],
    dataset_info: Dict[str, Any],
    output_manifest_path: str = "results/evidence_manifest.json",
    root_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Computes exact SHA-256 byte digests over generated report artifacts AFTER they are written to disk.
    Outputs a non-self-referential evidence manifest file.
    """
    base = Path(root_dir or PROJECT_ROOT)
    artifacts_digest_map = {}

    for rel_path in artifact_paths:
        full_path = base / rel_path if not Path(rel_path).is_absolute() else Path(rel_path)
        if full_path.exists():
            file_bytes = full_path.read_bytes()
            artifacts_digest_map[Path(rel_path).as_posix()] = {
                "sha256_digest": hashlib.sha256(file_bytes).hexdigest(),
                "byte_size": len(file_bytes)
            }

    manifest = {
        "manifest_version": "1.0.0",
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reproducibility_metadata": env_metadata,
        "dataset_metadata": dataset_info,
        "publication_metadata": {
            "publication_status": "PENDING_PUBLICATION",
            "report_persistence_commit": None,
            "published_at_utc": None
        },
        "artifacts": artifacts_digest_map
    }

    out_p = base / output_manifest_path if not Path(output_manifest_path).is_absolute() else Path(output_manifest_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
