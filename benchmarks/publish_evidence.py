"""
Publication Lifecycle Manager for EpistemicOS Security Evidence Manifests.

Transitions evidence manifest publication state from 'PENDING_PUBLICATION' to 'PUBLISHED'
and binds the exact report persistence Git commit SHA.
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

SHA1_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")


def publish_manifest(manifest_path: str, persistence_commit: str) -> dict:
    p = Path(manifest_path)
    if not p.exists():
        raise FileNotFoundError(f"Manifest file missing at path: {manifest_path}")

    data = json.loads(p.read_text(encoding="utf-8"))
    commit_sha = persistence_commit.strip()

    if not SHA1_REGEX.match(commit_sha):
        raise ValueError(f"Invalid 40-character persistence commit SHA: '{commit_sha}'")

    pub_meta = data.setdefault("publication_metadata", {})
    pub_meta["publication_status"] = "PUBLISHED"
    pub_meta["report_persistence_commit"] = commit_sha
    pub_meta["published_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def main():
    parser = argparse.ArgumentParser(description="Publish EpistemicOS Security Evidence Manifest")
    parser.add_argument("--manifest", default="results/evidence_manifest.json", help="Path to evidence manifest file")
    parser.add_argument("--persistence-commit", required=True, help="Full 40-character Git commit SHA storing the published report")
    args = parser.parse_args()

    try:
        updated = publish_manifest(args.manifest, args.persistence_commit)
        print(f"[PUBLISHED] Updated evidence manifest '{args.manifest}':")
        print(f"  - Status: {updated['publication_metadata']['publication_status']}")
        print(f"  - Persistence Commit: {updated['publication_metadata']['report_persistence_commit']}")
        print(f"  - Published At: {updated['publication_metadata']['published_at_utc']}")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Failed to publish manifest: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
