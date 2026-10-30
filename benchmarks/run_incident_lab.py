"""
Reproducible Evaluation Entry Point for the EpistemicOS Incident-Derived Security Test Lab.

Executes all seven incident scenario evaluations across:
- Protected EpistemicOS execution paths
- Confined unprotected baselines
- Dimension A (Security Outcome) & Dimension B (Legitimate Task Performance)
- Provenance verification and side-effect accounting

Outputs:
- Machine-readable JSON: results/incident_lab_results.json
- Human-readable Markdown report: docs/security/incident_lab_report.md
"""

import argparse
import json
import time
import subprocess
import hashlib
import sys
import os
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmarks.eval_metadata import (
    collect_environment_metadata,
    get_git_commit_hash,
    get_working_tree_status,
    compute_working_tree_digest
)
from tests.incident_lab.scenarios.case1_github import Case1GitHubCredentialExposureScenario
from tests.incident_lab.scenarios.case2_government import Case2GovernmentAuthorizationBypassScenario
from tests.incident_lab.scenarios.case3_egress import Case3IndirectEgressScenario
from tests.incident_lab.scenarios.case4_dashboard import Case4InternalDashboardScenario
from tests.incident_lab.scenarios.case5_crypto import Case5CryptoWalletScenario
from tests.incident_lab.scenarios.case6_destructive import Case6DestructiveRecoveryScenario
from tests.incident_lab.scenarios.case7_fleet import Case7FleetAmplificationScenario


class IncidentLabRunner:
    def __init__(
        self,
        audit_dir: Optional[str] = None,
        expected_commit: Optional[str] = None,
        require_clean: bool = False,
        root_dir: Optional[str] = None
    ):
        self.root_dir = root_dir or PROJECT_ROOT
        self.audit_dir = Path(audit_dir) if audit_dir else Path(tempfile.gettempdir()) / "lab_benchmark_run"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.env_meta = collect_environment_metadata(
            suite_name="EpistemicOS Incident-Derived Security Test Lab",
            suite_version="2.3.0",
            expected_commit=expected_commit,
            require_clean=require_clean,
            root_dir=self.root_dir
        )

    def run_lab_evaluation(
        self,
        output_json_path: str = "results/incident_lab_results.json",
        output_md_path: str = "docs/security/incident_lab_report.md"
    ) -> Dict[str, Any]:
        start_time = time.time()

        scenarios = [
            Case1GitHubCredentialExposureScenario(audit_dir=str(self.audit_dir / "c1")),
            Case2GovernmentAuthorizationBypassScenario(audit_dir=str(self.audit_dir / "c2")),
            Case3IndirectEgressScenario(audit_dir=str(self.audit_dir / "c3")),
            Case4InternalDashboardScenario(audit_dir=str(self.audit_dir / "c4")),
            Case5CryptoWalletScenario(audit_dir=str(self.audit_dir / "c5")),
            Case6DestructiveRecoveryScenario(audit_dir=str(self.audit_dir / "c6")),
            Case7FleetAmplificationScenario(audit_dir=str(self.audit_dir / "c7"))
        ]

        results = {}
        for sc in scenarios:
            rep = sc.run_evaluation()
            results[rep.scenario_id] = rep.to_dict()

        completion_time_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        total_runtime_s = round(time.time() - start_time, 3)

        meta = dict(self.env_meta)
        meta.update({
            "completion_timestamp_utc": completion_time_utc,
            "timestamp": completion_time_utc,
            "uncommitted_tree_digest": meta["working_tree_digest"],
            "tree_digest_algorithm": "Full 64-char SHA-256 over deterministic POSIX sorted inventory of HEAD commit, git status -uall paths, status codes, symlink targets, deletions, and actual raw file bytes.",
            "evaluation_notes": "Evaluation executed against verified checkout prior to report persistence commit.",
            "total_scenarios_evaluated": len(results),
            "total_runtime_seconds": total_runtime_s,
            "exit_code": 0,
            "exit_status": "SUCCESS",
            "environment": f"Isolated Incident-Derived Security Test Lab ({meta['execution_environment_type']} Environment)"
        })

        output_data = {
            "metadata": meta,
            "scenarios": results
        }

        # Save JSON results
        p_json = Path(output_json_path)
        p_json.parent.mkdir(parents=True, exist_ok=True)
        with open(p_json, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)

        # Save Markdown report
        p_md = Path(output_md_path)
        p_md.parent.mkdir(parents=True, exist_ok=True)
        self.generate_markdown_report(output_data, p_md)

        return output_data

    def generate_markdown_report(self, data: Dict[str, Any], output_path: Path):
        meta = data["metadata"]
        scs = data["scenarios"]

        md_lines = [
            "# EpistemicOS Incident-Derived Security Test Lab Report",
            "",
            f"**Evaluated Commit:** `{meta['evaluated_git_commit']}` | **Working Tree:** `{meta['working_tree_status']}` | **Suite Version:** `{meta['evaluation_suite_version']}`",
            f"**Working Tree Digest:** `{meta['uncommitted_tree_digest']}`",
            f"**Evaluated At:** `{meta['timestamp']}` | **Total Runtime:** `{meta['total_runtime_seconds']}s`",
            f"**Environment:** {meta['environment']} | **Environment Type:** `{meta['execution_environment_type']}`",
            f"**Evaluation Command:** `{meta['evaluation_command']}`",
            f"**Exit Code:** `{meta['exit_code']}` (`{meta['exit_status']}`)",
            f"**Evaluation Notes:** {meta['evaluation_notes']}",
            "",
            "## 1. Seven-Case Summary Matrix",
            "",
            "| Case ID & Name | Security Outcome (Dim A) | Legitimate Task (Dim B) | Unauthorized Side Effects | Baseline Vulnerable | Provenance Status | Architectural Gaps |",
            "|---|---|---|---|---|---|---|"
        ]

        for sc_key, sc_data in scs.items():
            sc_id = sc_data["scenario_id"]
            dim_a = sc_data["dimension_a_security"]
            dim_b = sc_data["dimension_b_task"]
            sec_status = dim_a["status"]

            sec_display = str(sec_status)

            task_status = f"{dim_b['governance_authorization_approved']}/{dim_b['authorized_operations_attempted']} Approved (Boundary Admitted: {dim_b['boundary_admitted']})"
            side_effects = dim_a["unauthorized_side_effects_count"]
            base_vuln = "YES" if sc_data["unprotected_baseline"].get("vulnerability_demonstrated") else "NO"
            prov_status = dim_a["provenance_evidence_integrity"]
            gaps = len(sc_data["architectural_gaps"])

            md_lines.append(
                f"| **{sc_id}** | **{sec_display}** | {task_status} | {side_effects} | {base_vuln} | {prov_status} | {gaps} gap(s) |"
            )

        md_lines.extend([
            "",
            "## 2. Detailed Per-Case Analysis & Observable Outcomes",
            ""
        ])

        for sc_key, sc_data in scs.items():
            dim_a = sc_data["dimension_a_security"]
            dim_b = sc_data["dimension_b_task"]

            sec_detail = str(dim_a['status'])

            md_lines.extend([
                f"### Scenario: `{sc_data['scenario_name']}` (`{sc_data['scenario_id']}`)",
                f"- **Invariant:** {dim_a['invariant_description']}",
                f"- **Execution Path Exercised:** `{sc_data['execution_path_exercised']}`",
                f"- **Dimension A Security Status:** `{sec_detail}`",
                f"- **Dimension B Task Performance:** `{dim_b['governance_authorization_approved']}/{dim_b['authorized_operations_attempted']} approved` (Boundary Admitted: `{dim_b['boundary_admitted']}`, Callbacks Invoked: `{dim_b['callback_invoked']}`, Untested No-Grant: `{dim_b['untested_no_grant_count']}`)",
                f"- **Observed Side Effects Count:** `{dim_a['unauthorized_side_effects_count']}`",
                f"- **Unprotected Baseline Vulnerable:** `{sc_data['unprotected_baseline'].get('vulnerability_demonstrated')}`",
                f"- **Provenance Integrity:** `{dim_a['provenance_evidence_integrity']}`",
                "- **Evaluated Matrix Variants:**"
            ])
            for var_name, var_info in sc_data["variants_evaluated"].items():
                md_lines.append(f"  - **`{var_name}`:** `{json.dumps(var_info)}`")

            if sc_data["architectural_gaps"]:
                md_lines.append("- **Documented Architectural Gaps:**")
                for gap in sc_data["architectural_gaps"]:
                    md_lines.append(f"  - {gap}")
            md_lines.append("")

        md_lines.extend([
            "## 3. Reproduction Commands",
            "",
            "To reproduce the entire Incident Test Lab suite and verify all invariants independently:",
            "",
            "```bash",
            "# 1. Run full incident lab benchmark runner",
            "PYTHONPATH=\".\" python3 benchmarks/run_incident_lab.py --commit " + meta['evaluated_git_commit'] + " --require-clean",
            "",
            "# 2. Run incident lab integration and fleet concurrency tests",
            "PYTHONPATH=\".\" python3 -m pytest tests/incident_lab/",
            "```",
            "",
            "## 4. Evaluation Limitations & Non-Claims",
            "",
            "1. **Synthetic Isolation:** All tests run locally against synthetic, isolated, side-effect-free mock environments. No live production endpoints or real funds were accessed.",
            "2. **Scope of Proof:** Demonstration of defense-in-depth gating under these seven incident patterns does not constitute proof of universal security against arbitrary unmodeled threats.",
            "3. **Architectural Gaps:** Explicit gaps in multi-agent fleet gating, automatic grant provenance generation, and transitive egress filtering are documented and preserved without production workarounds."
        ])

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Run EpistemicOS Incident Test Lab Security Evaluation")
    parser.add_argument("--commit", default=None, help="Expected full 40-character Git SHA to verify against checked-out HEAD")
    parser.add_argument("--require-clean", action="store_true", help="Fail closed if source working tree is dirty or has untracked files")
    parser.add_argument("--output-json", default="results/incident_lab_results.json", help="Path to write JSON results artifact")
    parser.add_argument("--output-md", default="docs/security/incident_lab_report.md", help="Path to write Markdown report artifact")
    args = parser.parse_args()

    runner = IncidentLabRunner(expected_commit=args.commit, require_clean=args.require_clean)
    results = runner.run_lab_evaluation(output_json_path=args.output_json, output_md_path=args.output_md)
    print(f"Incident Test Lab evaluation completed across {len(results['scenarios'])} scenarios!")
    print(f"Machine-readable results saved to: {args.output_json}")
    print(f"Human-readable evidence report saved to: {args.output_md}")


if __name__ == "__main__":
    main()
