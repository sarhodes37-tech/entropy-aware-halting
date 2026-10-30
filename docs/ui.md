# EpistemicOS Control Plane Observatory UI

The EpistemicOS Control Plane Observatory is a read-only client dashboard interface for inspecting system execution counts, authorization denials, deterministic halts, execution failures, tamper-evident audit logs, provenance event streams, reconciliation reports, and empirical benchmark workbench results.

## Overview & Architectural Principles

- **Strict Read-Only Design**: The UI contains zero policy mutation, execution triggering, or privileged controls.
- **Zero-Dependency Core Stack**: Serves a standalone REST API and static single-page app (SPA) using Python's standard library (`http.server`).
- **Neon Dusk Design System**: Early-vaporwave / retro-futurist scientific instrumentation visual foundation with restrained dark surfaces and high-contrast accents.
- **No Fabricated Data**: Metrics are derived directly from actual `TamperEvidentAuditTrail` logs, `LocalProvenanceStore` hash chains, and benchmark result files (`results/*.json`).
- **Explicit Unavailable & Unverified States**: When log files do not exist or are empty, cards display explicit `UNAVAILABLE` or `UNVERIFIED` indicators rather than default zeroes or synthetic placeholders.
- **Untrusted Input Escaping**: Dynamic DOM rendering uses strict DOM text-node binding (`textContent` and DOM element creation) to ensure untrusted event payloads cannot execute malicious scripts.

## Design System Tokens (Neon Dusk Palette)

The Observatory UI utilizes the Neon Dusk design system token palette:

Token | Variable Name | Hex / Value | Intended Usage
--- | --- | --- | ---
Background Base | `--bg-base` | `#120F24` | Midnight violet primary background
Primary Surface | `--bg-surface` | `#1D1833` | Deep plum panel surface
Elevated Surface | `--bg-elevated` | `#282044` | Purple graphite elevated card/modal
Border Default | `--border-default` | `#44365F` | Dusty violet structural dividers
Primary Accent | `--accent-primary` | `#B69AFF` | Electric lavender headers & identifiers
Secondary Accent | `--accent-secondary` | `#FF83B8` | Vaporwave pink highlights & alerts
Interactive Accent | `--accent-interactive` | `#64DED9` | Retro cyan hover/focus/tabs
Primary Text | `--text-primary` | `#F5F0FF` | Soft white high-contrast text
Secondary Text | `--text-secondary` | `#B6A9CA` | Muted lavender subtext
Semantic Verified | `--status-verified-fg` | `#2DD4BF` | Mint teal verification indicators
Semantic Failed / Denied | `--status-failed-fg` | `#FF83B8` | Vaporwave pink failure indicators
Semantic Halted | `--status-halted-fg` | `#FBBF24` | Amber yellow deterministic halt indicators

## Installation & Execution

### Running the Observatory Server

To launch the Control Plane Observatory API and UI server:

```bash
PYTHONPATH=. python3 -m epistemicos.ui.server --host 127.0.0.1 --port 8080
```

Optionally specify custom log paths:

```bash
PYTHONPATH=. python3 -m epistemicos.ui.server \
  --audit-log logs/epistemic_audit.jsonl \
  --provenance-log logs/provenance_audit.jsonl \
  --ablation-table results/ablation_table.json \
  --per-case-results results/per_case_results.json
```

Then open `http://127.0.0.1:8080` in any modern desktop or mobile browser.

## Views Provided

1. **Overview**: Executive system metrics (executions, denials, halts, failures), audit log health, and provenance store hash chain integrity status.
2. **Execution Trace Explorer**: Filterable trace lifecycle view grouping provenance events by `correlation_id` into `DENIED`, `HALTED`, `COMPLETED`, `FAILED`, and `OUTCOME_UNKNOWN` states, displaying authorization evidence and `ProvenanceReconciler` verification reports.
3. **Provenance Explorer**: Detailed event timeline displaying sequence numbers, timestamps, sources, targets, and SHA-256 entry hashes, with an explicit disclaimer regarding local chain scope.
4. **Benchmark Workbench**: Baseline condition confusion matrices (TC, FC, TR, FR), 95% confidence intervals, threshold ablations, attribution takeaways, and per-case evaluation outcomes.

## REST API Endpoints

- `GET /api/overview`: Aggregated executive metrics and log integrity statuses.
- `GET /api/traces`: Execution traces grouped by correlation ID.
- `GET /api/trace/<correlation_id>`: Detailed execution trace for a single correlation ID.
- `GET /api/provenance`: All recorded provenance events and chain integrity status.
- `GET /api/benchmarks`: Benchmark ablation tables and per-case evaluation records.

## Running Tests

To run unit, integration, and security tests for the UI subsystem:

```bash
PYTHONPATH=/home/jules/.pyenv/versions/3.12.13/lib/python3.12/site-packages:. /home/jules/.local/bin/pytest tests/ui/
```

## Security Design & Scope Limitations

- **Local Hash Chain Scope**: Valid local cryptographic hash chain integrity verifies append-only sequence chaining, but does NOT prove external source authenticity, non-repudiation, or trace completeness.
- **Path Sanitization**: The HTTP server enforces strict path validation preventing directory traversal (`..` blocking) and restricts static asset delivery to `epistemicos/ui/static/`.
- **Security Headers**: All HTTP responses set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and strict `Content-Security-Policy` headers.
