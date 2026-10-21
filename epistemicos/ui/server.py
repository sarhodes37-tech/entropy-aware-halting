"""
EpistemicOS Control Plane Observatory - HTTP API & Static File Server.

Lightweight, zero-dependency read-only server built on Python standard library.
Serves REST API endpoints and static frontend assets with strict security controls:
- GET-only HTTP methods
- Strict path sanitization against directory traversal
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options)
"""

import sys
import os
import json
import argparse
from pathlib import Path
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any
from urllib.parse import unquote

from epistemicos.audit import _sanitize_sensitive_data
from epistemicos.ui.adapters import ObservatoryDataAdapter


class ObservatoryRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP Handler serving read-only REST API endpoints and static assets.
    """

    adapter: ObservatoryDataAdapter = ObservatoryDataAdapter()
    static_dir: Path = Path(__file__).parent / "static"

    def do_GET(self) -> None:
        """Handles HTTP GET requests with strict path validation and security headers."""
        raw_path = self.path.split("?")[0]  # Strip query string

        # Iteratively unquote path to neutralize percent-encoded and double percent-encoded traversal attacks
        path = raw_path
        for _ in range(3):
            unquoted_path = unquote(path)
            if unquoted_path == path:
                break
            path = unquoted_path

        # Prevent directory traversal and null-byte injection
        if ".." in path or "\\" in path or "\x00" in path:
            self._send_json_response({"error": "Invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return

        # Route API requests
        if path.startswith("/api/"):
            self._handle_api_route(path)
            return

        # Serve static assets
        self._handle_static_route(path)

    def do_POST(self) -> None:
        self._send_method_not_allowed()

    def do_PUT(self) -> None:
        self._send_method_not_allowed()

    def do_DELETE(self) -> None:
        self._send_method_not_allowed()

    def do_PATCH(self) -> None:
        self._send_method_not_allowed()

    # -------------------------------------------------------------------------
    # Route Handlers
    # -------------------------------------------------------------------------
    def _handle_api_route(self, path: str) -> None:
        if path == "/api/overview":
            data = self.adapter.get_overview()
            self._send_json_response(data)
        elif path == "/api/traces":
            data = self.adapter.get_execution_traces()
            self._send_json_response(data)
        elif path.startswith("/api/trace/"):
            corr_id = path[len("/api/trace/"):]
            if not corr_id:
                self._send_json_response({"error": "Correlation ID required"}, status=HTTPStatus.BAD_REQUEST)
                return
            trace = self.adapter.get_execution_trace_by_id(corr_id)
            if trace:
                self._send_json_response(trace)
            else:
                # Sanitize requested ID to prevent leaking credentials or PII in URL parameters
                sanitized_corr_id = _sanitize_sensitive_data(corr_id)
                self._send_json_response({"error": f"Trace not found: {sanitized_corr_id}"}, status=HTTPStatus.NOT_FOUND)
        elif path == "/api/provenance":
            data = self.adapter.get_provenance_explorer_data()
            self._send_json_response(data)
        elif path == "/api/benchmarks":
            data = self.adapter.get_benchmark_data()
            self._send_json_response(data)
        else:
            self._send_json_response({"error": "API endpoint not found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_static_route(self, path: str) -> None:
        if path == "/" or path == "/index.html":
            file_path = self.static_dir / "index.html"
            content_type = "text/html; charset=utf-8"
        else:
            rel_path = path.lstrip("/")
            file_path = (self.static_dir / rel_path).resolve()
            # Ensure resolved path stays strictly within static_dir
            try:
                file_path.relative_to(self.static_dir.resolve())
            except ValueError:
                self._send_json_response({"error": "Access denied"}, status=HTTPStatus.FORBIDDEN)
                return

            if file_path.suffix == ".css":
                content_type = "text/css; charset=utf-8"
            elif file_path.suffix == ".js":
                content_type = "application/javascript; charset=utf-8"
            elif file_path.suffix in (".png", ".jpg", ".jpeg", ".svg", ".ico"):
                content_type = f"image/{file_path.suffix.lstrip('.')}"
            elif file_path.suffix == ".json":
                content_type = "application/json; charset=utf-8"
            else:
                content_type = "text/plain; charset=utf-8"

        if not file_path.exists() or not file_path.is_file():
            self._send_json_response({"error": "File not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(HTTPStatus.OK)
            self._set_security_headers(content_type, len(content))
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            # Do not leak internal exception details (str(e)) or filesystem paths to clients
            self._send_json_response({"error": "Failed to read file"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    # -------------------------------------------------------------------------
    # Helper Response Methods
    # -------------------------------------------------------------------------
    def _send_json_response(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self._set_security_headers("application/json; charset=utf-8", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def _send_method_not_allowed(self) -> None:
        self._send_json_response(
            {"error": "Method Not Allowed. EpistemicOS Observatory is strictly read-only."},
            status=HTTPStatus.METHOD_NOT_ALLOWED
        )

    def _set_security_headers(self, content_type: str, content_length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        )

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stdout logging during tests unless running directly."""
        if _is_verbose_logging_enabled():
            super().log_message(format, *args)


def _is_verbose_logging_enabled() -> bool:
    """
    Safely validate and parse the VERBOSE_OBSERVATORY environment variable.
    Ensures input is a string, strips whitespace, normalizes case, and strictly matches allowed truthy values.
    """
    raw_val = os.environ.get("VERBOSE_OBSERVATORY")
    if not isinstance(raw_val, str):
        return False
    clean_val = raw_val.strip().lower()
    return clean_val in ("1", "true", "yes", "on", "enabled")


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    adapter: Optional[ObservatoryDataAdapter] = None,
    static_dir: Optional[str] = None
) -> HTTPServer:
    """Factory creating an Observatory HTTPServer instance."""
    if adapter:
        ObservatoryRequestHandler.adapter = adapter
    if static_dir:
        ObservatoryRequestHandler.static_dir = Path(static_dir)

    server = HTTPServer((host, port), ObservatoryRequestHandler)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="EpistemicOS Control Plane Observatory Server")
    parser.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Binding port (default: 8080)")
    parser.add_argument("--audit-log", default="logs/epistemic_audit.jsonl", help="Path to audit log")
    parser.add_argument("--provenance-log", default="logs/provenance_audit.jsonl", help="Path to provenance log")
    parser.add_argument("--ablation-table", default="results/ablation_table.json", help="Path to ablation table")
    parser.add_argument("--per-case-results", default="results/per_case_results.json", help="Path to per-case results")

    args = parser.parse_args()

    adapter = ObservatoryDataAdapter(
        audit_log_path=args.audit_log,
        provenance_log_path=args.provenance_log,
        ablation_table_path=args.ablation_table,
        per_case_results_path=args.per_case_results
    )

    server = create_server(host=args.host, port=args.port, adapter=adapter)
    print(f"EpistemicOS Control Plane Observatory running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Observatory server.")
        server.server_close()


if __name__ == "__main__":
    main()
