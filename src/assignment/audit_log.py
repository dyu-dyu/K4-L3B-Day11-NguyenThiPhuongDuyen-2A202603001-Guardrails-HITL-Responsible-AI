"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        key = request_id or user_id
        self._open[key] = {
            "start_time": time.time(),
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "text": text,
            "request_id": request_id,
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        key = request_id or user_id
        pending = self._open.pop(key, None)
        start_time = pending["start_time"] if isinstance(pending, dict) else pending
        latency = (time.time() - start_time) if start_time else 0.0
        input_text = pending["text"] if isinstance(pending, dict) else ""

        entry = {
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "request_id": request_id,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency": round(latency, 4),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        out_path = Path(filepath or default_audit_log_path())
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return str(out_path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
