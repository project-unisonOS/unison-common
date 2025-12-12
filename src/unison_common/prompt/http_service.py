from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .engine import PromptEngine
from .errors import PromptEngineError
from .updates import PromptUpdateProposal, Risk, Target


def run_server(engine: PromptEngine, *, host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), _make_handler(engine))
    server.serve_forever()


def _make_handler(engine: PromptEngine):
    proposals: Dict[str, PromptUpdateProposal] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                self._json({"ok": True})
                return
            if parsed.path == "/prompt/compiled":
                qs = parse_qs(parsed.query or "")
                intent = (qs.get("intent") or ["prompt.get"])[0]
                session_id = (qs.get("session_id") or [""])[0]
                person_id = (qs.get("person_id") or [""])[0]
                compiled = engine.compile(
                    session_context={"intent": intent, "session_id": session_id, "person_id": person_id}
                )
                self._json({"ok": True, "markdown": compiled.markdown, "metadata": compiled.metadata})
                return
            self._json({"ok": False, "error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            body = self._read_json()
            if parsed.path == "/prompt/propose":
                target = body.get("target")
                ops = body.get("ops")
                rationale = body.get("rationale") or ""
                risk = body.get("risk") or "medium"
                if target not in ("identity", "priorities"):
                    self._json({"ok": False, "error": "target must be identity|priorities"}, status=400)
                    return
                if not isinstance(ops, list):
                    self._json({"ok": False, "error": "ops must be an array"}, status=400)
                    return
                if risk not in ("low", "medium", "high"):
                    self._json({"ok": False, "error": "risk must be low|medium|high"}, status=400)
                    return
                proposal = engine.propose_update(target=target, ops=ops, rationale=rationale, risk=risk)
                proposals[proposal.proposal_id] = proposal
                self._json(
                    {
                        "ok": True,
                        "proposal_id": proposal.proposal_id,
                        "engine_risk": proposal.engine_risk,
                        "requires_approval": proposal.engine_risk == "high",
                    }
                )
                return

            if parsed.path == "/prompt/apply":
                proposal_id = body.get("proposal_id")
                approved = body.get("approved", False)
                if not isinstance(proposal_id, str) or not proposal_id:
                    self._json({"ok": False, "error": "proposal_id required"}, status=400)
                    return
                proposal = proposals.get(proposal_id)
                if proposal is None:
                    self._json({"ok": False, "error": "unknown proposal_id"}, status=404)
                    return
                try:
                    result = engine.apply_update(proposal, approved=bool(approved))
                except PromptEngineError as exc:
                    self._json({"ok": False, "error": str(exc)}, status=400)
                    return
                self._json(result)
                return

            if parsed.path == "/prompt/rollback":
                snapshot = body.get("snapshot")
                if not isinstance(snapshot, str) or not snapshot:
                    self._json({"ok": False, "error": "snapshot required"}, status=400)
                    return
                try:
                    result = engine.rollback(snapshot=snapshot)
                except PromptEngineError as exc:
                    self._json({"ok": False, "error": str(exc)}, status=400)
                    return
                self._json(result)
                return

            self._json({"ok": False, "error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def _read_json(self) -> Dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except Exception:
                length = 0
            raw = self.rfile.read(length) if length else b"{}"
            try:
                obj = json.loads(raw.decode("utf-8"))
            except Exception:
                obj = {}
            return obj if isinstance(obj, dict) else {}

        def _json(self, data: Dict[str, Any], *, status: int = 200) -> None:
            payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    return Handler

