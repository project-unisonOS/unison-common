from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .compiler import CompiledPrompt, compile_prompt
from .errors import PromptConfigError, PromptUpdateError
from .layout import PromptLayout, resolve_prompt_root
from .resources import load_defaults
from .schema import validate_doc
from .store import PromptStore
from .updates import PromptUpdateProposal, Risk, Target, apply_update, new_proposal


@dataclass
class PromptEngine:
    root: Path
    store: PromptStore

    _last_fingerprint: Optional[str] = None
    _last_compiled: Optional[CompiledPrompt] = None

    @classmethod
    def for_person(cls, *, person_id: Optional[str] = None, root: Optional[str] = None) -> "PromptEngine":
        resolved = resolve_prompt_root(root, person_id=person_id)
        layout = PromptLayout(root=resolved)
        return cls(root=resolved, store=PromptStore(layout=layout))

    @property
    def layout(self) -> PromptLayout:
        return self.store.layout

    def ensure_initialized(self) -> None:
        self.store.ensure_layout()
        defaults = load_defaults()

        if not self.layout.base_policy_path.exists():
            self.store.write_text_atomic(self.layout.base_policy_path, defaults.base_policy.strip() + "\n")
        if not self.layout.identity_schema_path.exists():
            self.store.write_json_atomic(self.layout.identity_schema_path, defaults.identity_schema)
        if not self.layout.priorities_schema_path.exists():
            self.store.write_json_atomic(self.layout.priorities_schema_path, defaults.priorities_schema)
        if not self.layout.identity_path.exists():
            self.store.write_json_atomic(self.layout.identity_path, defaults.identity)
        if not self.layout.priorities_path.exists():
            self.store.write_json_atomic(self.layout.priorities_path, defaults.priorities)

    def load_layers(self) -> Tuple[str, Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        self.ensure_initialized()
        base_md = self.store.read_text(self.layout.base_policy_path)
        identity = self.store.read_json(self.layout.identity_path)
        priorities = self.store.read_json(self.layout.priorities_path)
        identity_schema = self.store.read_json(self.layout.identity_schema_path)
        priorities_schema = self.store.read_json(self.layout.priorities_schema_path)

        id_ok = validate_doc(identity, identity_schema)
        pr_ok = validate_doc(priorities, priorities_schema)
        if not id_ok.ok:
            raise PromptConfigError("identity.json invalid: " + "; ".join(id_ok.errors))
        if not pr_ok.ok:
            raise PromptConfigError("priorities.json invalid: " + "; ".join(pr_ok.errors))
        return base_md, identity, priorities, identity_schema, priorities_schema

    def compile(self, *, session_context: Optional[Dict[str, Any]] = None, force: bool = False) -> CompiledPrompt:
        base_md, identity, priorities, _, _ = self.load_layers()
        fp = self.store.fingerprint()
        if not force and self._last_fingerprint == fp and self._last_compiled is not None:
            return self._last_compiled
        compiled = compile_prompt(base_md, identity, priorities, session_context=session_context)
        self.store.write_text_atomic(self.layout.active_prompt_path, compiled.markdown)
        self._last_fingerprint = fp
        self._last_compiled = compiled
        return compiled

    def propose_update(
        self,
        *,
        target: Target,
        ops: list[dict[str, Any]],
        rationale: str,
        risk: Risk,
        proposal_id: Optional[str] = None,
    ) -> PromptUpdateProposal:
        if target not in ("identity", "priorities"):
            raise PromptUpdateError(f"unsupported target: {target}")
        proposal_id = proposal_id or str(uuid.uuid4())
        # Validate by dry-running update against schema.
        _, _, _, identity_schema, priorities_schema = self.load_layers()
        doc = self.store.read_json(self.layout.identity_path if target == "identity" else self.layout.priorities_path)
        schema = identity_schema if target == "identity" else priorities_schema
        _ = apply_update(doc=doc, schema=schema, ops=ops)
        return new_proposal(proposal_id, target=target, ops=ops, rationale=rationale, model_risk=risk)

    def apply_update(self, proposal: PromptUpdateProposal, *, approved: bool) -> Dict[str, Any]:
        if proposal.engine_risk == "high" and not approved:
            raise PromptUpdateError("high-risk update requires explicit approval")

        base_md, identity, priorities, identity_schema, priorities_schema = self.load_layers()
        target_path = self.layout.identity_path if proposal.target == "identity" else self.layout.priorities_path
        doc = identity if proposal.target == "identity" else priorities
        schema = identity_schema if proposal.target == "identity" else priorities_schema

        before_fp = self.store.fingerprint()
        snapshot_path = self.store.snapshot(reason=f"apply_update {proposal.proposal_id} target={proposal.target}")
        next_doc = apply_update(doc=doc, schema=schema, ops=proposal.ops)
        self.store.write_json_atomic(target_path, next_doc)

        after_fp = self.store.fingerprint()
        self.store.append_audit_log(
            {
                "ts": time.time(),
                "action": "apply_prompt_update",
                "proposal_id": proposal.proposal_id,
                "target": proposal.target,
                "model_risk": proposal.model_risk,
                "engine_risk": proposal.engine_risk,
                "approved": approved,
                "snapshot": str(snapshot_path),
                "fingerprint_before": before_fp,
                "fingerprint_after": after_fp,
            }
        )
        compiled = self.compile(force=True)
        return {"ok": True, "compiled_path": str(self.layout.active_prompt_path), "compiled_metadata": compiled.metadata}

    def rollback(self, *, snapshot: str) -> Dict[str, Any]:
        snap = Path(snapshot).expanduser().resolve()
        self.store.rollback(snap)
        self.store.append_audit_log(
            {
                "ts": time.time(),
                "action": "rollback_prompt_update",
                "snapshot": str(snap),
            }
        )
        compiled = self.compile(force=True)
        return {"ok": True, "compiled_path": str(self.layout.active_prompt_path), "compiled_metadata": compiled.metadata}

