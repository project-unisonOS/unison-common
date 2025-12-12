from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .engine import PromptEngine
from .http_service import run_server


def _parse_json(s: str) -> Dict[str, Any]:
    try:
        obj = json.loads(s)
    except Exception as exc:
        raise argparse.ArgumentTypeError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise argparse.ArgumentTypeError("expected a JSON object")
    return obj


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="unison-prompt-engine")
    parser.add_argument("--root", default=None, help="Prompt root directory (defaults to $UNISON_PROMPT_ROOT)")
    parser.add_argument("--person-id", default=None, help="Optional person_id (supports {person_id} templating)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Initialize prompt directory with defaults (idempotent)")
    p_init.set_defaults(cmd="init")

    p_compile = sub.add_parser("compile", help="Compile and write active system prompt")
    p_compile.add_argument("--session-context", default="{}", type=_parse_json, help="JSON object")
    p_compile.add_argument("--print", action="store_true", help="Print compiled prompt to stdout")
    p_compile.set_defaults(cmd="compile")

    p_serve = sub.add_parser("serve", help="Run local prompt assembly HTTP service")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=7777)
    p_serve.set_defaults(cmd="serve")

    args = parser.parse_args(argv)

    engine = PromptEngine.for_person(person_id=args.person_id, root=args.root)

    if args.cmd == "init":
        engine.ensure_initialized()
        print(str(engine.layout.root))
        return 0

    if args.cmd == "compile":
        compiled = engine.compile(session_context=args.session_context, force=True)
        if args.print:
            sys.stdout.write(compiled.markdown)
        else:
            print(str(engine.layout.active_prompt_path))
        return 0

    if args.cmd == "serve":
        run_server(engine, host=args.host, port=args.port)
        return 0

    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())

