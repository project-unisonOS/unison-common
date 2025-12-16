from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .errors import ModelPackError
from .resolver import ModelPackResolver, PackRef


def _print_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="unison-models", description="UnisonOS model pack manager")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List installed model packs")

    p_verify = sub.add_parser("verify", help="Verify installed model pack(s)")
    p_verify.add_argument("--pack-id", default=None)
    p_verify.add_argument("--pack-version", default=None)

    p_install = sub.add_parser("install", help="Install a model pack")
    g = p_install.add_mutually_exclusive_group(required=True)
    g.add_argument("--path", dest="path", default=None)
    g.add_argument("--fetch", dest="fetch", default=None, help="URL or alias (see UNISON_MODEL_PACK_ALIAS_MAP_JSON)")

    args = parser.parse_args(argv)
    r = ModelPackResolver.from_env()

    try:
        if args.cmd == "list":
            _print_json({"base_dir": str(r.base_dir), "packs": [p.__dict__ for p in r.list_packs()]})
            return 0
        if args.cmd == "verify":
            if args.pack_id and args.pack_version:
                ref = PackRef(pack_id=str(args.pack_id), pack_version=str(args.pack_version))
                res = r.verify_pack(ref=ref)
                _print_json({"ok": res.ok, "missing": res.missing, "invalid": res.invalid})
                return 0 if res.ok else 2
            packs = r.list_packs()
            results = {}
            ok_all = True
            for p in packs:
                res = r.verify_pack(ref=p)
                results[f"{p.pack_id}@{p.pack_version}"] = {"ok": res.ok, "missing": res.missing, "invalid": res.invalid}
                ok_all = ok_all and res.ok
            _print_json({"ok": ok_all, "results": results})
            return 0 if ok_all else 2
        if args.cmd == "install":
            if args.path:
                ref = r.install_from_path(pack_path=str(args.path))
            else:
                ref = r.install_from_url(url_or_alias=str(args.fetch))
            _print_json({"installed": ref.__dict__, "base_dir": str(r.base_dir)})
            return 0
    except ModelPackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

