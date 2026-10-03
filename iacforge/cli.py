"""Command line interface: validate, generate, rules."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .findings import has_errors, has_warnings
from .generator import generate, write_files
from .report import summary, to_json, to_text
from .rules import RULES
from .spec import SpecError, load_raw, normalize
from .validator import validate


def _failed(findings, strict: bool) -> bool:
    return has_errors(findings) or (strict and has_warnings(findings))


def _cmd_validate(args) -> int:
    results = {}
    for path in args.specs:
        results[path] = validate(load_raw(path))

    if args.format == "json":
        print(to_json(results))
    else:
        for path, findings in results.items():
            print(to_text(path, findings))

    return 1 if any(_failed(f, args.strict) for f in results.values()) else 0


def _cmd_generate(args) -> int:
    raw = load_raw(args.spec)
    findings = validate(raw)
    if findings:
        print(to_text(args.spec, findings), file=sys.stderr)
    if _failed(findings, args.strict):
        print("Nothing generated: fix the findings above first.", file=sys.stderr)
        return 1

    files = generate(normalize(raw))
    for path in write_files(files, args.output):
        print(f"wrote {path}")
    return 0


def _cmd_rules(_args) -> int:
    for r in RULES:
        print(f"{r.id:<8} {r.summary}")
    print(f"\n{len(RULES)} rules, plus schema checks SCH001 (structure) and SCH002 (unknown keys)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iacforge",
        description="Generate Terraform for AWS from a short YAML spec, and validate it before deployment.",
    )
    parser.add_argument("--version", action="version", version=f"iacforge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="check one or more specs against the rules")
    v.add_argument("specs", nargs="+", metavar="SPEC")
    v.add_argument("--format", choices=("text", "json"), default="text")
    v.add_argument("--strict", action="store_true", help="treat warnings as failures")
    v.set_defaults(func=_cmd_validate)

    g = sub.add_parser("generate", help="validate a spec, then write Terraform files")
    g.add_argument("spec", metavar="SPEC")
    g.add_argument("-o", "--output", default="build", help="output directory (default: build)")
    g.add_argument("--strict", action="store_true", help="refuse to generate when there are warnings")
    g.set_defaults(func=_cmd_generate)

    r = sub.add_parser("rules", help="list the validation rules")
    r.set_defaults(func=_cmd_rules)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (SpecError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
