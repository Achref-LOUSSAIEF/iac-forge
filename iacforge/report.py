"""Formatting validation results for humans and for machines."""

from __future__ import annotations

import json

from .findings import Finding


def summary(findings: list[Finding]) -> str:
    errors = sum(f.severity == "error" for f in findings)
    warnings = sum(f.severity == "warning" for f in findings)
    return f"{errors} error(s), {warnings} warning(s)"


def to_text(spec_path: str, findings: list[Finding]) -> str:
    if not findings:
        return f"{spec_path}: OK (no findings)"
    lines = [f"{spec_path}: {summary(findings)}"]
    for f in findings:
        where = f.path or "(root)"
        lines.append(f"  {f.severity.upper():<7} {f.rule:<7} {where}: {f.message}")
    return "\n".join(lines)


def to_json(results: dict[str, list[Finding]]) -> str:
    payload = {path: [f.to_dict() for f in findings] for path, findings in results.items()}
    return json.dumps(payload, indent=2)
