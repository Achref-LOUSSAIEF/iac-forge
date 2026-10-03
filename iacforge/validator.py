"""Entry point for validation: schema checks first, then the policy rules."""

from __future__ import annotations

from typing import Any

from .findings import Finding, has_errors
from .rules import RULES
from .schema import check_structure
from .spec import normalize


def validate(raw: Any) -> list[Finding]:
    findings = check_structure(raw)
    if has_errors(findings):
        # The rules assume a well-formed spec, so stop at the structural errors.
        return sorted(findings, key=Finding.sort_key)

    spec = normalize(raw)
    for r in RULES:
        findings.extend(r.check(spec))
    return sorted(findings, key=Finding.sort_key)
