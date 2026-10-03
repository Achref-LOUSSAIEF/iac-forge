"""The result type shared by the schema checks and the rules."""

from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"error": 0, "warning": 1}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # "error" | "warning"
    path: str  # dotted location inside the spec, e.g. "database.encrypted"
    message: str

    def sort_key(self):
        return (SEVERITY_ORDER[self.severity], self.path, self.rule)

    def to_dict(self) -> dict:
        return asdict(self)


def has_errors(findings) -> bool:
    return any(f.severity == "error" for f in findings)


def has_warnings(findings) -> bool:
    return any(f.severity == "warning" for f in findings)
