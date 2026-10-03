"""Structural checks: are the keys and value types what the generator expects?

These run before the policy rules. If any of them fails, the rules are skipped
because they assume a well-formed spec.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .findings import Finding

ENVIRONMENTS = ("dev", "staging", "prod")

Check = Callable[[Any], Optional[str]]


def non_empty_str(v: Any) -> Optional[str]:
    return None if isinstance(v, str) and v.strip() else "must be a non-empty string"


def boolean(v: Any) -> Optional[str]:
    return None if isinstance(v, bool) else "must be true or false"


def is_mapping(v: Any) -> Optional[str]:
    return None if isinstance(v, dict) else "must be a mapping"


def is_list(v: Any) -> Optional[str]:
    return None if isinstance(v, list) else "must be a list"


def integer(lo: int, hi: int) -> Check:
    def check(v: Any) -> Optional[str]:
        if isinstance(v, bool) or not isinstance(v, int):
            return "must be an integer"
        if not lo <= v <= hi:
            return f"must be between {lo} and {hi}"
        return None

    return check


def one_of(*choices: str) -> Check:
    def check(v: Any) -> Optional[str]:
        return None if v in choices else f"must be one of: {', '.join(choices)}"

    return check


def starts_with(prefix: str) -> Check:
    def check(v: Any) -> Optional[str]:
        if isinstance(v, str) and v.startswith(prefix):
            return None
        return f"must be a string starting with '{prefix}'"

    return check


TOP = {
    "name": (non_empty_str, True),
    "region": (non_empty_str, False),
    "environment": (one_of(*ENVIRONMENTS), False),
    "tags": (is_mapping, False),
    "network": (is_mapping, True),
    "instances": (is_list, False),
    "database": (is_mapping, False),
    "buckets": (is_list, False),
    "loadbalancer": (is_mapping, False),
}

NETWORK = {
    "cidr": (non_empty_str, True),
    "public_subnets": (integer(0, 8), False),
    "private_subnets": (integer(0, 8), False),
    "nat_gateway": (boolean, False),
}

INSTANCE = {
    "name": (non_empty_str, True),
    "count": (integer(1, 50), False),
    "instance_type": (non_empty_str, False),
    "placement": (one_of("private", "public"), False),
    "port": (integer(1, 65535), False),
    "ssh_cidr": (non_empty_str, False),
    "imdsv2": (boolean, False),
    "root_volume_gb": (integer(8, 16384), False),
}

DATABASE = {
    "engine": (one_of("postgres", "mysql"), False),
    "instance_class": (starts_with("db."), False),
    "storage_gb": (integer(20, 65536), False),
    "encrypted": (boolean, False),
    "multi_az": (boolean, False),
    "publicly_accessible": (boolean, False),
    "backup_retention_days": (integer(0, 35), False),
}

BUCKET = {
    "name": (non_empty_str, True),
    "versioning": (boolean, False),
    "encryption": (boolean, False),
    "public": (boolean, False),
}

LOADBALANCER = {
    "target": (non_empty_str, True),
    "listener": (one_of("http", "https"), False),
    "certificate_arn": (starts_with("arn:"), False),
    "health_check_path": (starts_with("/"), False),
}


def _prefix(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _fields(obj: dict, path: str, table: dict, out: list[Finding]) -> None:
    for key in obj:
        if key not in table:
            out.append(Finding("SCH002", "warning", _prefix(path, key), "Unknown key, it will be ignored"))
    for key, (check, required) in table.items():
        if obj.get(key) is None:
            if required:
                out.append(Finding("SCH001", "error", _prefix(path, key), "is required"))
            continue
        problem = check(obj[key])
        if problem:
            out.append(Finding("SCH001", "error", _prefix(path, key), problem))


def _items(raw: dict, key: str, table: dict, out: list[Finding]) -> None:
    items = raw.get(key)
    if not isinstance(items, list):
        return
    for i, item in enumerate(items):
        path = f"{key}[{i}]"
        if not isinstance(item, dict):
            out.append(Finding("SCH001", "error", path, "must be a mapping"))
        else:
            _fields(item, path, table, out)


def check_structure(raw: Any) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(raw, dict):
        return [Finding("SCH001", "error", "", "The top level of the spec must be a mapping")]

    _fields(raw, "", TOP, out)

    tags = raw.get("tags")
    if isinstance(tags, dict):
        for key, value in tags.items():
            if not isinstance(value, (str, int, float, bool)):
                out.append(Finding("SCH001", "error", f"tags.{key}", "must be a plain value (text, number or boolean)"))

    for key, table in (("network", NETWORK), ("database", DATABASE), ("loadbalancer", LOADBALANCER)):
        if isinstance(raw.get(key), dict):
            _fields(raw[key], key, table, out)

    _items(raw, "instances", INSTANCE, out)
    _items(raw, "buckets", BUCKET, out)
    return out
