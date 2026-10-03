"""Loading a YAML spec and filling in defaults."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DB_PORTS = {"postgres": 5432, "mysql": 3306}

INSTANCE_DEFAULTS: dict[str, Any] = {
    "count": 1,
    "instance_type": "t3.micro",
    "placement": "private",
    "port": 80,
    "ssh_cidr": None,
    "imdsv2": True,
    "root_volume_gb": 20,
}

DB_DEFAULTS: dict[str, Any] = {
    "engine": "postgres",
    "instance_class": "db.t3.micro",
    "storage_gb": 20,
    "encrypted": True,
    "multi_az": False,
    "publicly_accessible": False,
    "backup_retention_days": 7,
}

BUCKET_DEFAULTS: dict[str, Any] = {
    "versioning": True,
    "encryption": True,
    "public": False,
}

LB_DEFAULTS: dict[str, Any] = {
    "listener": "http",
    "certificate_arn": None,
    "health_check_path": "/",
}


class SpecError(Exception):
    """The spec file could not be read or is not a YAML mapping."""


def load_raw(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError(f"{path}: the top level of the spec must be a mapping")
    return data


def normalize(raw: dict) -> dict:
    """Return a copy of a structurally valid spec with every default filled in."""
    spec = copy.deepcopy(raw)
    spec.setdefault("region", "eu-west-3")
    spec.setdefault("environment", "dev")
    spec["tags"] = spec.get("tags") or {}

    net = spec["network"]
    net.setdefault("public_subnets", 2)
    net.setdefault("private_subnets", 2)
    net.setdefault("nat_gateway", False)

    spec["instances"] = [{**INSTANCE_DEFAULTS, **i} for i in (spec.get("instances") or [])]
    spec["buckets"] = [{**BUCKET_DEFAULTS, **b} for b in (spec.get("buckets") or [])]
    db = spec.get("database")
    spec["database"] = {**DB_DEFAULTS, **db} if db else None
    lb = spec.get("loadbalancer")
    spec["loadbalancer"] = {**LB_DEFAULTS, **lb} if lb else None
    return spec
