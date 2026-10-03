"""Policy rules, applied to a normalised spec.

Each rule is a small function that yields Findings. Register a new one with the
@rule decorator; the CLI, the tests and `iacforge rules` pick it up automatically.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .findings import Finding

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")  # 3 to 20 chars, DNS-safe
REQUIRED_TAGS = ("owner", "cost_center")
BIG_SIZES = {"xlarge", "2xlarge", "4xlarge", "8xlarge", "12xlarge", "16xlarge", "24xlarge", "metal"}


@dataclass(frozen=True)
class Rule:
    id: str
    summary: str
    check: Callable[[dict], Iterable[Finding]]


RULES: list[Rule] = []


def rule(rule_id: str, summary: str):
    def register(fn):
        RULES.append(Rule(rule_id, summary, fn))
        return fn

    return register


def _prod(spec: dict) -> bool:
    return spec["environment"] == "prod"


def _prod_error(spec: dict) -> str:
    """Severity that is an error in production and a warning elsewhere."""
    return "error" if _prod(spec) else "warning"


# --------------------------------------------------------------------- network


@rule("NET001", "VPC CIDR must be a private IPv4 range between /16 and /24")
def net001(spec):
    cidr = spec["network"]["cidr"]
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        yield Finding("NET001", "error", "network.cidr", f"'{cidr}' is not a valid CIDR: {exc}")
        return
    if net.version != 4:
        yield Finding("NET001", "error", "network.cidr", "Only IPv4 VPC CIDRs are supported")
    elif not net.is_private:
        yield Finding("NET001", "error", "network.cidr", f"{cidr} is not in a private (RFC 1918) range")
    elif not 16 <= net.prefixlen <= 24:
        yield Finding("NET001", "error", "network.cidr", f"/{net.prefixlen} is outside the supported /16 to /24 range")


@rule("NET002", "Instances must be placed in a subnet tier that exists")
def net002(spec):
    net = spec["network"]
    for i, inst in enumerate(spec["instances"]):
        tier = inst["placement"]
        if net[f"{tier}_subnets"] < 1:
            yield Finding(
                "NET002", "error", f"instances[{i}].placement",
                f"'{inst['name']}' is placed in {tier} subnets but network.{tier}_subnets is 0",
            )


@rule("NET003", "Private instances need a NAT gateway to reach the Internet")
def net003(spec):
    net = spec["network"]
    private = [i["name"] for i in spec["instances"] if i["placement"] == "private"]
    if private and net["private_subnets"] > 0 and not net["nat_gateway"]:
        yield Finding(
            "NET003", "warning", "network.nat_gateway",
            f"{', '.join(private)} sit in private subnets with no NAT gateway, so they have no outbound Internet access",
        )


@rule("NET004", "Databases need 2+ private subnets and load balancers 2+ public subnets")
def net004(spec):
    net = spec["network"]
    if spec["database"] and net["private_subnets"] < 2:
        yield Finding("NET004", "error", "network.private_subnets", "An RDS subnet group needs at least 2 private subnets")
    if spec["loadbalancer"] and net["public_subnets"] < 2:
        yield Finding("NET004", "error", "network.public_subnets", "An Application Load Balancer needs at least 2 public subnets")


@rule("NET005", "A NAT gateway needs a public subnet to live in")
def net005(spec):
    net = spec["network"]
    if net["nat_gateway"] and net["public_subnets"] < 1:
        yield Finding("NET005", "error", "network.nat_gateway", "nat_gateway is enabled but network.public_subnets is 0")


# -------------------------------------------------------------------- security


@rule("SEC001", "SSH must not be open to the whole Internet")
def sec001(spec):
    for i, inst in enumerate(spec["instances"]):
        cidr = inst["ssh_cidr"]
        if cidr is None:
            continue
        path = f"instances[{i}].ssh_cidr"
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            yield Finding("SEC001", "error", path, f"'{cidr}' is not a valid CIDR")
            continue
        if net.prefixlen == 0:
            yield Finding("SEC001", "error", path, "SSH (port 22) is open to the whole Internet; restrict it to a bastion or VPN range")


@rule("SEC002", "Databases must not be publicly accessible")
def sec002(spec):
    db = spec["database"]
    if db and db["publicly_accessible"]:
        yield Finding("SEC002", "error", "database.publicly_accessible", "The database is reachable from the Internet")


@rule("SEC003", "Database storage must be encrypted")
def sec003(spec):
    db = spec["database"]
    if db and not db["encrypted"]:
        yield Finding("SEC003", "error", "database.encrypted", "Database storage is not encrypted at rest")


@rule("SEC004", "S3 buckets must not be public")
def sec004(spec):
    for i, bucket in enumerate(spec["buckets"]):
        if bucket["public"]:
            yield Finding("SEC004", "error", f"buckets[{i}].public", f"Bucket '{bucket['name']}' is public")


@rule("SEC005", "S3 buckets must be encrypted")
def sec005(spec):
    for i, bucket in enumerate(spec["buckets"]):
        if not bucket["encryption"]:
            yield Finding("SEC005", "error", f"buckets[{i}].encryption", f"Bucket '{bucket['name']}' has no server-side encryption")


@rule("SEC006", "The load balancer should serve HTTPS (required in prod)")
def sec006(spec):
    lb = spec["loadbalancer"]
    if lb and lb["listener"] == "http":
        yield Finding(
            "SEC006", _prod_error(spec), "loadbalancer.listener",
            "Traffic is served over plain HTTP; use listener: https with a certificate",
        )


@rule("SEC007", "Instances must enforce IMDSv2")
def sec007(spec):
    for i, inst in enumerate(spec["instances"]):
        if not inst["imdsv2"]:
            yield Finding("SEC007", "error", f"instances[{i}].imdsv2", f"'{inst['name']}' allows IMDSv1, which is exposed to SSRF credential theft")


@rule("SEC008", "Prefer private subnets for instances")
def sec008(spec):
    for i, inst in enumerate(spec["instances"]):
        if inst["placement"] == "public":
            yield Finding("SEC008", "warning", f"instances[{i}].placement", f"'{inst['name']}' is placed in a public subnet; put it behind the load balancer instead")


# --------------------------------------------------------------- references


@rule("LB001", "An HTTPS listener needs a certificate")
def lb001(spec):
    lb = spec["loadbalancer"]
    if lb and lb["listener"] == "https" and not lb["certificate_arn"]:
        yield Finding("LB001", "error", "loadbalancer.certificate_arn", "listener is https but no certificate_arn is set")


@rule("REF001", "The load balancer target must be a declared instance group")
def ref001(spec):
    lb = spec["loadbalancer"]
    if not lb:
        return
    names = {i["name"] for i in spec["instances"]}
    if lb["target"] not in names:
        known = ", ".join(sorted(names)) or "none declared"
        yield Finding("REF001", "error", "loadbalancer.target", f"'{lb['target']}' is not an instance group (known: {known})")


# ------------------------------------------------------------- reliability


@rule("REL001", "Production databases should be Multi-AZ")
def rel001(spec):
    db = spec["database"]
    if db and _prod(spec) and not db["multi_az"]:
        yield Finding("REL001", "warning", "database.multi_az", "A production database without Multi-AZ has no automatic failover")


@rule("REL002", "Production databases should keep at least 7 days of backups")
def rel002(spec):
    db = spec["database"]
    if db and _prod(spec) and db["backup_retention_days"] < 7:
        yield Finding("REL002", "warning", "database.backup_retention_days", f"{db['backup_retention_days']} day(s) of backups is below the 7-day minimum for production")


@rule("REL003", "Production instance groups should have 2+ instances")
def rel003(spec):
    if not _prod(spec):
        return
    for i, inst in enumerate(spec["instances"]):
        if inst["count"] < 2:
            yield Finding("REL003", "warning", f"instances[{i}].count", f"'{inst['name']}' is a single point of failure in production")


# -------------------------------------------------------- hygiene and cost


@rule("TAG001", "Resources must carry the required tags (error in prod)")
def tag001(spec):
    for tag in REQUIRED_TAGS:
        if tag not in spec["tags"]:
            yield Finding("TAG001", _prod_error(spec), f"tags.{tag}", f"Required tag '{tag}' is missing")


@rule("NAME001", "Names must be 3-20 characters: lowercase letters, digits and hyphens")
def name001(spec):
    candidates = [("name", spec["name"])]
    candidates += [(f"instances[{i}].name", x["name"]) for i, x in enumerate(spec["instances"])]
    candidates += [(f"buckets[{i}].name", x["name"]) for i, x in enumerate(spec["buckets"])]
    for path, value in candidates:
        if not NAME_RE.match(value):
            yield Finding("NAME001", "error", path, f"'{value}' is not a valid name (3-20 chars, a-z, 0-9 and '-', starting with a letter)")


@rule("NAME002", "Instance group and bucket names must be unique")
def name002(spec):
    for key in ("instances", "buckets"):
        seen: set[str] = set()
        for i, item in enumerate(spec[key]):
            if item["name"] in seen:
                yield Finding("NAME002", "error", f"{key}[{i}].name", f"Duplicate name '{item['name']}'")
            seen.add(item["name"])


@rule("COST001", "Avoid xlarge-or-bigger instance types outside production")
def cost001(spec):
    if _prod(spec):
        return
    sized = [(f"instances[{i}].instance_type", x["instance_type"]) for i, x in enumerate(spec["instances"])]
    if spec["database"]:
        sized.append(("database.instance_class", spec["database"]["instance_class"]))
    for path, value in sized:
        if value.split(".")[-1] in BIG_SIZES:
            yield Finding("COST001", "warning", path, f"{value} is expensive for a {spec['environment']} environment")
