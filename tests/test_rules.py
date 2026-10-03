import copy
from pathlib import Path

import pytest
import yaml

from iacforge.rules import RULES
from iacforge.validator import validate

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return yaml.safe_load((ROOT / "examples" / name).read_text())


def ids(findings):
    return {f.rule for f in findings}


# One mutation per rule: starting from a clean spec, break exactly that rule.
CASES = [
    ("SCH001", lambda s: s.pop("name")),
    ("SCH002", lambda s: s.update(colour="blue")),
    ("NET001", lambda s: s["network"].update(cidr="8.8.0.0/16")),
    ("NET001", lambda s: s["network"].update(cidr="10.0.0.0/8")),
    ("NET001", lambda s: s["network"].update(cidr="10.0.0.5/16")),
    ("NET002", lambda s: s["network"].update(private_subnets=0)),
    ("NET003", lambda s: s["network"].update(nat_gateway=False)),
    ("NET004", lambda s: s["network"].update(public_subnets=1)),
    ("NET005", lambda s: s["network"].update(public_subnets=0)),
    ("SEC001", lambda s: s["instances"][0].update(ssh_cidr="0.0.0.0/0")),
    ("SEC002", lambda s: s["database"].update(publicly_accessible=True)),
    ("SEC003", lambda s: s["database"].update(encrypted=False)),
    ("SEC004", lambda s: s["buckets"][0].update(public=True)),
    ("SEC005", lambda s: s["buckets"][0].update(encryption=False)),
    ("SEC006", lambda s: s["loadbalancer"].update(listener="http")),
    ("SEC007", lambda s: s["instances"][0].update(imdsv2=False)),
    ("SEC008", lambda s: s["instances"][0].update(placement="public")),
    ("LB001", lambda s: s["loadbalancer"].pop("certificate_arn")),
    ("REF001", lambda s: s["loadbalancer"].update(target="nope")),
    ("REL001", lambda s: s["database"].update(multi_az=False)),
    ("REL002", lambda s: s["database"].update(backup_retention_days=1)),
    ("REL003", lambda s: s["instances"][0].update(count=1)),
    ("TAG001", lambda s: s["tags"].pop("owner")),
    ("NAME001", lambda s: s.update(name="Bad_Name")),
    ("NAME002", lambda s: s["instances"].append(dict(s["instances"][0]))),
    ("COST001", lambda s: (s.update(environment="dev"), s["instances"][0].update(instance_type="m5.4xlarge"))),
]


def test_clean_examples_have_no_findings():
    assert validate(load("webapp.yaml")) == []
    assert validate(load("api-dev.yaml")) == []


@pytest.mark.parametrize("rule_id,mutate", CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_each_rule_fires(rule_id, mutate):
    spec = copy.deepcopy(load("webapp.yaml"))
    mutate(spec)
    assert rule_id in ids(validate(spec))


def test_every_registered_rule_has_a_test_case():
    assert {r.id for r in RULES} <= {c[0] for c in CASES}


def test_rule_ids_are_unique():
    all_ids = [r.id for r in RULES]
    assert len(all_ids) == len(set(all_ids))


def test_bad_example_reports_many_errors():
    findings = validate(load("bad.yaml"))
    errors = [f for f in findings if f.severity == "error"]
    assert len(errors) >= 10
    assert {"NET001", "NET004", "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "REF001", "NAME001", "TAG001"} <= ids(findings)


def test_severity_depends_on_environment():
    spec = copy.deepcopy(load("webapp.yaml"))
    spec["loadbalancer"]["listener"] = "http"
    prod = [f for f in validate(spec) if f.rule == "SEC006"][0]
    spec["environment"] = "dev"
    dev = [f for f in validate(spec) if f.rule == "SEC006"][0]
    assert (prod.severity, dev.severity) == ("error", "warning")


def test_schema_errors_stop_rule_evaluation():
    findings = validate({"name": "x", "network": {"cidr": 5}})
    assert ids(findings) <= {"SCH001", "SCH002"}


def test_non_mapping_spec_is_reported():
    assert ids(validate(["not", "a", "mapping"])) == {"SCH001"}


def test_findings_are_sorted_errors_first():
    findings = validate(load("bad.yaml"))
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=lambda s: 0 if s == "error" else 1)
