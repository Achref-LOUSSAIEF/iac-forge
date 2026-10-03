import json
from pathlib import Path

from iacforge.cli import main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
GOOD = str(EXAMPLES / "webapp.yaml")
BAD = str(EXAMPLES / "bad.yaml")


def test_validate_clean_spec_exits_zero(capsys):
    assert main(["validate", GOOD]) == 0
    assert "OK" in capsys.readouterr().out


def test_validate_bad_spec_exits_one(capsys):
    assert main(["validate", BAD]) == 1
    out = capsys.readouterr().out
    assert "SEC002" in out and "ERROR" in out


def test_validate_multiple_specs_fails_if_any_fails():
    assert main(["validate", GOOD, BAD]) == 1


def test_json_output_is_machine_readable(capsys):
    main(["validate", BAD, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert any(f["rule"] == "SEC003" for f in data[BAD])


def test_strict_turns_warnings_into_failures(tmp_path):
    spec = tmp_path / "warn.yaml"
    spec.write_text(
        "name: demo\nenvironment: dev\nnetwork:\n  cidr: 10.0.0.0/16\n"
        "instances:\n  - name: app\n"
    )
    assert main(["validate", str(spec)]) == 0  # only warnings (tags, NAT)
    assert main(["validate", str(spec), "--strict"]) == 1


def test_generate_writes_terraform(tmp_path, capsys):
    out = tmp_path / "tf"
    assert main(["generate", GOOD, "-o", str(out)]) == 0
    assert (out / "network.tf").exists()
    assert "wrote" in capsys.readouterr().out


def test_generate_refuses_invalid_spec(tmp_path):
    out = tmp_path / "tf"
    assert main(["generate", BAD, "-o", str(out)]) == 1
    assert not out.exists()


def test_missing_file_exits_two(capsys):
    assert main(["validate", "does-not-exist.yaml"]) == 2
    assert "error:" in capsys.readouterr().err


def test_invalid_yaml_exits_two(tmp_path):
    spec = tmp_path / "broken.yaml"
    spec.write_text("name: [unclosed")
    assert main(["validate", str(spec)]) == 2


def test_rules_command_lists_rules(capsys):
    assert main(["rules"]) == 0
    assert "SEC002" in capsys.readouterr().out
