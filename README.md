# iac-forge

Describe an AWS application in about 15 lines of YAML. **iac-forge** validates it against a set of security and reliability rules, then generates the Terraform for it.

```
YAML spec ──► validate (22 rules) ──► generate ──► *.tf files ──► terraform plan/apply
                  │
                  └── fails the CI pipeline on errors, before anything is deployed
```

It is a small, dependency-light Python project (only PyYAML). It was built as a clean-room re-implementation of an internal IaC abstraction tool and its pre-deployment validator.

## Quick start

```bash
pip install -e ".[dev]"

iacforge validate examples/webapp.yaml          # exit 0, no findings
iacforge validate examples/bad.yaml             # exit 1, 15 errors
iacforge generate examples/webapp.yaml -o build # writes build/*.tf
iacforge rules                                  # list every rule
```

## The spec

```yaml
name: shop
region: eu-west-3
environment: prod            # dev | staging | prod
tags: {owner: platform-team, cost_center: cc-1042}

network:
  cidr: 10.20.0.0/16
  public_subnets: 2
  private_subnets: 2
  nat_gateway: true

instances:
  - {name: app, count: 2, instance_type: t3.small, port: 8080}

loadbalancer:
  target: app
  listener: https
  certificate_arn: arn:aws:acm:...

database: {engine: postgres, instance_class: db.t3.medium, multi_az: true}
buckets:
  - name: assets
```

Everything except `name` and `network.cidr` has a safe default (encryption on, IMDSv2 on, nothing public, 7 days of backups). See `examples/` for complete specs.

## What gets generated

| File | Contents |
|---|---|
| `providers.tf` | Terraform and AWS provider, default tags, shared locals |
| `network.tf` | VPC, public/private subnets (CIDRs carved from the VPC range), IGW, optional NAT, route tables |
| `security.tf` | Security groups: ALB open on 80/443, app tier reachable only from the ALB, database reachable only from the app tier |
| `compute.tf` | EC2 instances (Amazon Linux 2023, encrypted gp3 root disk, IMDSv2) |
| `database.tf` | RDS with managed master password in Secrets Manager, subnet group, backups |
| `storage.tf` | S3 buckets with versioning, encryption and public-access block |
| `loadbalancer.tf` | ALB, target group, HTTPS listener with HTTP-to-HTTPS redirect |
| `outputs.tf` | VPC id, ALB DNS name, DB endpoint, bucket names |

Plain `aws_*` resources only, so `terraform init` needs nothing but the AWS provider. Files with nothing to say (no database, no load balancer) are not written.

## The validator

`iacforge validate` runs structural checks (`SCH001`, `SCH002`) and then 22 policy rules, grouped by prefix:

- **NET**: private CIDR range, subnet tiers exist, NAT, subnet counts for RDS/ALB
- **SEC**: no SSH from `0.0.0.0/0`, no public or unencrypted database/bucket, HTTPS, IMDSv2
- **LB / REF**: certificate present, load balancer target exists
- **REL**: Multi-AZ, backups, no single instance in prod
- **TAG / NAME / COST**: required tags, valid unique names, oversized instances outside prod

Severity can depend on the environment: a plain-HTTP listener or a missing tag is an *error* in `prod` and a *warning* in `dev`.

```
$ iacforge validate examples/bad.yaml
examples/bad.yaml: 15 error(s), 4 warning(s)
  ERROR   SEC002  database.publicly_accessible: The database is reachable from the Internet
  ERROR   SEC001  instances[0].ssh_cidr: SSH (port 22) is open to the whole Internet; ...
  ...
```

Exit codes: `0` clean, `1` findings (errors, or warnings with `--strict`), `2` unreadable file. `--format json` gives machine-readable output.

### Adding a rule

Rules are plain functions in `iacforge/rules.py`:

```python
@rule("SEC009", "Buckets must have versioning in prod")
def sec009(spec):
    for i, bucket in enumerate(spec["buckets"]):
        if spec["environment"] == "prod" and not bucket["versioning"]:
            yield Finding("SEC009", "error", f"buckets[{i}].versioning", "...")
```

The CLI and `iacforge rules` pick it up automatically. A test in `tests/test_rules.py` fails until every registered rule has a test case.

## CI

- `.github/workflows/ci.yml`: runs the tests, validates the example specs with `--strict`, generates Terraform and runs `terraform validate` on it.
- `.gitlab-ci.yml`: the same validation gate for GitLab, with the validation job reusable as the first stage of a deployment pipeline.

The point of the gate: a spec that opens SSH to the world or leaves a database unencrypted never reaches `terraform apply`.

## Tests

```bash
pytest
```

Covers every rule (one failing case each), generator output, and the CLI exit codes.

## Limitations

- Rules check the YAML spec, not arbitrary Terraform; this is not a TFLint replacement.
- The generated Terraform has been checked structurally by the tests and by `terraform validate` in CI, but not applied to a real AWS account.
- One application per spec; no multi-account or multi-region layouts.
