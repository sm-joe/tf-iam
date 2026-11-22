# Changelog

## v1.1.0 — Stable Release

### Added
- Opt-in bounded generated S3 names and EC2 Name-tag scopes from saved plans and corroborated configuration.
- Local HashiCorp random_id classification without AWS permission grants.
- Exact instance-profile role resolution and optional computed EC2 key-name handling for the reviewed AWS provider version.
- Inline route and security-group operation inference and detailed launch dependency diagnostics.
- `pack-policy` for exact-grant policy optimization, managed-policy size partitioning and aggregate inline quota checks.
- Isolated mixed and storage-messaging lifecycle acceptance runners.

### Validation
- Maintainer-reported successful combined S3, SQS and DynamoDB create, update and destroy at the merged implementation revision, with empty state verification and subsequent cleanup.
- EC2 launch acceptance blocked by an organization SCP. Not verified by this suite.
- Exact-commit release evidence and signed distribution checks passed in [release workflow 45066119415](https://github.com/sm-joe/tf-iam/actions/runs/45066119415). [Download v1.1.0](https://github.com/sm-joe/tf-iam/releases/tag/v1.1.0).

## v1.0.0

Initial signed stable Linux x86_64 release, including Terraform HCL and saved-plan analysis, AWS resource scoping, risk gates, policy comparison, lifecycle separation, authorization metadata and optional AWS validation and runtime audit integrations.

See [release acceptance](docs/release-acceptance.md) and [release process](docs/release-process.md) for evidence boundaries.
