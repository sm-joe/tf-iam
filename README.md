# TF IAM Scope

AWS IAM permission analysis for Terraform CI/CD pipelines. Independent Python CLI; no Pike code or mappings imported. GCP, Azure and OpenTofu are outside the current scope.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
tfiam --help
python -m pytest -q
```

## Usage

```bash
tfiam scan ./examples/eks --phase plan --aws-account 123456789012 --aws-region us-east-1
tfiam scan ./examples/eks --format json --output report.json
tfiam generate ./examples/eks --phase apply --aws-account 123456789012 --aws-region us-east-1 --allow-partial --output policy.json
tfiam generate ./examples/aws --format terraform --allow-partial --output policy.tf.json
tfiam compare ./examples/aws --existing examples/existing-aws.json --fail-on-missing
```

The default provider is AWS. Other providers are rejected for policy generation and reported as unsupported during scans. Generate never deploys policies. Terraform JSON output belongs in a separate privileged policy-provisioning workspace. Scan has no cloud credentials requirement.


## Saved Terraform plan JSON (M02)

Use a separate, appropriately authorized planning identity to produce the saved plan. The CLI does not execute Terraform or request cloud credentials.

```bash
terraform -chdir=./infra plan -out=tfplan
terraform -chdir=./infra show -json tfplan > plan.json
tfiam scan ./infra --plan-json plan.json --aws-account 123456789012 --aws-region us-east-1
tfiam generate ./infra --plan-json plan.json --aws-account 123456789012 --aws-region us-east-1 --allow-partial --output apply-policy.json
tfiam compare ./infra --plan-json plan.json --aws-account 123456789012 --aws-region us-east-1 --existing existing.json --fail-on-missing
```

The directory is optional in plan mode; it supplies only backend configuration and provider lockfile, not additional resource changes. Without a directory, supply explicit S3 backend configuration via `--backend-config` or review the missing backend warning. The default phase is apply; create/update/delete select distinct catalog operation candidates, replacements use both before and after scopes, no-op and data reads use read candidates, and forget is state-only. `--phase plan` reports retrospective read candidates; it cannot establish all permissions needed to produce the plan. `--phase destroy` rejects plans containing managed creates or updates. Deferred/incomplete plans, imports, drift, unknown and unsupported operations remain explicit review items. Full module instance and deposed addresses retain provenance.

Terraform JSON plans may contain plaintext secrets and confidential infrastructure details. Keep saved plans and reports in protected ephemeral storage; never commit real plans or upload them to public logs. Values identified by Terraform sensitive/unknown masks are withheld, not copied into reports. Other unmarked resource identifiers can appear in scopes and source addresses. AWS aliases, account/region assumptions, provider version validation, and precise action-level scope still require review. Catalog candidates are not proven sufficient.

Reference: [Terraform JSON output format](https://developer.hashicorp.com/terraform/internals/json-format).

## Static inputs and modules (M03)

```bash
tfiam scan ./infra --var-file ./infra/prod.tfvars --var environment=prod --aws-account 123456789012 --aws-region us-east-1
```

Input precedence is defaults, TF_VAR environment, terraform.tfvars, terraform.tfvars.json, lexical auto.tfvars files, explicit --var-file, then --var. This last grouping is a CLI convention; use saved plans for exact Terraform interleaved flag semantics. Direct references, simple string interpolation, locals, child inputs and outputs are supported. Sensitive variables and unsupported expressions remain unresolved. Each module call has its own context; installed remote sources are discovered from .terraform/modules/modules.json without downloading or executing anything. Local modules outside the root, dynamic module instances, arbitrary functions, complex expressions, provider aliases and runtime values require saved plan or review. The report contains module inventory and dependency reference edges, not raw variable values. Do not pass secret values on the shell command line.

## Catalog

The packaged `tfiam/catalog/aws.json` stores independently authored resource and data-source rules; `schema.json` defines their schema. Each entry has lifecycle actions, optional attribute-triggered actions, references, validation status and exact tested provider versions. Catalog loading validates schema and rejects writable data rules. The current catalog contains 106 resource and 37 data-source entries; all are candidates, none has live version-specific validation. The report records the AWS provider lockfile version if available. This is not proof of version compatibility. Resource-level scope logic remains in the scanner; unknown dependencies must not be silently granted.

## Expanded AWS catalog (M04)

The catalog includes IAM, EKS access management, VPC networking, EC2, Auto Scaling, S3, KMS, ECR, ECS, RDS, Lambda, CloudWatch, CloudWatch Logs, ELB and Route 53. All entries remain candidate mappings. Lifecycle operation sets are distinct; each mapping links to the AWS Service Authorization Reference.

Expanded entries use an explicit scope strategy. Where action-specific authorization or dependency scopes cannot be established, actions are omitted with a review warning rather than silently emitted at wildcard scope. Some legitimate account-level actions require wildcard scope (for example EC2 Describe operations and KMS CreateKey); these are not evidence that all actions in the service support wildcard-only authorization. Multi-resource dependencies and full per-action authorization remain M05 work. Do not treat mapping coverage as deployment-ready policy coverage.

See [AWS catalog coverage](docs/aws-catalog.md).

## Coverage and gates

Root and reachable local modules, HCL and Terraform JSON, S3 state with lockfile/DynamoDB and optional KMS, local backend. Plan is read-oriented and may include backend locking mutations. Apply includes deletes for replacement; destroy includes read/delete. Variable defaults and direct references are only static approximations. Uninstalled remote modules, full expression evaluation, aliases and provider-specific dependencies remain incomplete. Do not use generated policies without review and isolated lifecycle testing. All scans currently remain PARTIAL. Exit codes: 0 completed; 1 input/error; 2 partial with --strict; 3 missing or denied candidate permissions with --fail-on-missing.

## Roadmap

1. AWS-only external catalog and risk diagnostics (this change).
2. Saved Terraform plan JSON and lifecycle operations (M02); installed module inventory and full configuration resolution (M03).
3. Expand AWS mappings with action-level ARN and IAM condition evidence; validate against pinned provider versions.
4. Planner, applier and destructive-operation policy separation; scope-aware comparison and Access Analyzer.
5. Live read-only IAM retrieval and CloudTrail evidence refinement.
6. Standalone Linux distribution and signed releases after acceptance tests.

See [reference architecture](docs/pike-reference.md). No live deployment validation has been performed.

### Troubleshooting plan input

Use the exported JSON, not the binary plan or streaming `terraform plan -json` output. Relative `--plan-json` paths resolve from the current shell directory, not the positional infrastructure directory. For example:

```bash
terraform -chdir=./infra plan -out=tfplan
terraform -chdir=./infra show -json tfplan > plan.json
tfiam scan ./infra --plan-json "$PWD/plan.json"
```

The scanner accepts UTF-8 and BOM-encoded UTF-16/UTF-32 JSON exports and reports missing files, empty input and malformed JSON without echoing sensitive plan contents.
