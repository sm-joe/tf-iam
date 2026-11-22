# tf-iam

**AWS IAM permission intelligence for Terraform CI/CD.**

[![CI](https://github.com/sm-joe/tf-iam/actions/workflows/ci.yml/badge.svg)](https://github.com/sm-joe/tf-iam/actions/workflows/ci.yml)
[![Linux build](https://github.com/sm-joe/tf-iam/actions/workflows/linux-build.yml/badge.svg)](https://github.com/sm-joe/tf-iam/actions/workflows/linux-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

tf-iam analyzes Terraform configuration and saved plans, derives scoped AWS IAM permission candidates, highlights security-sensitive operations and compares candidate grants with existing deployment identities. It is a standalone CLI for engineers reviewing infrastructure permissions before deployment.

## Features

| Capability | Description |
| --- | --- |
| Static analysis | Terraform HCL and JSON, variables, local references and installed modules |
| Plan analysis | Create, update, delete, replacement and no-op lifecycle candidates |
| Permission catalog | 108 managed resource types and 37 data-source types with version-aware evidence |
| Least-privilege candidates | Scoped ARNs, bounded future identifiers, service conditions and dependency review |
| Security enforcement | Delegation, destructive actions, privilege risk combinations and configurable gates |
| Policy separation | Planner, applier and break-glass permission partitions |
| IAM comparison | Offline policy or live role retrieval, deduplicated findings and service summaries |
| AWS validation | AWS authorization metadata and IAM Access Analyzer |
| Runtime evidence | Bounded CloudTrail management event analysis |
| Distribution | Python package and standalone Linux x86_64 build |

AWS and Terraform are the supported platforms. The standalone binary and built distribution wheel include the permission catalog and AWS authorization metadata. Normal analysis never downloads a provider, fetches metadata, invokes Terraform, or needs Git or AWS credentials. A source checkout includes the same permission catalog but may not contain the build-generated metadata snapshot. Generated policies are candidates requiring review; the tool does not provision resources, attach IAM policies or revoke permissions.

## Quick start

Requirements: Python 3.10 or later (CI covers 3.10, 3.12, 3.13 and 3.14), Bash and Git. Terraform is needed only to produce a saved plan. AWS credentials are optional for static analysis.

```bash
git clone https://github.com/sm-joe/tf-iam.git
cd tf-iam
python3 -m venv .venv
source .venv/bin/activate
python -m pip uninstall -y tf-iam-scope  # only needed when upgrading an older checkout
python -m pip install '.[aws]'
tfiam --help
```

Set the target account and region. Use a literal target account when working offline, or resolve the current AWS identity explicitly.

```bash
export AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export AWS_REGION=us-east-1
tfiam scan ./examples/eks --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION"
```

## Commands

| Command | Purpose |
| --- | --- |
| `scan` | Analyze configuration or a saved plan; report scope, coverage and risks |
| `generate` | Produce IAM JSON or Terraform JSON policy candidates |
| `compare` | Compare candidates against an identity policy or live IAM role |
| `split` | Separate read, mutation and privileged/destructive grants |
| `catalog-audit` | Offline catalog check against packaged AWS metadata |
| `validate-policy` | Validate an identity policy through IAM Access Analyzer |
| `runtime-audit` | Analyze CloudTrail observations for an exact IAM session issuer |

Run any command with `--help` for options. Scan defaults to a readable ASCII table. All seven commands support `--format table`; use `--format json --output report.json --show-table` to save full machine-readable output and print tables to stderr. Generate defaults to JSON; `--format terraform` remains available. Tables are review views, and very large comparison detail sections are explicitly abbreviated.

## Terraform workflow

Use an appropriately authorized planning identity to create the plan. tf-iam never invokes Terraform itself.

```bash
umask 077
terraform -chdir=./infra plan -out=tfplan
terraform -chdir=./infra show -json tfplan > plan.json
tfiam scan ./infra --plan-json plan.json --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --format json --output report.json
tfiam generate ./infra --plan-json plan.json --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --output policy.json
```

The directory supplies backend and lockfile data in plan mode, plus direct source-expression evidence for computed EKS role ARNs; it does not add static resource changes. For fresh EKS creates, a missing ARN can be derived from the exact planned role name and path only when the corresponding root source is an unambiguous direct role ARN reference, the saved plan confirms that reference and both resources use the default AWS provider. Use the same unchanged configuration that produced the plan. Unknown or sensitive names/paths, aliases, indexed/module instances and ambiguous expressions remain unresolved; no wildcard PassRole is emitted. Plan paths resolve relative to the current shell. Use exported JSON, not a binary plan or streaming UI JSON. UTF-8 and BOM-encoded UTF-16/32 are accepted. No-op resources emit read candidates; replacements retain before/after identities. Destroy mode rejects plans with managed create/update operations. Imports, drift, deferred changes and unknowns require review.

Static scanning also supports `--phase plan`, `--phase apply` and `--phase destroy`. Static apply includes possible deletions for replacement. A plan-phase scan is not proof of all permissions required to run Terraform plan.

## Policy generation and separation

Generation works without special acknowledgement when mappings and scopes are resolved. It blocks unmapped resources or unresolved permissions by default; `--allow-partial` deliberately overrides only those default checks. Explicit security gates and definite metadata incompatibilities still block output. Generated policies remain candidates, not guaranteed effective authorization.

```bash
tfiam generate ./infra --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --format terraform --output policy.tf.json
tfiam split ./infra --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --acknowledge-break-glass --output lifecycle-policies.json
```

The planner contains read candidates; the applier contains ordinary mutation candidates; break-glass contains delegation and all catalog destroy actions. Shared update/delete APIs are conservatively treated as privileged even when needed during update. Backend lock cleanup also requires review. These are partitions, not independently sufficient execution roles. Keep policy provisioning separate from infrastructure deployment and approve privileged operations explicitly.

## Security gates

```bash
tfiam scan ./infra --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --fail-on-risk CRITICAL --fail-on-unresolved --fail-on-unmapped --format json --output report.json
```

Use `--fail-on-risk HIGH` for stricter approval policy. Risk findings are potential security impacts, not proof of exploitation. Generation stops when configured gates fail. `--strict` rejects partial coverage, and `--require-compatible-metadata` requires a compatible metadata audit.

| Exit | Meaning |
| --- | --- |
| 0 | Command completed |
| 1 | Input, execution or definite policy compatibility error |
| 2 | Strict coverage/validation failure or bounded runtime retrieval truncated |
| 3 | Missing or explicitly denied permissions with `--fail-on-missing` |
| 4 | Configured security gate failed |

## Compare existing permissions

```bash
tfiam compare ./infra --existing existing-policy.json --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --output comparison.json
tfiam compare ./infra --role-name TerraformPipeline --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --fail-on-missing --output live-comparison.json
```

Live comparison reads managed policy default versions and inline policies. Findings are deduplicated by action, scope and condition; source addresses are retained. The summary includes unique grant counts and per-service missing, denied and potentially excessive counts. Conditions, policy variables, boundaries, SCPs and session/resource policies may require manual evaluation. Never automatically remove grants based on the report.

## AWS authorization and runtime evidence

```bash
tfiam scan ./infra --aws-account "$AWS_ACCOUNT_ID" --aws-region "$AWS_REGION" --format json --output report.json
tfiam validate-policy policy.json --aws-region "$AWS_REGION" --strict --output validation.json
tfiam runtime-audit --role-arn "$PIPELINE_ROLE_ARN" --start "$(date -u -d '1 hour ago' +%FT%TZ)" --end "$(date -u +%FT%TZ)" --aws-region "$AWS_REGION" --candidate report.json --max-pages 20 --max-seconds 60 --output runtime-report.json
```

Built distributions automatically audit permissions against packaged AWS metadata. An existing local snapshot can optionally override it. A source checkout without packaged metadata reports `not-run`; it never downloads anything to compensate. Metadata acquisition and provider-source review are internal build/maintenance tasks. The runtime command filters by exact role issuer and accepts explicitly known session names. It defaults to 100 pages and a cooperative 120-second budget; a truncated report is visibly partial. Alternatively pass `--events cloudtrail.json` for offline exports. Runtime audit separates observed actions outside the static candidates and ambiguous operation-to-action mappings. It never automatically adds or removes grants. Zero observations never imply unused permissions are safe to remove.

Live read access requires IAM GetRole, ListAttachedRolePolicies, ListRolePolicies, GetPolicy, GetPolicyVersion and GetRolePolicy as applicable; Access Analyzer ValidatePolicy; and CloudTrail LookupEvents. Use a dedicated limited identity.

## Coverage and architecture

The scanner reads root and reachable local modules plus previously installed remote modules without downloading them. Static input precedence is defaults, TF_VAR, terraform.tfvars, terraform.tfvars.json, lexical auto files, explicit var-files, then explicit vars. This grouping differs from interleaved Terraform CLI flags. Use saved plans for exact evaluation. Complex expressions, dynamic instances, aliases and unresolved dependencies remain review items.

Local backend and S3 state with optional DynamoDB locking, S3 lockfiles and KMS are modeled; workspace prefixes and provider-specific behavior require verification. Reports distinguish mapping coverage, scoped permissions, unresolved actions, metadata compatibility and provider-version evidence. A recognized action or resource is not proof of authorization. All current scans are partial; exact provider-version lifecycle evidence is still required.

- [AWS catalog coverage](docs/aws-catalog.md)
- [Action-specific scope](docs/action-scope.md)
- [Provider validation](docs/provider-validation.md)
- [Release acceptance](docs/release-acceptance.md)
- [Release process](docs/release-process.md)
- [Security policy](SECURITY.md)

## Linux distribution

CI publishes build artifacts for Linux x86_64. Extract the artifact in a directory **outside the source checkout** (the binary name is also the Python package directory name).

```bash
sha256sum -c SHA256SUMS
chmod +x tfiam
./tfiam --help
sudo install -m 0755 tfiam /usr/local/bin/tfiam
```

Stable release assets require reviewed lifecycle evidence, repeatability checks and signed provenance. Verify the release attestation with GitHub CLI: `gh attestation verify tfiam --repo sm-joe/tf-iam`. See the release process for details.

## Development

```bash
python -m pip install '.[test,aws,packaging]'
python -m pytest tests/ -q
python scripts/prepare-metadata.py  # maintainer build only; fresh checkout
bash scripts/build-linux.sh
```

If installation fails because the package directory is a file, move the conflicting file outside the checkout and restore the tracked `tfiam/` directory. Never extract a binary over the source package.

## Security and license

Saved plans and reports can contain confidential infrastructure identifiers or unmarked secrets. Restrict access; do not commit real state, plans or evidence. Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

Distributed under the [MIT License](LICENSE).

### Review tables

Computed and masked plan values are reported as information in the resource inventory, not repeated review warnings. Recovered exact role dependencies appear in a separate resolved-dependencies table. Unknown tag values retain the applicable catalog actions without exposing tag values. Actual missing dependency grants and unavailable scopes remain explicit unresolved permissions; `--fail-on-unresolved` blocks policy generation. Review requirements and validation limitations use tables. Provider lifecycle evidence is still required; successful Access Analyzer validation does not establish effective authorization.

### Newly added Terraform files

Static scans read all root `.tf` and `.tf.json` files, including newly added S3 configurations. Saved-plan scans intentionally analyze only the saved operations. If current root AWS declarations are absent from saved plan configuration, the scan lists them separately and generation/split refuse that stale input. Regenerate `terraform plan` and `terraform show -json` after changing configuration. This declaration check cannot detect every change to existing resource arguments or module instances. Explicit `aws_s3_bucket.name.id` dependencies resolve to the bucket's known name; generated names, sensitive values and ambiguous references remain unresolved.

### Catalog maintenance

The catalog is maintained and reviewed in repository CI. Source audits and lifecycle evidence tools are repository-only, documented in [maintainer validation](docs/provider-validation.md). End users do not download external provider source or run maintenance tools. Provider version is detected from the existing lockfile and the corresponding packaged mapping is selected automatically.

### Engineer decision reports

`generate` always prints a bordered decision report to stderr, leaving the IAM JSON on stdout or in the selected output file. The default is one compact policy summary showing mapping coverage, unresolved grants, lifecycle scope, global-scope actions and validation status. Detailed risk and field diagnostics are available with `--show-table`. Use `--show-table` for the complete policy grant inventory, or `--format table` for a human-readable report instead of IAM JSON. A blocked generation prints the blocking checks and does not write a new policy. PASS on mapping or metadata is not proof of deployment authorization. Risk findings describe permission capabilities, not observed attacks or confirmed vulnerabilities. Static apply includes destroy capabilities; use a saved plan to narrow the actual operation set.

### EKS and IAM dependency inference

Cluster and node group creation includes exact service-linked role bootstrap ARNs restricted by `iam:AWSServiceName`; these grants are needed only when the roles are absent. CreateCluster and DescribeAddonVersions are region-conditioned when the target region is supplied. API access mode and explicit KMS encryption configuration trigger scoped dependency candidates. Tagged EKS resources use their existing attribute mappings. Explicit IAM role boundaries constrain CreateRole and boundary updates. The comparison separates missing identity allows from conditional/complex unverified allows, and recognizes identical conditions. No result proves effective authorization. Nested EKS Auto Mode and pod identity delegation need additional context; no broad grants are added to hide gaps.

Static evaluation distinguishes masked configuration fields from omitted permission grants. Unevaluated trust documents and dependency expressions are informational; unknown optional delegation or permissions boundaries remain explicit unresolved permissions and block ordinary generation. Only top-level attribute names are retained, never their values.

The primary workflow is `tfiam generate . --output policy.json`. Static configuration apply covers the full lifecycle, including replacement/deletion. A saved plan narrows the operation set. `compare` is optional and intended for evaluating a separately supplied existing policy; self-comparison is only an internal regression check. It counts conditional grants and does not label identical candidate conditions as unresolved comparisons.

IAM user and group managed-policy attachments are supported. The generator resolves the identity ARN (including its IAM path) from a managed identity reference or a unique local declaration, or a matching saved-plan identity. Attach and detach grants are restricted by `iam:PolicyARN`; listing grants are scoped to the identity. For external identities with a known literal name but no known path, the offline generator uses two name-bound ARNs (`user/name` and `user/*/name`, or the group equivalent). IAM names are unique within an account regardless of path. This preserves the exact identity name and account without requiring AWS credentials. ARN names are case-sensitive: use the actual IAM name spelling. Unknown names or policy ARNs remain blocking.
