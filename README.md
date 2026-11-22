# tf-iam

**Least-privilege AWS IAM policy analysis for Terraform.**

[![Release](https://img.shields.io/github/v/release/sm-joe/tf-iam)](https://github.com/sm-joe/tf-iam/releases/latest)
[![CI](https://github.com/sm-joe/tf-iam/actions/workflows/ci.yml/badge.svg)](https://github.com/sm-joe/tf-iam/actions/workflows/ci.yml)
[![Linux build](https://github.com/sm-joe/tf-iam/actions/workflows/linux-build.yml/badge.svg)](https://github.com/sm-joe/tf-iam/actions/workflows/linux-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

tf-iam is an open-source security CLI that analyzes Terraform configurations and saved execution plans to derive scoped AWS IAM policy candidates, identify permission gaps and security risks, and support least-privilege infrastructure delivery.

Designed for cloud security, platform engineering and DevSecOps teams, it fits into existing infrastructure-as-code workflows without deploying resources, modifying IAM policies or requiring AWS credentials for offline analysis.

**[Download v1.0.0](https://github.com/sm-joe/tf-iam/releases/tag/v1.0.0)** · [Command reference](#command-reference) · [Coverage](#coverage-and-validation) · [Security](SECURITY.md)

## Why tf-iam?

Determining the permissions a Terraform deployment identity needs is difficult when resources have dependencies, attributes change, and provider operations require different authorization scopes. tf-iam provides a reviewable starting point for deployment policies rather than relying on broad administrator grants.

## Capabilities

| Capability | Description |
| --- | --- |
| Configuration analysis | Terraform HCL and JSON, variables, local references and reachable modules |
| Saved-plan analysis | Create, read, update, destroy, replacement and no-op operations |
| Resource coverage | 120 managed resource mappings and 37 data-source mappings |
| IAM policy generation | Resource ARNs, action-specific scopes and supported conditions; IAM JSON or Terraform JSON |
| Dependency resolution | Known IAM, VPC, EC2, S3, RDS, ECS and EKS dependencies |
| Multi-context analysis | Explicit provider aliases, accounts, regions and partitions |
| Risk assessment | Delegation, privilege combinations and destructive operations |
| Policy comparison | Existing policy documents or live IAM role grants |
| Lifecycle separation | Planner, applier and privileged break-glass candidates |
| AWS validation | Packaged authorization metadata and optional IAM Access Analyzer |
| Runtime auditing | Bounded, role-filtered CloudTrail management-event analysis |
| Automation | Machine-readable JSON, human-readable tables and configurable failure gates |
| Distribution | Standalone Linux x86_64 executable and Python source installation |

## Installation

### Standalone Linux executable (recommended)

Requirements: Linux x86_64, Bash, curl and GitHub CLI for provenance verification. Use the signed release rather than ordinary CI artifacts.

~~~bash
mkdir -p "$HOME/tfiam-download"
cd "$HOME/tfiam-download"

BASE=https://github.com/sm-joe/tf-iam/releases/download/v1.0.0
curl -fLO "$BASE/tfiam"
curl -fLO "$BASE/SHA256SUMS"
curl -fLO "$BASE/release-source.json"

sha256sum -c SHA256SUMS &&
  gh attestation verify tfiam --repo sm-joe/tf-iam &&
  gh attestation verify release-source.json --repo sm-joe/tf-iam &&
  sudo install -m 0755 tfiam /usr/local/bin/tfiam

tfiam --help
~~~

The executable includes the catalog and AWS authorization metadata and does not require a separate Python installation. Download outside the repository checkout to avoid a name collision with the Python package directory.

### Install from source

Requires Python 3.10+ and Git. The optional AWS extra enables live integrations.

~~~bash
git clone https://github.com/sm-joe/tf-iam.git
cd tf-iam
git checkout v1.0.0

python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[aws]'

tfiam --help
~~~

A raw source checkout may lack the build-generated authorization metadata snapshot. Normal commands never download it automatically.

## Quick start

Set the target account and region explicitly. Replace the example account with your actual deployment account.

~~~bash
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1

tfiam scan ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION"
~~~

Generate a candidate policy:

~~~bash
umask 077
tfiam generate ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --output policy.json
~~~

Review the decision table, unresolved permissions and validation status before using the output. The generated document is not attached to any identity.

## How it works

~~~text
Terraform HCL / JSON         Saved Terraform plan JSON
        |                               |
        +---------------+---------------+
                        |
               Context & resolution
                        |
             Version-aware AWS catalog
                        |
          Lifecycle & action-specific scopes
                        |
              Candidate permissions
                        |
          +-------------+--------------+
          |             |              |
       Risk review   Comparison     Validation
          |             |              |
          +-------------+--------------+
                        |
              Reports / IAM policies
~~~

Static analysis resolves known configuration values and dependencies, then selects lifecycle actions and applicable authorization scopes. Saved plans narrow the action set to represented operations and preserve before/after resource identities for replacements. Unknown or ambiguous values are reported rather than converted into unrestricted grants.

The version-aware catalog is selected from existing provider lockfile information or an explicit provider version. Resource mapping, authorization metadata compatibility and provider lifecycle evidence are reported separately.

## Command reference

| Command | Purpose |
| --- | --- |
| scan | Analyze resources, permission candidates, coverage and risks |
| generate | Render candidate IAM policies or Terraform JSON |
| compare | Compare with existing grants from a policy or IAM role |
| split | Partition planner, applier and break-glass candidates |
| catalog-audit | Check catalog actions against AWS authorization metadata |
| validate-policy | Run AWS IAM Access Analyzer policy validation |
| runtime-audit | Compare CloudTrail observations with scan candidates |

Use `tfiam COMMAND --help` for the full options. Scan defaults to a table; generate defaults to IAM JSON and writes its decision report to stderr. Use `--format json --output report.json --show-table` to preserve the complete structured report and view tables. Table views may abbreviate large detail sections.

## Analyze a saved Terraform plan

Use a planning identity with appropriate permissions. tf-iam does not run Terraform itself.

~~~bash
umask 077
terraform -chdir=./infra plan -out=tfplan
terraform -chdir=./infra show -json tfplan > plan.json

tfiam scan ./infra \
  --plan-json plan.json \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --format json --output report.json

tfiam generate ./infra \
  --plan-json plan.json \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --output policy.json
~~~

Use the unchanged configuration that produced the plan. The source directory supplies backend and selected dependency context, not additional static resource changes. Regenerate the plan after modifying configuration. Saved-plan input must be exported JSON, not the binary Terraform plan.

Static scans support `--phase plan`, `--phase apply` and `--phase destroy`. Static apply includes potential replacement and deletion permissions; use saved plans to narrow the actual operation set.

## Policy engineering

### Terraform JSON output

~~~bash
tfiam generate ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --format terraform --output policy.tf.json
~~~

Generation rejects unmapped resources and unresolved grants by default. The explicit `--allow-partial` override permits candidate output for review, but does not disable configured security gates or definite metadata compatibility failures. Do not treat partial output as deployment-ready.

### Separate lifecycle permissions

~~~bash
tfiam split ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --acknowledge-break-glass \
  --output lifecycle-policies.json
~~~

| Partition | Candidate permissions |
| --- | --- |
| Planner | Read and discovery operations |
| Applier | Ordinary mutations |
| Break-glass | Delegation and destructive or shared destructive operations |

Partitions are not independently sufficient execution identities. The applier may also need approved planner reads or privileged operations. Backend lock writes and cleanup require separate review. Never automatically attach the break-glass policy.

### Compare existing IAM permissions

~~~bash
tfiam compare ./infra \
  --existing existing-policy.json \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --format json --output comparison.json
~~~

To retrieve grants from a live role:

~~~bash
tfiam compare ./infra \
  --role-name TerraformPipeline \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --fail-on-missing \
  --format json --output live-comparison.json
~~~

Live comparison reads inline policies and managed policy default versions. Findings distinguish missing, explicitly denied, potentially excessive and uncertain grants. Conditions, policy variables, permissions boundaries, SCPs, session policies and resource policies can affect effective authorization. Never revoke grants based on comparison alone.

### Multiple providers and accounts

Provide a reviewed provider-context map for aliases and assumed-role targets:

~~~json
{
  "aws.west": {
    "account": "123456789012",
    "region": "us-west-2",
    "partition": "aws"
  }
}
~~~

~~~bash
tfiam scan ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --provider-contexts contexts.json \
  --format json --output report.json
~~~

The output is a combined candidate; review and partition grants by actual deployment identity. Credential and assume-role contexts are not guessed. For supported dynamic EC2 dependencies, `--scope-resource-tags` can use a known `tfiam:scope` tag as an authorization anchor. The condition covers all matching resources, so use controlled unique tags and restrict tag mutation.

## CI/CD security gates

~~~bash
tfiam scan ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --fail-on-risk CRITICAL \
  --fail-on-unresolved \
  --fail-on-unmapped \
  --format json --output tfiam-report.json
~~~

Use `--fail-on-risk HIGH` for stricter review. The `--strict` option rejects partial coverage; `--require-compatible-metadata` requires a compatible metadata audit. Risk findings identify potential permission capabilities, not confirmed attacks.

| Exit code | Meaning |
| --- | --- |
| 0 | Command completed |
| 1 | Input, execution or definite compatibility error |
| 2 | Strict coverage/validation failure or truncated runtime retrieval |
| 3 | Missing or denied grants when --fail-on-missing is enabled |
| 4 | Configured security gate failed |

A nonzero exit should block the corresponding CI approval stage. Keep reports private if they contain infrastructure identifiers.

## AWS validation and runtime evidence

### Authorization metadata

~~~bash
tfiam catalog-audit --strict --format json
~~~

Built distributions include AWS service authorization metadata. This checks catalog action recognition and applicable scope/condition compatibility; it does not establish effective IAM permissions.

### IAM Access Analyzer

~~~bash
tfiam validate-policy policy.json \
  --aws-region "$AWS_REGION" \
  --strict --output validation.json
~~~

### CloudTrail audit

Supply a **scan report** as the candidate, not a generated IAM policy document.

~~~bash
tfiam scan ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --format json --output report.json

tfiam runtime-audit \
  --role-arn "$PIPELINE_ROLE_ARN" \
  --start "$(date -u -d '1 hour ago' +%FT%TZ)" \
  --end "$(date -u +%FT%TZ)" \
  --aws-region "$AWS_REGION" \
  --candidate report.json \
  --max-pages 20 --max-seconds 60 \
  --output runtime-report.json
~~~

Set `PIPELINE_ROLE_ARN` to the actual role ARN. Use `--session-name` for a known STS session, `--aws-profile` to select dedicated audit credentials, or `--events` for an offline CloudTrail export. The live command defaults to 100 pages and a cooperative 120-second budget.

Runtime audit distinguishes observed actions outside the candidates and ambiguous API-to-IAM mappings. Missing events do not demonstrate that permissions are unnecessary.

| Optional integration | AWS actions, as applicable |
| --- | --- |
| Live IAM comparison | iam:GetRole, iam:ListAttachedRolePolicies, iam:ListRolePolicies, iam:GetPolicy, iam:GetPolicyVersion, iam:GetRolePolicy |
| Policy validation | access-analyzer:ValidatePolicy |
| Runtime audit | cloudtrail:LookupEvents |

Use a dedicated, least-privilege audit identity. No live AWS access is needed for static scanning, generation or local policy comparison.

## Coverage and validation

The catalog includes 157 resource and data-source mappings across IAM, EC2/VPC, EKS, ECS, S3, RDS, DynamoDB, SQS, SNS, Lambda, KMS, ECR, CloudWatch, ELB and other supported AWS services.

**v1.0.0 acceptance** was performed with AWS provider 6.73.0 using four isolated restricted-role fixtures:

| Fixture | Lifecycle acceptance |
| --- | --- |
| S3 general-purpose empty bucket | Passed |
| SQS standard empty queue | Passed |
| VPC and private subnet | Passed |
| DynamoDB on-demand empty table | Passed |

The suite covers create, read, update, replacement in both orders, destroy, negative authorization and cleanup evidence. All four candidate policies passed Access Analyzer validation. The session-filtered runtime audit recorded 441 matched management events and no unmapped operations.

These results validate the tested configurations, not every catalog entry. Provider review includes conditional and unresolved mappings, including legacy S3 and IAM operations. VPC default ACL, route-table and security-group discovery may leave computed IDs unavailable without additional read grants. The S3 fixture relies on supported provider tagging fallbacks.

### Analysis boundaries

- AWS and Terraform are supported; other cloud providers are not analyzed.
- The scanner reads root and reachable local modules and previously installed remote modules; it does not install modules or providers.
- Static variable precedence follows defaults, TF_VAR, standard tfvars, lexical auto files, explicit var-files, then explicit vars. Saved plans are preferred for exact Terraform evaluation.
- Local and S3 backends, S3 lockfiles, optional DynamoDB locking and KMS are modeled; workspace and provider-specific cases require review.
- Unknown names, sensitive fields, unsupported dependencies, ambiguous expressions and some generated IDs are reported explicitly.
- Candidate policies are not a substitute for effective authorization testing, organizational policy review or deployment approval.

## Documentation

| Guide | Description |
| --- | --- |
| [AWS catalog](docs/aws-catalog.md) | Supported mapping inventory and scope |
| [Action-specific scopes](docs/action-scope.md) | Resource scoping and dependency rules |
| [Provider validation](docs/provider-validation.md) | Provider-version and authorization evidence |
| [Release acceptance](docs/release-acceptance.md) | Validation requirements and lifecycle fixtures |
| [Release process](docs/release-process.md) | Maintainer build and signing procedures |
| [Security policy](SECURITY.md) | Vulnerability reporting and secure usage |

## Development and contributions

~~~bash
git clone https://github.com/sm-joe/tf-iam.git
cd tf-iam

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test,aws,packaging]'
python -m pytest -q
~~~

Build the standalone distribution:

~~~bash
python scripts/prepare-metadata.py
bash scripts/build-linux.sh
(cd dist && sha256sum -c SHA256SUMS)
~~~

Contributions are welcome through [issues](https://github.com/sm-joe/tf-iam/issues) and pull requests. Include a sanitized reproduction, provider version and tests for new mappings, scope changes or security-related behavior. Reference official AWS authorization documentation. Live acceptance is opt-in and must use an isolated AWS account.

## Security and license

Treat Terraform plans, state and analysis reports as confidential. The CLI does not attach generated permissions or deploy infrastructure. Report vulnerabilities privately as described in the [security policy](SECURITY.md).

Released under the [MIT License](LICENSE).
