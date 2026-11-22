# tf-iam

**Least-Privilege AWS IAM Policy Analysis For Terraform.**

[![Release](https://img.shields.io/github/v/release/sm-joe/tf-iam)](https://github.com/sm-joe/tf-iam/releases/latest)
[![CI](https://github.com/sm-joe/tf-iam/actions/workflows/ci.yml/badge.svg)](https://github.com/sm-joe/tf-iam/actions/workflows/ci.yml)
[![Linux build](https://github.com/sm-joe/tf-iam/actions/workflows/linux-build.yml/badge.svg)](https://github.com/sm-joe/tf-iam/actions/workflows/linux-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

tf-iam Is An Open-Source Security CLI That Analyzes Terraform Configurations And Saved Execution Plans To Derive Scoped AWS IAM Policy Candidates, Identify Permission Gaps And Security Risks, And Support Least-Privilege Infrastructure Delivery.

Designed For Cloud Security, Platform Engineering And DevSecOps Teams, It Fits Into Existing Infrastructure-As-Code Workflows Without Deploying Resources, Modifying IAM Policies Or Requiring AWS Credentials For Offline Analysis.

**[Download v1.1.0](https://github.com/sm-joe/tf-iam/releases/tag/v1.1.0)** · [Command Reference](#command-reference) · [Coverage](#coverage-and-validation) · [Security](SECURITY.md)

## Why tf-iam?

Determining The Permissions A Terraform Deployment Identity Needs Is Difficult When Resources Have Dependencies, Attributes Change, And Provider Operations Require Different Authorization Scopes. tf-iam Provides A Reviewable Starting Point For Deployment Policies Rather Than Relying On Broad Administrator Grants.

## Capabilities

| Capability | Description |
| --- | --- |
| Configuration Analysis | Terraform HCL And JSON, Variables, Local References And Reachable Modules |
| Saved-Plan Analysis | Create, Read, Update, Destroy, Replacement And No-Op Operations |
| Resource Coverage | 120 Managed Resource Mappings And 37 Data-Source Mappings |
| IAM Policy Generation | Resource ARNs, Action-Specific Scopes And Supported Conditions; IAM JSON Or Terraform JSON |
| Dependency Resolution | Known IAM, VPC, EC2, S3, RDS, ECS And EKS Dependencies |
| Multi-Context Analysis | Explicit Provider Aliases, Accounts, Regions And Partitions |
| Risk Assessment | Delegation, Privilege Combinations And Destructive Operations |
| Policy Comparison | Existing Policy Documents Or Live IAM Role Grants |
| Policy Size Management | Exact-Grant Consolidation, Managed Policy Partitioning And Inline Quotas |
| Lifecycle Separation | Planner, Applier And Privileged Break-Glass Candidates |
| AWS Validation | Packaged Authorization Metadata And Optional IAM Access Analyzer |
| Runtime Auditing | Bounded, Role-Filtered CloudTrail Management-Event Analysis |
| Automation | Machine-Readable JSON, Human-Readable Tables And Configurable Failure Gates |
| Distribution | Standalone Linux x86_64 Executable And Python Source Installation |

The Current Published Stable Release Is v1.1.0, Including `pack-policy` And `--scope-generated-names`.

## Installation

### Standalone Linux Executable (Recommended)

Requirements: Linux x86_64, Bash And Authenticated GitHub CLI For Download And Provenance Verification. Use The Signed Release Rather Than Ordinary CI Artifacts.

~~~bash
(
  set -Eeuo pipefail
  trap 'echo "ERROR: Installation Stopped At Line $LINENO." >&2' ERR

  WORK_DIR=$(mktemp -d)
  cd "$WORK_DIR"

  gh auth status
  gh release download v1.1.0 --repo sm-joe/tf-iam \
    --pattern tfiam --pattern SHA256SUMS --pattern release-source.json

  sha256sum -c SHA256SUMS
  gh attestation verify tfiam --repo sm-joe/tf-iam
  gh attestation verify release-source.json --repo sm-joe/tf-iam

  chmod +x tfiam
  ./tfiam generate --help > generate-help.txt
  grep -F -- '{json,terraform,table}' generate-help.txt
  grep -F -- '--show-table' generate-help.txt
  grep -F -- '[--allow-partial]' generate-help.txt

  if [ "$(id -u)" -eq 0 ]; then
    install -m 0755 tfiam /usr/local/bin/tfiam
  else
    sudo install -m 0755 tfiam /usr/local/bin/tfiam
  fi

  cmp tfiam /usr/local/bin/tfiam
  sha256sum /usr/local/bin/tfiam
  /usr/local/bin/tfiam generate --help
  echo "PASS: Verified Release Installed"
)
hash -r
type -a tfiam
~~~

If Any Verification Fails, Installation Stops And The Existing Executable Is Not Replaced. Use The Absolute Path Above To Avoid An Older Virtual Environment, Alias Or PATH Entry. Resolve Any GitHub Authentication Or Attestation Error Before Continuing.

The Executable Includes The Catalog And AWS Authorization Metadata And Does Not Require A Separate Python Installation. Download Outside The Repository Checkout To Avoid A Name Collision With The Python Package Directory.

### Install From Source

Requires Python 3.10+ And Git. The Optional AWS Extra Enables Live Integrations.

~~~bash
git clone https://github.com/sm-joe/tf-iam.git
cd tf-iam
git checkout v1.1.0

python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[aws]'

tfiam --help
~~~

A Raw Source Checkout May Lack The Build-Generated Authorization Metadata Snapshot. Normal Commands Never Download It Automatically.

## Quick Start

Set The Target Account And Region Explicitly. Replace The Example Account With Your Actual Deployment Account.

~~~bash
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1

tfiam scan ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION"
~~~

Generate A Candidate Policy:

~~~bash
umask 077
tfiam generate ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --output policy.json
~~~

Review The Decision Table, Unresolved Permissions And Validation Status Before Using The Output. The Generated Document Is Not Attached To Any Identity.

## How It Works

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

Static Analysis Resolves Known Configuration Values And Dependencies, Then Selects Lifecycle Actions And Applicable Authorization Scopes. Saved Plans Narrow The Action Set To Represented Operations And Preserve before/after Resource Identities For Replacements. Unknown Or Ambiguous Values Are Reported Rather Than Converted Into Unrestricted Grants.

The Version-Aware Catalog Is Selected From Existing Provider Lockfile Information Or An Explicit Provider Version. Resource Mapping, Authorization Metadata Compatibility And Provider Lifecycle Evidence Are Reported Separately.

## Command Reference

| Command | Purpose |
| --- | --- |
| scan | Analyze Resources, Permission Candidates, Coverage And Risks |
| generate | Render Candidate IAM Policies Or Terraform JSON |
| compare | Compare With Existing Grants From A Policy Or IAM Role |
| split | Partition Planner, Applier And Break-Glass Candidates |
| pack-policy | Optimize And Partition Generated Policies Within AWS Size Quotas |
| catalog-audit | Check Catalog Actions Against AWS Authorization Metadata |
| validate-policy | Run AWS IAM Access Analyzer Policy Validation |
| runtime-audit | Compare CloudTrail Observations With Scan Candidates |

Use `tfiam COMMAND --help` For The Full Options. Scan Defaults To A Table; Generate Defaults To IAM JSON And Writes Its Decision Report To Stderr. Use `--format json --output report.json --show-table` To Preserve The Complete Structured Report And View Tables. Table Views May Abbreviate Large Detail Sections.

## Analyze A Saved Terraform Plan

Use A Planning Identity With Appropriate Permissions. tf-iam Does Not Run Terraform Itself.

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

Use The Unchanged Configuration That Produced The Plan. The Source Directory Supplies Backend And Selected Dependency Context, Not Additional Static Resource Changes. Regenerate The Plan After Modifying Configuration. Saved-Plan Input Must Be Exported JSON, Not The Binary Terraform Plan.

Static Scans Support `--phase plan`, `--phase apply` And `--phase destroy`. Static Apply Includes Potential Replacement And Deletion Permissions; Use Saved Plans To Narrow The Actual Operation Set.

## Policy Engineering

### Terraform JSON Output

~~~bash
tfiam generate ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --format terraform --output policy.tf.json
~~~

Generation Rejects Unmapped Resources And Unresolved Grants By Default. The Explicit `--allow-partial` Override Permits Candidate Output For Review, But Does Not Disable Configured Security Gates Or Definite Metadata Compatibility Failures. Do Not Treat Partial Output As Deployment-Ready.

### Policy Size Management

Optimize A Generated Allow Policy Without Changing Its Action, Resource Or Condition Grants:

```bash
tfiam pack-policy policy.json --output-dir policy-bundle
```

The Output Directory Must Not Already Exist. The Manifest Reports Original And Optimized Sizes, Policy Count And Individual Policy Files. Managed Policies Are Limited To 6,144 Characters Each. The Default Budget Is 10 Attachments; Use `--max-policies` To Specify The Remaining Available Slots (Up To 20 Where The Account Quota Permits). Use `--max-chars` To Reserve Additional Headroom.

For Inline Policies, Use `--policy-type inline-role`, `inline-user` Or `inline-group`. The Aggregate Identity Limit Is Enforced; Splitting Cannot Bypass It. Existing Inline Policy Usage Must Be Accounted For With A Reduced `--max-chars`.

This Command Does Not Attach Policies Or Change AWS Resources. Review And Validate Each Generated Policy Document Independently.

See [Mixed Infrastructure Lifecycle Acceptance](docs/mixed-lifecycle.md) For The Maintainer's Isolated Create, Update And Destroy Workflow.

### Separate Lifecycle Permissions

~~~bash
tfiam split ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --acknowledge-break-glass \
  --output lifecycle-policies.json
~~~

| Partition | Candidate Permissions |
| --- | --- |
| Planner | Read And Discovery Operations |
| Applier | Ordinary Mutations |
| Break-Glass | Delegation And Destructive Or Shared Destructive Operations |

Partitions Are Not Independently Sufficient Execution Identities. The Applier May Also Need Approved Planner Reads Or Privileged Operations. Backend Lock Writes And Cleanup Require Separate Review. Never Automatically Attach The Break-Glass Policy.

### Compare Existing IAM Permissions

~~~bash
tfiam compare ./infra \
  --existing existing-policy.json \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --format json --output comparison.json
~~~

To Retrieve Grants From A Live Role:

~~~bash
tfiam compare ./infra \
  --role-name TerraformPipeline \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --fail-on-missing \
  --format json --output live-comparison.json
~~~

Live Comparison Reads Inline Policies And Managed Policy Default Versions. Findings Distinguish Missing, Explicitly Denied, Potentially Excessive And Uncertain Grants. Conditions, Policy Variables, Permissions Boundaries, SCPs, Session Policies And Resource Policies Can Affect Effective Authorization. Never Revoke Grants Based On Comparison Alone.

### Multiple Providers And Accounts

Provide A Reviewed Provider-Context Map For Aliases And Assumed-Role Targets:

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

The Output Is A Combined Candidate; Review And Partition Grants By Actual Deployment Identity. Credential And Assume-Role Contexts Are Not Guessed. For Supported Dynamic EC2 Dependencies, `--scope-resource-tags` Can Use A Known `tfiam:scope` Tag As An Authorization Anchor. The Condition Covers All Matching Resources, So Use Controlled Unique Tags And Restrict Tag Mutation.

For Saved Plans, `--scope-generated-names` Opts Into Corroborated EC2 Name-Tag Scopes And Bounded Random S3 Bucket Patterns. These Patterns Can Match Other Resources; Review Namespace Ownership, Tag Mutation And Collision Risk.

## CI/CD Security Gates

~~~bash
tfiam scan ./infra \
  --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" \
  --fail-on-risk CRITICAL \
  --fail-on-unresolved \
  --fail-on-unmapped \
  --format json --output tfiam-report.json
~~~

Use `--fail-on-risk HIGH` For Stricter Review. The `--strict` Option Rejects Partial Coverage; `--require-compatible-metadata` Requires A Compatible Metadata Audit. Risk Findings Identify Potential Permission Capabilities, Not Confirmed Attacks.

| Exit Code | Meaning |
| --- | --- |
| 0 | Command Completed |
| 1 | Input, Execution Or Definite Compatibility Error |
| 2 | Strict coverage/validation Failure Or Truncated Runtime Retrieval |
| 3 | Missing Or Denied Grants When --fail-on-missing Is Enabled |
| 4 | Configured Security Gate Failed |

A Nonzero Exit Should Block The Corresponding CI Approval Stage. Keep Reports Private If They Contain Infrastructure Identifiers.

## AWS Validation And Runtime Evidence

### Authorization Metadata

~~~bash
tfiam catalog-audit --strict --format json
~~~

Built Distributions Include AWS Service Authorization Metadata. This Checks Catalog Action Recognition And Applicable scope/condition Compatibility; It Does Not Establish Effective IAM Permissions.

### IAM Access Analyzer

~~~bash
tfiam validate-policy policy.json \
  --aws-region "$AWS_REGION" \
  --strict --output validation.json
~~~

### CloudTrail Audit

Supply A **Scan Report** As The Candidate, Not A Generated IAM Policy Document.

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

Set `PIPELINE_ROLE_ARN` To The Actual Role ARN. Use `--session-name` For A Known STS Session, `--aws-profile` To Select Dedicated Audit Credentials, Or `--events` For An Offline CloudTrail Export. The Live Command Defaults To 100 Pages And A Cooperative 120-Second Budget.

Runtime Audit Distinguishes Observed Actions Outside The Candidates And Ambiguous API-To-IAM Mappings. Missing Events Do Not Demonstrate That Permissions Are Unnecessary.

| Optional Integration | AWS Actions, As Applicable |
| --- | --- |
| Live IAM Comparison | Iam:GetRole, Iam:ListAttachedRolePolicies, Iam:ListRolePolicies, Iam:GetPolicy, Iam:GetPolicyVersion, Iam:GetRolePolicy |
| Policy Validation | Access-Analyzer:ValidatePolicy |
| Runtime Audit | Cloudtrail:LookupEvents |

Use A Dedicated, Least-Privilege Audit Identity. No Live AWS Access Is Needed For Static Scanning, Generation Or Local Policy Comparison.

## Coverage And Validation

The Catalog Includes 157 Resource And Data-Source Mappings Across IAM, EC2/VPC, EKS, ECS, S3, RDS, DynamoDB, SQS, SNS, Lambda, KMS, ECR, CloudWatch, ELB And Other Supported AWS Services.

**v1.0.0 Acceptance** Was Performed With AWS Provider 6.73.0 Using Four Isolated Restricted-Role Fixtures:

| Fixture | Lifecycle Acceptance |
| --- | --- |
| S3 General-Purpose Empty Bucket | Passed |
| SQS Standard Empty Queue | Passed |
| VPC And Private Subnet | Passed |
| DynamoDB On-Demand Empty Table | Passed |

The Suite Covers Create, Read, Update, Replacement In Both Orders, Destroy, Negative Authorization And Cleanup Evidence. All Four Candidate Policies Passed Access Analyzer Validation. The Session-Filtered Runtime Audit Recorded 441 Matched Management Events And No Unmapped Operations.

These Results Validate The Tested Configurations, Not Every Catalog Entry. Provider Review Includes Conditional And Unresolved Mappings, Including Legacy S3 And IAM Operations. VPC Default ACL, Route-Table And Security-Group Discovery May Leave Computed IDs Unavailable Without Additional Read Grants. The S3 Fixture Relies On Supported Provider Tagging Fallbacks.

**Additional Mixed-Fixture Acceptance:** The Maintainer Reported Successful Create, Update And Destroy Of A Combined S3, SQS And DynamoDB Fixture With Empty Terraform State At Source Revision `5bbef87ec3bbbca209242a3c1d979034522e5588`. The EC2 Fixture Was Blocked By An Organization SCP. These Reported Results Are Separate From The Signed v1.1.0 Release Evidence.

**v1.1.0 Release Acceptance:** The [Signed Release Workflow](https://github.com/sm-joe/tf-iam/actions/runs/45066119415) Passed The Exact-Commit Evidence Gate And Published Attested Build Artifacts For Source Commit `f47c56999623945dc96135b772be4792e806bd3b`. See [Release Acceptance](docs/release-acceptance.md).

### Analysis Boundaries

- AWS And Terraform Are Supported; Other Cloud Providers Are Not Analyzed.
- The Scanner Reads Root And Reachable Local Modules And Previously Installed Remote Modules; It Does Not Install Modules Or Providers.
- Static Variable Precedence Follows Defaults, TF_VAR, Standard tfvars, Lexical Auto Files, Explicit Var-Files, Then Explicit Vars. Saved Plans Are Preferred For Exact Terraform Evaluation.
- Local And S3 Backends, S3 Lockfiles, Optional DynamoDB Locking And KMS Are Modeled; Workspace And Provider-Specific Cases Require Review.
- Unknown Names, Sensitive Fields, Unsupported Dependencies, Ambiguous Expressions And Some Generated IDs Are Reported Explicitly.
- Candidate Policies Are Not A Substitute For Effective Authorization Testing, Organizational Policy Review Or Deployment Approval.

## Documentation

| Guide | Description |
| --- | --- |
| [AWS Catalog](docs/aws-catalog.md) | Supported Mapping Inventory And Scope |
| [Action-Specific Scopes](docs/action-scope.md) | Resource Scoping And Dependency Rules |
| [Provider Validation](docs/provider-validation.md) | Provider-Version And Authorization Evidence |
| [Release Acceptance](docs/release-acceptance.md) | Validation Requirements And Lifecycle Fixtures |
| [Release Process](docs/release-process.md) | Maintainer Build And Signing Procedures |
| [Security Policy](SECURITY.md) | Vulnerability Reporting And Secure Usage |

## Development And Contributions

~~~bash
git clone https://github.com/sm-joe/tf-iam.git
cd tf-iam

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test,aws,packaging]'
python -m pytest -q
~~~

Build The Standalone Distribution:

~~~bash
python scripts/prepare-metadata.py
bash scripts/build-linux.sh
(cd dist && sha256sum -c SHA256SUMS)
~~~

Contributions Are Welcome Through [Issues](https://github.com/sm-joe/tf-iam/issues) And Pull Requests. Include A Sanitized Reproduction, Provider Version And Tests For New Mappings, Scope Changes Or Security-Related Behavior. Reference Official AWS Authorization Documentation. Live Acceptance Is Opt-In And Must Use An Isolated AWS Account.

## Security And License

Treat Terraform Plans, State And Analysis Reports As Confidential. The CLI Does Not Attach Generated Permissions Or Deploy Infrastructure. Report Vulnerabilities Privately As Described In The [Security Policy](SECURITY.md).

Released Under The [MIT License](LICENSE).

