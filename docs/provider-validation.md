# Provider-version-aware validation (M06)

The lockfile provides the selected AWS provider version, not proof of permission accuracy. The scanner records the exact stable version and its provenance. Explicit --aws-provider-version is available for plan-only analysis and must agree with a present lockfile. Version-specific catalog overrides can replace lifecycle and attribute action sets for an exact version; untested versions fall back to candidate mappings. Evidence records require an exact provider version, HTTPS source reference and SHA-256 digest. A lifecycle-verified label requires a corresponding evidence record; no live evidence is asserted by this change.

Mapping coverage counts recognized non-skipped resource changes; it is not authorization confidence. Provider source review and lifecycle verification are separate. Neither the lockfile nor a recognized action proves a provider operation is authorized. All current entries remain candidates.

## Offline AWS service authorization metadata

Download public reference snapshots (no AWS credentials or infrastructure files are sent):

```bash
tfiam catalog-audit --metadata-dir .aws-auth --refresh --output catalog-audit.json
tfiam scan ./infra --plan-json plan.json --authorization-metadata .aws-auth --format json --output report.json
```

Without --refresh, the auditor reads local snapshots only. Reports include source URLs, metadata versions and SHA-256 digests. Action names, resource ARN templates and advertised condition-key compatibility are checked. Missing services, incomplete metadata, global scopes where resource scoping is supported, and unlisted condition keys are reported separately. Global condition availability and actual request context cannot be inferred from a service's key list. The auditor does not certify multi-resource completeness, condition values, provider API calls or effective IAM permission. Metadata findings do not upgrade provider validation. Generation with supplied metadata rejects definite incompatibilities. Use --strict to gate a catalog audit (exit 2 for any finding).

Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html

The snapshots are user-managed evidence, not signed AWS attestations. Retain them with reports for reproducibility. No live AWS provisioning tests have been performed.

## Source-backed reconciliation (M14)

The AWS Service Authorization Reference is the action, ARN and condition-key authority. Its Operations/AuthorizedActions entries map SDK operations to possible actions, not necessarily all required simultaneously. Provider source defines which operations are called. The initial source inventory covers nine S3, EKS and IAM resource types. Use the official pinned tag:

```bash
git clone --depth 1 --branch v6.73.0 https://github.com/hashicorp/terraform-provider-aws.git /tmp/tfiam-provider-6.73.0
tfiam catalog-audit --metadata-dir /tmp/tfiam-aws-auth --refresh
tfiam provider-audit --source-dir /tmp/tfiam-provider-6.73.0 --aws-provider-version 6.73.0 --metadata-dir /tmp/tfiam-aws-auth --format json --show-table --output provider-source-audit.json
```

The report contains provider commit, source SHA-256, metadata digests, call-site lines, and candidate differences. Direct-call matches do not certify transitively invoked helpers or conditional behavior. Do not add every AuthorizedActions alternative to a policy. Review each missing candidate against its actual provider branch, resource scope, and AWS action documentation before adding it.

## Isolated live S3 lifecycle acceptance (M15)

Requires Terraform, Python AWS extra, a separate dedicated AWS test account, an audit profile with read-only IAM inspection permissions, and a dedicated assumed-role profile. The harness creates two uniquely named, empty general-purpose buckets sequentially; it does not attach IAM policies, use production state, or auto-escalate. AWS API usage and charges are possible. Use an administrator to review the candidate and configure the dedicated role before executing the run. Do not add broad managed policies.

```bash
python scripts/accept-s3.py prepare /tmp/tfiam-s3-fixture --version 6.73.0 --account "$AWS_ACCOUNT_ID" --region "$AWS_REGION"
tfiam validate-policy /tmp/tfiam-s3-fixture/candidate-policy.json --aws-region "$AWS_REGION" --strict --format table
# Review and provision dedicated role with exactly candidate-policy.json first.
python scripts/accept-s3.py run /tmp/tfiam-s3-fixture --account "$AWS_ACCOUNT_ID" --test-profile tfiam-test --audit-profile tfiam-audit --role-name TfiamS3Acceptance --confirm-isolated-aws-account
```

The runner checks exact identity policy grants, assumed-role identity and the selected provider lockfile. It executes create, no-op read, update, both replacement orders and destroy, checks expected plan actions before applying, and tests denial of ListAllMyBuckets. Logs and Terraform state/plans stay private. If a step fails, stop and inspect; partial state can remain and must be cleaned up with a separately authorized identity. The fixture evidence is scoped to these configurations, not certification of every branch or service. Do not relabel the catalog validated solely on fixture completion.

## Runtime reconciliation and reviewed catalog (M16–M17)

Collect positive CloudTrail observations for the same dedicated role and interval after the events are available. CloudTrail does not log every authorization decision (notably PassRole) and regional history excludes data events. Inspect denied and unknown operations. Retain source review, AWS metadata, exact configuration/plan digests, reviewed roles and lifecycle reports. A maintainer reviews these before committing version-specific evidence; no unreviewed run automatically changes the packaged catalog. Broader EKS/IAM fixture coverage and catalog-wide verification remain required.
