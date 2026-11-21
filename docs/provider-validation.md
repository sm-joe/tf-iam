# Maintainer-only provider and catalog validation

This document is for maintainers and CI, not the end-user workflow. Normal scans and policy generation read packaged mappings, and built distributions include AWS authorization metadata. They never fetch provider source or metadata. Do not ask users to run the commands below as a condition of using tf-iam.

The lockfile provides the selected AWS provider version, not proof of permission accuracy. The scanner records the exact stable version and its provenance. Explicit --aws-provider-version is available for plan-only analysis and must agree with a present lockfile. Version-specific catalog overrides can replace lifecycle and attribute action sets for an exact version; untested versions fall back to candidate mappings. Evidence records require an exact provider version, HTTPS source reference and SHA-256 digest. A lifecycle-verified label requires a corresponding evidence record; no live evidence is asserted by this change.

Mapping coverage counts recognized non-skipped resource changes; it is not authorization confidence. Provider source review and lifecycle verification are separate. Neither the lockfile nor a recognized action proves a provider operation is authorized. All current entries remain candidates.

## Offline AWS service authorization metadata

Download public reference snapshots (no AWS credentials or infrastructure files are sent):

```bash
python scripts/maintainer.py catalog-audit --metadata-dir .aws-auth --refresh --output catalog-audit.json
tfiam scan ./infra --plan-json plan.json --authorization-metadata .aws-auth --format json --output report.json
```

Without --refresh, the auditor reads local snapshots only. Reports include source URLs, metadata versions and SHA-256 digests. Action names, resource ARN templates and advertised condition-key compatibility are checked. Missing services, incomplete metadata, global scopes where resource scoping is supported, and unlisted condition keys are reported separately. Global condition availability and actual request context cannot be inferred from a service's key list. The auditor does not certify multi-resource completeness, condition values, provider API calls or effective IAM permission. Metadata findings do not upgrade provider validation. Generation with supplied metadata rejects definite incompatibilities. Use --strict to gate a catalog audit (exit 2 for any finding).

Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html

The snapshots are user-managed evidence, not signed AWS attestations. Retain them with reports for reproducibility. No live AWS provisioning tests have been performed.

## Source-backed reconciliation (M14)

The AWS Service Authorization Reference is the action, ARN and condition-key authority. Its Operations/AuthorizedActions entries map SDK operations to possible actions, not necessarily all required simultaneously. Provider source defines which operations are called. The initial source inventory covers nine S3, EKS and IAM resource types. Use the official pinned tag:

```bash
git clone --depth 1 --branch v6.73.0 https://github.com/hashicorp/terraform-provider-aws.git /tmp/tfiam-provider-6.73.0
python scripts/maintainer.py catalog-audit --metadata-dir /tmp/tfiam-aws-auth --refresh
python scripts/maintainer.py provider-audit --source-dir /tmp/tfiam-provider-6.73.0 --aws-provider-version 6.73.0 --metadata-dir /tmp/tfiam-aws-auth --format json --show-table --output provider-source-audit.json
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

The source-reviewed v6.73.0 overrides for general-purpose S3 public access block and versioning are pinned to the actual provider file digests. Create/update/delete retain the documented operation actions; versioning deletion suspends versioning, while DeletePublicAccessBlock authorizes PutBucketPublicAccessBlock. Directory buckets and MFA-specific cases are not covered by the fixture. Both entries remain candidate mappings, not lifecycle-verified.

### Reconcile live results

Run the new evidence command after CloudTrail history has ingested the test events:

```bash
python scripts/maintainer.py evidence-audit \
  --lifecycle /tmp/tfiam-s3-fixture/lifecycle-evidence.json \
  --policy /tmp/tfiam-s3-fixture/candidate-policy.json \
  --lockfile /tmp/tfiam-s3-fixture/.terraform.lock.hcl \
  --source-report provider-source-audit.json \
  --metadata-dir /tmp/tfiam-aws-auth \
  --aws-profile tfiam-audit \
  --strict --format json --show-table --output s3-evidence-audit.json
```

Offline `--events` supports CloudTrail Records or LookupEvents exports. Matching requires the exact session ARN and role issuer ARN, the fixture time window, the pinned provider version, matching candidate and lockfile digests, all six expected lifecycle plan shapes, and matching metadata digests. The result also requires positive create, delete, public-access-block and versioning observations and the expected ListAllMyBuckets denial. Unmapped and conditional operations are surfaced. The report is a review gate for this fixture only, not an automatic catalog promotion.

The v6.73.0 IAM role override also includes source-confirmed role inline-policy reads, role description updates, and the unconditional instance-profile inventory preceding role deletion. The instance-profile removal branch requires actual instance-profile identities; this correction does not issue broad instance-profile mutation grants. This override remains a candidate, with additional conditional branches surfaced through provider-audit. The CI source-evidence job recreates the public provider/metadata report and checks the reviewed source file digests. Add `--require-lifecycle-verified` to scan/generate/split/compare when exact-version verified-only results are required; it fails closed until evidence exists for every applicable resource and no permission is unresolved.

## Distribution assembly

CI executes `python scripts/prepare-metadata.py` once before building a distribution. It fetches official AWS metadata for the union of base and version-specific catalog actions, rejects unrecognized actions, and packages the original snapshots and SHA-256 manifest. Both the Linux binary and wheel contain that data. Runtime scans check local snapshot integrity and automatically audit generated grants. No runtime network fallback is permitted. Release repeatability uses the same prepared snapshot for both builds. Source installations without the build-produced snapshot remain usable for offline catalog inference and explicitly report metadata as not run.
