# Maintainer-Only Provider And Catalog Validation

This Document Is For Maintainers And CI, Not The End-User Workflow. Normal Scans And Policy Generation Read Packaged Mappings, And Built Distributions Include AWS Authorization Metadata. They Never Fetch Provider Source Or Metadata. Do Not Ask Users To Run The Commands Below As A Condition Of Using tf-iam.

The Lockfile Provides The Selected AWS Provider Version, Not Proof Of Permission Accuracy. The Scanner Records The Exact Stable Version And Its Provenance. Explicit --aws-provider-version Is Available For Plan-Only Analysis And Must Agree With A Present Lockfile. Version-Specific Catalog Overrides Can Replace Lifecycle And Attribute Action Sets For An Exact Version; Untested Versions Fall Back To Candidate Mappings. Evidence Records Require An Exact Provider Version, HTTPS Source Reference And SHA-256 Digest. A Lifecycle-Verified Label Requires A Corresponding Evidence Record; The Stable Release Has Separate Live Fixture Evidence.

Mapping Coverage Counts Recognized Non-Skipped Resource Changes; It Is Not Authorization Confidence. Provider Source Review And Lifecycle Verification Are Separate. Neither The Lockfile Nor A Recognized Action Proves A Provider Operation Is Authorized. All Current Entries Remain Candidates.

## Offline AWS Service Authorization Metadata

Download Public Reference Snapshots (No AWS Credentials Or Infrastructure Files Are Sent):

```bash
python scripts/maintainer.py catalog-audit --metadata-dir .aws-auth --refresh --output catalog-audit.json
tfiam scan ./infra --plan-json plan.json --authorization-metadata .aws-auth --format json --output report.json
```

Without --refresh, The Auditor Reads Local Snapshots Only. Reports Include Source URLs, Metadata Versions And SHA-256 Digests. Action Names, Resource ARN Templates And Advertised Condition-Key Compatibility Are Checked. Missing Services, Incomplete Metadata, Global Scopes Where Resource Scoping Is Supported, And Unlisted Condition Keys Are Reported Separately. Global Condition Availability And Actual Request Context Cannot Be Inferred From A Service's Key List. The Auditor Does Not Certify Multi-Resource Completeness, Condition Values, Provider API Calls Or Effective IAM Permission. Metadata Findings Do Not Upgrade Provider Validation. Generation With Supplied Metadata Rejects Definite Incompatibilities. Use --strict To Gate A Catalog Audit (Exit 2 For Any Finding).

Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html

The Snapshots Are User-Managed Evidence, Not Signed AWS Attestations. Retain Them With Reports For Reproducibility. The Stable Release Includes Isolated Live Acceptance For S3, SQS, VPC/subnet And DynamoDB; These Snapshots Alone Do Not Establish That Evidence.

## Source-Backed Reconciliation (M14)

The AWS Service Authorization Reference Is The Action, ARN And Condition-Key Authority. Its Operations/AuthorizedActions Entries Map SDK Operations To Possible Actions, Not Necessarily All Required Simultaneously. Provider Source Defines Which Operations Are Called. The Initial Source Inventory Covers Nine S3, EKS And IAM Resource Types. Use The Official Pinned Tag:

```bash
git clone --depth 1 --branch v6.73.0 https://github.com/hashicorp/terraform-provider-aws.git /tmp/tfiam-provider-6.73.0
python scripts/maintainer.py catalog-audit --metadata-dir /tmp/tfiam-aws-auth --refresh
python scripts/maintainer.py provider-audit --source-dir /tmp/tfiam-provider-6.73.0 --aws-provider-version 6.73.0 --metadata-dir /tmp/tfiam-aws-auth --format json --show-table --output provider-source-audit.json
```

The Report Contains Provider Commit, Source SHA-256, Metadata Digests, Call-Site Lines, And Candidate Differences. Direct-Call Matches Do Not Certify Transitively Invoked Helpers Or Conditional Behavior. Do Not Add Every AuthorizedActions Alternative To A Policy. Review Each Missing Candidate Against Its Actual Provider Branch, Resource Scope, And AWS Action Documentation Before Adding It.

## Isolated Live S3 Lifecycle Acceptance (M15)

Requires Terraform, Python AWS Extra, A Separate Dedicated AWS Test Account, An Audit Profile With Read-Only IAM Inspection Permissions, And A Dedicated Assumed-Role Profile. The Harness Creates Two Uniquely Named, Empty General-Purpose Buckets Sequentially; It Does Not Attach IAM Policies, Use Production State, Or Auto-Escalate. AWS API Usage And Charges Are Possible. Use An Administrator To Review The Candidate And Configure The Dedicated Role Before Executing The Run. Do Not Add Broad Managed Policies.

```bash
python scripts/accept-s3.py prepare /tmp/tfiam-s3-fixture --version 6.73.0 --account "$AWS_ACCOUNT_ID" --region "$AWS_REGION"
tfiam validate-policy /tmp/tfiam-s3-fixture/candidate-policy.json --aws-region "$AWS_REGION" --strict --format table
# Review and provision dedicated role with exactly candidate-policy.json first.
python scripts/accept-s3.py run /tmp/tfiam-s3-fixture --account "$AWS_ACCOUNT_ID" --test-profile tfiam-test --audit-profile tfiam-audit --role-name TfiamS3Acceptance --confirm-isolated-aws-account
```

The Runner Checks Exact Identity Policy Grants, Assumed-Role Identity And The Selected Provider Lockfile. It Executes Create, No-Op Read, Update, Both Replacement Orders And Destroy, Checks Expected Plan Actions Before Applying, And Tests Denial Of ListAllMyBuckets. Logs And Terraform state/plans Stay Private. If A Step Fails, Stop And Inspect; Partial State Can Remain And Must Be Cleaned Up With A Separately Authorized Identity. The Fixture Evidence Is Scoped To These Configurations, Not Certification Of Every Branch Or Service. Do Not Relabel The Catalog Validated Solely On Fixture Completion.

## Runtime Reconciliation And Reviewed Catalog (M16–M17)

Collect Positive CloudTrail Observations For The Same Dedicated Role And Interval After The Events Are Available. CloudTrail Does Not Log Every Authorization Decision (Notably PassRole) And Regional History Excludes Data Events. Inspect Denied And Unknown Operations. Retain Source Review, AWS Metadata, Exact configuration/plan Digests, Reviewed Roles And Lifecycle Reports. A Maintainer Reviews These Before Committing Version-Specific Evidence; No Unreviewed Run Automatically Changes The Packaged Catalog. Broader EKS/IAM Fixture Coverage And Catalog-Wide Verification Remain Required.

The Source-Reviewed v6.73.0 Overrides For General-Purpose S3 Public Access Block And Versioning Are Pinned To The Actual Provider File Digests. Create/update/delete Retain The Documented Operation Actions; Versioning Deletion Suspends Versioning, While DeletePublicAccessBlock Authorizes PutBucketPublicAccessBlock. Directory Buckets And MFA-Specific Cases Are Not Covered By The Fixture. Both Entries Remain Candidate Mappings, Not Lifecycle-Verified.

### Reconcile Live Results

Run The New Evidence Command After CloudTrail History Has Ingested The Test Events:

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

Offline `--events` Supports CloudTrail Records Or LookupEvents Exports. Matching Requires The Exact Session ARN And Role Issuer ARN, The Fixture Time Window, The Pinned Provider Version, Matching Candidate And Lockfile Digests, All Six Expected Lifecycle Plan Shapes, And Matching Metadata Digests. The Result Also Requires Positive Create, Delete, Public-Access-Block And Versioning Observations And The Expected ListAllMyBuckets Denial. Unmapped And Conditional Operations Are Surfaced. The Report Is A Review Gate For This Fixture Only, Not An Automatic Catalog Promotion.

The v6.73.0 IAM Role Override Also Includes Source-Confirmed Role Inline-Policy Reads, Role Description Updates, And The Unconditional Instance-Profile Inventory Preceding Role Deletion. The Instance-Profile Removal Branch Requires Actual Instance-Profile Identities; This Correction Does Not Issue Broad Instance-Profile Mutation Grants. This Override Remains A Candidate, With Additional Conditional Branches Surfaced Through Provider-Audit. The CI Source-Evidence Job Recreates The Public provider/metadata Report And Checks The Reviewed Source File Digests. Add `--require-lifecycle-verified` To scan/generate/split/compare When Exact-Version Verified-Only Results Are Required; It Fails Closed Until Evidence Exists For Every Applicable Resource And No Permission Is Unresolved.

## Distribution Assembly

CI Executes `python scripts/prepare-metadata.py` Once Before Building A Distribution. It Fetches Official AWS Metadata For The Union Of Base And Version-Specific Catalog Actions, Rejects Unrecognized Actions, And Packages The Original Snapshots And SHA-256 Manifest. Both The Linux Binary And Wheel Contain That Data. Runtime Scans Check Local Snapshot Integrity And Automatically Audit Generated Grants. No Runtime Network Fallback Is Permitted. Release Repeatability Uses The Same Prepared Snapshot For Both Builds. Source Installations Without The Build-Produced Snapshot Remain Usable For Offline Catalog Inference And Explicitly Report Metadata As Not Run.
