# Release Process

CI Tests Python 3.10, 3.12, 3.13 And 3.14 And Builds A Standalone Linux x86_64 Executable On Ubuntu 22.04. Ordinary CI Artifacts Are Unsigned And Are Not Releases.

## Isolated AWS Lifecycle Acceptance

Use A Clean Checkout At The Release Commit, Terraform, And `python -m pip install -e '.[aws,test]'`. Use An Isolated Commercial AWS Account And Four Dedicated Test Roles, Plus A Separate Audit Identity. These Tests Create And Destroy Real Resources And Can Incur Charges. Never Use Production Identities Or Upload The Fixture Directories.

```bash
umask 077
export AWS_PROVIDER_VERSION=6.73.0
EVIDENCE_DIR=$(mktemp -d)
for service in s3 sqs vpc dynamodb; do
  python "scripts/accept-$service.py" prepare "$EVIDENCE_DIR/$service" \
    --version "$AWS_PROVIDER_VERSION" --account "$AWS_ACCOUNT_ID" --region "$AWS_REGION"
done
```

Review Each Generated Candidate Policy Independently, Provision A Dedicated Temporary Assumed Role With Exactly Those Identity Grants, And Configure The Test And Audit Profiles Locally. No Script Creates Or Attaches IAM Policies. Run Each Fixture With Its Own Role And Profile:

```bash
for service in s3 sqs vpc dynamodb; do
  python "scripts/accept-$service.py" run "$EVIDENCE_DIR/$service" \
    --account "$AWS_ACCOUNT_ID" --test-profile "tfiam-$service" \
    --audit-profile tfiam-audit --role-name "tfiam-$service" \
    --confirm-isolated-aws-account || break
done
```

After All Four Pass, Independently Review Their CloudTrail And Identity Evidence, Then Collect Only The Required Sanitized Evidence Artifacts:

```bash
mkdir -p "$EVIDENCE_DIR/release"
python scripts/check-release.py "$EVIDENCE_DIR/release/lifecycle.json" \
  --collect-lifecycle --fixture-dir "$EVIDENCE_DIR/s3" \
  --fixture-dir "$EVIDENCE_DIR/sqs" --fixture-dir "$EVIDENCE_DIR/vpc" --fixture-dir "$EVIDENCE_DIR/dynamodb" \
  --expected-commit "$(git rev-parse HEAD)" --provider-version "$AWS_PROVIDER_VERSION"
```

Set The Manifest's `restricted-role-lifecycle` Artifact To `lifecycle.json` And Its Actual SHA-256. Include The Bundle's Referenced Files. Do Not Manufacture Evidence Or Publish Raw State, Logs Or Plans. The Fixture Suite Tests Representative Resource Families, Not Every Mapped AWS Resource. If A Fixture Fails, Retain Private State And Arrange Authorized Cleanup.

## Acceptance And Private Signing

Keep The Full Evidence Under A Private Persistent Local Directory. The Public
Repository Must Not Receive AWS Account Identifiers, Session ARNs, Candidate
Policies, State, Plans, Or CloudTrail Exports As Workflow Artifacts Or Commits.
A Successful Lifecycle Bundle Covers Only The Four Exact Fixtures, And The
Release Gate Verifies Structure And Digests Rather Than The Truth Of Evidence.

After All Four Access Analyzer Validations And Session-Filtered Runtime Audits
Have Been Collected, Run From The Exact Clean Accepted Source Checkout. The
Release Tooling May Be Fetched Separately Without Changing The Accepted Commit.
Use The Exact Successful main CI And Linux Build Run IDs:

```bash
umask 077
git fetch origin main
SOURCE_COMMIT=$(git rev-parse HEAD)
git show origin/main:scripts/assemble-release-evidence.py > "$EVIDENCE_DIR/assemble-release-evidence.py"
python "$EVIDENCE_DIR/assemble-release-evidence.py" prepare \
  --evidence-dir "$EVIDENCE_DIR" --source-commit "$SOURCE_COMMIT" \
  --provider-version "$AWS_PROVIDER_VERSION" \
  --ci-run-id "$CI_RUN_ID" --linux-run-id "$LINUX_RUN_ID"
```

Review `release/review-summary.json`, `release/provider-source-audit.json` And
All Referenced Evidence Privately. The Source Inventory May Have Review Items:
A Match Does Not Certify Transitive Provider Calls. S3 v6.73.0 Supports A
Fallback When Newer AWS Tagging Calls Are Denied. VPC v6.73.0 Logs Warnings And
May Leave Default Network ACL, Route Table And Security-Group IDs Unavailable
When The Corresponding Discovery Calls Are Denied. Configurations Relying On
Those Computed IDs Are Outside The Validated Fixture Scope.

Only After Independent Review, Seal The Manifest And Compact Evidence Archive:

```bash
python "$EVIDENCE_DIR/assemble-release-evidence.py" seal \
  --evidence-dir "$EVIDENCE_DIR" --source-commit "$SOURCE_COMMIT" \
  --provider-version "$AWS_PROVIDER_VERSION" --confirm-reviewed
python scripts/check-release.py "$EVIDENCE_DIR/release/manifest.json" \
  --expected-commit "$SOURCE_COMMIT"
```

Transfer The Compressed Archive Using A Temporary Actions Secret (Not An
Artifact). The Archive Has A 36,000-Byte Limit Before base64 Encoding, And The
Helper Refuses Larger Archives. Use Only A Trusted Repository With Reviewed
Workflows And Restrict Write Access: Privileged Repository Collaborators Can
Modify Workflows That Consume Secrets. Delete The Temporary Secret After The
Signing Run Has Consumed It. Do Not Split Or Upload Raw Evidence To Bypass A
Size Error.

```bash
set -o pipefail
ARCHIVE="$EVIDENCE_DIR/release-evidence.tar.gz"
EVIDENCE_SHA256=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
base64 -w 0 "$ARCHIVE" | gh secret set TFIAM_RELEASE_EVIDENCE --repo sm-joe/tf-iam
gh workflow run release-prepare.yml --repo sm-joe/tf-iam --ref main \
  -f source_commit="$SOURCE_COMMIT" -f evidence_sha256="$EVIDENCE_SHA256" \
  -f review_confirmed=true
```

The Workflow Verifies The Tested Source Is An Ancestor Of main, Checks The
Reviewed Archive And All Evidence Digests, Removes The Private Files, And
Rebuilds That Exact Source Twice. No AWS Inputs Are Published. The Public
Artifact Contains The Linux Executable, Checksums, And An Attested Digest-Only
`release-source.json` That Binds The Binary To The Tested Source And Evidence
Digests. GitHub'S Build Provenance Also Identifies The Workflow's Own Commit,
Which May Be A Later Release-Tooling Commit; The Release Tag Must Identify The
Tested Source Commit, Not The Release-Tooling Commit.

After The Signed Workflow Succeeds, Download Its Release Artifact And Verify:

```bash
gh run download "$SIGNED_RUN_ID" --repo sm-joe/tf-iam \
  --name tfiam-linux-x86_64-release --dir "$EVIDENCE_DIR/signed"
(cd "$EVIDENCE_DIR/signed" && sha256sum -c SHA256SUMS && \
  gh attestation verify tfiam --repo sm-joe/tf-iam && \
  gh attestation verify release-source.json --repo sm-joe/tf-iam)
gh secret delete TFIAM_RELEASE_EVIDENCE --repo sm-joe/tf-iam
```

Review The Receipt's Tested Source Commit, Archive Digest, Workflow Run ID And
Binary Digest. Publish Stable v1.0.0 Only After These Checks And Independent
Review, Targeting The Exact Accepted Commit. This Workflow Does Not Publish
Automatically. GitHub Attestation Availability Depends On Repository Plan.
Binary Repeatability Is Measured Within One Build Environment; Unlocked
Dependency Ranges Prevent A Guarantee Of Cross-Machine Reproducibility.

See [Acceptance Checklist](release-acceptance.md).
