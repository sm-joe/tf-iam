# Release process

CI tests Python 3.10, 3.12, 3.13 and 3.14 and builds a standalone Linux x86_64 executable on Ubuntu 22.04. Ordinary CI artifacts are unsigned and are not releases.

## Isolated AWS lifecycle acceptance

Use a clean checkout at the release commit, Terraform, and `python -m pip install -e '.[aws,test]'`. Use an isolated commercial AWS account and four dedicated test roles, plus a separate audit identity. These tests create and destroy real resources and can incur charges. Never use production identities or upload the fixture directories.

```bash
umask 077
export AWS_PROVIDER_VERSION=6.73.0
EVIDENCE_DIR=$(mktemp -d)
for service in s3 sqs vpc dynamodb; do
  python "scripts/accept-$service.py" prepare "$EVIDENCE_DIR/$service" \
    --version "$AWS_PROVIDER_VERSION" --account "$AWS_ACCOUNT_ID" --region "$AWS_REGION"
done
```

Review each generated candidate policy independently, provision a dedicated temporary assumed role with exactly those identity grants, and configure the test and audit profiles locally. No script creates or attaches IAM policies. Run each fixture with its own role and profile:

```bash
for service in s3 sqs vpc dynamodb; do
  python "scripts/accept-$service.py" run "$EVIDENCE_DIR/$service" \
    --account "$AWS_ACCOUNT_ID" --test-profile "tfiam-$service" \
    --audit-profile tfiam-audit --role-name "tfiam-$service" \
    --confirm-isolated-aws-account || break
done
```

After all four pass, independently review their CloudTrail and identity evidence, then collect only the required sanitized evidence artifacts:

```bash
mkdir -p "$EVIDENCE_DIR/release"
python scripts/check-release.py "$EVIDENCE_DIR/release/lifecycle.json" \
  --collect-lifecycle --fixture-dir "$EVIDENCE_DIR/s3" \
  --fixture-dir "$EVIDENCE_DIR/sqs" --fixture-dir "$EVIDENCE_DIR/vpc" --fixture-dir "$EVIDENCE_DIR/dynamodb" \
  --expected-commit "$(git rev-parse HEAD)" --provider-version "$AWS_PROVIDER_VERSION"
```

Set the manifest's `restricted-role-lifecycle` artifact to `lifecycle.json` and its actual SHA-256. Include the bundle's referenced files. Do not manufacture evidence or publish raw state, logs or plans. The fixture suite tests representative resource families, not every mapped AWS resource. If a fixture fails, retain private state and arrange authorized cleanup.

## Acceptance and private signing

Keep the full evidence under a private persistent local directory. The public
repository must not receive AWS account identifiers, session ARNs, candidate
policies, state, plans, or CloudTrail exports as workflow artifacts or commits.
A successful lifecycle bundle covers only the four exact fixtures, and the
release gate verifies structure and digests rather than the truth of evidence.

After all four Access Analyzer validations and session-filtered runtime audits
have been collected, run from the exact clean accepted source checkout. The
release tooling may be fetched separately without changing the accepted commit.
Use the exact successful main CI and Linux build run IDs:

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

Review `release/review-summary.json`, `release/provider-source-audit.json` and
all referenced evidence privately. The source inventory may have review items:
a match does not certify transitive provider calls. S3 v6.73.0 supports a
fallback when newer AWS tagging calls are denied. VPC v6.73.0 logs warnings and
may leave default network ACL, route table and security-group IDs unavailable
when the corresponding discovery calls are denied. Configurations relying on
those computed IDs are outside the validated fixture scope.

Only after independent review, seal the manifest and compact evidence archive:

```bash
python "$EVIDENCE_DIR/assemble-release-evidence.py" seal \
  --evidence-dir "$EVIDENCE_DIR" --source-commit "$SOURCE_COMMIT" \
  --provider-version "$AWS_PROVIDER_VERSION" --confirm-reviewed
python scripts/check-release.py "$EVIDENCE_DIR/release/manifest.json" \
  --expected-commit "$SOURCE_COMMIT"
```

Transfer the compressed archive using a temporary Actions secret (not an
artifact). The archive has a 36,000-byte limit before base64 encoding, and the
helper refuses larger archives. Use only a trusted repository with reviewed
workflows and restrict write access: privileged repository collaborators can
modify workflows that consume secrets. Delete the temporary secret after the
signing run has consumed it. Do not split or upload raw evidence to bypass a
size error.

```bash
set -o pipefail
ARCHIVE="$EVIDENCE_DIR/release-evidence.tar.gz"
EVIDENCE_SHA256=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
base64 -w 0 "$ARCHIVE" | gh secret set TFIAM_RELEASE_EVIDENCE --repo sm-joe/tf-iam
gh workflow run release-prepare.yml --repo sm-joe/tf-iam --ref main \
  -f source_commit="$SOURCE_COMMIT" -f evidence_sha256="$EVIDENCE_SHA256" \
  -f review_confirmed=true
```

The workflow verifies the tested source is an ancestor of main, checks the
reviewed archive and all evidence digests, removes the private files, and
rebuilds that exact source twice. No AWS inputs are published. The public
artifact contains the Linux executable, checksums, and an attested digest-only
`release-source.json` that binds the binary to the tested source and evidence
digests. GitHub's build provenance also identifies the workflow's own commit,
which may be a later release-tooling commit; the release tag must identify the
tested source commit, not the release-tooling commit.

After the signed workflow succeeds, download its release artifact and verify:

```bash
gh run download "$SIGNED_RUN_ID" --repo sm-joe/tf-iam \
  --name tfiam-linux-x86_64-release --dir "$EVIDENCE_DIR/signed"
(cd "$EVIDENCE_DIR/signed" && sha256sum -c SHA256SUMS && \
  gh attestation verify tfiam --repo sm-joe/tf-iam && \
  gh attestation verify release-source.json --repo sm-joe/tf-iam)
gh secret delete TFIAM_RELEASE_EVIDENCE --repo sm-joe/tf-iam
```

Review the receipt's tested source commit, archive digest, workflow run ID and
binary digest. Publish stable v1.0.0 only after these checks and independent
review, targeting the exact accepted commit. This workflow does not publish
automatically. GitHub attestation availability depends on repository plan.
Binary repeatability is measured within one build environment; unlocked
dependency ranges prevent a guarantee of cross-machine reproducibility.

See [acceptance checklist](release-acceptance.md).
