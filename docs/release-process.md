# Release process

CI tests Python 3.10, 3.12, 3.13 and 3.14 and builds a standalone Linux x86_64 executable on Ubuntu 22.04. Ordinary CI artifacts are unsigned and are not releases.

## Isolated AWS lifecycle acceptance

Use a clean checkout at the release commit, Terraform, and `python -m pip install -e '.[aws,test]'`. Use an isolated commercial AWS account and three dedicated test roles, plus a separate audit identity. These tests create and destroy real resources and can incur charges. Never use production identities or upload the fixture directories.

```bash
umask 077
export AWS_PROVIDER_VERSION=6.73.0
EVIDENCE_DIR=$(mktemp -d)
for service in s3 sqs vpc; do
  python "scripts/accept-$service.py" prepare "$EVIDENCE_DIR/$service" \
    --version "$AWS_PROVIDER_VERSION" --account "$AWS_ACCOUNT_ID" --region "$AWS_REGION"
done
```

Review each generated candidate policy independently, provision a dedicated temporary assumed role with exactly those identity grants, and configure the test and audit profiles locally. No script creates or attaches IAM policies. Run each fixture with its own role and profile:

```bash
for service in s3 sqs vpc; do
  python "scripts/accept-$service.py" run "$EVIDENCE_DIR/$service" \
    --account "$AWS_ACCOUNT_ID" --test-profile "tfiam-$service" \
    --audit-profile tfiam-audit --role-name "tfiam-$service" \
    --confirm-isolated-aws-account || break
done
```

After all three pass, independently review their CloudTrail and identity evidence, then collect only the required sanitized evidence artifacts:

```bash
mkdir -p "$EVIDENCE_DIR/release"
python scripts/check-release.py "$EVIDENCE_DIR/release/lifecycle.json" \
  --collect-lifecycle --fixture-dir "$EVIDENCE_DIR/s3" \
  --fixture-dir "$EVIDENCE_DIR/sqs" --fixture-dir "$EVIDENCE_DIR/vpc" \
  --expected-commit "$(git rev-parse HEAD)" --provider-version "$AWS_PROVIDER_VERSION"
```

Set the manifest's `restricted-role-lifecycle` artifact to `lifecycle.json` and its actual SHA-256. Include the bundle's referenced files. Do not manufacture evidence or publish raw state, logs or plans. The fixture suite tests representative resource families, not every mapped AWS resource. If a fixture fails, retain private state and arrange authorized cleanup.

## Acceptance

Prepare a private evidence directory with manifest.json and sanitized artifacts. Each required check is defined in scripts/check-release.py and must contain status "passed", artifact (relative path), and sha256. Include the exact tested commit and provider_version. Use only reviewed real results; do not upload secrets or raw state. The checker verifies integrity and presence, not the truth of the contents.

```bash
python scripts/check-release.py evidence/manifest.json --expected-commit "$(git rev-parse HEAD)"
```

The maintainer must review the actual evidence before using the manual signed-release workflow. Its artifact input must be a trusted GitHub Actions run containing the reviewed evidence manifest and files. Restrict access to acceptance evidence. The workflow refuses a mismatched commit, runs regressions, builds twice in the same environment, checks byte equality and smoke-tests the executable before creating signed GitHub build provenance. This repeatability check is not a guarantee of reproducibility across machines or future dependency selections; dependency ranges remain unlocked.

Verify the resulting artifact:

```bash
sha256sum -c SHA256SUMS
gh attestation verify tfiam --repo sm-joe/tf-iam
```

Only after all checks and independent review should the maintainer create the stable v1.0.0 tag and release using the exact attested artifact. This workflow deliberately does not automatically publish a release. GitHub artifact attestation availability depends on repository visibility and plan.

See [acceptance checklist](release-acceptance.md).
