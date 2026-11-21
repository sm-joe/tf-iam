# Release process

CI tests Python 3.10, 3.12, 3.13 and 3.14 and builds a standalone Linux x86_64 executable on Ubuntu 22.04. Ordinary CI artifacts are unsigned and are not releases.

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
