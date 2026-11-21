# Release process

The Linux build workflow produces an unsigned standalone x86_64 executable and SHA256SUMS on every PR and main push. It does not publish a release. Python is required on the build host, not the target Linux host. AWS credentials are never required for the build. The build uses a fixed runner family but dependency ranges are not a reproducible lock; byte-for-byte reproducibility and signing remain required before stable publication.

Run the acceptance checker against a private evidence manifest:

```bash
python scripts/check-release.py evidence/manifest.json
```

The manifest contains commit, provider_version, and checks keyed by the names in REQUIRED. Each check has status passed, artifact (relative path below the manifest directory), and sha256. A passing checker verifies presence and integrity, not the truth of the evidence. Review actual logs and isolated AWS authorization results before creating a tag. No release or tag is created by this branch.
