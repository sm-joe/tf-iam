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
