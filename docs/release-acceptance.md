# Release acceptance gates

- [x] Real EKS no-op saved plan: user reported all 13 resources recognized and read-only candidates.
- [ ] Real Terraform create, update, delete and both replacement orders: verify generated policy matches the exact planned operation.
- [ ] Execute isolated AWS Terraform lifecycle with generated restricted CI/CD identities; capture CloudTrail and authorization failures.
- [ ] Validate policy actions, ARN types and conditions using AWS IAM Access Analyzer and provider-version-specific evidence.
- [ ] Validate module inputs, nested and installed modules against Terraform plan output.
- [ ] Verify no silent privilege wildcard fallback, backend locks and state access, strict coverage gates and secret redaction.
- [ ] Signed reproducible Linux CLI release and passing CI.
 
Unit tests and mapping coverage are not equivalent to live acceptance.

- [ ] Validate each expanded AWS service family with provider-version-pinned lifecycle fixtures and action-specific resource authorization; recognized mappings alone do not satisfy acceptance.

- [ ] Verify M05 multi-resource authorization, tag conditions, KMS before/after keys and EKS identity scopes in isolated AWS lifecycle executions. Confirm all omissions are resolved before production release.

- [ ] M06: retain exact provider version, source review and lifecycle evidence digests; validate all supported mappings against AWS authorization metadata.
