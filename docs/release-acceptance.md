# Release acceptance gates

## Evidence reported by the maintainer

- [x] EKS no-op saved plan: 13 mapped resources, read-only candidates, exact Pod Identity ARN.
- [x] EKS destroy plan: 13 mapped resources and five conditional detach permissions; no resources destroyed.
- [x] AWS catalog action-name audit: 442 recognized actions, zero findings.
- [x] AWS provider lockfile extraction (6.73.0).
- [x] IAM Access Analyzer integration returned zero findings for the submitted policy.
- [x] Live IAM policy retrieval and comparison against an existing read-only role.
- [x] CloudTrail connectivity and empty-result handling; the selected role was not used in the period.
- [x] CI and standalone binary build on prior merged commits.

## Outstanding stable-release requirements

- [ ] Exact final commit CI and binary smoke test.
- [ ] Real isolated AWS create, read, update, delete and both replacement order tests using separate restricted Terraform identities for S3, SQS and VPC/subnet; service-specific denied operations and empty-state verification. Collect all three results using the structured evidence bundle described in [release process](release-process.md).
- [ ] Verify provider-version-specific API calls and action/ARN/condition compatibility across supported service families.
- [ ] Positive CloudTrail role activity and denial observations; verify no false claim of unused permissions.
- [ ] Validate module resolution, backend locking, privilege separation, security gates and secret redaction with reviewed evidence.
- [ ] Verify binary repeatability and signed build provenance.
- [ ] Digest-verified acceptance manifest linked to the exact release commit.
- [ ] Publish stable release only after review.

Unit tests and metadata compatibility do not substitute for live authorization verification. No production IAM policy should be attached solely on the basis of these reports.
