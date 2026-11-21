# Security Policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/sm-joe/tf-iam/security/advisories/new) when available. If it is unavailable, contact the repository maintainer privately before sharing details publicly. Include the affected commit/version, reproducible steps, impact and a sanitized minimal example. Do not include AWS access keys, tokens, real Terraform state, plan files, role credentials or proprietary infrastructure data.

Do not test against systems you do not own or have authorization to assess. Public issues are appropriate for non-sensitive bugs.

## Security model

TF IAM Scope performs local analysis by default. Optional integrations retrieve public metadata or use AWS read/validation APIs with the caller's credentials. The tool does not attach policies, deploy Terraform, mutate infrastructure or automatically revoke permissions. Use a separate least-privilege audit identity and external approval controls.

Generated policies are candidate artifacts, not verified least-privilege guarantees. Mapping coverage, Access Analyzer and runtime observations do not establish effective policy authority. Review boundaries, SCPs, resource policies, session policies, unknown dependencies, service-linked roles and provider-version lifecycle behavior. Never automatically deploy a break-glass policy.

## Sensitive data

Terraform plans and state may contain plaintext secrets. Store them in protected ephemeral storage, restrict output access and avoid uploading or committing them. Terraform-marked sensitive/unknown values are withheld from inference where supported; unmarked identifiers can remain in outputs. Do not pass secrets via command-line variables. Redact reports before sharing.

## Distribution integrity

Use trusted repository releases, verify SHA-256 checksums and signed GitHub build provenance. CI build artifacts are not stable releases; accept only reviewed artifacts. See [release process](docs/release-process.md).

## Supported versions

Security fixes are developed on the main branch. Once a stable release is published, consult release notes for supported versions. No maintenance SLA or response-time guarantee is implied.
