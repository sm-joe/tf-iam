# Security policy

## Supported versions

| Version | Security maintenance |
| --- | --- |
| 1.0.0 | Supported stable release |
| Unreleased development revisions | Best effort; use the latest stable release |

Security fixes are developed on the default branch and distributed through reviewed releases. This is a community-maintained project; no contractual response-time or support SLA is provided.

## Reporting a vulnerability

Report suspected vulnerabilities privately using [GitHub private vulnerability reporting](https://github.com/sm-joe/tf-iam/security/advisories/new). If private reporting is unavailable, contact the repository maintainer privately before disclosing technical details.

Please include:

- Affected release, commit and AWS provider version.
- Environment and the relevant CLI command.
- A minimal, sanitized Terraform configuration or policy that reproduces the issue.
- Expected behavior, actual behavior, and potential confidentiality, integrity, availability or privilege impact.
- Any suggested mitigation, if known.

Do not send AWS credentials, session tokens, real Terraform state, unredacted saved plans or proprietary infrastructure information. Public issues are appropriate for non-sensitive defects and feature requests.

Reports are reviewed for reproducibility, impact and affected versions. We aim to coordinate disclosure and publish remediation guidance when appropriate. Do not publicly disclose actionable exploit details before a fix or coordinated disclosure.

## Scope

Security-relevant reports include incorrect authorization or resource scoping, unsafe policy generation, bypass of configured risk gates, disclosure of sensitive inputs, command execution, dependency or distribution compromise, and unexpected AWS mutations.

A recognized resource mapping, partial coverage or an explicitly documented unsupported configuration is not by itself a vulnerability. Reports describing false confidence, missing mandatory permissions or excessive privilege should include the applicable configuration and provider behavior.

Only test systems and AWS accounts that you own or are explicitly authorized to assess. Avoid destructive tests, service disruption and access to third-party data.

## Security model

tf-iam is an analysis tool. Local scanning and policy generation do not execute Terraform, download providers, attach IAM policies or modify AWS infrastructure. Optional live integrations use AWS read and validation APIs with the caller's credentials.

Generated policies are candidates for independent review, not guarantees of least privilege or effective authorization. IAM permissions boundaries, service control policies, session policies, resource policies, conditional grants and provider behavior may alter the final authorization decision.

Use a dedicated audit identity for live integrations, separate policy approval from deployment, and never attach break-glass policies automatically. Do not suppress unresolved or risk findings solely to make a pipeline pass. Treat runtime observations as supporting evidence, not proof that unobserved permissions are unnecessary.

## Protecting sensitive data

Terraform state, saved plan JSON, reports and candidate policies may expose credentials, account identifiers, resource names or confidential architecture. Sensitive and unknown fields are withheld from inference where supported, but unmarked data may still appear in output.

- Restrict input and output directories to authorized users; use a restrictive umask.
- Do not commit real state, plans, credentials or private acceptance evidence.
- Avoid passing secrets through CLI values or shell history.
- Redact artifacts before sharing and enforce retention controls in CI.
- Use isolated AWS accounts for live lifecycle acceptance and review any cleanup operation before execution.

The project does not require AWS credentials for offline analysis. Optional cloud integrations should be enabled only when required.

## Release integrity

Download stable assets from [official GitHub releases](https://github.com/sm-joe/tf-iam/releases). Ordinary CI build artifacts are not signed stable releases.

Verify the executable and the signed source receipt before installation:

~~~bash
sha256sum -c SHA256SUMS
gh attestation verify tfiam --repo sm-joe/tf-iam
gh attestation verify release-source.json --repo sm-joe/tf-iam
~~~

Review the receipt's tested source commit against the release tag. Do not install artifacts that fail checksum or attestation verification. The release workflow rebuilds the exact accepted source, checks binary repeatability in its build environment and publishes GitHub build provenance. See [release process](docs/release-process.md) for maintainer procedures.

## Validation boundaries

The v1.0.0 release includes live restricted-role acceptance for four representative AWS fixtures. It does not certify every AWS service, Terraform configuration or effective IAM policy. Review the [provider validation guide](docs/provider-validation.md) for evidence scope and known limitations.

## License

tf-iam is distributed under the [MIT License](LICENSE).
