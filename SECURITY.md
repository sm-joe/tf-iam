# Security

Treat generated roles as untrusted permission recommendations. Review resource scopes, privilege escalation paths, role assignments and provider API requirements before deployment. Never grant the scanner credentials or use it to automatically revoke permissions. Use separate state and deployment identities where practical. Report vulnerabilities privately to the repository maintainer; do not publish credentials or sensitive state in issues.

Saved Terraform plan JSON can contain secrets in cleartext. Restrict file and report access; do not commit real plan files. The scanner masks values marked sensitive or unknown by Terraform, but unmarked identifiers may be emitted in IAM scopes.
