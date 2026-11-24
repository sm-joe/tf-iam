# Security Policy

## Supported Versions

| Version | Security Maintenance |
| --- | --- |
| 1.0.0 | Previous Stable Release; Upgrade To 1.1.0 |
| 1.1.0 | Latest Stable Release |
| Unreleased Development Revisions | Best Effort; Use The Latest Stable Release |

Security Fixes Are Developed On The Default Branch And Distributed Through Reviewed Releases. This Is A Community-Maintained Project; No Contractual Response-Time Or Support SLA Is Provided.

## Reporting A Vulnerability

Report Suspected Vulnerabilities Privately Using [GitHub Private Vulnerability Reporting](https://github.com/sm-joe/tf-iam/security/advisories/new). If Private Reporting Is Unavailable, Contact The Repository Maintainer Privately Before Disclosing Technical Details.

Please Include:

- Affected Release, Commit And AWS Provider Version.
- Environment And The Relevant CLI Command.
- A Minimal, Sanitized Terraform Configuration Or Policy That Reproduces The Issue.
- Expected Behavior, Actual Behavior, And Potential Confidentiality, Integrity, Availability Or Privilege Impact.
- Any Suggested Mitigation, If Known.

Do Not Send AWS Credentials, Session Tokens, Real Terraform State, Unredacted Saved Plans Or Proprietary Infrastructure Information. Public Issues Are Appropriate For Non-Sensitive Defects And Feature Requests.

Reports Are Reviewed For Reproducibility, Impact And Affected Versions. We Aim To Coordinate Disclosure And Publish Remediation Guidance When Appropriate. Do Not Publicly Disclose Actionable Exploit Details Before A Fix Or Coordinated Disclosure.

## Scope

Security-Relevant Reports Include Incorrect Authorization Or Resource Scoping, Unsafe Policy Generation, Bypass Of Configured Risk Gates, Disclosure Of Sensitive Inputs, Command Execution, Dependency Or Distribution Compromise, And Unexpected AWS Mutations.

A Recognized Resource Mapping, Partial Coverage Or An Explicitly Documented Unsupported Configuration Is Not By Itself A Vulnerability. Reports Describing False Confidence, Missing Mandatory Permissions Or Excessive Privilege Should Include The Applicable Configuration And Provider Behavior.

Only Test Systems And AWS Accounts That You Own Or Are Explicitly Authorized To Assess. Avoid Destructive Tests, Service Disruption And Access To Third-Party Data.

## Security Model

tf-iam Is An Analysis Tool. Local Scanning And Policy Generation Do Not Execute Terraform, Download Providers, Attach IAM Policies Or Modify AWS Infrastructure. Optional Live Integrations Use AWS Read And Validation APIs With The Caller's Credentials.

Generated Policies Are Candidates For Independent Review, Not Guarantees Of Least Privilege Or Effective Authorization. IAM Permissions Boundaries, Service Control Policies, Session Policies, Resource Policies, Conditional Grants And Provider Behavior May Alter The Final Authorization Decision.

Use A Dedicated Audit Identity For Live Integrations, Separate Policy Approval From Deployment, And Never Attach Break-Glass Policies Automatically. Do Not Suppress Unresolved Or Risk Findings Solely To Make A Pipeline Pass. Treat Runtime Observations As Supporting Evidence, Not Proof That Unobserved Permissions Are Unnecessary.

## IAM Tag Boundaries

Where Terraform Declares A Resolvable `tfiam:scope` Or `Name` Tag, The Generator Can Restrict Certain EC2 Tagging And Destructive Operations With AWS Resource-Tag Conditions. `ec2:CreateAction` Limits Creation-Time Tagging, And `aws:TagKeys` Limits Existing-Resource Tag Operations To Declared Keys.

A `Name` Tag Is Neither A Unique Resource Identifier Nor An Immutable Security Boundary. A Principal With Separate Broad Tag Permissions Can Potentially Change The Resource Set Matching A Tag Condition. Require Dedicated Ownership Tags, Controlled Tag Mutation, Resource-Specific ARNs From Saved Plans, Or Additional IAM Guardrails Where Strong Isolation Is Necessary.

Offline Generation Does Not Verify That AWS Will Authorize A Particular Terraform Apply. Use The Existing AWS Access Analyzer Validation Command For Policy Findings And A Separately Authorized, Isolated AWS Lifecycle Test For Create/Update/Destroy. Neither A Green CLI Test Nor A Successful Policy File Write Is Equivalent To Live Authorization Evidence.

## Protecting Sensitive Data

Terraform State, Saved Plan JSON, Reports And Candidate Policies May Expose Credentials, Account Identifiers, Resource Names Or Confidential Architecture. Sensitive And Unknown Fields Are Withheld From Inference Where Supported, But Unmarked Data May Still Appear In Output.

- Restrict Input And Output Directories To Authorized Users; Use A Restrictive Umask.
- Do Not Commit Real State, Plans, Credentials Or Private Acceptance Evidence.
- Avoid Passing Secrets Through CLI Values Or Shell History.
- Redact Artifacts Before Sharing And Enforce Retention Controls In CI.
- Use Isolated AWS Accounts For Live Lifecycle Acceptance And Review Any Cleanup Operation Before Execution.

The Project Does Not Require AWS Credentials For Offline Analysis. Optional Cloud Integrations Should Be Enabled Only When Required.

## Release Integrity

Download Stable Assets From [Official GitHub Releases](https://github.com/sm-joe/tf-iam/releases). Ordinary CI Build Artifacts Are Not Signed Stable Releases.

Verify The Executable And The Signed Source Receipt Before Installation:

~~~bash
sha256sum -c SHA256SUMS
gh attestation verify tfiam --repo sm-joe/tf-iam
gh attestation verify release-source.json --repo sm-joe/tf-iam
~~~

Review The Receipt's Tested Source Commit Against The Release Tag. Do Not Install Artifacts That Fail Checksum Or Attestation Verification. The Release Workflow Rebuilds The Exact Accepted Source, Checks Binary Repeatability In Its Build Environment And Publishes GitHub Build Provenance. See [Release Process](docs/release-process.md) For Maintainer Procedures.

## Validation Boundaries

The v1.0.0 And v1.1.0 Releases Include Live Restricted-Role Acceptance For Four Representative AWS Fixtures. It Does Not Certify Every AWS Service, Terraform Configuration Or Effective IAM Policy. Review The [Provider Validation Guide](docs/provider-validation.md) For Evidence Scope And Known Limitations.

Policy Packing Preserves The Exact Generated Action, Resource And Condition Union. It Does Not Resolve External Denies Or Validate Effective Permissions. Review Each Packed Policy And Remaining Attachment Quotas Before Deployment.

## License

tf-iam Is Distributed Under The [MIT License](LICENSE).
