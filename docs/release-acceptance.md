# Release Acceptance Gates

## Stable v1.0.0 Evidence

The Initial Stable Release Was Validated Against AWS Provider 6.73.0 At Source Commit `261cd42ffe8abd8d7a0356b769f43be4f0da29fd`.

| Evidence | Result |
| --- | --- |
| Exact-Source CI And Linux Binary Smoke Tests | Passed |
| Restricted-Role S3, SQS, VPC/subnet And DynamoDB Lifecycle Fixtures | Passed |
| Create, Read, Update, Destroy And Both Replacement Orders | Passed |
| Negative Authorization And Empty-State Verification | Passed |
| IAM Access Analyzer | No Findings For The Four Candidate Policies |
| Session-Filtered CloudTrail Management Events | 441 Matched; Zero Unmapped Operations |
| Module Resolution, Backend Locking, Risk Gates And Sensitive-Value Regression Tests | Passed |
| Reviewed Evidence Manifest And Signed Linux Build | Passed |
| Stable v1.0.0 Publication | Completed |

The Signed Build Is Recorded In [GitHub Actions](https://github.com/sm-joe/tf-iam/actions/runs/45046329922). Download The Executable And Attested Source Receipt From The [Stable Release](https://github.com/sm-joe/tf-iam/releases/tag/v1.0.0).

## Validation Scope

The Four Isolated Fixtures Validate Only Their Tested Configurations. Catalog-Wide Provider Call Verification Remains Incomplete; Conditional Dependencies And Missing Candidates Require Review. The CloudTrail Report Is Session-Filtered And Does Not Cover Every Authorization Decision. VPC Default-Resource Discovery And S3 Tagging Fallback Limitations Are Documented In The [Provider Validation Guide](provider-validation.md) And [README](../README.md).

For Future Releases, Follow The [Release Process](release-process.md), Collecting Fresh Evidence Against The Exact Source To Be Released. Unit Tests And Metadata Compatibility Do Not Substitute For Live Authorization Verification. Do Not Attach Production Policies Solely On The Basis Of These Reports.

## v1.1.0 Preparation

Maintainer-Reported Acceptance On The Merged Source Revision `5bbef87ec3bbbca209242a3c1d979034522e5588`: Combined S3, SQS And DynamoDB Create, Update And Destroy Passed; Empty Terraform State Verified. Cleanup Was Also Reported Complete. EC2 Launch Was Blocked By An Explicit Organization SCP Deny. These Are Reported Results, Not Independently Reconciled Evidence Or Coverage Of Every Mapped Resource.

The Existing Signing Gate Remains Mandatory. The Combined Fixture Does Not Replace The Four Exact Restricted-Role Fixtures Or Their Evidence Requirements. Fresh Evidence Must Be Collected Against The Exact Release Source, Reviewed Privately, And Sealed Before Signing. No Prior Evidence May Be Relabeled With A New Commit.
