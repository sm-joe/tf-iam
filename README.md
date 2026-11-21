# TF IAM Scope

Offline, multi-cloud Terraform IAM candidate policy analyzer for CI/CD deployment identities. Version 0.1.0 is a starter implementation, not a certified least-privilege engine.

## Install (Linux / macOS / Bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
tfiam --help
python -m pytest -q
```

## Usage

```bash
tfiam scan ./examples/multicloud
tfiam scan ./examples/multicloud --format json --output report.json
tfiam scan ./examples/aws-hcl --phase plan
tfiam generate ./examples/multicloud --provider aws --allow-partial --output aws-policy.json
tfiam generate ./examples/multicloud --provider gcp --name TerraformPipeline --scope my-project --format terraform --allow-partial --output gcp-role.tf.json
tfiam generate ./examples/multicloud --provider azure --scope /subscriptions/SUBSCRIPTION_ID --allow-partial --output azure-role.json
tfiam compare ./examples/multicloud --provider aws --existing examples/existing-aws.json --fail-on-missing
```

Terraform output is native Terraform JSON syntax (`.tf.json`), not HCL text. Save generated policy resources **outside** the scanned application directory and run a separate privileged provisioning workflow. The tool does not create role assignments, attach policies, execute Terraform, read credentials or call cloud APIs.

## Design

- `scan.py`: parse root module and reachable local child modules inside the root; collect source-level permissions, warnings, and backend evidence.
- `rules.py`: explicit starter resource-to-permission mappings across AWS, Google Cloud and Azure; no fallback to administrator permissions for unknown resources.
- `cli.py`: candidate policy rendering and static comparisons.
- Plan includes read permissions plus backend locking; apply includes read/write/delete for replacements; destroy includes read/delete. All are candidates and provider-specific operations may require additional actions.
- AWS scopes literal S3 bucket/object names and named DynamoDB tables/SQS queues where possible. Supply `--aws-account` and `--aws-region` for the latter. Other AWS actions can have `Resource: "*"`; review every such grant.
- GCP/Azure generated role definitions aggregate permissions, not assignments. Split backend and infrastructure grants, and assign at the narrowest supported scope. GCP permissions must be checked for custom-role eligibility. Azure data and management actions remain separate.

## Backend support

S3 state and lockfile, optional DynamoDB locking and KMS ARN; GCS objects; Azure Blob data actions; local state; basic `terraform_remote_state` data sources. Supply partial backend values through `--backend-config backend.json` (flat JSON, root backend only). No secrets should be placed in that file. S3 default workspace only; non-default workspaces, custom endpoints, encryption and identity configuration need review. GCS/Azure lock actions are included conservatively. Azure storage account discovery and additional authentication permissions may be required.

## Compare existing roles

Supply an exported AWS identity policy, GCP custom role definition (`includedPermissions`), or Azure custom role definition. Output reports missing/unverified actions, explicit simple AWS denies and potentially broad or unused grants. Example AWS export commands (requires separate read permissions):

```bash
aws iam get-role-policy --role-name TerraformPipeline --policy-name InlinePolicy --query PolicyDocument --output json > existing.json
gcloud iam roles describe TerraformPipeline --project=my-project --format=json > existing-gcp.json
az role definition list --name TerraformPipeline --query '[0]' --output json > existing-azure.json
```

This is not an effective-access simulator. Conditions, NotAction/NotResource, inherited grants, permissions boundaries, SCPs, deny assignments, role bindings and real resource scopes are not fully evaluated. Do not automatically remove reported excess. Wildcard matching is approximate.

## CI/CD

```bash
tfiam scan ./infra --format json --output iam-report.json
tfiam compare ./infra --provider aws --existing existing.json --fail-on-missing --output comparison.json
```

Exit codes: 0 command completed (not a compliance pass); 1 input/runtime error; 2 partial analysis with `--strict`; 3 comparison found missing/unverified or denied candidate permissions with `--fail-on-missing`. Current starter catalog always reports PARTIAL, so strict scans intentionally fail. Generate requires `--allow-partial`. Keep human approval before policy deployment.

## Coverage and limitations

See `tfiam/rules.py` for the supported resource types. This is not a full Terraform evaluator: no variable evaluation, provider alias resolution, remote module download, dynamic block evaluation, plan/state inspection, provider version binding, or full action/resource matrices. Local child module inputs are not resolved. Optional operations, tags, encryption, IAM delegation, force-destroy, provider initialization, and cloud API dependencies may change permissions. Rules may overestimate or underestimate. Files that cannot be parsed and unmapped types are reported; missing mappings never become broad action grants. The CLI does not guarantee a deployable role on every input. Validate with provider docs, policy validation, and isolated CI execution with cloud audit logs before production use.

## References

- [Terraform S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)
- [Terraform GCS backend](https://developer.hashicorp.com/terraform/language/backend/gcs)
- [Terraform AzureRM backend](https://developer.hashicorp.com/terraform/language/backend/azurerm)
- [AWS service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)
- [GCP Compute permissions](https://docs.cloud.google.com/iam/docs/roles-permissions/compute)
- [Azure custom roles](https://learn.microsoft.com/azure/role-based-access-control/custom-roles)

## Test status

Local JSON-path unit tests passed; HCL integration test was skipped because installation of python-hcl2 could not reach the package registry in the build environment. CI installs the dependency and runs the full suite. No real cloud deployment or provider API validation has been performed.

### EKS regression coverage

```bash
tfiam scan examples/eks --phase plan --aws-account 123456789012 --aws-region us-east-1
tfiam generate examples/eks --provider aws --aws-account 123456789012 --aws-region us-east-1 --allow-partial --output policy.json
```

The EKS catalog supports cluster, managed node group, add-on and Pod Identity association lifecycle candidates. Direct references and variable defaults are resolved across files in the same module. Defaults may be overridden at runtime: verify actual inputs before deployment. IAM role mutations and PassRole are omitted when their required scope cannot be inferred. Attach/detach grants restrict `iam:PolicyARN`; PassRole grants restrict `iam:PassedToService`. First-use service-linked roles, optional KMS/access-entry dependencies and provider-version-specific operations still require validation. The example is a static scan fixture, not a runnable EKS configuration. Text output groups identical grants; JSON retains per-resource provenance. Conditional policy comparison remains manual. AWS authorization reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html
