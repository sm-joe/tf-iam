# AWS Permission Catalog

## Inventory

120 Managed Resource Mappings And 37 Data-Source Mappings (157 Distinct mode/type Entries). Catalog Entries Are Candidate Mappings With Explicit Source References And Validation Status.

| Service | Examples |
|---|---|
| IAM | Inline Policies, Users, Groups, OIDC, Instance Profiles |
| EKS | Access Entries, Access Policy Associations, Fargate Profiles |
| EC2/VPC | Gateways, Routes, Security Rules, Endpoints, ACLs, ENIs, EBS |
| Auto Scaling | Groups, Policies, Schedules |
| S3 | Bucket Policies, ACLs, Replication, Lifecycle, Logging |
| KMS | Keys, Aliases, Grants, Key Policies |
| ECR | Repositories, Policies, Lifecycle, Scanning |
| ECS | Clusters, Services, Task Definitions, Capacity Providers |
| RDS | DB Instances, Clusters, Subnet And Parameter Groups |
| Lambda | Functions, Permissions, Aliases, Event Mappings, Layers |
| CloudWatch/Logs | Alarms, Dashboards, Log Groups, Streams, Filters |
| ELB | Load Balancers, Listeners, Rules, Target Groups |
| Route 53 | Zones, Records, VPC Associations |

## Scope And Accuracy

Read/create/update/delete Sets Are Candidates, Not Tested Provider API Call Traces. Named Resource Scope Strategies Are Supplemented By Explicitly Account-Level Actions. The review/manual Strategy Emits Only Known Account-Level Candidates; Other Actions Are Omitted And Reported, So Those Entries Are Recognized But Not Fully Generatable. KMS Alias updates/deletes And Instance-Profile Role Mutations Remain Incomplete Until All Required Resource Identities Are Resolved. This Avoids Guessed Privilege Grants. Action-Specific Scope, Tag Conditions And Dependent Permissions Are Modeled For Supported Configurations. Complex And Unresolved Cases Require Individual Review. Version-Specific Live Acceptance Covers Four Representative Fixtures: S3, SQS, VPC/subnet And DynamoDB.

References: [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html), [EKS](https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html), [KMS Alias Authorization](https://docs.aws.amazon.com/kms/latest/developerguide/alias-access.html), [Lambda](https://docs.aws.amazon.com/service-authorization/latest/reference/list_lambda.html), [ECS](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecs.html). Individual Entries Carry Service References.

Use Saved Terraform Plans For Precise Lifecycle Operations. All Scans Remain PARTIAL Until Provider And Lifecycle Evidence Establish Completeness.
