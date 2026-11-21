# AWS permission catalog — M04

## Inventory

106 managed resource mappings and 37 data-source mappings (143 distinct mode/type entries). All are independently authored candidate mappings; no Pike mappings imported.

| Service | Examples |
|---|---|
| IAM | Inline policies, users, groups, OIDC, instance profiles |
| EKS | Access entries, access policy associations, Fargate profiles |
| EC2/VPC | Gateways, routes, security rules, endpoints, ACLs, ENIs, EBS |
| Auto Scaling | Groups, policies, schedules |
| S3 | Bucket policies, ACLs, replication, lifecycle, logging |
| KMS | Keys, aliases, grants, key policies |
| ECR | Repositories, policies, lifecycle, scanning |
| ECS | Clusters, services, task definitions, capacity providers |
| RDS | DB instances, clusters, subnet and parameter groups |
| Lambda | Functions, permissions, aliases, event mappings, layers |
| CloudWatch/Logs | Alarms, dashboards, log groups, streams, filters |
| ELB | Load balancers, listeners, rules, target groups |
| Route 53 | Zones, records, VPC associations |

## Scope and accuracy

Read/create/update/delete sets are candidates, not tested provider API call traces. Named resource scope strategies are supplemented by explicitly account-level actions. The review/manual strategy emits only known account-level candidates; other actions are omitted and reported, so those entries are recognized but not fully generatable. KMS alias updates/deletes and instance-profile role mutations remain incomplete until all required resource identities are resolved. This avoids guessed privilege grants. EC2/VPC/ELB multi-resource authorization is a priority for M05. Full action-level authorization, tag conditions, secondary dependent actions and live version-specific testing remain open.

References: [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html), [EKS](https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html), [KMS alias authorization](https://docs.aws.amazon.com/kms/latest/developerguide/alias-access.html), [Lambda](https://docs.aws.amazon.com/service-authorization/latest/reference/list_lambda.html), [ECS](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecs.html). Individual entries carry service references.

Use saved Terraform plans for precise lifecycle operations. All scans remain PARTIAL until provider and lifecycle evidence establish completeness.
