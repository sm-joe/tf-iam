# Action-Specific Scope (M05)

The Candidate Engine Separates API action/resource Pairs Instead Of Assigning A Single ARN To All Actions Of A Terraform Type. EC2 parent/dependency Grants And Newly Allocated Resource Identifiers Are Distinct. Required Identities Are Evaluated As An Atomic Group; Unresolved Dependencies Withhold The Action And Appear In unresolved_permissions. Future Identifiers Use account/region/type-bounded Wildcards Only For Supported Create Operations. Account-Level Read Actions Retain Resource "*". Review The scope_summary Counts (Permission Observations, Not Unique Statements).

Supported Examples: EC2 Volume Attachment (Instance And Volume); subnet/route-table/security-group Creation (VPC And New Resource); Route Mutation (Route Table); Simple RunInstances (Image, Subnet, Security Groups, Instance, Volume, ENI); ELBv2 Listener Creation (Parent Load Balancer) And Target Registration; KMS Alias Update (Alias, Old Key, New Key); EKS Pod Identity Association ID And Access Entry ARN. Request-Tag Restrictions Are Generated Only For Known Tags On Selected Creates. Create-Time Tags Are Restricted By The Service CreateAction Condition Where Supported. Existing-Resource Tag Conditions Must Be Reviewed Against Actual Provider Requests; Do Not Assume Tags Intended To Be Added Already Exist.

References: [EC2 Authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html), [EC2 Policy Examples](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html), [ELBv2 Authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_elbv2.html), [ELB Tag-On-Create](https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/tagging-resources-during-creation.html), [EKS Authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html), [KMS Aliases](https://docs.aws.amazon.com/kms/latest/developerguide/alias-access.html).

Not A Complete IAM Authorization Evaluator. Launch Templates, Default subnets/security Groups, Instance Profile Role Lookup, NAT Gateway And Complex Endpoint Dependencies, Unknown Existing IDs, Service-Linked Roles, Provider Aliases And Full Per-Action Condition Support Require Further Evidence. A Saved Plan Is Recommended. Candidate Mappings Remain PARTIAL Until Provider-Version And Real Lifecycle Validation.

Optional `--scope-resource-tags` Applies EC2 Resource Tag Conditions To A Limited Set Of Existing-Resource Mutations When The Saved Plan Confirms Tags Are Stable Before And After The Change. It Is Disabled By Default And Does Not Add Conditions Derived From Newly Added Or Changed Tags. Review IAM Condition Support And Tag Lifecycle Before Deploying.


## Auto Scaling Groups And EC2 Launch Templates

For a statically resolved Auto Scaling group name, the generator scopes supported lifecycle actions to the AWS documented `autoScalingGroup:*:autoScalingGroupName/<name>` ARN. AWS Auto Scaling describe actions use `Resource: "*"` because resource-level IAM permissions are not supported for those calls.

A launch template's ID is assigned by AWS, not derived from the Terraform `name` field. The generator uses an exact ID only when supplied in trusted saved-plan values. For new templates, the generator automatically uses the prospective `arn:...:launch-template/*` ARN, scoped to the verified account, region and resource class; no custom Terraform tags are necessary. This resource-class scope can affect other launch templates in the account/region and must be reviewed as a least-privilege tradeoff. If an existing `tfiam:scope` tag is already declared by the user's Terraform, the tool can further restrict create and mutation actions using `aws:RequestTag` and `ec2:ResourceTag`. The tag must actually be applied to the launch template. `ec2:CreateTags` for creation is limited with `ec2:CreateAction = CreateLaunchTemplate`. AWS does not provide an IAM condition mapping a Terraform launch-template name to its future EC2-generated ID. The tool therefore uses a disclosed, account- and region-bounded prospective resource ARN rather than inventing a resource ID or requiring users to edit Terraform.

Auto Scaling groups using launch templates require independently validated `ec2:RunInstances` dependencies across AMI, instances, networking, volumes and instance profile roles. These cannot be inferred from the ASG name alone; when such configuration is detected, the generator reports an explicit unresolved dependency instead of producing an apparently complete deployment policy. A custom service-linked role is granted `iam:PassRole` only when a matching exact ARN can be proven. Review and validate all IAM statements before use.


### Auto Scaling Instance Launch Validation

For ordinary Auto Scaling groups using a single launch template, AWS checks
`ec2:RunInstances` when a group is created or modified. The generator
emits AWS-documented `ec2:LaunchTemplate`-conditioned permissions across
the relevant regional EC2 resource classes instead of a global
`Resource: "*"` allow. When Terraform cannot know the template's
AWS-assigned ID before apply, an account/region-constrained
`launch-template/*` pattern is used. The scan information explains that
this pattern can match other templates and that AMI/subnet/security-group
wildcard scopes need review; it is not proof of effective authorization.

Mixed-instances policies, inferred instance-profile `iam:PassRole`,
encryption keys, SSM-backed AMIs and special launch features require
additional evidence and must not be silently treated as fully verified
authorization. No `RunInstances` grants are inferred for destroy/read
operations. AWS references:
https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-launch-template-permissions.html
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html
