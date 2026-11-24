# AWS Networking IAM Coverage

tf-iam maps Terraform networking resources to AWS IAM actions, resource types,
and associated authorization dependencies. It does not modify Terraform files,
add tags, contact AWS during ordinary scans, or silently issue global mutation
permissions when dependencies are unknown.

| Terraform Resource | IAM Service | Authorization Scope |
| --- | --- | --- |
| `aws_vpc` | EC2 | VPC resource and permitted global Describe actions |
| `aws_subnet` | EC2 | Subnet plus its VPC dependency |
| `aws_internet_gateway` | EC2 | Gateway plus VPC attachment dependencies |
| `aws_nat_gateway` | EC2 | NAT gateway, subnet and Elastic IP as applicable |
| `aws_route_table` | EC2 | Route table plus VPC dependency |
| `aws_route_table_association` | EC2 | Route table and subnet or gateway association |
| `aws_security_group` | EC2 | Security group plus VPC dependency |
| `aws_network_acl` | EC2 | Network ACL plus VPC dependency |
| `aws_eip` | EC2 | Elastic IP allocation |
| `aws_vpc_peering_connection` | EC2 | Peering lifecycle and supported regional dependencies |
| `aws_ec2_transit_gateway` | EC2 | Transit gateway; prospective IDs are class-scoped |
| `aws_vpc_endpoint` | EC2 | Endpoint, VPC, service and applicable subnets/security groups |
| `aws_route53_zone` | Route 53 | Hosted zone ID when known; prospective hosted zone otherwise |
| `aws_route53_record` | Route 53 | Hosted zone plus normalized record-name, type and lifecycle-action conditions |
| `aws_vpn_gateway` | EC2 | VPN gateway plus VPC attachment dependencies |

**Limits:** AWS may not assign resource IDs until after creation. Saved plans
with evaluated IDs allow narrower scopes than static source alone. Prospective
ARNs such as `transit-gateway/*`, `vpn-gateway/*` and
`route53:::hostedzone/*` can authorize operations on other resources in the
same class. Read actions that AWS only supports globally use `Resource: "*"`
(and EC2 regional request conditions when applicable). Unknown required
dependencies remain unresolved rather than being disguised as full coverage.

## Test From Linux Bash

```bash
git fetch origin
git switch feat/aws-networking-15-resource-support
git pull --ff-only origin feat/aws-networking-15-resource-support

python -m pytest tests/test_networking_coverage.py -v
python -m pytest -q

tfiam scan "$TF_ROOT" --aws-account "$AWS_ACCOUNT_ID" \
  --aws-region "$AWS_REGION" --format json \
  --output /tmp/tfiam-network-scan.json

jq '{mapping: .mapping_coverage, unresolved: .unresolved_permissions,
      authorization: .authorization_metadata.status}' /tmp/tfiam-network-scan.json
```

Provider profiles, aliases, cross-account and assumed-role configurations may
require `--provider-contexts` to validate the exact target account and region.
The successful generation of an IAM JSON document is not proof of effective
AWS authorization; use AWS IAM Access Analyzer and a controlled create/update/
destroy acceptance environment before declaring lifecycle coverage validated.
