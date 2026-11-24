"""Networking authorization coverage and scoped regression tests."""
import json
from tfiam.scan import scan
from tfiam.catalog_loader import CATALOG

ACCOUNT="123456789012"
REGION="us-east-1"
NETWORKING=(
    "aws_vpc","aws_subnet","aws_internet_gateway","aws_nat_gateway",
    "aws_route_table","aws_route_table_association","aws_security_group",
    "aws_network_acl","aws_eip","aws_vpc_peering_connection",
    "aws_ec2_transit_gateway","aws_vpc_endpoint","aws_route53_zone",
    "aws_route53_record","aws_vpn_gateway",
)

def source(tmp_path, resources):
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":resources}))
    return scan(tmp_path,account=ACCOUNT,region=REGION)

def grants(report,action):
    return [p for p in report["permissions"] if p["action"]==action]

def test_all_fifteen_networking_resources_in_catalog():
    assert all(name in CATALOG["resources"] for name in NETWORKING)

def test_transit_gateway_create_scope(tmp_path):
    report=source(tmp_path,{"aws_ec2_transit_gateway":{"main":{"description":"network transit"}}})
    assert report["mapping_coverage"]["eligible_resources"]==1
    assert report["mapping_coverage"]["unmapped_resources"]==0
    assert any(p["scope"]=="arn:aws:ec2:us-east-1:123456789012:transit-gateway/*" for p in grants(report,"ec2:CreateTransitGateway"))
    assert any(p["scope"]=="*" for p in grants(report,"ec2:DescribeTransitGateways"))
    assert not any(p["scope"]=="*" for p in grants(report,"ec2:CreateTransitGateway"))

def test_vpn_gateway_create_and_vpc_dependency(tmp_path):
    report=source(tmp_path,{"aws_vpn_gateway":{"main":{"vpc_id":"vpc-aabbccdd","amazon_side_asn":"64512"}}})
    assert report["mapping_coverage"]["unmapped_resources"]==0
    assert any(p["scope"]=="arn:aws:ec2:us-east-1:123456789012:vpn-gateway/*" for p in grants(report,"ec2:CreateVpnGateway"))
    assert {p["scope"] for p in grants(report,"ec2:AttachVpnGateway")}=={
        "arn:aws:ec2:us-east-1:123456789012:vpn-gateway/*",
        "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-aabbccdd",
    }
    assert not any(p["scope"]=="*" for p in grants(report,"ec2:AttachVpnGateway"))

def test_vpn_gateway_unknown_vpc_cannot_attach(tmp_path):
    report=source(tmp_path,{"aws_vpn_gateway":{"main":{"vpc_id":"${var.unknown_vpc}"}}})
    assert not grants(report,"ec2:AttachVpnGateway")
    assert any(p["action"]=="ec2:AttachVpnGateway" for p in report["unresolved_permissions"])

def test_route53_record_has_name_type_and_change_action_restrictions(tmp_path):
    report=source(tmp_path,{"aws_route53_record":{"main":{"zone_id":"Z123456789ABC","name":"app.example.com","type":"A","ttl":300,"records":["192.0.2.1"]}}})
    action=grants(report,"route53:ChangeResourceRecordSets")
    assert len(action)==1
    row=action[0]
    assert row["scope"]=="arn:aws:route53:::hostedzone/Z123456789ABC"
    condition=row["condition"]["ForAllValues:StringEquals"]
    assert condition["route53:ChangeResourceRecordSetsNormalizedRecordNames"]==["app.example.com"]
    assert condition["route53:ChangeResourceRecordSetsRecordTypes"]==["A"]
    assert condition["route53:ChangeResourceRecordSetsActions"]==["CREATE","UPSERT","DELETE"]
    assert any(p["scope"]=="arn:aws:route53:::change/*" for p in grants(report,"route53:GetChange"))

def test_route53_unknown_zone_uses_prospective_arn(tmp_path):
    report=source(tmp_path,{"aws_route53_record":{"main":{"zone_id":"${aws_route53_zone.main.zone_id}","name":"app.example.com","type":"A"}}})
    assert any(p["scope"]=="arn:aws:route53:::hostedzone/*" for p in grants(report,"route53:ChangeResourceRecordSets"))
    assert any("prospective hostedzone/*" in i for i in report["information"])

def test_route53_record_unknown_name_fails_closed(tmp_path):
    report=source(tmp_path,{"aws_route53_record":{"main":{"zone_id":"Z123456789ABC","name":"${var.unknown}","type":"A"}}})
    assert not grants(report,"route53:ChangeResourceRecordSets")
    assert any(x["action"]=="route53:ChangeResourceRecordSets" for x in report["unresolved_permissions"])


def test_vpc_peering_same_region_exact_endpoints(tmp_path):
    report=source(tmp_path,{"aws_vpc_peering_connection":{"main":{
        "vpc_id":"vpc-aabbccdd",
        "peer_vpc_id":"vpc-11223344",
        "auto_accept":True,
    }}})
    rows=grants(report,"ec2:CreateVpcPeeringConnection")
    assert len(rows)==2,rows
    requester="arn:aws:ec2:us-east-1:123456789012:vpc/vpc-aabbccdd"
    accepter="arn:aws:ec2:us-east-1:123456789012:vpc/vpc-11223344"
    assert any(x["scope"]==requester for x in rows)
    peering=next(x for x in rows if x["scope"].endswith("vpc-peering-connection/*"))
    assert peering["condition"]=={"ArnEquals":{"ec2:AccepterVpc":accepter}}
    assert all(x["scope"]!="*" for x in rows)


def test_vpc_peering_cross_account_uses_exact_peer_condition(tmp_path):
    report=source(tmp_path,{"aws_vpc_peering_connection":{"main":{
        "vpc_id":"vpc-aabbccdd","peer_vpc_id":"vpc-11223344",
        "peer_owner_id":"999999999999",
    }}})
    rows=grants(report,"ec2:CreateVpcPeeringConnection")
    assert len(rows)==2
    target=next(x for x in rows if x["scope"].endswith("vpc-peering-connection/*"))
    assert target["condition"]=={"ArnEquals":{"ec2:AccepterVpc":"arn:aws:ec2:us-east-1:999999999999:vpc/vpc-11223344"}}
    assert not any(x["action"]=="ec2:CreateVpcPeeringConnection" for x in report["unresolved_permissions"])


def test_all_fifteen_networking_declarations_are_discovered(tmp_path):
    resources={
        "aws_vpc":{"main":{"cidr_block":"10.60.0.0/16"}},
        "aws_subnet":{"main":{"vpc_id":"vpc-aabbccdd","cidr_block":"10.60.1.0/24"}},
        "aws_internet_gateway":{"main":{"vpc_id":"vpc-aabbccdd"}},
        "aws_nat_gateway":{"main":{"subnet_id":"subnet-aabbccdd","allocation_id":"eipalloc-aabbccdd"}},
        "aws_route_table":{"main":{"vpc_id":"vpc-aabbccdd"}},
        "aws_route_table_association":{"main":{"subnet_id":"subnet-aabbccdd","route_table_id":"rtb-aabbccdd"}},
        "aws_security_group":{"main":{"vpc_id":"vpc-aabbccdd","name":"network-sg"}},
        "aws_network_acl":{"main":{"vpc_id":"vpc-aabbccdd"}},
        "aws_eip":{"main":{"domain":"vpc"}},
        "aws_vpc_peering_connection":{"main":{"vpc_id":"vpc-aabbccdd","peer_vpc_id":"vpc-11223344"}},
        "aws_ec2_transit_gateway":{"main":{"description":"transit"}},
        "aws_vpc_endpoint":{"main":{"vpc_id":"vpc-aabbccdd","service_name":"com.amazonaws.us-east-1.s3","vpc_endpoint_type":"Gateway"}},
        "aws_route53_zone":{"main":{"name":"sample.example.com"}},
        "aws_route53_record":{"main":{"zone_id":"Z123456789ABC","name":"app.sample.example.com","type":"A","ttl":60,"records":["192.0.2.2"]}},
        "aws_vpn_gateway":{"main":{"vpc_id":"vpc-aabbccdd"}},
    }
    report=source(tmp_path,resources)
    assert report["mapping_coverage"]=={
        "eligible_resources":15,
        "mapped_resources":15,
        "unmapped_resources":0,
        "mapping_percent":100.0,
    }
    assert {row["type"] for row in report["resources"] if row["status"]!="UNSUPPORTED"}==set(NETWORKING)
    assert grants(report,"ec2:CreateTransitGateway")
    assert grants(report,"ec2:CreateVpnGateway")
    assert grants(report,"route53:ChangeResourceRecordSets")


def test_route53_wildcard_record_name_uses_aws_octal_condition(tmp_path):
    report=source(tmp_path,{"aws_route53_record":{"main":{
        "zone_id":"Z123456789ABC","name":"*.example.com.","type":"CNAME"
    }}})
    row=grants(report,"route53:ChangeResourceRecordSets")[0]
    assert row["condition"]["ForAllValues:StringEquals"][
        "route53:ChangeResourceRecordSetsNormalizedRecordNames"
    ]==[chr(92)+"052.example.com"]


def test_vpn_without_vpc_does_not_require_attach(tmp_path):
    report=source(tmp_path,{"aws_vpn_gateway":{"main":{"amazon_side_asn":"64512"}}})
    assert grants(report,"ec2:CreateVpnGateway")
    assert not grants(report,"ec2:AttachVpnGateway")
    assert not any(x["action"]=="ec2:AttachVpnGateway" for x in report["unresolved_permissions"])


def test_cross_account_peer_unknown_owner_fails_closed(tmp_path):
    report=source(tmp_path,{"aws_vpc_peering_connection":{"main":{
        "vpc_id":"vpc-aabbccdd","peer_vpc_id":"vpc-11223344",
        "peer_owner_id":"${var.owner}",
    }}})
    assert not grants(report,"ec2:CreateVpcPeeringConnection")
    assert any(x["action"]=="ec2:CreateVpcPeeringConnection" for x in report["unresolved_permissions"])


def test_computed_networking_references_generate_prospective_scopes(tmp_path):
    resources={
        "aws_vpc":{"main":{"cidr_block":"10.60.0.0/16"}},
        "aws_subnet":{"private":{"vpc_id":"${aws_vpc.main.id}","cidr_block":"10.60.1.0/24"}},
        "aws_route_table":{"private":{"vpc_id":"${aws_vpc.main.id}"}},
        "aws_route_table_association":{"private":{
            "route_table_id":"${aws_route_table.private.id}",
            "subnet_id":"${aws_subnet.private.id}",
        }},
        "aws_internet_gateway":{"main":{"vpc_id":"${aws_vpc.main.id}"}},
        "aws_nat_gateway":{"main":{
            "subnet_id":"${aws_subnet.private.id}",
            "allocation_id":"${aws_eip.nat.id}",
        }},
        "aws_eip":{"nat":{"domain":"vpc"}},
    }
    report=source(tmp_path,resources)
    assert not report["unresolved_permissions"],report["unresolved_permissions"]
    checks={
        "ec2:CreateSubnet":"arn:aws:ec2:us-east-1:123456789012:vpc/*",
        "ec2:DeleteVpc":"arn:aws:ec2:us-east-1:123456789012:vpc/*",
        "ec2:CreateNatGateway":"arn:aws:ec2:us-east-1:123456789012:natgateway/*",
        "ec2:AssociateRouteTable":"arn:aws:ec2:us-east-1:123456789012:route-table/*",
        "ec2:ReleaseAddress":"arn:aws:ec2:us-east-1:123456789012:elastic-ip/*",
    }
    for action,scope in checks.items():
        assert any(p["scope"]==scope for p in grants(report,action)),(action,grants(report,action))


def test_unknown_external_dependency_remains_unresolved(tmp_path):
    report=source(tmp_path,{"aws_subnet":{"main":{"vpc_id":"${var.external_vpc}","cidr_block":"10.0.1.0/24"}}})
    assert not grants(report,"ec2:CreateSubnet")
    assert any(x["action"]=="ec2:CreateSubnet" for x in report["unresolved_permissions"])


def test_endpoint_lifecycle_scope_not_withheld_by_missing_creation_service(tmp_path):
    """A managed endpoint's mutation scope must not depend on create-time inputs."""
    report=source(tmp_path,{"aws_vpc_endpoint":{"s3":{
        "vpc_id":"vpc-aabbccdd",
        "vpc_endpoint_type":"Gateway",
    }}})
    prospective="arn:aws:ec2:us-east-1:123456789012:vpc-endpoint/*"
    for action in ("ec2:ModifyVpcEndpoint","ec2:DeleteVpcEndpoints","ec2:DeleteTags"):
        assert any(row["scope"]==prospective for row in grants(report,action)),(action,report["unresolved_permissions"])
        assert not any(row["action"]==action for row in report["unresolved_permissions"])
    # Creating an endpoint still requires an actual known service target.
    assert any(row["action"]=="ec2:CreateVpcEndpoint" for row in report["unresolved_permissions"])


def test_managed_vpc_peering_reference_scopes_accepter(tmp_path):
    report=source(tmp_path,{
        "aws_vpc":{"main":{"cidr_block":"10.0.0.0/16"},
                   "peer":{"cidr_block":"10.1.0.0/16"}},
        "aws_vpc_peering_connection":{"peer":{
            "vpc_id":"${aws_vpc.main.id}",
            "peer_vpc_id":"${aws_vpc.peer.id}",
        }},
    })
    action=grants(report,"ec2:CreateVpcPeeringConnection")
    assert any(row["scope"]=="arn:aws:ec2:us-east-1:123456789012:vpc/*" for row in action), action
    assert any(row.get("condition")=={
        "ArnEquals":{"ec2:AccepterVpc":"arn:aws:ec2:us-east-1:123456789012:vpc/*"}
    } for row in action), action
    assert not any(row["action"]=="ec2:CreateVpcPeeringConnection" for row in report["unresolved_permissions"])
