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
    assert peering["condition"]=={"ArnEquals":{"ec2:AccepterVpc":accepter,"ec2:RequesterVpc":requester}}
    assert all(x["scope"]!="*" for x in rows)


def test_vpc_peering_cross_account_does_not_invent_peer_permission(tmp_path):
    report=source(tmp_path,{"aws_vpc_peering_connection":{"main":{
        "vpc_id":"vpc-aabbccdd","peer_vpc_id":"vpc-11223344",
        "peer_owner_id":"999999999999",
    }}})
    assert not grants(report,"ec2:CreateVpcPeeringConnection")
    assert any(x["action"]=="ec2:CreateVpcPeeringConnection" for x in report["unresolved_permissions"])
