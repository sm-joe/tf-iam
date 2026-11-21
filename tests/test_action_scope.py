import json
from tfiam.scan import scan

ACCOUNT="123456789012"
REGION="us-east-1"
def doc(kind,body,actions=("create",),before=None):
    return {"format_version":"1.2","terraform_version":"1.10.0","resource_changes":[{
        "address":kind+".example","mode":"managed","type":kind,"provider_name":"registry.terraform.io/hashicorp/aws",
        "change":{"actions":list(actions),"before":before,"after":body}}]}
def scan_doc(*args,**kwargs):
    return scan(plan=doc(*args,**kwargs),account=ACCOUNT,region=REGION)
def scopes(r,action):
    return {p["scope"] for p in r["permissions"] if p["action"]==action}
def test_volume_attachment_multi_resource():
    r=scan_doc("aws_volume_attachment",{"instance_id":"i-1234abcd","volume_id":"vol-1234abcd"})
    assert scopes(r,"ec2:AttachVolume")=={
        "arn:aws:ec2:us-east-1:123456789012:instance/i-1234abcd",
        "arn:aws:ec2:us-east-1:123456789012:volume/vol-1234abcd"}
    assert not scopes(r,"ec2:DetachVolume")
def test_atomic_unresolved_attachment():
    r=scan_doc("aws_volume_attachment",{"instance_id":"i-1234abcd","volume_id":None})
    assert not scopes(r,"ec2:AttachVolume")
    assert any(p["action"]=="ec2:AttachVolume" for p in r["unresolved_permissions"])
def test_route_table_create_parent_and_request_tag():
    r=scan_doc("aws_route_table",{"vpc_id":"vpc-abcd1234","tags":{"Team":"platform"}})
    assert scopes(r,"ec2:CreateRouteTable")=={"arn:aws:ec2:us-east-1:123456789012:vpc/vpc-abcd1234","arn:aws:ec2:us-east-1:123456789012:route-table/*"}
    p=next(p for p in r["permissions"] if p["action"]=="ec2:CreateRouteTable" and p["scope"].endswith("route-table/*"))
    assert p["condition"]["StringEquals"]["aws:RequestTag/Team"]=="platform"
    assert not scopes(r,"ec2:DeleteRouteTable")
def test_run_instances_multi_resource_and_no_global_mutation():
    r=scan_doc("aws_instance",{"ami":"ami-1234abcd","subnet_id":"subnet-abcd1234","vpc_security_group_ids":["sg-abcd1234"]})
    assert scopes(r,"ec2:RunInstances")=={
        "arn:aws:ec2:us-east-1::image/ami-1234abcd",
        "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-abcd1234",
        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-abcd1234",
        "arn:aws:ec2:us-east-1:123456789012:instance/*",
        "arn:aws:ec2:us-east-1:123456789012:network-interface/*",
        "arn:aws:ec2:us-east-1:123456789012:volume/*"}
    assert not scopes(r,"ec2:TerminateInstances")
def test_kms_alias_update_requires_old_and_new_keys():
    alias="arn:aws:kms:us-east-1:123456789012:alias/project"
    old="arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
    new="arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"
    r=scan_doc("aws_kms_alias",{"name":"alias/project","target_key_id":new},("update",),{"name":"alias/project","target_key_id":old})
    assert scopes(r,"kms:UpdateAlias")=={alias,old,new}
    r=scan_doc("aws_kms_alias",{"name":"alias/project","target_key_id":new},("update",),{"name":"alias/project"})
    assert not scopes(r,"kms:UpdateAlias")
def test_elb_listener_parent_scope():
    lb="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/abcdef0123456789"
    r=scan_doc("aws_lb_listener",{"load_balancer_arn":lb})
    assert scopes(r,"elasticloadbalancing:CreateListener")=={lb}
    assert not scopes(r,"elasticloadbalancing:DeleteListener")
def test_pod_identity_exact_association():
    r=scan_doc("aws_eks_pod_identity_association",{"cluster_name":"demo","association_id":"a-123456"},("no-op",))
    assert scopes(r,"eks:DescribePodIdentityAssociation")=={"arn:aws:eks:us-east-1:123456789012:podidentityassociation/demo/a-123456"}
def test_eks_access_entry_arn_and_condition():
    identity="arn:aws:iam::123456789012:role/ci/reader"
    entry="arn:aws:eks:us-east-1:123456789012:access-entry/demo/role/123456789012/reader/uuid"
    r=scan_doc("aws_eks_access_entry",{"cluster_name":"demo","principal_arn":identity,"access_entry_arn":entry},("no-op",))
    assert scopes(r,"eks:DescribeAccessEntry")=={entry}
    assert r["scope_summary"]["conditional"]==1
