"""Regression: the 23 remaining ECS/ELBv2/VPC endpoint candidate gaps.

A constructed 43-resource plan exercises create-time computed dependency
collections. It is not the user's uploaded plan, which contains only reports.
"""
from test_ecs_43_resource_acceptance import fixture, ACCOUNT, REGION
from tfiam.scan import scan

ELB_READS = {
    ("aws_lb.main","elasticloadbalancing:DescribeLoadBalancerAttributes"),
    ("aws_lb_listener.http","elasticloadbalancing:DescribeListenerAttributes"),
    ("aws_lb_target_group.app","elasticloadbalancing:DescribeTargetGroupAttributes"),
}

def _computed_endpoint_plan():
    data=fixture()
    for row in data["resource_changes"]:
        if row["type"]!="aws_vpc_endpoint":
            continue
        after=row["change"]["after"]
        unknown=row["change"]["after_unknown"]
        if row["address"]=="aws_vpc_endpoint.s3":
            after["route_table_ids"]=None
            unknown["route_table_ids"]=True
        else:
            after["subnet_ids"]=None
            after["security_group_ids"]=None
            unknown["subnet_ids"]=True
            unknown["security_group_ids"]=True
    return data


def test_all_nine_computed_vpc_endpoint_create_and_create_tags_are_present():
    report=scan(plan=_computed_endpoint_plan(),account=ACCOUNT,region=REGION)
    assert report["mapping_coverage"]["mapped_resources"]==43
    for row in report["resources"]:
        if row["type"]!="aws_vpc_endpoint":
            continue
        source=row["address"]
        for action in ("ec2:CreateVpcEndpoint","ec2:CreateTags"):
            assert any(p["source"]==source and p["action"]==action
                       for p in report["permissions"]),(source,action)
            assert not any(p["source"]==source and p["action"]==action
                           for p in report["unresolved_permissions"]),(source,action)
        creates=[x for x in report["permissions"]
                 if x["source"]==source and x["action"]=="ec2:CreateVpcEndpoint"]
        assert any(":vpc-endpoint/*" in x["scope"] for x in creates)
        assert any(":vpc/*" in x["scope"] for x in creates)
        assert all(x["scope"]!="*" for x in creates)
    assert not any(x["source"]=="aws_ecs_service.app" and x["action"]=="iam:PassRole"
                   for x in report["permissions"]+report["unresolved_permissions"])


def test_elbv2_attribute_read_actions_use_aws_global_resource_scope():
    report=scan(plan=fixture(),account=ACCOUNT,region=REGION)
    for source,action in ELB_READS:
        rows=[x for x in report["permissions"] if x["source"]==source and x["action"]==action]
        assert len(rows)==1,(source,action,rows)
        assert rows[0]["scope"]=="*"
        assert not any(x["source"]==source and x["action"]==action
                       for x in report["unresolved_permissions"])
    listener=[x for x in report["permissions"]
              if x["source"]=="aws_lb_listener.http" and x["action"]=="elasticloadbalancing:AddTags"]
    assert listener
    assert all(x["scope"].startswith(
        f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/ecs-demo-dev-alb/*/")
               for x in listener)
    assert all(x["condition"]=={
        "StringEquals":{"elasticloadbalancing:CreateAction":"CreateListener"}
    } for x in listener)


def test_computed_endpoint_does_not_fabricate_a_missing_vpc_identity():
    plan=_computed_endpoint_plan()
    row=next(x for x in plan["resource_changes"] if x["address"]=='aws_vpc_endpoint.s3')
    row["change"]["after"]["vpc_id"]=None
    row["change"]["after_unknown"]["vpc_id"]=True
    config=next(x for x in plan["configuration"]["root_module"]["resources"]
                if x["address"]=="aws_vpc_endpoint.s3")
    config["expressions"].pop("vpc_id",None)
    report=scan(plan=plan,account=ACCOUNT,region=REGION)
    assert any(x["source"]=="aws_vpc_endpoint.s3" and
               x["action"]=="ec2:CreateVpcEndpoint"
               for x in report["unresolved_permissions"])
