"""Regression coverage for prospective AWS resource dependencies in plan JSON.

Tests use Terraform's official configuration.expressions.references graph;
no source-only HCL evaluation or tags are needed to infer created resources.
"""
import json
from tfiam.scan import scan
from tfiam.cli import main


ACCOUNT="638631156706"
REGION="us-east-1"
AWS="registry.terraform.io/hashicorp/aws"


def planned_node(kind,name,after,refs=None):
    address=f"{kind}.{name}"
    unknown={"id":True}
    expressions={}
    for field,source in (refs or {}).items():
        unknown[field]=True
        expressions[field]={"references":[source]}
    row={
        "address":address,"mode":"managed","type":kind,
        "provider_name":AWS,
        "change":{"actions":["create"],"before":None,"after":after,
                  "after_unknown":unknown},
    }
    config={
        "address":address,"mode":"managed","type":kind,
        "provider_config_key":"aws","expressions":expressions,
    }
    return row,config


def test_plan_graph_resolves_vpc_subnet_route_table_and_security_group_without_source_or_tags():
    specs=[
        ("aws_vpc","main",{"cidr_block":"10.0.0.0/16"},{}),
        ("aws_subnet","private",{"vpc_id":None,"cidr_block":"10.0.1.0/24"},
         {"vpc_id":"aws_vpc.main.id"}),
        ("aws_route_table","private",{"vpc_id":None},
         {"vpc_id":"aws_vpc.main.id"}),
        ("aws_security_group","ecs",{"name":"ecs","vpc_id":None},
         {"vpc_id":"aws_vpc.main.id"}),
    ]
    rows,configs=zip(*(planned_node(*spec) for spec in specs))
    doc={
        "format_version":"1.2","terraform_version":"1.17.1",
        "resource_changes":list(rows),
        "configuration":{"root_module":{"resources":list(configs)}},
    }
    report=scan(plan=doc,account=ACCOUNT,region=REGION)
    vpc=f"arn:aws:ec2:{REGION}:{ACCOUNT}:vpc/*"
    expected={
        "aws_subnet.private":("ec2:CreateSubnet","subnet/*"),
        "aws_route_table.private":("ec2:CreateRouteTable","route-table/*"),
        "aws_security_group.ecs":("ec2:CreateSecurityGroup","security-group/*"),
    }
    for source,(action,suffix) in expected.items():
        scopes={
            row["scope"] for row in report["permissions"]
            if row["source"]==source and row["action"]==action
        }
        assert vpc in scopes,(source,action,scopes)
        assert f"arn:aws:ec2:{REGION}:{ACCOUNT}:{suffix}" in scopes
        assert not any(
            x["source"]==source and x["action"]==action
            for x in report["unresolved_permissions"]
        ),source
    assert not any(
        row["action"]=="ec2:CreateSubnet" and row["scope"]=="*"
        for row in report["permissions"]
    )


def test_plan_without_parent_creation_cannot_invent_prospective_reference():
    vpc,config_vpc=planned_node("aws_vpc","main",{"id":"vpc-12345678"})
    vpc["change"]={"actions":["no-op"],"before":{"id":"vpc-12345678"},
                   "after":{"id":"vpc-12345678"},"after_unknown":{}}
    subnet,config_subnet=planned_node(
        "aws_subnet","private",{"vpc_id":None},
        {"vpc_id":"aws_vpc.main.id"}
    )
    doc={"format_version":"1.2","terraform_version":"1.17.1",
         "resource_changes":[vpc,subnet],
         "configuration":{"root_module":{"resources":[config_vpc,config_subnet]}}}
    report=scan(plan=doc,account=ACCOUNT,region=REGION)
    assert any(x["source"]=="aws_subnet.private" and
               x["action"]=="ec2:CreateSubnet"
               for x in report["unresolved_permissions"])


def test_cli_candidate_uses_prospective_scoped_dependencies(tmp_path):
    specs=[
        planned_node("aws_vpc","main",{"cidr_block":"10.0.0.0/16"}),
        planned_node("aws_subnet","private",{"vpc_id":None,"cidr_block":"10.0.1.0/24"},
                     {"vpc_id":"aws_vpc.main.id"}),
    ]
    doc={"format_version":"1.2","terraform_version":"1.17.1",
         "resource_changes":[x[0] for x in specs],
         "configuration":{"root_module":{"resources":[x[1] for x in specs]}}}
    saved=tmp_path/"plan.json"
    saved.write_text(json.dumps(doc))
    output=tmp_path/"candidate.json"
    assert main(["generate","--plan-json",str(saved),
                 "--aws-account",ACCOUNT,"--aws-region",REGION,
                 "--output",str(output)])==0
    data=json.loads(output.read_text())
    scoped=[x for x in data["Statement"] if "ec2:CreateSubnet" in x["Action"]]
    assert scoped
    assert all(x["Resource"]!="*" for x in scoped)
    assert any("vpc/*" in str(x["Resource"]) for x in scoped)
