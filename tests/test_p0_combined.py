import json
from tfiam.scan import scan
from tfiam.action_scope import network

A="123456789012"
R="us-east-1"

def write(tmp_path,doc):
    (tmp_path/"main.tf.json").write_text(json.dumps(doc))

def test_provider_contexts(tmp_path):
    write(tmp_path,{"provider":{"aws":[{"region":R},{"alias":"west","region":"us-west-2","assume_role":{"role_arn":"arn:aws:iam::999999999999:role/deploy"}}]},"resource":{"aws_sqs_queue":{"east":{"name":"east"},"west":{"provider":"aws.west","name":"west"}}}})
    blocked=scan(tmp_path,account=A,region=R)
    assert any(p["action"]=="AWS provider context" for p in blocked["unresolved_permissions"])
    result=scan(tmp_path,account=A,region=R,provider_contexts={"aws.west":{"account":"999999999999","region":"us-west-2"}})
    assert not result["unresolved_permissions"]
    assert {x["scope"] for x in result["permissions"]}=={f"arn:aws:sqs:{R}:{A}:east","arn:aws:sqs:us-west-2:999999999999:west"}

def test_tag_bound_parent(tmp_path):
    write(tmp_path,{"resource":{"aws_vpc":{"v":{"cidr_block":"10.0.0.0/16","tags":{"tfiam:scope":"fixture-vpc"}}},"aws_subnet":{"s":{"vpc_id":"\u0024{aws_vpc.v.id}","cidr_block":"10.0.1.0/24","tags":{"tfiam:scope":"fixture-subnet"}}}}})
    result=scan(tmp_path,account=A,region=R,scope_resource_tags=True)
    assert not result["unresolved_permissions"], result["unresolved_permissions"]
    assert any(p["action"]=="ec2:CreateSubnet" and p["scope"]==f"arn:aws:ec2:{R}:{A}:vpc/*" and p.get("condition")=={"StringEquals":{"ec2:ResourceTag/tfiam:scope":"fixture-vpc"}} for p in result["permissions"])

def test_snapshot_and_named_groups(tmp_path):
    write(tmp_path,{"resource":{"aws_db_instance":{"d":{"identifier":"target","snapshot_identifier":"source","db_subnet_group_name":"my-subnet","parameter_group_name":"my-param"}}}})
    result=scan(tmp_path,account=A,region=R)
    assert not result["unresolved_permissions"],result["unresolved_permissions"]
    assert {p["scope"] for p in result["permissions"] if p["action"]=="rds:RestoreDBInstanceFromDBSnapshot"}=={f"arn:aws:rds:{R}:{A}:{s}" for s in ("db:target","snapshot:source","subgrp:my-subnet","pg:my-param")}
    assert not any(p["action"]=="rds:CreateDBInstance" for p in result["permissions"])

def test_update_minimization():
    plan={"format_version":"1.2","terraform_version":"1.10.0","resource_changes":[{"address":"aws_sqs_queue.q","mode":"managed","type":"aws_sqs_queue","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["update"],"before":{"name":"q","tags":{"Name":"a"}},"after":{"name":"q","tags":{"Name":"b"}}}}]}
    result=scan(plan=plan,account=A,region=R)
    acts={p["action"] for p in result["permissions"]}
    assert "sqs:TagQueue" in acts
    assert not {"sqs:SetQueueAttributes","sqs:DeleteQueue","sqs:CreateQueue"} & acts

def test_sqs_acceptance_fixture(tmp_path):
    import importlib.util
    from pathlib import Path
    spec=importlib.util.spec_from_file_location("accept_sqs",Path(__file__).resolve().parents[1]/"scripts/accept-sqs.py")
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    from argparse import Namespace
    dest=tmp_path/"accept"
    mod.prepare(Namespace(directory=dest,version="6.73.0",account=A,region=R))
    info=json.loads((dest/"prepare.json").read_text())
    assert len(info["queues"])==3
    grants=mod.grants(json.loads((dest/"candidate-policy.json").read_text()))
    assert {scope for action,scope in grants}=={f"arn:aws:sqs:{R}:{A}:{q}" for q in info["queues"]}
    assert all(action.startswith("sqs:") and "*" not in action+scope for action,scope in grants)
