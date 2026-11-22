import json
from tfiam.scan import scan
from tfiam.plan import parse_plan
from tfiam.optimization import minimize
from tfiam.provider_context import plan_contexts
from tfiam.dependencies import dependencies

A="123456789012"
R="us-east-1"

def test_masked_prior_values_do_not_remove_actions():
    doc={"format_version":"1.2","terraform_version":"1.10.0","resource_changes":[{
        "address":"aws_iam_user.x","mode":"managed","type":"aws_iam_user",
        "provider_name":"registry.terraform.io/hashicorp/aws","change":{
            "actions":["update"],"before":{"name":"old","path":"/"},
            "after":{"name":None,"path":"/"},"before_sensitive":{"name":True}}}]}
    _,tasks,_,_=parse_plan(doc,"apply")
    task=tasks[0]
    assert "iam:UpdateUser" in minimize("aws_iam_user",["iam:UpdateUser"],task["body"],task)

def test_provider_override_cannot_bypass_provider_identity():
    doc={"configuration":{"provider_config":{"wrong":{"full_name":"registry.terraform.io/hashicorp/random"}},
        "root_module":{"resources":[{"address":"aws_sqs_queue.q","provider_config_key":"wrong"}]}}}
    select=plan_contexts(doc,(A,R,"aws"),{"wrong":(A,R,"aws")})
    assert select("aws_sqs_queue.q") is None

def test_generated_vpc_endpoint_lists(tmp_path):
    doc={"resource":{
        "aws_vpc":{"v":{"cidr_block":"10.0.0.0/16","tags":{"tfiam:scope":"vpc"}}},
        "aws_subnet":{"s":{"vpc_id":"${aws_vpc.v.id}","cidr_block":"10.0.1.0/24","tags":{"tfiam:scope":"subnet"}}},
        "aws_security_group":{"g":{"vpc_id":"${aws_vpc.v.id}","name":"test","tags":{"tfiam:scope":"group"}}},
        "aws_vpc_endpoint":{"e":{"vpc_id":"${aws_vpc.v.id}","service_name":"com.amazonaws.us-east-1.sqs","vpc_endpoint_type":"Interface","subnet_ids":["${aws_subnet.s.id}"],"security_group_ids":["${aws_security_group.g.id}"],"tags":{"tfiam:scope":"endpoint"}}}}}
    (tmp_path/"main.tf.json").write_text(json.dumps(doc))
    candidate=scan(tmp_path,account=A,region=R,scope_resource_tags=True)
    rows=[p for p in candidate["permissions"] if p["action"]=="ec2:CreateVpcEndpoint"]
    assert any(p["scope"]==f"arn:aws:ec2:{R}:{A}:subnet/*" and p.get("condition")=={"StringEquals":{"ec2:ResourceTag/tfiam:scope":"subnet"}} for p in rows)
    assert any(p["scope"]==f"arn:aws:ec2:{R}:{A}:security-group/*" and p.get("condition")=={"StringEquals":{"ec2:ResourceTag/tfiam:scope":"group"}} for p in rows)
    doc["resource"]["aws_vpc_endpoint"]["e"]["subnet_ids"].append("${var.unknown}")
    (tmp_path/"main.tf.json").write_text(json.dumps(doc))
    candidate=scan(tmp_path,account=A,region=R,scope_resource_tags=True)
    assert not any(p["action"]=="ec2:CreateVpcEndpoint" for p in candidate["permissions"])

def test_final_cluster_snapshot_scope():
    grants=[]; missing=[]
    emit=lambda a,r,c=None: grants.append((a,r))
    dependencies("aws_rds_cluster",{"skip_final_snapshot":False,"final_snapshot_identifier":"final-test"},["rds:DeleteDBCluster"],A,R,"aws",lambda v:v,emit,missing.append,{"operation":"delete"},"destroy")
    assert grants==[("rds:DeleteDBCluster",f"arn:aws:rds:{R}:{A}:cluster-snapshot:final-test")]
    assert not missing
    dependencies("aws_rds_cluster",{"skip_final_snapshot":False},["rds:DeleteDBCluster"],A,R,"aws",lambda v:v,emit,missing.append,{"operation":"delete","unknown_fields":["final_snapshot_identifier"]},"destroy")
    assert missing==["rds:DeleteDBCluster"]
