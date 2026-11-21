import json
from pathlib import Path
import pytest
from tfiam.cli import main
from tfiam.scan import scan
from tfiam.plan import masked

FIXTURE=Path(__file__).resolve().parents[1]/"examples"/"plans"/"mixed.plan.json"
ACCOUNT="123456789012"
REGION="us-east-1"

def load():
    return json.loads(FIXTURE.read_text())

def run(phase="apply", doc=None, root=None):
    return scan(root,phase,ACCOUNT,REGION,plan=load() if doc is None else doc)

def grants(report, source):
    return {(r["action"],r["scope"]) for r in report["permissions"] if r["source"]==source}

def test_operation_specific_scope():
    r=run()
    assert r["input"]=="terraform-plan-json"
    assert r["plan"]["change_count"]==11
    assert r["coverage"]=="PARTIAL"
    assert ("s3:CreateBucket","arn:aws:s3:::new-pipeline-bucket") in grants(r,"aws_s3_bucket.created")
    assert not any(a=="s3:DeleteBucket" for a,s in grants(r,"aws_s3_bucket.created"))
    assert ("s3:DeleteBucket","arn:aws:s3:::old-bucket") in grants(r,"aws_s3_bucket.removed")
    assert not any(a=="s3:CreateBucket" for a,s in grants(r,"aws_s3_bucket.removed"))
    assert ("sqs:SetQueueAttributes","arn:aws:sqs:us-east-1:123456789012:pipeline-queue") in grants(r,"aws_sqs_queue.updated")
    assert not any(a in ("sqs:CreateQueue","sqs:DeleteQueue") for a,s in grants(r,"aws_sqs_queue.updated"))

def test_replacement_and_full_instance_address():
    r=run()
    addr='module.child["blue"].aws_iam_role.runner[0]'
    g=grants(r,addr)
    assert ("iam:DeleteRole","arn:aws:iam::123456789012:role/ci/old-role") in g
    assert ("iam:CreateRole","arn:aws:iam::123456789012:role/ci/new-role") in g
    assert ("iam:CreateRole","arn:aws:iam::123456789012:role/ci/old-role") not in g
    assert ("iam:DeleteRole","arn:aws:iam::123456789012:role/ci/new-role") not in g
    assert sum(e["address"]==addr for e in r["resources"])==1
    doc=load()
    replacement=next(x for x in doc["resource_changes"] if x["address"]==addr)
    replacement["change"]["actions"]=["create","delete"]
    assert grants(run(doc=doc),addr)==g

def test_sensitive_unknown_and_foreign_provider():
    r=run()
    assert "do-not-leak-sensitive-role" not in json.dumps(r)
    for source in ("aws_iam_role.hidden","aws_s3_bucket.unknown","aws_iam_policy.unknown","aws_s3_bucket.forgotten","random_pet.name"):
        assert not grants(r,source)
    assert not any(p["scope"]=="*" and p["action"].startswith("iam:") for p in r["permissions"])
    assert masked({"a":[{"secret":"x","public":"y"}]},{"a":[{"secret":True}]})=={"a":[{"secret":None,"public":"y"}]}

def test_noop_data_and_read_phase():
    r=run()
    assert grants(r,"aws_eks_cluster.unchanged")=={("eks:DescribeCluster","arn:aws:eks:us-east-1:123456789012:cluster/existing")}
    assert grants(r,"data.aws_ami.base")=={("ec2:DescribeImages","*")}
    read=run("plan")
    assert all(not any(x in p["action"] for x in ("Create","Delete","Update","AttachRole","Detach","PassRole","Put","Set")) for p in read["permissions"])
    with pytest.raises(ValueError,match="destroy-only"):
        run("destroy")
    doc=load()
    doc["resource_changes"]=[x for x in doc["resource_changes"] if x["change"]["actions"]==["delete"]]
    assert ("s3:DeleteBucket","arn:aws:s3:::old-bucket") in grants(run("destroy",doc),"aws_s3_bucket.removed")

def test_plan_validation_and_deposed():
    for doc in ({}, {"format_version":"2.0","terraform_version":"1.10.5","resource_changes":[]}, {"format_version":"1.0","terraform_version":"1.10.5","values":{}}, {**load(),"errored":True}):
        with pytest.raises(ValueError):
            run(doc=doc)
    doc=load()
    doc["complete"]=False
    doc["resource_changes"][2]["deposed"]="abcd1234"
    r=run(doc=doc)
    assert any("incomplete" in w for w in r["warnings"])
    assert grants(r,"aws_s3_bucket.removed (deposed abcd1234)")

def test_directory_only_supplies_backend(tmp_path):
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_s3_bucket":{"not_in_plan":{"bucket":"unplanned-bucket"}}},"terraform":{"backend":{"s3":{"bucket":"state-bucket","key":"prod.tfstate","use_lockfile":True}}}}))
    r=run(root=tmp_path)
    assert not any("unplanned-bucket" in p["scope"] for p in r["permissions"])
    assert any(p["scope"]=="arn:aws:s3:::state-bucket/prod.tfstate.tflock" for p in r["permissions"])

def test_cli_outputs(tmp_path):
    args=["--plan-json",str(FIXTURE),"--aws-account",ACCOUNT,"--aws-region",REGION]
    report=tmp_path/"report.json"; out=tmp_path/"policy.json"
    assert main(["scan",*args,"--format","json","--strict","--output",str(report)])==2
    assert json.loads(report.read_text())["plan"]["change_count"]==11
    assert main(["generate",*args,"--allow-partial","--output",str(out)])==0
    assert json.loads(out.read_text())["Statement"]
    existing=tmp_path/"existing.json"
    existing.write_text('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}')
    assert main(["compare",*args,"--existing",str(existing),"--output",str(report)])==0
    assert json.loads(report.read_text())["input"]=="terraform-plan-json"
    assert main(["scan"])==1
