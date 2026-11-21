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

@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-32"])
def test_plan_file_encodings(tmp_path, encoding):
    p=tmp_path/"plan.json"
    p.write_bytes(json.dumps(load()).encode(encoding))
    assert main(["scan","--plan-json",str(p),"--format","json"])==0

@pytest.mark.parametrize("raw, message", [(b"", "empty"), (b"not-json-secret", "line 1, column 1"), (b'{"x":', "line 1"), (b"[]", "JSON object")])
def test_invalid_plan_file(tmp_path, capsys, raw, message):
    p=tmp_path/"plan.json"
    p.write_bytes(raw)
    assert main(["scan","--plan-json",str(p)])==1
    err=capsys.readouterr().err
    assert message in err
    assert "not-json-secret" not in err

def test_missing_plan_file(tmp_path, capsys):
    p=tmp_path/"missing.json"
    assert main(["scan","--plan-json",str(p)])==1
    assert "file not found" in capsys.readouterr().err

def fresh_eks_plan(tmp_path):
    roles=[("cluster","aws_eks_cluster.this","role_arn"),("node","aws_eks_node_group.managed","node_role_arn"),("pods","aws_eks_pod_identity_association.ebs_csi","role_arn")]
    changes=[]; cfg=[]; resources={}
    for name,address,field in roles:
        target="aws_iam_role."+name
        typ,instance=address.split(".")
        resources.setdefault(typ,{})[instance]={field:"\u0024{"+target+".arn}"}
        resources.setdefault("aws_iam_role",{})[name]={"name":name,"path":"/ci/"}
        for addr,kind,after,unknown in [(target,"aws_iam_role",{"name":name,"path":"/ci/"},{"arn":True}),(address,typ,{"name":"demo","cluster_name":"demo","node_group_name":"nodes"},{"role_arn":True,"node_role_arn":True})]:
            changes.append({"address":addr,"type":kind,"mode":"managed","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":None,"after":after,"after_unknown":unknown,"after_sensitive":{}}})
        cfg.extend([{"address":target,"provider_config_key":"aws"},{"address":address,"provider_config_key":"aws","expressions":{field:{"references":[target+".arn",target]}}}])
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":resources}))
    return {"format_version":"1.2","terraform_version":"1.17.2","configuration":{"root_module":{"resources":cfg}},"resource_changes":changes}

def test_fresh_eks_role_arn_recovery(tmp_path):
    doc=fresh_eks_plan(tmp_path)
    r=run(doc=doc,root=tmp_path)
    expected={"aws_eks_cluster.this":"cluster","aws_eks_node_group.managed":"node","aws_eks_pod_identity_association.ebs_csi":"pods"}
    for source,name in expected.items():
        assert ("iam:PassRole","arn:aws:iam::123456789012:role/ci/"+name) in grants(r,source)
    assert not any(x["action"]=="iam:PassRole" for x in r["unresolved_permissions"])
    assert all(p["scope"]!="*" and p.get("condition") for p in r["permissions"] if p["action"]=="iam:PassRole")

@pytest.mark.parametrize("case",["sensitive","unknown_name","unknown_path","alias","ambiguous","transformed","no_source"])
def test_fresh_eks_role_arn_fail_closed(tmp_path,case):
    doc=fresh_eks_plan(tmp_path)
    change=doc["resource_changes"][1]["change"]
    role=doc["resource_changes"][0]["change"]
    if case=="sensitive": change["after_sensitive"]={"role_arn":True}
    if case=="unknown_name": role["after_unknown"]["name"]=True
    if case=="unknown_path": role["after_unknown"]["path"]=True
    if case=="alias": doc["configuration"]["root_module"]["resources"][0]["provider_config_key"]="aws.other"
    if case=="ambiguous": doc["configuration"]["root_module"]["resources"][1]["expressions"]["role_arn"]["references"].append("aws_iam_role.other.arn")
    if case=="transformed":
        p=tmp_path/"main.tf.json"; body=json.loads(p.read_text()); body["resource"]["aws_eks_cluster"]["this"]["role_arn"]="\u0024{replace(aws_iam_role.cluster.arn, \"a\", \"b\")}"
        p.write_text(json.dumps(body))
    r=run(doc=doc,root=None if case=="no_source" else tmp_path)
    assert not any(a=="iam:PassRole" for a,s in grants(r,"aws_eks_cluster.this"))
    assert any(x["source"]=="aws_eks_cluster.this" and x["action"]=="iam:PassRole" for x in r["unresolved_permissions"])

def test_computed_values_and_resolved_dependencies_are_not_warnings(tmp_path):
    doc=fresh_eks_plan(tmp_path)
    report=run(doc=doc,root=tmp_path)
    assert len(report["resolved_dependencies"])==3
    assert any("computed or unknown" in x for x in report["information"])
    assert not any("unknown values withheld" in x or "PassRole inferred" in x or "Starter catalog" in x for x in report["warnings"])
    assert any("lifecycle authorization evidence" in x for x in report["warnings"])
    assert not report["unresolved_permissions"]

def test_unknown_tag_actions_and_missing_kms_scope(tmp_path):
    doc=fresh_eks_plan(tmp_path)
    change=doc["resource_changes"][1]["change"]
    change["after_unknown"]["tags"]=True
    change["after"]["encryption_config"]=[{"provider":[{"key_arn":None}]}]
    report=run(doc=doc,root=tmp_path)
    actions={p["action"] for p in report["permissions"] if p["source"]=="aws_eks_cluster.this"}
    assert {"eks:TagResource","eks:UntagResource"} <= actions
    assert {"kms:DescribeKey","kms:CreateGrant"} <= {x["action"] for x in report["unresolved_permissions"]}
