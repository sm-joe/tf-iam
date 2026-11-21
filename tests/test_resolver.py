import json
from tfiam.scan import scan
from tfiam.cli import main
from tfiam.resolver import root_inputs

def put(folder,name,obj):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/name).write_text(json.dumps(obj))

def test_input_precedence(tmp_path):
    decl={"name":{"default":"default"}}
    put(tmp_path,"terraform.tfvars.json",{"name":"regular"})
    put(tmp_path,"z.auto.tfvars.json",{"name":"auto"})
    put(tmp_path,"explicit.json",{"name":"explicit"})
    assert root_inputs(tmp_path,decl,[tmp_path/"explicit.json"],[("name","cli")],lambda x:None,{"TF_VAR_name":"env"})["name"]=="cli"
    assert root_inputs(tmp_path,decl,[],[],lambda x:None,{"TF_VAR_name":"env"})["name"]=="auto"

def test_repeated_module_and_output(tmp_path):
    put(tmp_path,"main.tf.json",{"module":{"a":{"source":"./child","name":"alpha"},"b":{"source":"./child","name":"beta"}},"resource":{"aws_eks_cluster":{"x":{"name":"demo","role_arn":"${module.a.arn}"}}}})
    put(tmp_path/"child","main.tf.json",{"variable":{"name":{}},"resource":{"aws_iam_role":{"r":{"name":"${var.name}","path":"/ci/"}}},"output":{"arn":{"value":"${aws_iam_role.r.arn}"}}})
    r=scan(tmp_path,"apply","123456789012","us-east-1")
    assert {x["address"] for x in r["resources"]}=={"module.a.aws_iam_role.r","module.b.aws_iam_role.r","aws_eks_cluster.x"}
    assert any(p["action"]=="iam:PassRole" and p["scope"].endswith("/ci/alpha") for p in r["permissions"])
    assert not any(p["action"]=="iam:PassRole" and p["scope"].endswith("/ci/beta") for p in r["permissions"])

def test_installed_module(tmp_path):
    source="example/test/aws"
    put(tmp_path,"main.tf.json",{"module":{"remote":{"source":source}}})
    put(tmp_path/".terraform/modules","modules.json",{"Modules":[{"Key":"remote","Source":source,"Dir":".terraform/modules/remote"}]})
    put(tmp_path/".terraform/modules/remote","main.tf.json",{"resource":{"aws_s3_bucket":{"b":{"bucket":"installed-bucket"}}}})
    r=scan(tmp_path)
    assert r["modules"][0]["status"]=="RESOLVED"
    assert any(p["scope"]=="arn:aws:s3:::installed-bucket" for p in r["permissions"])

def test_unknown_sensitive_and_cycle(tmp_path):
    put(tmp_path,"main.tf.json",{"variable":{"secret":{"default":"private-bucket","sensitive":True}},"locals":{"a":"${local.b}","b":"${local.a}"},"resource":{"aws_s3_bucket":{"x":{"bucket":"${var.secret}"},"y":{"bucket":"${local.a}"}}}})
    r=scan(tmp_path)
    assert not r["permissions"]
    assert "private-bucket" not in json.dumps(r)
    assert any("unresolved" in x for x in r["warnings"])

def test_cli_variable_and_interpolation(tmp_path):
    put(tmp_path,"main.tf.json",{"variable":{"environment":{"default":"dev"}},"resource":{"aws_s3_bucket":{"x":{"bucket":"company-${var.environment}"}}}})
    out=tmp_path/"report.json"
    assert main(["scan",str(tmp_path),"--var","environment=prod","--format","json","--output",str(out)])==0
    assert any(p["scope"]=="arn:aws:s3:::company-prod" for p in json.loads(out.read_text())["permissions"])

def test_role_attachment_path(tmp_path):
    put(tmp_path,"main.tf.json",{"resource":{"aws_iam_role":{"r":{"name":"runner","path":"/ci/"}},"aws_iam_role_policy_attachment":{"a":{"role":"${aws_iam_role.r.name}","policy_arn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}}})
    r=scan(tmp_path,"apply","123456789012","us-east-1")
    assert any(p["action"]=="iam:AttachRolePolicy" and p["scope"].endswith("/ci/runner") for p in r["permissions"])
