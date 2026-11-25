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

def test_s3_hcl_id_dependencies_new_file(tmp_path):
    (tmp_path/"main.tf").write_text('resource "aws_sqs_queue" "q" { name = "test-queue" }\n')
    (tmp_path/"s3.tf").write_text("""
resource "aws_s3_bucket" "example" {
  bucket = "my-unique-app-bucket-2026"
  tags = { Name = "MyAppBucket", Environment = "Production" }
}
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration { status = "Enabled" }
}
""")
    r=scan(tmp_path,account="123456789012",region="us-east-1")
    expected={"aws_s3_bucket.example":"s3:CreateBucket","aws_s3_bucket_public_access_block.example":"s3:PutBucketPublicAccessBlock","aws_s3_bucket_versioning.example":"s3:PutBucketVersioning"}
    for source,action in expected.items():
        assert any(x["address"]==source for x in r["resources"])
        assert any(p["source"]==source and p["action"]==action and p["scope"]=="arn:aws:s3:::my-unique-app-bucket-2026" for p in r["permissions"])
    assert not r["unresolved_permissions"]

def test_s3_generated_or_sensitive_bucket_id_not_guessed(tmp_path):
    put(tmp_path,"main.tf.json",{"variable":{"secret":{"default":"private-bucket","sensitive":True}},"resource":{"aws_s3_bucket":{"prefix":{"bucket_prefix":"random-"},"hidden":{"bucket":"\u0024{var.secret}"}},"aws_s3_bucket_versioning":{"a":{"bucket":"\u0024{aws_s3_bucket.prefix.id}"},"b":{"bucket":"\u0024{aws_s3_bucket.hidden.id}"}}}})
    r=scan(tmp_path)
    assert not r["permissions"]
    assert "private-bucket" not in json.dumps(r)

def test_unevaluated_trust_and_dependency_fields_not_generic_warnings(tmp_path):
    put(tmp_path,"main.tf.json",{"resource":{"aws_iam_role":{"r":{"name":"fixture","assume_role_policy":"\u0024{jsonencode(local.trust)}"}},"aws_eks_addon":{"a":{"cluster_name":"demo","addon_name":"coredns","depends_on":["\u0024{aws_iam_role.r}"]}}}})
    r=scan(tmp_path,account="123456789012",region="us-east-1")
    assert not r["unresolved_permissions"]
    assert not any("unresolved or sensitive attributes" in w for w in r["warnings"])
    assert any("assume_role_policy" in w for w in r["information"])
    assert any(p["action"]=="iam:CreateRole" for p in r["permissions"])

def test_unknown_optional_delegation_and_boundary_block_generation(tmp_path):
    put(tmp_path,"main.tf.json",{"variable":{"secret":{"default":"arn:aws:iam::123456789012:policy/hidden","sensitive":True}},"resource":{"aws_iam_role":{"r":{"name":"fixture","permissions_boundary":"\u0024{var.secret}"}},"aws_eks_addon":{"a":{"cluster_name":"demo","addon_name":"coredns","service_account_role_arn":"\u0024{var.unknown}"}}}})
    r=scan(tmp_path,account="123456789012",region="us-east-1")
    assert {"iam:CreateRole","iam:PutRolePermissionsBoundary","iam:PassRole"} <= {p["action"] for p in r["unresolved_permissions"]}
    assert not any(p["action"]=="iam:CreateRole" for p in r["permissions"])
    assert "policy/hidden" not in json.dumps(r)
    output=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--aws-account","123456789012","--aws-region","us-east-1","--output",str(output)])==0
    assert output.is_file()
    candidate=json.loads(output.read_text())
    assert any("iam:PassRole" in row["Action"] and "REPLACE_WITH" in row["Resource"] for row in candidate["Statement"])
    assert "policy/hidden" not in output.read_text()
    report=json.loads((tmp_path/"policy.json.report.json").read_text())
    assert report["candidate_status"]=="INCOMPLETE"
    assert {"iam:PassRole","iam:CreateRole","iam:PutRolePermissionsBoundary"} <= {
        row["action"] for row in report["fallback_permissions"]}
    assert "policy/hidden" not in json.dumps(report)
    assert main(["generate",str(tmp_path),"--aws-account","123456789012","--aws-region","us-east-1","--require-complete"])==4

def test_new_iam_user_and_group_attachment_files(tmp_path):
    put(tmp_path,"main.tf.json",{"resource":{"aws_s3_bucket":{"b":{"bucket":"fixture-bucket"}}}})
    initial=scan(tmp_path,account="123456789012",region="us-east-1")
    assert len(initial["resources"])==1
    policy="arn:aws:iam::aws:policy/ReadOnlyAccess"
    put(tmp_path,"iam-user.tf.json",{"resource":{"aws_iam_user":{"dev":{"name":"developer","path":"/team/"}},"aws_iam_user_policy_attachment":{"dev_readonly":{"user":"\u0024{aws_iam_user.dev.name}","policy_arn":policy}},"aws_iam_group":{"dev":{"name":"developers","path":"/team/"}},"aws_iam_group_policy_attachment":{"dev_readonly":{"group":"developers","policy_arn":policy}}}})
    result=scan(tmp_path,account="123456789012",region="us-east-1")
    assert len(result["resources"])==5
    assert not result["unresolved_permissions"]
    assert result["mapping_coverage"]["unmapped_resources"]==0
    for kind,name in (("User","developer"),("Group","developers")):
        source="aws_iam_"+kind.lower()+"_policy_attachment.dev_readonly"
        rows={p["action"]:p for p in result["permissions"] if p["source"]==source}
        assert set(rows)=={"iam:Attach"+kind+"Policy","iam:Detach"+kind+"Policy","iam:ListAttached"+kind+"Policies"}
        assert all(p["scope"]=="arn:aws:iam::123456789012:"+kind.lower()+"/team/"+name for p in rows.values())
        assert rows["iam:Attach"+kind+"Policy"]["condition"]=={"ArnEquals":{"iam:PolicyARN":policy}}
        assert rows["iam:Detach"+kind+"Policy"]["condition"]==rows["iam:Attach"+kind+"Policy"]["condition"]
        assert not rows["iam:ListAttached"+kind+"Policies"].get("condition")
    assert main(["generate",str(tmp_path),"--aws-account","123456789012","--aws-region","us-east-1","--output",str(tmp_path/"policy.json")])==0

def test_external_user_attachment_exact_name_across_paths(tmp_path):
    put(tmp_path,"main.tf.json",{"resource":{"aws_iam_user_policy_attachment":{"a":{"user":"external","policy_arn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}}})
    result=scan(tmp_path,account="123456789012",region="us-east-1")
    assert result["mapping_coverage"]["unmapped_resources"]==0
    assert not result["unresolved_permissions"]
    assert len(result["permissions"])==6
    assert {p["scope"] for p in result["permissions"]}=={"arn:aws:iam::123456789012:user/external","arn:aws:iam::123456789012:user/*/external"}
    from tfiam.comparison import matches
    for p in result["permissions"]:
        assert not matches(p["scope"],"arn:aws:iam::123456789012:user/team/other")
        assert not matches(p["scope"],"arn:aws:iam::999999999999:user/team/external")
        if p["action"]!="iam:ListAttachedUserPolicies":
            assert p["condition"]=={"ArnEquals":{"iam:PolicyARN":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}
    assert main(["generate",str(tmp_path),"--aws-account","123456789012","--output",str(tmp_path/"policy.json")])==0

def test_external_group_attachment_unknown_policy_is_blocked(tmp_path):
    put(tmp_path,"main.tf.json",{"resource":{"aws_iam_group_policy_attachment":{"a":{"group":"external","policy_arn":"\u0024{var.unknown}"}}}})
    result=scan(tmp_path,account="123456789012")
    assert {p["action"] for p in result["permissions"]}=={"iam:ListAttachedGroupPolicies"}
    assert {p["action"] for p in result["unresolved_permissions"]}=={"iam:AttachGroupPolicy","iam:DetachGroupPolicy"}


def test_local_random_id_does_not_block_aws_generation(tmp_path):
    put(tmp_path,"main.tf.json",{"terraform":{"required_providers":{"random":{"source":"hashicorp/random"}}},"resource":{"random_id":{"suffix":{"byte_length":4}},"aws_s3_bucket":{"b":{"bucket":"known-fixture-bucket"}}}})
    report=scan(tmp_path,account="123456789012",region="us-east-1")
    entry=next(x for x in report["resources"] if x["type"]=="random_id")
    assert entry["mapping_status"]=="SKIPPED"
    assert report["mapping_coverage"]["unmapped_resources"]==0
    assert not any(x["source"]=="random_id.suffix" for x in report["permissions"])
    dest=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--aws-account","123456789012","--aws-region","us-east-1","--output",str(dest)])==0
    assert dest.exists()


def test_random_id_unknown_bucket_and_custom_provider_still_block(tmp_path):
    config={"resource":{"random_id":{"suffix":{"byte_length":4}},"aws_s3_bucket":{"b":{"bucket":"fixture-${random_id.suffix.hex}"}}}}
    put(tmp_path,"main.tf.json",config)
    report=scan(tmp_path,account="123456789012",region="us-east-1")
    assert report["unresolved_permissions"]
    assert not any(x["scope"]=="*" for x in report["permissions"] if x["action"].startswith("s3:"))
    config["terraform"]={"required_providers":{"random":{"source":"example/custom"}}}
    put(tmp_path,"main.tf.json",config)
    report=scan(tmp_path,account="123456789012",region="us-east-1")
    assert report["mapping_coverage"]["unmapped_resources"]==1
