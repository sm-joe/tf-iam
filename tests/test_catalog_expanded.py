import json
from tfiam.catalog_loader import CATALOG, get_rule, operation_actions
from tfiam.scan import scan

def write(root, resources, data=None):
    (root/"main.tf.json").write_text(json.dumps({"resource":resources,"data":data or {}}))

def test_catalog_inventory():
    assert len(CATALOG["resources"])>=108
    assert {"aws_iam_user_policy_attachment","aws_iam_group_policy_attachment"} <= CATALOG["resources"].keys()
    assert len(CATALOG["data"])==37
    for kind, rule in CATALOG["resources"].items():
        assert rule["validation"]=="candidate"
        assert set(rule["write"])==set(rule["create"]+rule["update"])
        assert set(operation_actions(rule,"read"))==set(rule["read"])
    assert not get_rule("data","aws_ecr_repository")["write"]

def test_expanded_scopes(tmp_path):
    write(tmp_path,{
        "aws_ecr_repository":{"app":{"name":"pipeline/app"}},
        "aws_lambda_function":{"f":{"function_name":"processor","role":"arn:aws:iam::123456789012:role/ci/runtime"}},
        "aws_s3_bucket_policy":{"p":{"bucket":"pipeline-bucket"}},
        "aws_iam_openid_connect_provider":{"oidc":{"url":"https://token.actions.githubusercontent.com"}},
        "aws_kms_key_policy":{"k":{"key_id":"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"}},
        "aws_eks_access_entry":{"a":{"cluster_name":"demo","principal_arn":"arn:aws:iam::123456789012:role/ci/reader"}},
    })
    report=scan(tmp_path,"apply","123456789012","us-east-1")
    rows=report["permissions"]
    def has(action,scope):
        return any(p["action"]==action and p["scope"]==scope for p in rows)
    assert has("ecr:CreateRepository","arn:aws:ecr:us-east-1:123456789012:repository/pipeline/app")
    assert has("lambda:CreateFunction","arn:aws:lambda:us-east-1:123456789012:function:processor")
    assert has("s3:PutBucketPolicy","arn:aws:s3:::pipeline-bucket")
    assert has("iam:CreateOpenIDConnectProvider","arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com")
    assert has("kms:PutKeyPolicy","arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
    assert has("eks:CreateAccessEntry","arn:aws:eks:us-east-1:123456789012:cluster/demo")
    grant=next(p for p in rows if p["action"]=="iam:PassRole")
    assert grant["condition"]=={"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}
    assert not any(p["scope"]=="*" and p["action"].startswith("iam:") for p in rows)

def test_unresolved_and_global_read(tmp_path):
    write(tmp_path,{
        "aws_iam_role_policy":{"x":{"role":"external","name":"inline"}},
        "aws_kms_key_policy":{"x":{"key_id":"unknown"}},
        "aws_vpc_endpoint":{"x":{}},
        "aws_eks_access_policy_association":{"x":{"cluster_name":"demo","policy_arn":"arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"}},
    })
    report=scan(tmp_path,"apply","123456789012","us-east-1")
    assert all(r["status"]=="PARTIAL" for r in report["resources"])
    assert {(p["action"],p["scope"]) for p in report["permissions"]}=={("ec2:DescribeVpcEndpoints","*")}
    assert any("omitted" in w for w in report["warnings"])

def test_expanded_plan_operation(tmp_path):
    doc={"format_version":"1.2","terraform_version":"1.10.0","resource_changes":[
        {"address":"aws_ecr_repository.app","mode":"managed","type":"aws_ecr_repository","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["update"],"before":{"name":"app"},"after":{"name":"app"}}}
    ]}
    report=scan(plan=doc,account="123456789012",region="us-east-1")
    actions={p["action"] for p in report["permissions"]}
    assert "ecr:PutImageTagMutability" in actions
    assert "ecr:CreateRepository" not in actions
    assert "ecr:DeleteRepository" not in actions

def test_all_service_families_mapped(tmp_path):
    types=["aws_iam_instance_profile","aws_eks_access_entry","aws_internet_gateway","aws_launch_template","aws_autoscaling_group","aws_s3_bucket_policy","aws_kms_key","aws_ecr_repository","aws_ecs_service","aws_db_instance","aws_lambda_function","aws_cloudwatch_log_group","aws_lb","aws_route53_record"]
    write(tmp_path,{t:{"example":{}} for t in types})
    report=scan(tmp_path)
    assert {r["type"] for r in report["resources"]}==set(types)
    assert all(r["status"]=="PARTIAL" for r in report["resources"])
