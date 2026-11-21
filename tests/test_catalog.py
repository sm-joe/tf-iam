from tfiam.catalog_loader import operation_actions
import json
from pathlib import Path
from tfiam.catalog_loader import load_catalog, get_rule, actions_for, attribute_values
from tfiam.scan import scan
from tfiam.cli import main

def test_catalog_and_lifecycle():
    c=load_catalog()
    assert c["provider"]=="registry.terraform.io/hashicorp/aws"
    r=get_rule("resource","aws_eks_cluster")
    assert "eks:CreateCluster" in actions_for(r,"apply")
    assert "eks:CreateCluster" not in actions_for(r,"plan")
    assert "eks:CreateCluster" not in actions_for(r,"destroy")
    bucket_data=get_rule("data","aws_s3_bucket")
    bucket_resource=get_rule("resource","aws_s3_bucket")
    assert bucket_data is not bucket_resource
    assert bucket_data["read"]
    assert not any(bucket_data[k] for k in ("create","update","write","delete"))
    assert "s3:CreateBucket" in operation_actions(bucket_resource,"create")
    assert "s3:CreateBucket" not in operation_actions(bucket_data,"read")
    assert get_rule("data","aws_iam_role_policy_attachment") is None
    assert get_rule("data","aws_eks_cluster")["write"]==[]

def test_nested_attributes():
    assert attribute_values({"encryption_config":[{"provider":[{"key_arn":"arn:example"}]}]},"encryption_config.provider.key_arn")==["arn:example"]

def test_aws_only_and_attribute_rules(tmp_path):
    body={"resource":{"aws_eks_cluster":{"x":{"name":"test","tags":{"owner":"ci"},"encryption_config":[{"provider":[{"key_arn":"arn:aws:kms:us-east-1:123456789012:key/example"}]}]}},"google_storage_bucket":{"x":{}}}}
    (tmp_path/"main.tf.json").write_text(json.dumps(body))
    report=scan(tmp_path,"apply","123456789012","us-east-1")
    assert all(p["provider"]=="aws" for p in report["permissions"])
    assert any(r["status"]=="UNSUPPORTED" for r in report["resources"])
    grant=next(p for p in report["permissions"] if p["action"]=="kms:CreateGrant")
    assert grant["condition"]=={"Bool":{"kms:GrantIsForAWSResource":"true"}}
    assert not any(r.get("provider_version_validated") for r in report["resources"])
    assert "eks:TagResource" in {p["action"] for p in report["permissions"]}
    assert "kms:CreateGrant" not in {p["action"] for p in scan(tmp_path,"plan","123456789012","us-east-1")["permissions"]}
