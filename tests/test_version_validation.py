import json
import pytest
from tfiam.scan import scan
from tfiam.cli import main
from tfiam.versioning import selected_version,rule_for_version,evidence_status
from tfiam.authorization import audit,template_matches,condition_matches

def fixture(root):
    (root/"main.tf.json").write_text(json.dumps({"resource":{"aws_s3_bucket":{"b":{"bucket":"demo-bucket"}}}}))
def metadata(root):
    root.mkdir()
    (root/"s3.json").write_text(json.dumps({"Name":"s3","Version":"v1.5","Actions":[{"Name":"GetObject","Resources":[{"Name":"object"}],"ActionConditionKeys":["s3:ExistingObjectTag/${TagKey}"]},{"Name":"ListBucket","Resources":[{"Name":"bucket"}]},{"Name":"ListAllMyBuckets","Resources":[]}],"Resources":[{"Name":"bucket","ARNFormats":["arn:${Partition}:s3:::${BucketName}"]},{"Name":"object","ARNFormats":["arn:${Partition}:s3:::${BucketName}/${ObjectName}"]}]}))
def test_lockfile_version(tmp_path):
    pytest.importorskip("hcl2")
    (tmp_path/".terraform.lock.hcl").write_text('provider "registry.terraform.io/hashicorp/aws" {\n version = "6.10.0"\n}\n')
    assert selected_version(tmp_path)["version"]=="6.10.0"
    with pytest.raises(ValueError,match="conflicts"): selected_version(tmp_path,"6.11.0")
def test_version_override_and_evidence():
    base={"validation":"candidate","provider_versions":[],"read":["x:A"],"version_overrides":{"6.0.0":{"validation":"candidate","read":["x:B"],"evidence":[]}}}
    assert rule_for_version(base,"6.0.0")["read"]==["x:B"]
    assert rule_for_version(base,"6.1.0")["read"]==["x:A"]
    assert evidence_status(rule_for_version(base,"6.0.0"),"6.0.0")=="version-unvalidated"
def test_coverage_is_not_confidence(tmp_path):
    fixture(tmp_path)
    r=scan(tmp_path,provider_version="6.10.0")
    assert r["mapping_coverage"]["mapping_percent"]==100
    assert r["authorization_confidence"]["lifecycle_verified_resources"]==0
    assert r["resources"][0]["validation_level"]=="version-unvalidated"
    assert r["coverage"]=="PARTIAL"
def test_metadata_checks(tmp_path):
    folder=tmp_path/"meta";metadata(folder)
    permissions=[
        {"action":"s3:GetObject","scope":"arn:aws:s3:::demo-bucket","source":"wrong"},
        {"action":"s3:ListBucket","scope":"*","source":"wide"},
        {"action":"s3:ListAllMyBuckets","scope":"arn:aws:s3:::demo-bucket","source":"global"},
        {"action":"s3:GetObject","scope":"arn:aws:s3:::demo-bucket/key","source":"ok","condition":{"StringEquals":{"s3:ExistingObjectTag/Team":"x"}}},
    ]
    r=audit({"s3:NotAnAction","eks:DescribeCluster"},permissions,folder)
    assert r["status"]=="issues"
    assert {"unknown-action","metadata-missing","resource-type-mismatch","global-scope-review","action-requires-global-scope"} <= {x["code"] for x in r["findings"]}
    assert not any(x.get("source")=="ok" for x in r["findings"])
    assert len(r["evidence"]["s3"]["sha256"])==64
def test_catalog_cli_missing_metadata(tmp_path):
    assert main(["catalog-audit","--metadata-dir",str(tmp_path),"--strict"])==2
def test_invalid_explicit_version():
    with pytest.raises(ValueError): selected_version(None,"~> 6.0")
