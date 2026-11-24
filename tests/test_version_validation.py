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

def test_eks_documented_global_metadata_fallback(tmp_path):
    (tmp_path/"eks.json").write_text(json.dumps({"Name":"eks","Actions":[{"Name":"CreateCluster"},{"Name":"DescribeAddonVersions"},{"Name":"DescribeCluster"}]}))
    actions=["eks:CreateCluster","eks:DescribeAddonVersions","eks:DescribeCluster"]
    rows=[{"action":a,"scope":"*","source":"fixture"} for a in actions]
    out=audit(actions,rows,tmp_path)
    assert {x["action"] for x in out["reference_fallbacks"]}==set(actions[:2])
    assert [x["action"] for x in out["findings"]]==["eks:DescribeCluster"]
    rows[0]["scope"]="arn:aws:eks:us-east-1:123456789012:cluster/demo"
    assert any(x["code"]=="action-requires-global-scope" for x in audit(actions,rows,tmp_path)["findings"])


def test_public_cli_has_no_maintainer_source_commands(capsys):
    with pytest.raises(SystemExit) as e: main(["--help"])
    assert e.value.code==0
    text=capsys.readouterr().out
    assert "provider-audit" not in text and "evidence-audit" not in text
    with pytest.raises(SystemExit) as e: main(["catalog-audit","--refresh"])
    assert e.value.code==2

def test_normal_scan_and_generate_require_no_network_or_provider_checkout(tmp_path,monkeypatch):
    import subprocess
    import tfiam.authorization as auth
    def forbidden(*args,**kwargs): raise AssertionError("External call attempted")
    monkeypatch.setattr(auth,"urlopen",forbidden)
    monkeypatch.setattr(subprocess,"run",forbidden)
    monkeypatch.setattr(auth,"bundled_metadata",lambda:None)
    fixture(tmp_path)
    output=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--allow-partial","--output",str(output)])==0
    assert json.loads(output.read_text())["Statement"]
    assert scan(tmp_path)["authorization_metadata"]["metadata_source"]=="not-packaged-in-source-checkout"

def test_packaged_snapshot_automatically_selected(tmp_path,monkeypatch):
    import tfiam.authorization as auth
    root=tmp_path/"metadata"
    metadata(root)
    fixture(tmp_path)
    monkeypatch.setattr(auth,"bundled_metadata",lambda:root)
    report=scan(tmp_path)
    assert report["authorization_metadata"]["metadata_source"]=="packaged"
    assert report["authorization_metadata"]["status"]=="issues" # deliberately incomplete test snapshot
    report=scan(tmp_path,authorization_metadata=root)
    assert report["authorization_metadata"]["metadata_source"]=="explicit-offline-snapshot"


def test_global_autoscaling_and_sts_reference_fallback(tmp_path):
    actions=[
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeScalingActivities",
        "autoscaling:DescribeTags",
        "sts:GetCallerIdentity",
    ]
    for service, names in (
        ("autoscaling",[a.split(":")[1] for a in actions[:3]]),
        ("sts",["GetCallerIdentity"]),
    ):
        (tmp_path/(service+".json")).write_text(json.dumps({
            "Name":service,
            "Actions":[{"Name":name} for name in names]
        }))
    rows=[{"action":action,"scope":"*","source":"fixture"} for action in actions]
    out=audit(actions,rows,tmp_path)
    assert out["status"]=="compatible",out["findings"]
    assert {x["action"] for x in out["reference_fallbacks"]}==set(actions)
    rows[0]["scope"]="arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:*:autoScalingGroupName/test"
    out=audit(actions,rows,tmp_path)
    assert any(x["action"]==actions[0] and x["code"]=="action-requires-global-scope" for x in out["findings"])
