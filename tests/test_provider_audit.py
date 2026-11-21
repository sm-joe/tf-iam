import json
import subprocess
from tfiam.provider_audit import audit_provider, reconcile, operation_index

def fixture():
    return {"Name":"s3","Actions":[{"Name":"PutBucketPublicAccessBlock"},{"Name":"GetBucketPublicAccessBlock"},{"Name":"ListBucket"}],
            "Operations":[{"Name":"DeletePublicAccessBlock","AuthorizedActions":[{"Name":"PutBucketPublicAccessBlock","Service":"s3"}]},
                          {"Name":"HeadBucket","AuthorizedActions":[{"Name":"ListBucket","Service":"s3"}]},
                          {"Name":"Other","AuthorizedActions":[{"Name":"One","Service":"s3"},{"Name":"Two","Service":"iam"}]}]}

def test_documented_aliases_and_conditional_review():
    source="conn.DeletePublicAccessBlock(ctx,input)\nconn.HeadBucket(ctx,input)\nconn.Other(ctx,input)\nconn.Missing(ctx,input)"
    rows={r["operation"]:r for r in reconcile("aws_s3_bucket_public_access_block",source,fixture(),"6.73.0")}
    assert rows["DeletePublicAccessBlock"]["actions"]==["s3:PutBucketPublicAccessBlock"]
    assert rows["DeletePublicAccessBlock"]["status"]=="MATCHED"
    assert rows["HeadBucket"]["status"]=="MISSING_CANDIDATE"
    assert rows["Other"]["status"]=="CONDITIONAL_REVIEW"
    assert rows["Missing"]["status"]=="METADATA_UNAVAILABLE"

def test_provider_audit_uses_tag_not_worktree(tmp_path):
    src=tmp_path/"src"; src.mkdir()
    def git(*args):
        return subprocess.run(["git","-C",str(src),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    git("init"); git("config","user.email","test@example.invalid"); git("config","user.name","Test")
    p=src/"internal/service/s3/bucket_public_access_block.go"; p.parent.mkdir(parents=True)
    p.write_text("conn.DeletePublicAccessBlock(ctx,input)")
    git("add","."); git("commit","-m","test"); git("tag","v1.2.3")
    p.write_text("conn.Untrusted(ctx,input)")
    md=tmp_path/"metadata"; md.mkdir(); (md/"s3.json").write_text(json.dumps(fixture()))
    out=audit_provider(src,"1.2.3",md,["aws_s3_bucket_public_access_block"])
    assert out["status"]=="review" # tag is not independently pinned
    assert out["resources"][0]["operations"][0]["operation"]=="DeletePublicAccessBlock"
    assert len(out["resources"][0]["sha256"])==64

def test_role_source_corrections_are_version_specific(tmp_path):
    from tfiam.catalog_loader import get_rule
    from tfiam.scan import scan
    from tfiam.risk import destructive
    role=get_rule("resource","aws_iam_role","6.73.0")
    assert "iam:ListInstanceProfilesForRole" in role["delete"]
    assert "iam:UpdateRoleDescription" in role["update"]
    assert "iam:GetRolePolicy" in role["read"]
    assert "iam:ListInstanceProfilesForRole" not in get_rule("resource","aws_iam_role","6.72.0")["delete"]
    assert not destructive({"action":"iam:ListInstanceProfilesForRole"})
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_iam_role":{"r":{"name":"fixture","path":"/"}}}}))
    report=scan(tmp_path,"destroy","123456789012","us-east-1",provider_version="6.73.0")
    assert any(p["action"]=="iam:ListInstanceProfilesForRole" and p["scope"]=="arn:aws:iam::123456789012:role/fixture" for p in report["permissions"])

def test_verified_only_policy_mode_blocks_unverified(tmp_path):
    from tfiam.cli import main
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_s3_bucket":{"b":{"bucket":"test-bucket"}}}}))
    dest=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--aws-provider-version","6.73.0","--allow-partial","--require-lifecycle-verified","--output",str(dest)])==4
    assert not dest.exists()
