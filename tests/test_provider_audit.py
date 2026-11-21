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
