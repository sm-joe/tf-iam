import json
from datetime import datetime, timezone, timedelta
import pytest
from tfiam.evidence_audit import reconcile, EXPECTED, RESOURCES, KINDS, sha
from tfiam.provider_audit import PINNED, FILES
from tfiam.catalog_loader import get_rule
from tfiam.versioning import evidence_status

def test_exact_version_source_records():
    for kind in ("aws_s3_bucket_public_access_block","aws_s3_bucket_versioning"):
        r=get_rule("resource",kind,"6.73.0")
        assert evidence_status(r,"6.73.0")=="provider-source-reviewed"
        assert r["validation"]=="candidate"
        assert evidence_status(get_rule("resource",kind,"6.73.1"),"6.73.1")=="version-unvalidated"

def test_fixture_reconciliation(tmp_path):
    version="6.73.0"; role="arn:aws:iam::123456789012:role/test"; session="arn:aws:sts::123456789012:assumed-role/test/session"
    start=datetime(2026,1,1,tzinfo=timezone.utc)
    def at(n): return (start+timedelta(seconds=n)).isoformat()
    lock=tmp_path/".terraform.lock.hcl"; lock.write_text('provider "registry.terraform.io/hashicorp/aws" {\n version = "6.73.0"\n}\n')
    names=["CreateBucket","DeleteBucket","PutBucketVersioning","PutBucketPublicAccessBlock","ListAllMyBuckets"]
    md=tmp_path/"s3.json"; md.write_text(json.dumps({"Name":"s3","Actions":[{"Name":n} for n in names]}))
    raw=json.dumps({"Statement":[{"Effect":"Allow","Action":["s3:"+n for n in names[:-1]],"Resource":["arn:aws:s3:::tfiam-test-"+"a"*32+"-a","arn:aws:s3:::tfiam-test-"+"a"*32+"-b"]}]}).encode()
    run={"fixture":"s3-general-purpose-empty","status":"fixture-passed","provider_version":version,"candidate_sha256":sha(raw),"lockfile_sha256":sha(lock.read_bytes()),"negative_authorization":"passed","identity_grants_rechecked":True,"start":at(0),"end":at(20),"role_arn":role,"session_arn":session,"steps":{k:{"status":"passed","plan_sha256":"a"*64,"completed":at(i+1),"operations":{a:v for a in RESOURCES}} for i,(k,v) in enumerate(EXPECTED.items())}}
    source={"provider_version":version,"provider_commit":PINNED[version],"pin_verified":True,"aws_metadata":{"s3":{"sha256":sha(md.read_bytes())}},"resources":[{"resource":r,"reference":"https://github.com/hashicorp/terraform-provider-aws/blob/"+PINNED[version]+"/internal/service/"+FILES[r],"sha256":"b"*64,"operations":[{}]} for r in KINDS]}
    def event(i,name,error=None,session_arn=session):
        return {"eventID":str(i),"eventTime":at(i),"eventSource":"s3.amazonaws.com","eventName":name,"errorCode":error,"userIdentity":{"arn":session_arn,"sessionContext":{"sessionIssuer":{"arn":role}}}}
    events=[event(1,"CreateBucket"),event(2,"DeleteBucket"),event(3,"PutBucketVersioning"),event(4,"PutPublicAccessBlock"),event(5,"ListBuckets","AccessDenied"),event(6,"Unexpected",session_arn=session+"-other")]
    result=reconcile(run,raw,lock,source,tmp_path,events)
    assert result["status"]=="fixture-evidence-reconciled"
    assert result["matched_events"]==5
    assert result["negative_observed"]
    assert reconcile(run,raw,lock,source,tmp_path,events[:-2])["status"]=="review"
    with pytest.raises(ValueError): reconcile(run,raw+b" ",lock,source,tmp_path,events)
