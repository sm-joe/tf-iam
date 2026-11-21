import json
from datetime import datetime,timezone
from tfiam.risk import assess,gate
from tfiam.cloud import role_policies,validate_policy,refine
from tfiam.cli import main,policy
from tfiam.lifecycle import split_policies

def row(action,scope="*",condition=None):
    return {"provider":"aws","action":action,"scope":scope,"source":"fixture","plane":"management",**({"condition":condition} if condition else {})}

def test_risk_severity_and_gate():
    rows=[row("iam:PassRole"),row("ec2:TerminateInstances"),row("iam:DeleteRolePermissionsBoundary")]
    risks=assess(rows)
    assert any(x["severity"]=="CRITICAL" and x["actions"]==["iam:PassRole"] for x in risks)
    assert any(x["kind"]=="destructive" for x in risks)
    assert gate({"risks":risks},"CRITICAL")

def test_split_preserves_grants():
    rows=[row("iam:GetRole"),row("iam:PassRole","arn:aws:iam::123456789012:role/example",{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}),row("ec2:CreateVpc"),row("ec2:DeleteVpc")]
    result=split_policies({"phase":"apply","coverage":"PARTIAL","permissions":rows},policy)
    assert result["counts"]=={"planner":1,"applier":1,"break_glass":2}
    assert any(s.get("Condition")==rows[1]["condition"] for s in result["policies"]["break_glass"]["Statement"])

class Paginator:
    def __init__(self,pages): self.pages=pages
    def paginate(self,**kwargs): return iter(self.pages)
class IAM:
    def get_role(self,**kwargs): return {"Role":{"Arn":"arn:aws:iam::123456789012:role/example"}}
    def get_paginator(self,name):
        return Paginator([{"AttachedPolicies":[{"PolicyArn":"arn:aws:iam::123456789012:policy/example"}]}] if name=="list_attached_role_policies" else [{"PolicyNames":["inline"]}])
    def get_policy(self,**kwargs): return {"Policy":{"DefaultVersionId":"v2"}}
    def get_policy_version(self,**kwargs): return {"PolicyVersion":{"Document":{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}}}
    def get_role_policy(self,**kwargs): return {"PolicyDocument":{"Statement":{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}}}
def test_live_role_policies():
    p,m=role_policies(IAM(),"example")
    assert len(p["Statement"])==2
    assert m["managed_policies"][0]["version"]=="v2"
    assert m["inline_policies"]==["inline"]

class Analyzer:
    def get_paginator(self,name):
        assert name=="validate_policy"
        return Paginator([{"findings":[{"findingType":"ERROR"}]},{"findings":[{"findingType":"SECURITY_WARNING"}]}])
def test_access_analyzer():
    r=validate_policy(Analyzer(),{"Statement":[]})
    assert r["status"]=="issues" and r["counts"]["ERROR"]==1

def test_runtime_scope_and_dedup():
    arn="arn:aws:iam::123456789012:role/example"
    e={"eventID":"1","eventSource":"s3.amazonaws.com","eventName":"DeleteBucketOwnershipControls","userIdentity":{"sessionContext":{"sessionIssuer":{"arn":arn}}},"requestParameters":{"secret":"not retained"}}
    r=refine([e,e,{**e,"eventID":"2","errorCode":"AccessDenied"},{**e,"userIdentity":{}}],arn,{"s3:PutBucketOwnershipControls","s3:GetObject"})
    assert r["matched_events"]==2
    assert r["observations"][0]["successful"]==1 and r["observations"][0]["denied"]==1
    assert r["unobserved_candidates"]==["s3:GetObject"]
    assert "not retained" not in json.dumps(r)

def test_gate_blocks_policy_output(tmp_path):
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_iam_role":{"r":{"name":"example"}}}}))
    output=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--aws-account","123456789012","--allow-partial","--fail-on-risk","HIGH","--output",str(output)])==4
    assert not output.exists()

def test_cloudtrail_bounded_and_session_filtered(monkeypatch):
    from tfiam import cloud
    monkeypatch.setattr(cloud.time,"sleep",lambda _:None)
    arn="arn:aws:iam::123456789012:role/example"
    event={"eventID":"1","userIdentity":{"sessionContext":{"sessionIssuer":{"arn":arn}}}}
    class Trail:
        def __init__(self): self.calls=[]
        def lookup_events(self,**kw):
            self.calls.append(kw)
            return {"Events":[{"CloudTrailEvent":json.dumps(event)}],"NextToken":"next"}
    trail=Trail(); stats={}
    start=cloud.parse_time("2026-01-01T00:00:00Z"); end=cloud.parse_time("2026-01-02T00:00:00Z")
    assert len(list(cloud.lookup_events(trail,arn,start,end,session_names=["build-123"],max_pages=2,stats=stats)))==2
    assert len(trail.calls)==2 and trail.calls[0]["LookupAttributes"]==[{"AttributeKey":"Username","AttributeValue":"build-123"}]
    assert trail.calls[1]["NextToken"]=="next"
    assert stats["complete"] is False and stats["stop_reason"]=="page-limit"
def test_cloudtrail_exhausted():
    from tfiam import cloud
    class Trail:
        def lookup_events(self,**kw): return {"Events":[]}
    stats={}
    list(cloud.lookup_events(Trail(),"arn:aws:iam::123456789012:role/example",cloud.parse_time("2026-01-01T00:00:00Z"),cloud.parse_time("2026-01-02T00:00:00Z"),stats=stats))
    assert stats["complete"] and stats["stop_reason"]=="exhausted"

def test_all_catalog_destroy_actions_are_risky():
    from tfiam.catalog_loader import CATALOG
    actions={a for rule in CATALOG["resources"].values() for a in rule["delete"]}
    result=split_policies({"phase":"apply","coverage":"PARTIAL","permissions":[row(a) for a in actions]},policy)
    assert result["counts"]["break_glass"]==len(actions)
    assert result["counts"]["applier"]==0

def test_comparison_dedup_conditions_and_service_summary():
    from tfiam.cli import compare
    base=row("iam:PassRole","arn:aws:iam::123456789012:role/example",{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}})
    report={"permissions":[base,{**base,"source":"second"}]}
    stmt={"Effect":"Allow","Action":["IAM:PassRole","iam:PassRole","s3:GetObject"],"Resource":"*"}
    result=compare(report,"aws",{"Statement":[stmt,stmt]})
    assert result["summary"]["unique_candidates"]==1
    assert result["summary"]["unique_existing_grants"]==2
    assert result["summary"]["by_service"]["potentially_excessive"]=={"iam":1,"s3":1}
    assert "missing-candidate-condition" in result["potentially_excessive"][0]["reasons"]
    result=compare(report,"aws",{"Statement":[]})
    assert result["missing_or_unverified"][0]["sources"]==["fixture","second"]
    assert result["missing_or_unverified"][0]["observations"]==2

def test_runtime_reports_observed_actions_outside_candidates(tmp_path):
    arn="arn:aws:iam::123456789012:role/example"
    doc={"Name":"s3","Actions":[{"Name":"GetBucketVersioning"},{"Name":"PutBucketVersioning"}],"Operations":[{"Name":"PutBucketVersioning","AuthorizedActions":[{"Service":"s3","Name":"PutBucketVersioning"}]},{"Name":"Ambiguous","AuthorizedActions":[{"Service":"s3","Name":"GetBucketVersioning"},{"Service":"s3","Name":"PutBucketVersioning"}]}]}
    (tmp_path/"s3.json").write_text(json.dumps(doc))
    event={"eventSource":"s3.amazonaws.com","userIdentity":{"sessionContext":{"sessionIssuer":{"arn":arn}}}}
    events=[{**event,"eventID":"1","eventName":"PutBucketVersioning"},{**event,"eventID":"2","eventName":"Ambiguous"}]
    result=refine(events,arn,{"s3:GetBucketVersioning"},metadata_dir=tmp_path)
    assert result["observed_outside_candidates"][0]["action"]=="s3:PutBucketVersioning"
    assert result["conditional_operations"][0]["operation"]=="Ambiguous"
    assert result["unobserved_candidates"]==["s3:GetBucketVersioning"]

def test_generate_simple_default_and_unmapped_gate(tmp_path):
    output=tmp_path/"policy.json"
    config=tmp_path/"main.tf.json"
    config.write_text(json.dumps({"resource":{"aws_s3_bucket":{"b":{"bucket":"fixture-bucket"}}}}))
    assert main(["generate",str(tmp_path),"--output",str(output)])==0
    output.unlink()
    config.write_text(json.dumps({"resource":{"aws_s3_bucket":{"b":{"bucket":"fixture-bucket"}},"aws_fake_resource":{"x":{}}}}))
    assert main(["generate",str(tmp_path),"--output",str(output)])==4
    assert not output.exists()
    assert main(["generate",str(tmp_path),"--allow-partial","--output",str(output)])==0
