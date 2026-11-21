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
    assert result["counts"]=={"planner":1,"applier":2,"break_glass":1}
    assert result["policies"]["break_glass"]["Statement"][0]["Condition"]==rows[1]["condition"]

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
