#!/usr/bin/env python3
"""Opt-in live acceptance for isolated, empty standard SQS queues.

No IAM mutation. Prepare generates the exact candidate policy; a separate
administrator must review and attach it to a dedicated test role.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from tfiam.scan import scan
from tfiam.cli import policy
from tfiam.cloud import role_policies
from tfiam.versioning import VERSION, selected_version

RESOURCES=("aws_sqs_queue.example",)
STEPS=("create","read","update","replace-delete-first","replace-create-first","destroy")
def now(): return datetime.now(timezone.utc).isoformat()
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,doc): path.write_text(json.dumps(doc,indent=2)+"\n",encoding="utf-8")

def config(version,region,queue,updated=False,create_first=False):
    return {"terraform":{"required_providers":{"aws":{"source":"hashicorp/aws","version":"="+version}}},
            "provider":{"aws":{"region":region}},
            "resource":{"aws_sqs_queue":{"example":{"name":queue,
                "message_retention_seconds":86400 if updated else 43200,
                "sqs_managed_sse_enabled":True,
                "tags":{"Purpose":"tfiam-acceptance","Revision":"2" if updated else "1"},
                "lifecycle":{"create_before_destroy":create_first}}}}}

def grants(doc):
    result=set()
    for s in doc["Statement"]:
        if s.get("Effect")!="Allow" or set(s)-{"Effect","Action","Resource","Sid"}: raise ValueError("Role must contain only exact unconditional candidate allows")
        actions=s["Action"] if isinstance(s["Action"],list) else [s["Action"]]
        resources=s["Resource"] if isinstance(s["Resource"],list) else [s["Resource"]]
        for a in actions:
            for r in resources:
                if not isinstance(a,str) or not a.startswith("sqs:") or not isinstance(r,str) or not re.fullmatch(r"arn:aws:sqs:[a-z0-9-]+:[0-9]{12}:tfiam-test-[a-f0-9]{32}-[abc]",r) or any(c in a+r for c in "*?"): raise ValueError("Unexpected or wildcard grant in SQS acceptance policy")
                result.add((a,r))
    return result

def check_operations(plan,expected):
    if plan.get("errored") or plan.get("complete") is False or plan.get("deferred_changes"):
        raise ValueError("Plan is incomplete")
    rows={}
    for r in plan.get("resource_changes",[]):
        if r.get("mode")!="managed" or r.get("provider_name")!="registry.terraform.io/hashicorp/aws": raise ValueError("Unexpected resource in fixture plan")
        if r["address"] in rows: raise ValueError("Duplicate resource change")
        rows[r["address"]]=r["change"]["actions"]
    if set(rows)!=set(RESOURCES) or any(rows[x]!=expected for x in RESOURCES):
        raise ValueError("Unexpected lifecycle operations; refusing apply")
    return rows

def prepare(args):
    root=args.directory.resolve()
    if not VERSION.fullmatch(args.version) or not re.fullmatch(r"[0-9]{12}",args.account) or not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]+",args.region): raise ValueError("Invalid version, account or commercial AWS region")
    root.mkdir(mode=0o700,parents=False,exist_ok=False)
    prefix="tfiam-test-"+uuid.uuid4().hex
    names=[prefix+"-a",prefix+"-b",prefix+"-c"]
    records=[]
    for name in names:
        write(root/"main.tf.json",config(args.version,args.region,name))
        r=scan(root,account=args.account,region=args.region,provider_version=args.version)
        if r["unresolved_permissions"] or r["mapping_coverage"]["mapped_resources"]!=1: raise ValueError("Fixture candidate scan incomplete")
        records.extend(r["permissions"])
    candidate=policy({"permissions":records},"aws","SQSAcceptance",None)
    grants(candidate)
    write(root/"candidate-policy.json",candidate)
    write(root/"prepare.json",{"version":args.version,"account":args.account,"region":args.region,"queues":names,"candidate_sha256":digest(root/"candidate-policy.json")})
    write(root/"main.tf.json",config(args.version,args.region,names[0]))
    print("Prepared isolated fixture:",root)
    print("Review candidate-policy.json and attach only these grants to a new dedicated test role. No cloud changes performed.")

def run(args):
    import boto3
    from botocore.exceptions import ClientError
    root=args.directory.resolve()
    info=json.loads((root/"prepare.json").read_bytes())
    candidate=json.loads((root/"candidate-policy.json").read_bytes())
    if digest(root/"candidate-policy.json")!=info["candidate_sha256"]: raise ValueError("Candidate changed after preparation")
    if args.account!=info["account"]: raise ValueError("Explicit test account does not match fixture")
    if not args.confirm_isolated_aws_account: raise ValueError("Explicit isolated-account confirmation is required")
    expected_grants=grants(candidate)
    expected_actions={"sqs:GetQueueAttributes","sqs:GetQueueUrl","sqs:ListQueueTags","sqs:CreateQueue","sqs:SetQueueAttributes","sqs:TagQueue","sqs:UntagQueue","sqs:DeleteQueue"}
    if {a for a,_ in expected_grants}!=expected_actions: raise ValueError("Unexpected SQS acceptance action inventory")
    if not all(re.fullmatch(r"tfiam-test-[a-f0-9]{32}-[abc]",b) for b in info["queues"]) or len(set(info["queues"]))!=3: raise ValueError("Invalid fixture queue identities")
    expected_scopes={f"arn:aws:sqs:{info['region']}:{info['account']}:{b}" for b in info["queues"]}
    if expected_grants!={(a,r) for a in expected_actions for r in expected_scopes}: raise ValueError("Candidate does not contain the exact action/queue grant matrix")
    if any(x.name not in {"prepare.json","candidate-policy.json","main.tf.json"} for x in root.iterdir()): raise ValueError("Acceptance requires a fresh dedicated fixture directory")
    if any(x.is_symlink() for x in root.iterdir()): raise ValueError("Fixture files must not be symlinks")
    if json.loads((root/"main.tf.json").read_bytes())!=config(info["version"],info["region"],info["queues"][0]): raise ValueError("Fixture configuration changed since preparation")
    region=info["region"]; version=info["version"]
    test=boto3.Session(profile_name=args.test_profile,region_name=region)
    frozen=test.get_credentials().get_frozen_credentials()
    if not frozen.token: raise ValueError("Test identity must use temporary assumed-role credentials")
    fixed=boto3.Session(aws_access_key_id=frozen.access_key,aws_secret_access_key=frozen.secret_key,aws_session_token=frozen.token,region_name=region)
    identity=fixed.client("sts").get_caller_identity()
    if identity["Account"]!=info["account"] or not re.fullmatch(r"arn:aws:sts::"+info["account"]+r":assumed-role/"+re.escape(args.role_name)+r"/[^/]+",identity["Arn"]): raise ValueError("Unexpected test identity")
    auditor=boto3.Session(profile_name=args.audit_profile,region_name=region)
    iam=auditor.client("iam")
    def check_role():
        role=iam.get_role(RoleName=args.role_name)["Role"]
        if identity["UserId"].split(":")[0]!=role["RoleId"]: raise ValueError("Role identity mismatch")
        if role["Arn"].split(":")[4]!=info["account"]: raise ValueError("Audit account differs from test account")
        existing,_=role_policies(iam,args.role_name)
        if grants(existing)!=expected_grants: raise ValueError("Test role's identity grants differ from the reviewed candidate")
        return role["Arn"]
    role_arn=check_role()
    # Prevent ambient AWS or Terraform CLI settings from changing credentials,
    # backend, provider source, CLI arguments or workspace.
    env={k:v for k,v in os.environ.items() if not k.startswith(("AWS_","TF_"))}
    (root/"terraform-cli.rc").write_text("")
    env.update({"AWS_ACCESS_KEY_ID":frozen.access_key,"AWS_SECRET_ACCESS_KEY":frozen.secret_key,"AWS_SESSION_TOKEN":frozen.token,"AWS_REGION":region,"AWS_DEFAULT_REGION":region,"AWS_EC2_METADATA_DISABLED":"true","TF_IN_AUTOMATION":"1","TF_CLI_CONFIG_FILE":str(root/"terraform-cli.rc")})
    evidence={"schema_version":1,"fixture":"sqs-standard-empty","provider_version":version,"candidate_sha256":info["candidate_sha256"],"role_arn":role_arn,"session_arn":identity["Arn"],"region":region,"start":now(),"steps":{},"status":"incomplete"}
    out=root/"lifecycle-evidence.json"
    write(out,evidence)
    def command(label,*arguments,allowed=(0,)):
        result=subprocess.run(["terraform",*arguments],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (root/(label+".log")).write_bytes(result.stdout+b"\n"+result.stderr)
        if result.returncode not in allowed: raise ValueError(label+" failed; inspect private local log")
        return result.stdout
    def stage(name,expected,extra=(),apply=True):
        print("Lifecycle:",name,flush=True)
        path=root/(name+".tfplan")
        command(name+"-plan","plan","-input=false","-out="+str(path),*extra)
        # Parse raw JSON in memory only, never put raw plan JSON in evidence.
        # Terraform's binary plans and local logs must remain private.
        shown=subprocess.run(["terraform","show","-json",str(path)],cwd=root,env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL).stdout
        actions=check_operations(json.loads(shown),expected)
        if apply: command(name+"-apply","apply","-input=false",str(path))
        evidence["steps"][name]={"status":"passed","operations":actions,"plan_sha256":digest(path),"completed":now()}
        write(out,evidence)
    try:
        command("init","init","-input=false")
        if selected_version(root)["version"]!=version: raise ValueError("Installed provider version does not match requested version")
        evidence["lockfile_sha256"]=digest(root/".terraform.lock.hcl")
        stage("create",["create"])
        stage("read",["no-op"],apply=False)
        write(root/"main.tf.json",config(version,region,info["queues"][0],updated=True))
        stage("update",["update"])
        write(root/"main.tf.json",config(version,region,info["queues"][1],updated=True))
        stage("replace-delete-first",["delete","create"])
        write(root/"main.tf.json",config(version,region,info["queues"][2],updated=True,create_first=True))
        stage("replace-create-first",["create","delete"])
        stage("destroy",["delete"],("-destroy",))
        try:
            fixed.client("sqs").list_queues(QueueNamePrefix="tfiam-test-")
        except ClientError as exc:
            if exc.response.get("Error",{}).get("Code") not in ("AccessDenied","AccessDeniedException","AWS.SimpleQueueService.AccessDenied"): raise
        else: raise ValueError("Negative authorization failed: ListQueues was allowed")
        evidence["negative_authorization"]="passed"
        check_role()
        evidence["identity_grants_rechecked"]=True
        evidence["status"]="fixture-passed"
    finally:
        evidence["end"]=now()
        write(out,evidence)
        print("Evidence:",out)
        if evidence["status"]!="fixture-passed":
            print("Acceptance incomplete. Preserve fixture state and use authorized cleanup; no automatic fallback to admin credentials.")

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="mode",required=True)
    prep=sub.add_parser("prepare")
    prep.add_argument("directory",type=Path); prep.add_argument("--version",required=True); prep.add_argument("--account",required=True); prep.add_argument("--region",required=True)
    test=sub.add_parser("run")
    test.add_argument("directory",type=Path); test.add_argument("--account",required=True); test.add_argument("--test-profile",required=True); test.add_argument("--audit-profile",required=True); test.add_argument("--role-name",required=True); test.add_argument("--confirm-isolated-aws-account",action="store_true")
    args=p.parse_args()
    try:
        (prepare if args.mode=="prepare" else run)(args)
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        print("Acceptance failed:",str(exc)); return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
