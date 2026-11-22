#!/usr/bin/env python3
"""Opt-in live acceptance for isolated, empty on-demand DynamoDB tables.

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

RESOURCES=("aws_dynamodb_table.example",)
STEPS=("create","read","update","replace-delete-first","replace-create-first","destroy")
def now(): return datetime.now(timezone.utc).isoformat()
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,doc): path.write_text(json.dumps(doc,indent=2)+"\n",encoding="utf-8")

def config(version,region,table,updated=False,create_first=False):
    return {"terraform":{"required_providers":{"aws":{"source":"hashicorp/aws","version":"="+version}}},
            "provider":{"aws":{"region":region}},
            "resource":{"aws_dynamodb_table":{"example":{"name":table,
                "billing_mode":"PAY_PER_REQUEST","hash_key":"id",
                "attribute":[{"name":"id","type":"S"}],
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
                if not isinstance(a,str) or not a.startswith("dynamodb:") or not isinstance(r,str) or not re.fullmatch(r"arn:aws:dynamodb:[a-z0-9-]+:[0-9]{12}:table/tfiam-test-[a-f0-9]{32}-[abc]",r) or any(c in a+r for c in "*?"): raise ValueError("Unexpected or wildcard grant in DynamoDB acceptance policy")
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

def candidate_for(info):
    import tempfile
    records=[]
    with tempfile.TemporaryDirectory(prefix="tfiam-dynamodb-policy-") as tmp:
        path=Path(tmp)
        for name in info["tables"]:
            write(path/"main.tf.json",config(info["version"],info["region"],name))
            r=scan(path,account=info["account"],region=info["region"],provider_version=info["version"])
            if r["unresolved_permissions"] or r["mapping_coverage"]["mapped_resources"]!=1: raise ValueError("Fixture candidate scan incomplete")
            records.extend(r["permissions"])
    candidate=policy({"permissions":records},"aws","DynamoDBAcceptance",None)
    grants(candidate)
    return candidate

def prepare(args):
    root=args.directory.resolve()
    if not VERSION.fullmatch(args.version) or not re.fullmatch(r"[0-9]{12}",args.account) or not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]+",args.region): raise ValueError("Invalid version, account or commercial AWS region")
    root.mkdir(mode=0o700,parents=False,exist_ok=False)
    prefix="tfiam-test-"+uuid.uuid4().hex
    names=[prefix+"-a",prefix+"-b",prefix+"-c"]
    info={"version":args.version,"account":args.account,"region":args.region,"tables":names}
    candidate=candidate_for(info)
    write(root/"candidate-policy.json",candidate)
    info["candidate_sha256"]=digest(root/"candidate-policy.json")
    write(root/"prepare.json",info)
    write(root/"main.tf.json",config(args.version,args.region,names[0]))
    print("Prepared isolated fixture:",root)
    print("Review candidate-policy.json and attach only these grants to a new dedicated test role. No cloud changes performed.")

def run(args):
    import boto3
    from botocore.exceptions import ClientError
    from botocore.config import Config
    client_config=Config(ignore_configured_endpoint_urls=True)
    root=args.directory.resolve()
    if root.stat().st_mode & 0o077: raise ValueError("Fixture directory must be private (0700)")
    if any(x.is_symlink() for x in root.iterdir()): raise ValueError("Fixture files must not be symlinks")
    info=json.loads((root/"prepare.json").read_bytes())
    candidate=json.loads((root/"candidate-policy.json").read_bytes())
    if digest(root/"candidate-policy.json")!=info["candidate_sha256"]: raise ValueError("Candidate changed after preparation")
    if args.account!=info["account"]: raise ValueError("Explicit test account does not match fixture")
    if not args.confirm_isolated_aws_account: raise ValueError("Explicit isolated-account confirmation is required")
    expected_grants=grants(candidate)
    expected_actions={"dynamodb:DescribeTable","dynamodb:ListTagsOfResource","dynamodb:DescribeTimeToLive","dynamodb:DescribeContinuousBackups","dynamodb:CreateTable","dynamodb:UpdateTable","dynamodb:TagResource","dynamodb:UntagResource","dynamodb:UpdateTimeToLive","dynamodb:UpdateContinuousBackups","dynamodb:DeleteTable"}
    if {a for a,_ in expected_grants}!=expected_actions: raise ValueError("Unexpected DynamoDB acceptance action inventory")
    if not all(re.fullmatch(r"tfiam-test-[a-f0-9]{32}-[abc]",b) for b in info["tables"]) or len(set(info["tables"]))!=3: raise ValueError("Invalid fixture table identities")
    expected_scopes={f"arn:aws:dynamodb:{info['region']}:{info['account']}:table/{b}" for b in info["tables"]}
    if expected_grants!={(a,r) for a in expected_actions for r in expected_scopes}: raise ValueError("Candidate does not contain the exact action/table grant matrix")
    if not VERSION.fullmatch(info["version"]) or not re.fullmatch(r"[0-9]{12}",info["account"]) or not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]+",info["region"]): raise ValueError("Invalid fixture context")
    if expected_grants!=grants(candidate_for(info)): raise ValueError("Candidate differs from regenerated fixture policy")
    if any(x.name not in {"prepare.json","candidate-policy.json","main.tf.json"} for x in root.iterdir()): raise ValueError("Acceptance requires a fresh dedicated fixture directory")
    if any(x.is_symlink() for x in root.iterdir()): raise ValueError("Fixture files must not be symlinks")
    if json.loads((root/"main.tf.json").read_bytes())!=config(info["version"],info["region"],info["tables"][0]): raise ValueError("Fixture configuration changed since preparation")
    region=info["region"]; version=info["version"]
    test=boto3.Session(profile_name=args.test_profile,region_name=region)
    credentials=test.get_credentials()
    if credentials is None: raise ValueError("Test profile has no AWS credentials")
    frozen=credentials.get_frozen_credentials()
    if not frozen or not frozen.token: raise ValueError("Test identity must use temporary assumed-role credentials")
    fixed=boto3.Session(aws_access_key_id=frozen.access_key,aws_secret_access_key=frozen.secret_key,aws_session_token=frozen.token,region_name=region)
    identity=fixed.client("sts",config=client_config).get_caller_identity()
    if identity["Account"]!=info["account"] or not re.fullmatch(r"arn:aws:sts::"+info["account"]+r":assumed-role/"+re.escape(args.role_name)+r"/[^/]+",identity["Arn"]): raise ValueError("Unexpected test identity")
    auditor=boto3.Session(profile_name=args.audit_profile,region_name=region)
    audit_identity=auditor.client("sts",config=client_config).get_caller_identity()
    if audit_identity["Account"]!=info["account"] or audit_identity["UserId"].split(":")[0]==identity["UserId"].split(":")[0]: raise ValueError("Audit profile must be a separate identity in the fixture account")
    iam=auditor.client("iam",config=client_config)
    def check_role():
        role=iam.get_role(RoleName=args.role_name)["Role"]
        if identity["UserId"].split(":")[0]!=role["RoleId"]: raise ValueError("Role identity mismatch")
        if role["Arn"].split(":")[4]!=info["account"]: raise ValueError("Audit account differs from test account")
        existing,_=role_policies(iam,args.role_name)
        if grants(existing)!=expected_grants: raise ValueError("Test role's identity grants differ from the reviewed candidate")
        return role["Arn"]
    role_arn=check_role()
    checkout=Path(__file__).resolve().parents[1]
    source_commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=checkout,text=True).strip()
    if not re.fullmatch(r"[a-f0-9]{40}",source_commit) or subprocess.check_output(["git","status","--porcelain","--untracked-files=no"],cwd=checkout).strip(): raise ValueError("Run acceptance from a clean committed repository checkout")
    # Prevent ambient AWS or Terraform CLI settings from changing credentials,
    # backend, provider source, CLI arguments or workspace.
    env={k:v for k,v in os.environ.items() if not k.startswith(("AWS_","TF_"))}
    (root/"terraform-cli.rc").write_text("")
    env.update({"AWS_ACCESS_KEY_ID":frozen.access_key,"AWS_SECRET_ACCESS_KEY":frozen.secret_key,"AWS_SESSION_TOKEN":frozen.token,"AWS_REGION":region,"AWS_DEFAULT_REGION":region,"AWS_EC2_METADATA_DISABLED":"true","TF_IN_AUTOMATION":"1","TF_CLI_CONFIG_FILE":str(root/"terraform-cli.rc")})
    evidence={"schema_version":1,"fixture":"dynamodb-ondemand-empty","provider_version":version,"source_commit":source_commit,"candidate_sha256":info["candidate_sha256"],"role_arn":role_arn,"session_arn":identity["Arn"],"region":region,"start":now(),"steps":{},"status":"incomplete"}
    out=root/"lifecycle-evidence.json"
    write(out,evidence)
    def command(label,*arguments,allowed=(0,)):
        result=subprocess.run(["terraform",*arguments],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1800)
        (root/(label+".log")).write_bytes(result.stdout+b"\n"+result.stderr)
        if result.returncode not in allowed: raise ValueError(label+" failed; inspect private local log")
        return result.stdout
    def stage(name,expected,extra=(),apply=True):
        check_role()
        print("Lifecycle:",name,flush=True)
        path=root/(name+".tfplan")
        command(name+"-plan","plan","-input=false","-out="+str(path),*extra)
        # Parse raw JSON in memory only, never put raw plan JSON in evidence.
        # Terraform's binary plans and local logs must remain private.
        shown=subprocess.run(["terraform","show","-json",str(path)],cwd=root,env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL).stdout
        actions=check_operations(json.loads(shown),expected)
        check_role()
        if apply: command(name+"-apply","apply","-input=false",str(path))
        check_role()
        evidence["steps"][name]={"status":"passed","operations":actions,"plan_sha256":digest(path),"completed":now()}
        write(out,evidence)
    try:
        command("init","init","-input=false")
        if selected_version(root)["version"]!=version: raise ValueError("Installed provider version does not match requested version")
        evidence["lockfile_sha256"]=digest(root/".terraform.lock.hcl")
        stage("create",["create"])
        stage("read",["no-op"],apply=False)
        write(root/"main.tf.json",config(version,region,info["tables"][0],updated=True))
        stage("update",["update"])
        write(root/"main.tf.json",config(version,region,info["tables"][1],updated=True))
        stage("replace-delete-first",["delete","create"])
        write(root/"main.tf.json",config(version,region,info["tables"][2],updated=True,create_first=True))
        stage("replace-create-first",["create","delete"])
        stage("destroy",["delete"],("-destroy",))
        state=command("verify-empty-state","state","list")
        if state.strip(): raise ValueError("Fixture state is not empty after destroy")
        evidence["empty_state_verified"]=True
        try:
            fixed.client("dynamodb",config=client_config).list_tables(Limit=1)
        except ClientError as exc:
            if exc.response.get("Error",{}).get("Code") not in ("AccessDenied","AccessDeniedException","AccessDeniedException"): raise
        else: raise ValueError("Negative authorization failed: ListTables was allowed")
        evidence["negative_authorization"]="passed"
        evidence["negative_action"]="dynamodb:ListTables"
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
