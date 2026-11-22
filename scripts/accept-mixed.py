#!/usr/bin/env python3
"""Explicit live acceptance with a planner and a dedicated candidate-only applier.

No IAM attachment automation. Each phase is independently prepared, reviewed,
and run against a saved plan. This is intentionally a sandbox-only workflow.
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
from tfiam.policy_size import partition, grants, compact
from tfiam.cloud import role_policies, validate_policy

VERSION="6.73.0"
AWS="registry.terraform.io/hashicorp/aws"
def now(): return datetime.now(timezone.utc).isoformat()
def write(path,value): path.write_text(json.dumps(value,indent=2)+"\n")
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def config(info,revision):
    prefix=info["prefix"]
    def tags(name): return {"Name":prefix+"-"+name,"Revision":str(revision)}
    def ref(x): return "${"+x+"}"
    return {"terraform":{"required_providers":{"aws":{"source":"hashicorp/aws","version":"="+VERSION},"random":{"source":"hashicorp/random","version":"=3.7.2"}}},
      "provider":{"aws":{"region":info["region"],"allowed_account_ids":[info["account"]]}},
      "data":{"aws_ami":{"linux":{"most_recent":True,"owners":["amazon"],"filter":[{"name":"name","values":["al2023-ami-2023.*-x86_64"]},{"name":"virtualization-type","values":["hvm"]},{"name":"root-device-type","values":["ebs"]}]}}},
      "resource":{
        "random_id":{"suffix":{"byte_length":4}},
        "aws_vpc":{"main":{"cidr_block":"10.240.0.0/16","enable_dns_support":True,"tags":tags("vpc")}},
        "aws_subnet":{"private":{"count":2,"vpc_id":ref("aws_vpc.main.id"),"cidr_block":ref("cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)"),"map_public_ip_on_launch":False,"tags":{"Name":prefix+"-private-"+ref("count.index"),"Revision":str(revision)}}},
        "aws_route_table":{"private":{"vpc_id":ref("aws_vpc.main.id"),"tags":tags("rt")}},
        "aws_route_table_association":{"private":{"count":2,"subnet_id":ref("aws_subnet.private[count.index].id"),"route_table_id":ref("aws_route_table.private.id")}},
        "aws_security_group":{"app":{"name":prefix+"-sg","description":"Isolated acceptance","vpc_id":ref("aws_vpc.main.id"),"tags":tags("sg")}},
        "aws_iam_role":{"app":{"name":prefix+"-role","assume_role_policy":json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}),"tags":tags("role")}},
        "aws_iam_role_policy_attachment":{"ssm":{"role":ref("aws_iam_role.app.name"),"policy_arn":"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"}},
        "aws_iam_instance_profile":{"app":{"name":prefix+"-profile","role":ref("aws_iam_role.app.name"),"tags":tags("profile")}},
        "aws_instance":{"app":{"ami":ref("data.aws_ami.linux.id"),"instance_type":"t3.micro","subnet_id":ref("aws_subnet.private[0].id"),"vpc_security_group_ids":[ref("aws_security_group.app.id")],"iam_instance_profile":ref("aws_iam_instance_profile.app.name"),"associate_public_ip_address":False,"metadata_options":{"http_tokens":"required"},"tags":tags("instance")}},
        "aws_s3_bucket":{"storage":{"bucket":prefix+"-storage-"+ref("random_id.suffix.hex"),"tags":tags("storage")}},
        "aws_s3_bucket_public_access_block":{"storage":{"bucket":ref("aws_s3_bucket.storage.id"),"block_public_acls":True,"block_public_policy":True,"ignore_public_acls":True,"restrict_public_buckets":True}},
        "aws_s3_bucket_versioning":{"storage":{"bucket":ref("aws_s3_bucket.storage.id"),"versioning_configuration":{"status":"Enabled"}}}
      }}

def environment(profile,info,role=None):
    import boto3
    from botocore.config import Config
    opts=Config(ignore_configured_endpoint_urls=True)
    session=boto3.Session(profile_name=profile,region_name=info["region"])
    frozen=session.get_credentials().get_frozen_credentials()
    fixed=boto3.Session(aws_access_key_id=frozen.access_key,aws_secret_access_key=frozen.secret_key,aws_session_token=frozen.token,region_name=info["region"])
    identity=fixed.client("sts",config=opts).get_caller_identity()
    if identity["Account"]!=info["account"]: raise ValueError("Wrong AWS account")
    if role and (not frozen.token or not re.fullmatch(r"arn:aws:sts::"+info["account"]+r":assumed-role/"+re.escape(role)+r"/[^/]+",identity["Arn"])): raise ValueError("Expected dedicated assumed-role session")
    env={k:v for k,v in os.environ.items() if not k.startswith(("AWS_","TF_"))}
    env.update({"AWS_ACCESS_KEY_ID":frozen.access_key,"AWS_SECRET_ACCESS_KEY":frozen.secret_key,"AWS_REGION":info["region"],"AWS_DEFAULT_REGION":info["region"],"AWS_EC2_METADATA_DISABLED":"true","TF_IN_AUTOMATION":"1"})
    if frozen.token: env["AWS_SESSION_TOKEN"]=frozen.token
    return fixed,identity,env,opts

def command(root,env,label,*args):
    env={**env,"TF_CLI_CONFIG_FILE":str(root/"terraform-cli.rc")}
    result=subprocess.run(["terraform",*args],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1800)
    if label: (root/(label+".log")).write_bytes(result.stdout+b"\n"+result.stderr)
    if result.returncode: raise ValueError(label+" failed; inspect local private log")
    return result.stdout

def operations(plan,phase,info):
    if plan.get("errored") or plan.get("complete") is False or plan.get("deferred_changes"): raise ValueError("Incomplete saved plan")
    expected=config(info,1)["resource"]
    allowed={typ+"."+name for typ,items in expected.items() for name in items}
    rows={}
    for row in plan.get("resource_changes",[]):
        if row.get("mode")=="data":
            if row["address"]!="data.aws_ami.linux" or row.get("provider_name")!=AWS: raise ValueError("Unexpected data resource")
            continue
        addr=row["address"]; base=re.sub(r"\[[0-9]+\]$","",addr)
        if base not in allowed or addr in rows: raise ValueError("Unexpected resource address")
        provider="registry.terraform.io/hashicorp/random" if base.startswith("random_id.") else AWS
        if row.get("provider_name")!=provider or row.get("mode")!="managed": raise ValueError("Unexpected provider")
        actions=row["change"]["actions"]
        if actions not in ({"create":[["create"]],"update":[["update"],["no-op"]],"destroy":[["delete"]]}[phase]): raise ValueError("Unexpected lifecycle operation")
        rows[addr]=actions
    expected_addresses={a for a in allowed if a not in ("aws_subnet.private","aws_route_table_association.private")}
    expected_addresses.update(a+"["+str(i)+"]" for a in ("aws_subnet.private","aws_route_table_association.private") for i in range(2))
    if set(rows)!=expected_addresses: raise ValueError("Missing or extra fixture resources")
    if phase=="update" and not any(v==["update"] for v in rows.values()): raise ValueError("No actual update in plan")
    return rows

def prepare(args,root):
    if not re.fullmatch(r"[0-9]{12}",args.account) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",args.region): raise ValueError("Invalid account/region")
    root.mkdir(mode=0o700)
    info={"account":args.account,"region":args.region,"prefix":"tfiam-live-"+uuid.uuid4().hex[:16],"next":"create","steps":{}}
    write(root/"fixture.json",info)
    (root/"terraform-cli.rc").write_text("")
    print("Created private isolated fixture directory:",root)

def load(root,args):
    if root.stat().st_mode & 0o077 or any(p.is_symlink() for p in root.iterdir()): raise ValueError("Fixture directory must be private/no symlinks")
    info=json.loads((root/"fixture.json").read_bytes())
    if args.account!=info["account"] or not re.fullmatch(r"tfiam-live-[a-f0-9]{16}",info["prefix"]): raise ValueError("Fixture account or namespace mismatch")
    return info

def plan_phase(args,root,info):
    phase=args.phase
    if phase!=info["next"]: raise ValueError("Wrong lifecycle phase")
    if any(p.name.endswith((".tf",".tf.json")) and p.name!="main.tf.json" for p in root.iterdir()): raise ValueError("Unexpected Terraform configuration")
    if (root/(phase+"-policies")).exists(): raise ValueError("Phase already prepared; preserve evidence")
    planner,ident,env,opts=environment(args.planner_profile,info)
    write(root/"main.tf.json",config(info,1 if phase=="create" else 2))
    if phase=="create":
        if (root/"terraform.tfstate").exists(): raise ValueError("Expected empty initial state")
        command(root,env,"init","init","-input=false")
    lock=root/".terraform.lock.hcl"
    from tfiam.versioning import selected_version
    if selected_version(root)["version"]!=VERSION: raise ValueError("Unexpected provider version")
    plan=root/(phase+".tfplan")
    command(root,env,phase+"-plan","plan","-input=false","-out="+str(plan),*(["-destroy"] if phase=="destroy" else []))
    raw=command(root,env,"","show","-json",str(plan))
    parsed=json.loads(raw)
    rows=operations(parsed,phase,info)
    report=scan(root,account=info["account"],region=info["region"],plan=parsed,phase="destroy" if phase=="destroy" else "apply",scope_generated_names=True,provider_version=VERSION)
    # Save private diagnostics even if strict gate fails; never deploy a partial policy.
    write(root/(phase+"-scan.json"),report)
    if report["unresolved_permissions"] or report["mapping_coverage"]["unmapped_resources"] or report.get("input_blockers") or report.get("source_only_resources") or report["authorization_metadata"]["status"]=="issues": raise ValueError("Incomplete candidate; inspect private phase scan")
    candidate=policy(report,"aws","",None)
    bundle=partition(candidate)
    directory=root/(phase+"-policies"); directory.mkdir(mode=0o700)
    analyzer=planner.client("accessanalyzer",config=opts)
    for item in bundle["policies"]:
        write(directory/(item["name"]+".json"),item["document"])
        validation=validate_policy(analyzer,item["document"])
        write(directory/(item["name"]+".validation"),validation)
        if validation["status"]!="no-findings": raise ValueError("Access Analyzer review required")
    write(directory/"manifest.json",bundle)
    info["prepared"]={"phase":phase,"plan_sha256":digest(plan),"config_sha256":digest(root/"main.tf.json"),"lock_sha256":digest(lock),"operations":rows,"planner":ident["Arn"],"bundle_sha256":digest(directory/"manifest.json")}
    write(root/"fixture.json",info)
    print("Prepared phase",phase,". Review and attach ONLY these policy documents to the dedicated applier role.")

def apply_phase(args,root,info):
    phase=args.phase
    prep=info.get("prepared",{})
    if phase!=info["next"] or prep.get("phase")!=phase: raise ValueError("Phase not prepared")
    plan=root/(phase+".tfplan"); directory=root/(phase+"-policies")
    if digest(plan)!=prep["plan_sha256"] or digest(root/"main.tf.json")!=prep["config_sha256"] or digest(root/".terraform.lock.hcl")!=prep["lock_sha256"] or digest(directory/"manifest.json")!=prep["bundle_sha256"]: raise ValueError("Prepared inputs changed")
    if json.loads((root/"main.tf.json").read_bytes())!=config(info,1 if phase=="create" else 2): raise ValueError("Fixture changed")
    if any(p.name.endswith((".tf",".tf.json")) and p.name!="main.tf.json" for p in root.iterdir()): raise ValueError("Unexpected Terraform source")
    session,identity,env,opts=environment(args.test_profile,info,args.role_name)
    auditor,audit_identity,_,aopts=environment(args.audit_profile,info)
    if identity["UserId"].split(":")[0]==audit_identity["UserId"].split(":")[0]: raise ValueError("Audit identity must differ")
    iam=auditor.client("iam",config=aopts)
    expected=set().union(*(grants(p["document"]) for p in json.loads((directory/"manifest.json").read_bytes())["policies"]))
    def check():
        role=iam.get_role(RoleName=args.role_name)["Role"]
        if role["RoleId"]!=identity["UserId"].split(":")[0]: raise ValueError("Role mismatch")
        existing,_=role_policies(iam,args.role_name)
        if grants(existing)!=expected: raise ValueError("Applier grants differ from exact reviewed phase policy union")
        return role["Arn"]
    role=check()
    parsed=json.loads(command(root,env,"","show","-json",str(plan)))
    if operations(parsed,phase,info)!=prep["operations"]: raise ValueError("Plan operations changed")
    attempt={"status":"incomplete","role_arn":role,"session_arn":identity["Arn"],"start":now(),"plan_sha256":prep["plan_sha256"]}
    info["steps"][phase]=attempt; write(root/"fixture.json",info)
    try:
        check()
        command(root,env,phase+"-apply","apply","-input=false",str(plan))
        check()
        if phase=="destroy":
            if command(root,env,"state-list","state","list").strip(): raise ValueError("Nonempty Terraform state after destroy")
            attempt["empty_state_verified"]=True
        attempt["status"]="passed"
        info["next"]={"create":"update","update":"destroy","destroy":"complete"}[phase]
        info.pop("prepared",None)
    finally:
        attempt["end"]=now(); write(root/"fixture.json",info)
    print("Phase passed:",phase,"; next:",info["next"])

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=["prepare","plan","apply"])
    p.add_argument("directory",type=Path); p.add_argument("--account",required=True)
    p.add_argument("--region",default="us-east-1"); p.add_argument("--phase",choices=["create","update","destroy"])
    p.add_argument("--planner-profile"); p.add_argument("--test-profile"); p.add_argument("--audit-profile"); p.add_argument("--role-name")
    p.add_argument("--confirm-isolated-aws-account",action="store_true")
    args=p.parse_args(); root=args.directory.resolve()
    try:
        if args.mode=="prepare": prepare(args,root)
        else:
            if not args.confirm_isolated_aws_account or not args.phase: raise ValueError("Explicit isolated AWS account and phase required")
            info=load(root,args)
            if args.mode=="plan":
                if not args.planner_profile: raise ValueError("Explicit planner profile required")
                plan_phase(args,root,info)
            else:
                if not all((args.test_profile,args.audit_profile,args.role_name)): raise ValueError("Explicit test and audit profiles and role required")
                apply_phase(args,root,info)
    except Exception as exc:
        print("Acceptance failed:",str(exc) if isinstance(exc,(ValueError,OSError)) else type(exc).__name__)
        print("Preserve private state and logs. No automatic administrator fallback.")
        return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
