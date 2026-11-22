"""Validate and collect structural restricted-role fixture evidence.

Digests and schema checks are not proof of AWS activity. Independently review
CloudTrail and role authorization before publishing.
"""
import hashlib
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

FIXTURES={
    "s3-general-purpose-empty":({"aws_s3_bucket.example","aws_s3_bucket_versioning.example","aws_s3_bucket_public_access_block.example"},"s3:ListAllMyBuckets"),
    "sqs-standard-empty":({"aws_sqs_queue.example"},"sqs:ListQueues"),
    "dynamodb-ondemand-empty":({"aws_dynamodb_table.example"},"dynamodb:ListTables"),
    "vpc-private-subnet":({"aws_vpc.example","aws_subnet.example"},"ec2:CreateInternetGateway"),
}
STEPS={"create":["create"],"read":["no-op"],"update":["update"],"replace-delete-first":["delete","create"],"replace-create-first":["create","delete"],"destroy":["delete"]}
SHA256=re.compile(r"[a-f0-9]{64}")
SHA1=re.compile(r"[a-f0-9]{40}")
VERSION=re.compile(r"\d+\.\d+\.\d+")

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def timestamp(value):
    if not isinstance(value,str): raise ValueError("Missing evidence timestamp")
    out=datetime.fromisoformat(value.replace("Z","+00:00"))
    if out.tzinfo is None: raise ValueError("Evidence timestamp must include a timezone")
    return out

def artifact(base,row):
    if not isinstance(row,dict) or not isinstance(row.get("artifact"),str) or not isinstance(row.get("sha256"),str) or not SHA256.fullmatch(row["sha256"]):
        raise ValueError("Invalid fixture artifact record")
    relative=Path(row["artifact"])
    if relative.is_absolute() or ".." in relative.parts: raise ValueError("Artifact must be inside release evidence directory")
    path=base/relative
    if any((base.joinpath(*relative.parts[:i])).is_symlink() for i in range(1,len(relative.parts)+1)):
        raise ValueError("Artifact symlinks are not accepted")
    path=path.resolve()
    if not path.is_relative_to(base.resolve()) or not path.is_file() or digest(path)!=row["sha256"]:
        raise ValueError("Missing or changed fixture artifact")
    return path

def check_fixture(evidence,fixture,version,commit,candidate,lockfile):
    resources,negative=FIXTURES[fixture]
    if not isinstance(evidence,dict) or evidence.get("schema_version")!=1 or evidence.get("fixture")!=fixture or evidence.get("status")!="fixture-passed":
        raise ValueError("Fixture has no successful acceptance result")
    if evidence.get("source_commit")!=commit or evidence.get("provider_version")!=version:
        raise ValueError("Fixture source commit or provider version mismatch")
    if evidence.get("negative_authorization")!="passed" or evidence.get("negative_action")!=negative or evidence.get("identity_grants_rechecked") is not True or evidence.get("empty_state_verified") is not True:
        raise ValueError("Fixture missing denial, role recheck or cleanup evidence")
    if evidence.get("candidate_sha256")!=digest(candidate) or evidence.get("lockfile_sha256")!=digest(lockfile):
        raise ValueError("Fixture candidate or lockfile changed")
    role=evidence.get("role_arn",""); session=evidence.get("session_arn","")
    match=re.fullmatch(r"arn:aws:iam::([0-9]{12}):role/(?:[^/*?\s]+/)*([^/*?\s]+)",role)
    if not match or not re.fullmatch(r"arn:aws:sts::"+match.group(1)+r":assumed-role/"+re.escape(match.group(2))+r"/[^/\s]+",session):
        raise ValueError("Fixture does not identify a matching assumed role session")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]+",evidence.get("region","")):
        raise ValueError("Invalid fixture region")
    start=timestamp(evidence.get("start")); end=timestamp(evidence.get("end"))
    if end<=start: raise ValueError("Invalid fixture interval")
    steps=evidence.get("steps")
    if not isinstance(steps,dict) or set(steps)!=set(STEPS): raise ValueError("Missing or unexpected lifecycle stage")
    previous=start
    for name,ops in STEPS.items():
        step=steps[name]
        if not isinstance(step,dict) or step.get("status")!="passed": raise ValueError("Lifecycle stage did not pass")
        operations=step.get("operations")
        if not isinstance(operations,dict) or set(operations)!=resources or any(value!=ops for value in operations.values()):
            raise ValueError("Unexpected Terraform lifecycle operations")
        if not isinstance(step.get("plan_sha256"),str) or not SHA256.fullmatch(step["plan_sha256"]): raise ValueError("Missing plan hash")
        completed=timestamp(step.get("completed"))
        if not previous<=completed<=end: raise ValueError("Lifecycle stage timestamps not ordered")
        previous=completed
    return role

def check_bundle(path,commit,version):
    path=Path(path)
    doc=json.loads(path.read_bytes())
    if not isinstance(doc,dict) or doc.get("schema_version")!=1 or doc.get("commit")!=commit or doc.get("provider_version")!=version:
        raise ValueError("Lifecycle bundle does not match release commit/provider")
    fixtures=doc.get("fixtures")
    if not isinstance(fixtures,dict) or set(fixtures)!=set(FIXTURES): raise ValueError("All four restricted-role fixtures are required")
    roles=set()
    for name,records in fixtures.items():
        if not isinstance(records,dict) or set(records)!={"evidence","candidate","lockfile"}: raise ValueError("Incomplete fixture bundle")
        evidence=artifact(path.parent,records["evidence"])
        candidate=artifact(path.parent,records["candidate"])
        lockfile=artifact(path.parent,records["lockfile"])
        role=check_fixture(json.loads(evidence.read_bytes()),name,version,commit,candidate,lockfile)
        if role in roles: raise ValueError("Each fixture requires a distinct reviewed role")
        roles.add(role)

def collect_bundle(destination,dirs,commit,version):
    destination=Path(destination)
    if not SHA1.fullmatch(commit) or not VERSION.fullmatch(version): raise ValueError("Expected an exact commit and provider version")
    if destination.exists(): raise ValueError("Use a new lifecycle evidence bundle")
    found={}
    for raw in dirs:
        root=Path(raw).resolve()
        evidence=root/"lifecycle-evidence.json"
        candidate=root/"candidate-policy.json"
        lockfile=root/".terraform.lock.hcl"
        if any(p.is_symlink() or not p.is_file() for p in (evidence,candidate,lockfile)): raise ValueError("Fixture artifacts missing or symlinked")
        data=json.loads(evidence.read_bytes())
        name=data.get("fixture")
        if name not in FIXTURES or name in found: raise ValueError("Unknown or duplicate fixture")
        check_fixture(data,name,version,commit,candidate,lockfile)
        found[name]=(evidence,candidate,lockfile)
    if set(found)!=set(FIXTURES): raise ValueError("All four fixtures must be provided")
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    out={"schema_version":1,"commit":commit,"provider_version":version,"fixtures":{}}
    base=destination.parent
    target=base/"lifecycle-fixtures"
    target.mkdir(mode=0o700,exist_ok=False)
    for name,paths in sorted(found.items()):
        folder=target/name
        folder.mkdir(mode=0o700)
        records={}
        for label,src,filename in zip(("evidence","candidate","lockfile"),paths,("lifecycle-evidence.json","candidate-policy.json","terraform.lock.hcl")):
            dst=folder/filename
            shutil.copyfile(src,dst)
            dst.chmod(0o600)
            records[label]={"artifact":str(dst.relative_to(base)),"sha256":digest(dst)}
        out["fixtures"][name]=records
    destination.write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
    destination.chmod(0o600)
    check_bundle(destination,commit,version)
    return out
