"""Reconcile fixture lifecycle results with exact-session CloudTrail evidence.

No raw events, credentials or request payloads enter this report. This checks
evidence consistency and positive observations; maintainer review is required.
"""
import hashlib
import json
import re
from pathlib import Path
from .authorization import load_snapshot
from .cloud import parse_time
from .provider_audit import PINNED, FILES, GENERAL_S3, operation_index
from .versioning import selected_version

EXPECTED={
    "create":["create"],"read":["no-op"],"update":["update"],
    "replace-delete-first":["delete","create"],"replace-create-first":["create","delete"],"destroy":["delete"],
}
RESOURCES={"aws_s3_bucket.example","aws_s3_bucket_public_access_block.example","aws_s3_bucket_versioning.example"}
KINDS={x.rsplit(".",1)[0] for x in RESOURCES}
REQUIRED={"s3:CreateBucket","s3:DeleteBucket","s3:PutBucketVersioning","s3:PutBucketPublicAccessBlock"}

def sha(raw): return hashlib.sha256(raw).hexdigest()
def is_sha(v): return isinstance(v,str) and re.fullmatch(r"[a-f0-9]{64}",v) is not None
def read_events(path):
    raw=json.loads(Path(path).read_bytes())
    if isinstance(raw,dict) and "Records" in raw: raw=raw["Records"]
    elif isinstance(raw,dict) and "Events" in raw:
        raw=[json.loads(r["CloudTrailEvent"]) for r in raw["Events"]]
    if not isinstance(raw,list): raise ValueError("Expected CloudTrail Records, event array or LookupEvents response")
    return raw

def validate_fixture(run,policy_raw,lock,source,docs):
    if run.get("fixture")!="s3-general-purpose-empty" or run.get("status")!="fixture-passed": raise ValueError("Completed S3 fixture evidence required")
    version=run["provider_version"]
    if version not in PINNED or source.get("provider_version")!=version or source.get("provider_commit")!=PINNED[version] or source.get("pin_verified") is not True:
        raise ValueError("Pinned matching provider source evidence required")
    if run.get("candidate_sha256")!=sha(policy_raw) or run.get("lockfile_sha256")!=sha(lock.read_bytes()) or selected_version(lock.parent)["version"]!=version:
        raise ValueError("Candidate policy or provider lockfile evidence mismatch")
    if run.get("negative_authorization")!="passed" or run.get("identity_grants_rechecked") is not True:
        raise ValueError("Restricted-role and negative authorization evidence required")
    if set(run.get("steps",{}))!=set(EXPECTED): raise ValueError("All lifecycle stages required")
    start,end=parse_time(run["start"]),parse_time(run["end"])
    if start>=end: raise ValueError("Invalid lifecycle interval")
    last=start
    for name,expected in EXPECTED.items():
        row=run["steps"][name]
        completed=parse_time(row["completed"])
        if row.get("status")!="passed" or not is_sha(row.get("plan_sha256")) or not last<=completed<=end or row.get("operations")!={a:expected for a in RESOURCES}:
            raise ValueError("Invalid lifecycle stage: "+name)
        last=completed
    role=run["role_arn"]; session=run["session_arn"]
    if not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[^*?\s]+",role) or not re.fullmatch(r"arn:aws:sts::"+role.split(":")[4]+r":assumed-role/"+re.escape(role.rsplit("/",1)[1])+r"/[^/]+",session):
        raise ValueError("Role and session evidence mismatch")
    entries=[r for r in source.get("resources",[]) if r.get("resource") in KINDS]
    if len(entries)!=len(KINDS) or {r["resource"] for r in entries}!=KINDS:
        raise ValueError("Missing source evidence for S3 fixture")
    for r in entries:
        expected="https://github.com/hashicorp/terraform-provider-aws/blob/"+PINNED[version]+"/internal/service/"+FILES[r["resource"]]
        if r.get("reference")!=expected or not is_sha(r.get("sha256")) or not r.get("operations"):
            raise ValueError("Invalid source evidence")
    if source.get("aws_metadata",{}).get("s3",{}).get("sha256")!=docs["s3"]["sha256"]:
        raise ValueError("AWS S3 metadata snapshot changed")
    actions=set()
    policy=json.loads(policy_raw)
    scopes=set()
    for row in policy["Statement"]:
        if row.get("Effect")!="Allow" or set(row)-{"Effect","Action","Resource","Sid"}: raise ValueError("Unexpected candidate statement")
        for a in row["Action"] if isinstance(row["Action"],list) else [row["Action"]]:
            if not re.fullmatch(r"s3:[A-Za-z0-9]+",a): raise ValueError("Unexpected candidate action")
            actions.add(a)
        for arn in row["Resource"] if isinstance(row["Resource"],list) else [row["Resource"]]:
            if not re.fullmatch(r"arn:aws:s3:::tfiam-test-[a-f0-9]{32}-[ab]",arn): raise ValueError("Unexpected candidate scope")
            scopes.add(arn)
    if len(scopes)!=2 or not REQUIRED<=actions or "s3:ListAllMyBuckets" in actions: raise ValueError("Invalid fixture candidate")
    return actions,start,end

def reconcile(run,policy_raw,lock,source,metadata_dir,events):
    docs,metadata,missing=load_snapshot(metadata_dir,{"s3"})
    if missing: raise ValueError("Missing S3 authorization metadata")
    actions,start,end=validate_fixture(run,policy_raw,lock,source,metadata)
    known={a["Name"] for a in docs["s3"]["Actions"]}
    operation_map=operation_index(docs["s3"])
    successes=set(); negative=False; findings=[]; seen=set(); counts={}
    def row(op,status,related=()):
        key=(op,status,tuple(sorted(related)))
        counts[key]=counts.get(key,0)+1
    for e in events:
        if not isinstance(e,dict): continue
        ident=e.get("userIdentity",{})
        if ident.get("arn")!=run["session_arn"] or ident.get("sessionContext",{}).get("sessionIssuer",{}).get("arn")!=run["role_arn"]: continue
        t=parse_time(e.get("eventTime",""))
        if not start<=t<=end: continue
        event_id=e.get("eventID")
        if not isinstance(event_id,str) or not event_id: raise ValueError("Matching event is missing event ID")
        if event_id in seen: continue
        seen.add(event_id)
        op=e.get("eventName",""); service=e.get("eventSource",""); error=e.get("errorCode")
        if not re.fullmatch(r"[A-Za-z0-9]+",op): continue
        denied=bool(error and ("denied" in str(error).lower() or "unauthorized" in str(error).lower()))
        if service=="sts.amazonaws.com" and op=="GetCallerIdentity":
            row(op,"NO_PERMISSION_REQUIRED"); continue
        if service!="s3.amazonaws.com":
            row(op,"UNEXPECTED_SERVICE"); continue
        alias=GENERAL_S3.get(op)
        possible=operation_map.get(op,set())
        if alias and alias in known and (not possible or "s3:"+alias in possible):
            action="s3:"+alias
        elif len(possible)==1: action=next(iter(possible))
        else:
            row(op,"CONDITIONAL_REVIEW" if possible else "METADATA_UNAVAILABLE",possible); continue
        if action=="s3:ListAllMyBuckets" and denied and action not in actions:
            negative=True; row(op,"EXPECTED_DENIAL",[action]); continue
        if denied: row(op,"UNEXPECTED_DENIAL",[action]); continue
        if action not in actions: row(op,"OUTSIDE_CANDIDATE",[action]); continue
        if error: row(op,"OTHER_API_ERROR",[action]); continue
        successes.add(action); row(op,"OBSERVED",[action])
    observations=[{"operation":op,"status":s,"actions":list(a),"count":n} for (op,s,a),n in sorted(counts.items())]
    missing_success=sorted(REQUIRED-successes)
    # Some normal provider reads return NotFound during polling. Keep all
    # such results visible; no raw error text is retained.
    blockers=sorted({r["status"] for r in observations if r["status"] not in ("OBSERVED","EXPECTED_DENIAL","NO_PERMISSION_REQUIRED","OTHER_API_ERROR")})
    if missing_success: blockers.append("required-positive-observations-missing")
    if not negative: blockers.append("negative-observation-missing")
    return {"provider_version":run["provider_version"],"provider_commit":source["provider_commit"],
            "fixture":run["fixture"],"status":"fixture-evidence-reconciled" if not blockers else "review",
            "candidate_sha256":run["candidate_sha256"],"source_sha256":{r["resource"]:r["sha256"] for r in source["resources"] if r["resource"] in KINDS},
            "metadata_sha256":metadata["s3"]["sha256"],"matched_events":len(seen),"observations":observations,
            "missing_required_observations":missing_success,"negative_observed":negative,"blockers":blockers,
            "unobserved_candidates":sorted(actions-successes),
            "limitation":"Fixture evidence consistency and selected positive CloudTrail observations only. Other API errors and source findings require review; unobserved permissions must not be removed. No catalog entry is automatically promoted."}
