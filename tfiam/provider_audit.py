"""Reconcile pinned provider SDK call sites with official AWS operation metadata.

A deliberately bounded source inventory, never a complete Go call graph.
No unreviewed operations become policy grants.
"""
import hashlib
import re
import subprocess
from pathlib import Path
from .authorization import load_snapshot
from .catalog_loader import get_rule
from .versioning import VERSION

PROVIDER="https://github.com/hashicorp/terraform-provider-aws"
PINNED={"6.73.0":"22e15d8b32e0c8bac1378a058b6d087c0191c1da"}
FILES={
    "aws_s3_bucket":"s3/bucket.go",
    "aws_s3_bucket_public_access_block":"s3/bucket_public_access_block.go",
    "aws_s3_bucket_versioning":"s3/bucket_versioning.go",
    "aws_eks_cluster":"eks/cluster.go",
    "aws_eks_node_group":"eks/node_group.go",
    "aws_eks_addon":"eks/addon.go",
    "aws_eks_pod_identity_association":"eks/pod_identity_association.go",
    "aws_iam_role":"iam/role.go",
    "aws_iam_role_policy_attachment":"iam/role_policy_attachment.go",
}
S3_DOC="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html"
# General-purpose bucket operations reviewed against AWS's documented table.
# Explicitly separate API names from policy actions; alternative actions in
# AWS operation metadata may be conditional, cross-service, or resource-specific.
GENERAL_S3={
    "HeadBucket":"ListBucket",
    "CreateBucket":"CreateBucket",
    "DeleteBucket":"DeleteBucket",
    "ListBuckets":"ListAllMyBuckets",
    "GetBucketPublicAccessBlock":"GetBucketPublicAccessBlock",
    "PutBucketPublicAccessBlock":"PutBucketPublicAccessBlock",
    "DeleteBucketPublicAccessBlock":"PutBucketPublicAccessBlock",
    "GetPublicAccessBlock":"GetBucketPublicAccessBlock",
    "PutPublicAccessBlock":"PutBucketPublicAccessBlock",
    "DeletePublicAccessBlock":"PutBucketPublicAccessBlock",
    "GetBucketVersioning":"GetBucketVersioning",
    "PutBucketVersioning":"PutBucketVersioning",
}
CALL=re.compile(r"\b(?:conn|client)\.([A-Z][A-Za-z0-9]+)\(")
PAGER=re.compile(r"\b(?:s3|eks|iam)\.New([A-Z][A-Za-z0-9]+)Paginator\(")
def direct_calls(source):
    # Retain source line numbers. Ignore full comment lines; this is a
    # lexical inventory, not semantic Go analysis.
    found={}
    for n,line in enumerate(source.splitlines(),1):
        if line.lstrip().startswith("//"): continue
        for op in CALL.findall(line)+PAGER.findall(line):
            found.setdefault(op,[]).append(n)
    return found

def operation_index(doc):
    result={}
    for op in doc.get("Operations",[]):
        if not isinstance(op,dict) or not isinstance(op.get("Name"),str): continue
        actions=op.get("AuthorizedActions")
        if not isinstance(actions,list): continue
        names=set()
        for a in actions:
            if isinstance(a,dict) and isinstance(a.get("Service"),str) and isinstance(a.get("Name"),str):
                if re.fullmatch(r"[a-z0-9-]+",a["Service"]) and re.fullmatch(r"[A-Za-z0-9]+",a["Name"]):
                    names.add(a["Service"]+":"+a["Name"])
        if names: result.setdefault(op["Name"],set()).update(names)
    return result

def git(root,*args):
    try:
        return subprocess.run(["git","-C",str(root),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30).stdout
    except (OSError,subprocess.SubprocessError):
        raise ValueError("Unable to read exact provider Git object; clone the official version tag first") from None

def reconcile(kind,source,doc,version):
    rule=get_rule("resource",kind,version)
    if not rule: raise ValueError("No catalog rule for "+kind)
    listed=set(rule["read"]+rule["write"]+rule["delete"])
    for attr in rule["attributes"]: listed.update(attr["actions"])
    # Scope engine dependencies are separate from the base rule.
    if kind.startswith("aws_eks_"): listed.add("iam:PassRole")
    known={doc["Name"]+":"+a["Name"] for a in doc["Actions"]}
    operations=operation_index(doc)
    rows=[]
    for op,lines in sorted(direct_calls(source).items()):
        authorized=operations.get(op,set())
        reviewed="s3:"+GENERAL_S3[op] if doc["Name"]=="s3" and op in GENERAL_S3 else None
        if reviewed and reviewed in known:
            if authorized and reviewed not in authorized:
                status="METADATA_CONFLICT"; actions=sorted(authorized)
            else:
                status="MATCHED" if reviewed in listed else "MISSING_CANDIDATE"
                actions=[reviewed]
            basis=S3_DOC
        elif authorized:
            actions=sorted(authorized)
            # Multiple possible actions need branch/context review; never
            # treat the entire operation's list as mandatory.
            status="MATCHED" if len(actions)==1 and actions[0] in listed else "MISSING_CANDIDATE" if len(actions)==1 else "CONDITIONAL_REVIEW"
            basis="AWS operation metadata"
        else:
            actions=[]; status="METADATA_UNAVAILABLE"; basis="No documented operation mapping in snapshot"
        rows.append({"operation":op,"lines":lines,"actions":actions,"status":status,"basis":basis,
                     "not_in_catalog":sorted(set(actions)-listed)})
    return rows

def audit_provider(root,version,metadata_dir,resources=None):
    if not VERSION.fullmatch(version): raise ValueError("Exact stable provider version required")
    root=Path(root)
    commit=git(root,"rev-parse","--verify","refs/tags/v"+version+"^{commit}").decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40}",commit): raise ValueError("Invalid provider commit")
    if version in PINNED and commit!=PINNED[version]: raise ValueError("Provider tag does not match official pinned commit")
    chosen=sorted(set(resources or FILES))
    if any(x not in FILES for x in chosen): raise ValueError("No registered source path for requested resource")
    services={FILES[x].split("/")[0] for x in chosen}
    docs,evidence,missing=load_snapshot(metadata_dir,services)
    if missing: raise ValueError("Missing AWS metadata snapshots: "+", ".join(missing))
    reports=[]
    for kind in chosen:
        path="internal/service/"+FILES[kind]
        raw=git(root,"show",commit+":"+path)
        if len(raw)>4*1024*1024: raise ValueError("Provider source exceeds size limit")
        rows=reconcile(kind,raw.decode("utf-8"),docs[FILES[kind].split("/")[0]],version)
        digest=hashlib.sha256(raw).hexdigest()
        rule=get_rule("resource",kind,version)
        records=[e for e in rule.get("evidence",[]) if e["provider_version"]==version and e["level"]=="provider-source-reviewed"]
        if records and not any(e["sha256"]==digest and e["reference"]==PROVIDER+"/blob/"+commit+"/"+path for e in records):
            raise ValueError("Reviewed provider source digest mismatch for "+kind)
        reports.append({"resource":kind,"reference":PROVIDER+"/blob/"+commit+"/"+path,
                        "sha256":digest,"source_review_record_matched":bool(records),"operations":rows})
    counts={}
    for row in reports:
        for op in row["operations"]: counts[op["status"]]=counts.get(op["status"],0)+1
    return {"provider_version":version,"provider_commit":commit,"pin_verified":version in PINNED,
            "status":"review" if not version in PINNED or any(k!="MATCHED" for k in counts) or any(not r["operations"] for r in reports) else "direct-calls-matched",
            "resources":reports,"counts":counts,"aws_metadata":evidence,
            "limitation":"Direct SDK call inventory only; shared helpers, conditional paths, paginators outside these files, provider initialization, pass-role and forwarded access require review. This report does not authorize new permissions or certify lifecycle coverage."}
