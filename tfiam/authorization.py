"""Offline audit of AWS's machine-readable service authorization reference.

The downloader fetches only public AWS service metadata, never a user's plan.
Checks are compatibility diagnostics, not a provider invocation trace.
"""
import hashlib
import json
import re
from pathlib import Path
from importlib.resources import files
from urllib.request import urlopen
from .catalog_loader import CATALOG, get_rule

BASE="https://servicereference.us-east-1.amazonaws.com"
SERVICE=re.compile(r"[a-z0-9-]+")
MAX_BYTES=32*1024*1024
# Official SAR explicitly lists no resource types for these EKS actions.
# Only fill an absent Resources field; never override a conflicting snapshot.
DOCUMENTED_GLOBAL={"eks:createcluster","eks:describeaddonversions","ecs:describetaskdefinition","ecs:deregistertaskdefinition","ec2:describekeypairs","sts:getcalleridentity","autoscaling:describeautoscalinggroups","autoscaling:describescalingactivities","autoscaling:describetags"}
EKS_REFERENCE="https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html"
EC2_REFERENCE="https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html"
EC2_DOCUMENTED_GLOBAL={"ec2:"+x.lower() for x in "DescribeSubnets DescribeImages DescribeInstanceStatus DescribeInstances DescribeInternetGateways DescribeNetworkInterfaces DescribeRouteTables DescribeSecurityGroupRules DescribeSecurityGroups DescribeTags DescribeVolumes DescribeVpcs DescribeVpcEndpoints DescribeVpcPeeringConnections DescribeNatGateways DescribeNetworkAcls DescribeLaunchTemplates DescribeLaunchTemplateVersions".split()}
DOCUMENTED_GLOBAL.update(EC2_DOCUMENTED_GLOBAL)

def catalog_actions(version=None):
    out=set()
    for category in ("resources","data"):
        for kind in CATALOG[category]:
            rule=get_rule("resource" if category=="resources" else "data",kind,version)
            for field in ("read","write","delete"): out.update(rule[field])
            for attr in rule["attributes"]: out.update(attr["actions"])
    out.update({"iam:CreateServiceLinkedRole","eks:CreateAccessEntry","iam:PutRolePermissionsBoundary","iam:DeleteRolePermissionsBoundary","eks:AssociateEncryptionConfig","iam:PassRole","kms:GenerateDataKey","kms:Decrypt","kms:DescribeKey","kms:CreateGrant","s3:PutObjectAcl","s3:PutObjectLegalHold","s3:PutObjectRetention","s3:ListBucketVersions","s3:DeleteObjectVersion","s3:BypassGovernanceRetention","rds:RestoreDBInstanceFromDBSnapshot","rds:RestoreDBClusterFromSnapshot","rds:CreateDBInstanceReadReplica","rds:RestoreDBInstanceToPointInTime","rds:RestoreDBClusterToPointInTime","rds:PromoteReadReplica","secretsmanager:CreateSecret","secretsmanager:TagResource"})
    return out

def download_snapshot(folder,services):
    folder=Path(folder)
    folder.mkdir(parents=True,exist_ok=True)
    for service in sorted(set(services)):
        if not SERVICE.fullmatch(service): raise ValueError("Invalid AWS service prefix")
        url=f"{BASE}/v1/{service}/{service}.json"
        try:
            with urlopen(url,timeout=30) as response:
                if not response.geturl().startswith(BASE+"/"): raise ValueError("Unexpected AWS metadata redirect")
                raw=response.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES: raise ValueError("AWS metadata exceeds size limit")
            doc=json.loads(raw)
            validate_service(doc,service)
        except Exception:
            raise ValueError("Unable to retrieve AWS authorization metadata for "+service) from None
        (folder/(service+".json")).write_bytes(raw)

def validate_service(doc,service):
    if not isinstance(doc,dict) or doc.get("Name")!=service or not isinstance(doc.get("Actions"),list):
        raise ValueError("Invalid AWS service metadata: "+service)
    for action in doc["Actions"]:
        if not isinstance(action,dict) or not isinstance(action.get("Name"),str):
            raise ValueError("Invalid action metadata: "+service)
    if not doc["Actions"]: raise ValueError("Empty AWS service metadata: "+service)

def load_snapshot(folder,services):
    docs={}; evidence={}; missing=[]
    for service in sorted(set(services)):
        if not SERVICE.fullmatch(service): raise ValueError("Invalid AWS service prefix")
        path=Path(folder)/(service+".json")
        if not path.is_file():
            missing.append(service); continue
        raw=path.read_bytes()
        if len(raw)>MAX_BYTES: raise ValueError("AWS metadata exceeds size limit")
        try:
            doc=json.loads(raw)
            validate_service(doc,service)
        except (ValueError,TypeError):
            raise ValueError("Invalid AWS metadata file: "+str(path)) from None
        docs[service]=doc
        evidence[service]={"sha256":hashlib.sha256(raw).hexdigest(),"metadata_version":doc.get("Version"),"reference":f"{BASE}/v1/{service}/{service}.json"}
    return docs,evidence,missing

def template_matches(template,value):
    # AWS ARN placeholders may contain slashes. Preserve literal separators and
    # distinguish S3 bucket ARNs from object ARNs.
    parts=re.split(r"(\$\{[^}]+\})",template)
    pattern="".join((r"[^:/]+" if p in ("${Partition}","${Region}","${Account}","${BucketName}") else r".+") if p.startswith("${") else re.escape(p) for p in parts)
    return re.fullmatch(pattern,value) is not None

def condition_matches(template,key):
    pattern=re.escape(template)
    pattern=re.sub(r"\\\$\\\{[^}]+\\\}",r".+",pattern)
    if template.endswith("/key"): pattern=re.escape(template[:-3])+r".+"
    return re.fullmatch(pattern,key,re.IGNORECASE) is not None

def audit(actions,permissions,folder):
    actions=set(actions)|{p["action"] for p in permissions}
    services={a.split(":",1)[0] for a in actions}
    docs,evidence,missing=load_snapshot(folder,services)
    by_action={}
    for service,doc in docs.items():
        for action in doc["Actions"]: by_action[service+":"+action["Name"].lower()]=action
    findings=[]
    def issue(code,action,source=None,severity="error",**details):
        row={"code":code,"action":action,"severity":severity,**details}
        if source is not None: row["source"]=source
        if row not in findings: findings.append(row)
    valid=0
    for action in sorted(actions):
        service=action.split(":",1)[0]
        if service in missing:
            issue("metadata-missing",action,severity="unknown"); continue
        if action.lower() not in by_action: issue("unknown-action",action); continue
        valid+=1
    checked=0
    reference_fallbacks=set()
    for p in permissions:
        action=p["action"]; service=action.split(":",1)[0]; meta=by_action.get(action.lower())
        if not meta: continue
        source=p["source"]; scope=p["scope"]; doc=docs[service]
        refs=meta.get("Resources")
        resources=doc.get("Resources")
        if "Resources" not in meta and action.lower() in DOCUMENTED_GLOBAL:
            refs=[]
            reference_fallbacks.add(action)
        if not isinstance(refs,list) or (refs and not isinstance(resources,list)):
            issue("resource-metadata-unavailable",action,source,"unknown"); continue
        definitions={r.get("Name"):r for r in (resources or []) if isinstance(r,dict)}
        names=[r.get("Name") for r in refs if isinstance(r,dict)]
        matched=[]
        if scope=="*":
            if names: issue("global-scope-review",action,source,"review")
        elif not names:
            issue("action-requires-global-scope",action,source)
        else:
            formats={n:definitions.get(n,{}).get("ARNFormats",[]) for n in names}
            matched=[n for n,templates in formats.items() if any(template_matches(t,scope) for t in templates if isinstance(t,str))]
            if not matched:
                issue("resource-type-mismatch" if all(formats.values()) else "resource-format-unavailable",action,source,"error" if all(formats.values()) else "unknown",supported_resource_types=names)
        keys=meta.get("ActionConditionKeys",[])
        for r in refs:
            if isinstance(r,dict) and (scope=="*" or r.get("Name") in matched):
                keys=keys+r.get("ConditionKeys",[])
                keys=keys+r.get("ResourceConditionKeys",[])
        for name in matched:
            keys=keys+definitions.get(name,{}).get("ConditionKeys",[])
        for conditions in p.get("condition",{}).values():
            for key in conditions:
                if key.lower()=='aws:requestedregion': continue  # AWS global request context key
                if not any(condition_matches(k,key) for k in keys if isinstance(k,str)):
                    # The metadata does not enumerate all globally available context keys.
                    # Unlisted keys are unverified, not automatically invalid.
                    issue("condition-key-unverified",action,source,"review",condition_key=key)
        checked+=1
    findings.sort(key=lambda f:(f["action"],f.get("source",""),f["code"],f.get("condition_key","")))
    return {"status":"issues" if any(f["severity"]=="error" for f in findings) else "review" if findings else "compatible",
            "actions_total":len(actions),"actions_recognized":valid,"permission_observations_checked":checked,
            "reference_fallbacks":[{"action":a,"resource_scope":"global","reference":EC2_REFERENCE if a.lower().startswith("ec2:") else "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerservice.html" if a.lower().startswith("ecs:") else "https://docs.aws.amazon.com/service-authorization/latest/reference/list_autoscaling.html" if a.lower().startswith("autoscaling:") else "https://docs.aws.amazon.com/service-authorization/latest/reference/list_sts.html" if a.lower().startswith("sts:") else EKS_REFERENCE} for a in sorted(reference_fallbacks)],"missing_services":missing,"metadata_directory":str(Path(folder).resolve()),"evidence":evidence,"findings":findings,
            "diagnostics":(["Missing service snapshots; use an updated official distribution or a complete offline snapshot."] if missing else []),
            "limitation":"Metadata compatibility only; required multi-resource groups, condition values, provider API calls and effective IAM authorization are not established."}


def all_catalog_actions():
    """Union baseline and exact-version rule variants for distribution checks."""
    versions={None}
    for category in ("resources","data"):
        for rule in CATALOG[category].values():
            versions.update(rule.get("version_overrides",{}))
    return set().union(*(catalog_actions(version) for version in versions))

def bundled_metadata():
    """Local immutable package data only. Never performs network I/O."""
    root=Path(str(files("tfiam").joinpath("catalog","authorization")))
    manifest=root/"manifest.json"
    if not manifest.is_file():
        if root.exists() and any(root.iterdir()):
            raise ValueError("Packaged AWS metadata manifest missing")
        return None
    data=json.loads(manifest.read_bytes())
    if data.get("schema_version")!=1 or not isinstance(data.get("services"),dict):
        raise ValueError("Invalid packaged authorization metadata manifest")
    expected={a.split(":",1)[0] for a in all_catalog_actions()}
    if set(data["services"])!=expected:
        raise ValueError("Packaged AWS metadata does not cover the bundled catalog")
    for service,record in data["services"].items():
        if not SERVICE.fullmatch(service) or not isinstance(record,dict):
            raise ValueError("Invalid packaged authorization metadata entry")
        path=root/(service+".json")
        if not path.is_file() or path.stat().st_size>MAX_BYTES:
            raise ValueError("Packaged AWS metadata missing or too large: "+service)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=record.get("sha256"):
            raise ValueError("Packaged AWS metadata digest mismatch: "+service)
    return root


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
