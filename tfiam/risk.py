"""Conservative candidate risk detection; combinations do not prove exploitability."""
LEVELS={"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
DELEGATION={
    "iam:PassRole":"HIGH","iam:AttachRolePolicy":"HIGH","iam:PutRolePolicy":"HIGH",
    "iam:UpdateAssumeRolePolicy":"HIGH","iam:CreatePolicyVersion":"HIGH",
    "iam:SetDefaultPolicyVersion":"HIGH","iam:CreateAccessKey":"HIGH",
    "iam:PutUserPolicy":"HIGH","iam:AttachUserPolicy":"HIGH","iam:PutGroupPolicy":"HIGH",
    "iam:AttachGroupPolicy":"HIGH","iam:AddUserToGroup":"HIGH",
    "iam:DeleteRolePermissionsBoundary":"CRITICAL","iam:DeleteUserPermissionsBoundary":"CRITICAL",
    "iam:PutRolePermissionsBoundary":"HIGH","iam:PutUserPermissionsBoundary":"HIGH",
    "kms:PutKeyPolicy":"HIGH","s3:PutBucketPolicy":"HIGH","eks:AssociateAccessPolicy":"HIGH",
    "lambda:AddPermission":"HIGH",
}
COMBOS=[
    ("iam:PassRole","ec2:RunInstances"),("iam:PassRole","lambda:CreateFunction"),
    ("iam:PassRole","eks:CreateCluster"),("iam:PassRole","ecs:RegisterTaskDefinition"),
    ("iam:PassRole","lambda:UpdateFunctionConfiguration"),
    ("iam:CreatePolicyVersion","iam:SetDefaultPolicyVersion"),
    ("iam:CreateRole","iam:AttachRolePolicy"),
    ("iam:CreateRole","iam:PutRolePolicy"),
]
DESTRUCTIVE={
    "s3:DeleteBucket","s3:DeleteObject","s3:DeleteObjectVersion","ec2:TerminateInstances",
    "ec2:DeleteVolume","ec2:DeleteSnapshot","rds:DeleteDBInstance","rds:DeleteDBCluster",
    "dynamodb:DeleteTable","kms:ScheduleKeyDeletion","eks:DeleteCluster","eks:DeleteNodegroup",
    "ecr:DeleteRepository","logs:DeleteLogGroup","lambda:DeleteFunction",
    "sqs:DeleteQueue","route53:DeleteHostedZone","elasticloadbalancing:DeleteLoadBalancer",
}
# All catalog destroy actions are security-sensitive, including APIs also used
# for ordinary updates. IAM policy cannot distinguish Terraform's intent.
from .catalog_loader import CATALOG
DESTROY_ACTIONS = {a.lower() for rule in CATALOG["resources"].values()
                   for variant in [rule]+list(rule.get("version_overrides",{}).values())
                   for a in variant.get("delete",[])}
def destructive(row):
    action=row["action"].lower()
    return action in DESTROY_ACTIONS or action in {a.lower() for a in DESTRUCTIVE}

def assess(rows):
    grouped={}
    for row in rows:
        if row["provider"]=="aws": grouped.setdefault(row["action"].lower(),[]).append(row)
    findings=[]
    def add(kind,actions,severity,message):
        evidence=[r for a in actions for r in grouped.get(a.lower(),[])]
        findings.append({"provider":"aws","kind":kind,"severity":severity,"actions":list(actions),
                         "sources":sorted({r["source"] for r in evidence}),"message":message})
    for action,severity in sorted(DELEGATION.items()):
        evidence=grouped.get(action.lower(),[])
        if not evidence: continue
        if action=="iam:PassRole":
            unrestricted=any(r["scope"]=="*" or "*" in r["scope"] or "?" in r["scope"] or not any(isinstance(v,str) and v and "*" not in v and "?" not in v and v.endswith(".amazonaws.com") for v in [r.get("condition",{}).get("StringEquals",{}).get("iam:PassedToService")]) for r in evidence)
            severity="CRITICAL" if unrestricted else "HIGH"
            message="Potential unrestricted role delegation." if unrestricted else "Scoped role delegation; verify effective target role privileges."
        elif "PermissionsBoundary" in action: message="Permissions boundary modification or removal; review independent enforcement."
        elif action=="iam:UpdateAssumeRolePolicy": message="Trust policy mutation may change who can assume a role."
        else: message="Review delegation, boundaries and effective resource conditions."
        add("delegation",[action],severity,message)
    for combo in COMBOS:
        if all(a.lower() in grouped for a in combo):
            add("combination",combo,"HIGH","Potential delegation combination; exploitability depends on scope, identity and conditions.")
    for key, evidence in sorted(grouped.items()):
        if any(destructive(row) for row in evidence):
            add("destructive",[evidence[0]["action"]],"HIGH","Permission is used by a destroy lifecycle or destructive API; require explicit approval. Shared update/delete APIs are treated conservatively.")
    return findings

def gate(report,threshold=None,unresolved=False,unmapped=False,metadata=False):
    failures=[]
    if threshold:
        findings=[f for f in report["risks"] if LEVELS[f["severity"]]>=LEVELS[threshold]]
        if findings: failures.append({"kind":"risk-threshold","count":len(findings),"threshold":threshold})
    if unresolved and report.get("unresolved_permissions"):
        failures.append({"kind":"unresolved","count":len(report["unresolved_permissions"])})
    if unmapped and report["mapping_coverage"]["unmapped_resources"]:
        failures.append({"kind":"unmapped","count":report["mapping_coverage"]["unmapped_resources"]})
    if metadata and report["authorization_metadata"]["status"]!="compatible":
        failures.append({"kind":"metadata","status":report["authorization_metadata"]["status"]})
    return failures
