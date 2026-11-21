"""Heuristic risk indicators, not an effective-access or escalation proof."""
RULES = {
    "aws": {"iam:PassRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:CreateAccessKey", "iam:PutUserPolicy", "iam:AttachUserPolicy"},
    "gcp": {"iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.setIamPolicy", "resourcemanager.projects.setIamPolicy", "iam.roles.update"},
    "azure": {"Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/roleDefinitions/write"},
}
COMBINATIONS = {"aws": [("iam:PassRole", "ec2:RunInstances"), ("iam:PassRole", "lambda:CreateFunction"), ("iam:PassRole", "eks:CreateCluster")]}
def assess(rows):
    findings = []
    for provider, actions in RULES.items():
        grouped = {}
        for row in rows:
            if row["provider"] == provider:
                grouped.setdefault(row["action"].lower(), []).append(row)
        for action in sorted(actions):
            evidence = grouped.get(action.lower(), [])
            if evidence:
                findings.append({"provider": provider, "kind": "delegation", "actions": [action], "sources": sorted({r["source"] for r in evidence}), "message": "Review delegation, boundaries and effective resource conditions."})
        for combo in COMBINATIONS.get(provider, []):
            if all(a.lower() in grouped for a in combo):
                findings.append({"provider": provider, "kind": "combination", "actions": list(combo), "sources": sorted({r["source"] for a in combo for r in grouped[a.lower()]}), "message": "Potential delegation combination; exploitability depends on scope and conditions."})
    return findings
