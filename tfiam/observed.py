"""Offline reconciliation of generated IAM and observed IAM Live identity policies.

No AWS calls, automatic privilege escalation, or policy attachments are made.
Grant differences are exact tuples, not proof of effective authorization.
"""
from .policy_size import grants, optimize, document, size, LIMITS


def _normalize(policy, label):
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ValueError(label + " must be a versioned IAM identity policy")
    rows = policy.get("Statement")
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise ValueError(label + " must contain IAM Statement array")
    cleaned = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("Effect") != "Allow":
            raise ValueError(label + " statement " + str(index) + " must be an Allow identity statement")
        if set(row) - {"Sid", "Effect", "Action", "Resource", "Condition"}:
            raise ValueError(label + " statement " + str(index) + " contains unsupported IAM fields")
        cleaned.append({k: row[k] for k in ("Effect", "Action", "Resource", "Condition") if k in row})
    normalized = document(cleaned)
    grants(normalized)  # Validate action, resource and nonempty condition shape.
    return normalized


def _describe(items):
    import json
    return [
        {"action": action, "resource": resource,
         **({"condition": json.loads(condition)} if condition != "null" else {})}
        for action, resource, condition in sorted(items)
    ]


def reconcile(generated, observed):
    candidate = _normalize(generated, "Generated")
    evidence = _normalize(observed, "Observed")
    a, b = grants(candidate), grants(evidence)
    merged = optimize(document(candidate["Statement"] + evidence["Statement"]))
    if grants(merged) != (a | b):
        raise ValueError("Observed permission reconciliation changed grant semantics")
    extra = b - a
    missing = a - b
    return {
        "report": {
            "schema_version": 1,
            "status": "MATCHED" if a == b else "DIFFERENCES",
            "comparison": "exact-action-resource-condition-grant",
            "generated_grants": len(a),
            "observed_grants": len(b),
            "observed_not_in_generated": _describe(extra),
            "generated_not_observed": _describe(missing),
            "merged_grants": len(a | b),
            "merged_policy_characters": size(merged),
            "managed_policy_limit": LIMITS["managed"],
            "requires_policy_packing": size(merged) > LIMITS["managed"],
            "warnings": [
                "IAM Live CSM can observe action names without exact resources; Resource '*' remains broad.",
                "Exact-grant differences do not establish effective IAM authorization or actual missing permissions.",
                "A single recording may not cover create, update, refresh and destroy Terraform lifecycle operations.",
                "A merged policy may grant more permissions than the generated policy; review before attachment.",
            ],
        },
        "merged_policy": merged,
    }
