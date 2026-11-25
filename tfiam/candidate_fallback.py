"""Candidate-only broad fallback for actions with unresolved resource scope.

Static scan reports retain the unresolved diagnostics. Generation keeps mapped
lifecycle action names instead of silently outputting only Describe permissions.
"""
import re
from .risk import assess

IAM_ACTION = re.compile(r"^[a-z][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$")


def include_unresolved(report):
    existing = {
        (row["source"], row["action"], row["scope"], row.get("plane", "management"))
        for row in report["permissions"] if row["provider"] == "aws"
    }
    fallbacks = []
    for missing in report.get("unresolved_permissions", []):
        source, action = missing.get("source"), missing.get("action")
        if not isinstance(source, str) or not isinstance(action, str) or not IAM_ACTION.fullmatch(action):
            continue
        key = (source, action, "*", "management")
        if key in existing:
            continue
        existing.add(key)
        report["permissions"].append({
            "provider": "aws", "action": action, "scope": "*",
            "source": source, "plane": "management"
        })
        fallbacks.append({
            "source": source, "action": action, "scope": "*",
            "reason": missing["reason"],
            "scope_status": "BROAD_FALLBACK",
        })
    report["fallback_permissions"] = sorted(fallbacks, key=lambda row: (row["source"], row["action"]))
    if fallbacks:
        report["warnings"].append(
            f"{len(fallbacks)} unresolved IAM grants included with Resource '*' "
            "as broad generation fallbacks; verify the action/resource requirements "
            "and expected Terraform lifecycle behavior before attachment."
        )
        report["permissions"].sort(key=lambda row: (row["provider"], row["action"], row["scope"], row["source"]))
        report["scope_summary"]["global"] = sum(row["scope"] == "*" for row in report["permissions"])
        report["scope_summary"]["bounded_wildcard"] = sum(
            row["scope"] != "*" and ("*" in row["scope"] or "?" in row["scope"])
            for row in report["permissions"]
        )
        report["scope_summary"]["exact"] = sum(
            "*" not in row["scope"] and "?" not in row["scope"]
            for row in report["permissions"]
        )
        report["scope_summary"]["conditional"] = sum(bool(row.get("condition")) for row in report["permissions"])
        report["risks"] = assess(report["permissions"])
    return report
