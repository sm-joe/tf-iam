"""Opt-in read-only AWS policy validation using the configured Boto3 credential chain.

Access Analyzer checks policy validity; IAM simulation checks supplied action/ARN
pairs. Neither proves Terraform lifecycle completeness or effective SCP behavior.
"""
import json
import re
from . import cloud

PLACEHOLDER = re.compile(r"<(?:REPLACE_WITH_[A-Z0-9_]+|AWS_ACCOUNT_ID|AWS_REGION|[^<>]*REPLACE_WITH_[^<>]*)>")

def unresolved_resources(document):
    pending = set()
    for statement in cloud.statements(document):
        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        for resource in resources:
            if isinstance(resource, str) and ("<" in resource or ">" in resource):
                pending.add(resource)
    return sorted(pending)

def validate(document, *, region=None, profile=None, simulate=False, max_tests=200):
    cloud.policy_object(document)
    pending = unresolved_resources(document)
    if pending:
        return {"status": "requires-replacement", "aws_called": False,
                "placeholder_resources": pending, "placeholder_count": len(pending),
                "instruction": "Replace every resource ARN placeholder before AWS validation.",
                "limitation": "AWS cannot validate or simulate an unresolved IAM policy template."}
    analyzer = cloud.client("accessanalyzer", profile, region)
    result = {"status": "validated", "aws_called": True,
              "access_analyzer": cloud.validate_policy(analyzer, document)}
    if result["access_analyzer"]["status"] == "issues":
        result["status"] = "issues"
    if simulate:
        tests = []
        for statement in cloud.statements(document):
            if statement.get("Effect") != "Allow" or statement.get("NotAction") or statement.get("NotResource"):
                continue
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            if isinstance(actions, str): actions = [actions]
            if isinstance(resources, str): resources = [resources]
            if not isinstance(actions, list) or not isinstance(resources, list):
                continue
            for action in actions:
                if not isinstance(action, str) or "*" in action or "?" in action:
                    continue
                for resource in resources:
                    if isinstance(resource, str):
                        tests.append((action, resource, bool(statement.get("Condition"))))
        tests = sorted(set(tests))
        if len(tests) > max_tests:
            result["simulation"] = {"status": "not-run", "reason": "test-limit-exceeded",
                                    "requested_tests": len(tests), "limit": max_tests}
            result["status"] = "review"
            return result
        iam = cloud.client("iam", profile, region)
        policy_text = json.dumps(document, separators=(",", ":"))
        outputs = []
        # IAM simulator is not a proof for condition-dependent grants without
        # accurate request context. Report them, never silently call them allowed.
        for action, resource, conditioned in tests:
            if conditioned:
                outputs.append({"action": action, "resource": resource,
                                "decision": "not-evaluated", "reason": "request-context-required"})
                continue
            response = iam.simulate_custom_policy(
                PolicyInputList=[policy_text], ActionNames=[action], ResourceArns=[resource])
            records = response.get("EvaluationResults", [])
            while response.get("IsTruncated"):
                response = iam.simulate_custom_policy(
                    PolicyInputList=[policy_text], ActionNames=[action], ResourceArns=[resource],
                    Marker=response["Marker"])
                records.extend(response.get("EvaluationResults", []))
            decisions = {row.get("EvalDecision", "unknown") for row in records}
            decision = "allowed" if decisions == {"allowed"} else (
                "explicitDeny" if "explicitDeny" in decisions else "implicitDeny"
                if "implicitDeny" in decisions else "unknown")
            outputs.append({"action": action, "resource": resource, "decision": decision})
        failures = [row for row in outputs if row["decision"] != "allowed"]
        result["simulation"] = {"status": "review" if failures else "passed",
                                "tested": len(outputs), "allowed": len(outputs)-len(failures),
                                "unverified": len(failures), "results": outputs,
                                "limitation": "Candidate-policy simulation only; no principal SCP, boundary, resource policies, or Terraform lifecycle proof."}
        if failures and result["status"] != "issues":
            result["status"] = "review"
    return result
