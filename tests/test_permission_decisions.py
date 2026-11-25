"""Regression tests for authoritative optional IAM permission decisions."""
import json

from tfiam.candidate_fallback import include_unresolved
from tfiam.cli import main
from tfiam.scan import scan


ACCOUNT = "638631156706"
REGION = "us-east-1"
SOURCE = "aws_ecs_service.app"


def _source(tmp_path, role_marker=None):
    service = {"name": "app", "cluster": "demo"}
    if role_marker is not None:
        service["iam_role"] = role_marker
    (tmp_path / "main.tf.json").write_text(json.dumps({
        "resource": {"aws_ecs_service": {"app": service}}
    }))
    return service


def _fallback(report):
    # Replay a stale unresolved diagnostic, as can occur when another resolver
    # still reports an optional action. The final generator must not resurrect it.
    report["unresolved_permissions"].append({
        "source": SOURCE, "action": "iam:PassRole",
        "reason": "stale optional role dependency",
    })
    return include_unresolved(report)


def test_absent_legacy_ecs_role_is_not_required_and_cannot_reappear(tmp_path):
    _source(tmp_path)
    report = scan(tmp_path, account=ACCOUNT, region=REGION)
    assert any(x["source"] == SOURCE and x["action"] == "iam:PassRole"
               for x in report["not_required_permissions"])
    assert not any(x["source"] == SOURCE and x["action"] == "iam:PassRole"
                   for x in report["unresolved_permissions"])
    _fallback(report)
    assert not any(x["source"] == SOURCE and x["action"] == "iam:PassRole"
                   for x in report["fallback_permissions"])
    assert not any(x["source"] == SOURCE and x["action"] == "iam:PassRole"
                   for x in report["permissions"])
    policy = tmp_path / "policy.json"
    assert main(["generate", str(tmp_path), "--aws-account", ACCOUNT,
                 "--aws-region", REGION, "--output", str(policy)]) == 0
    artifact = json.loads(policy.read_text())
    assert all("iam:PassRole" not in statement["Action"]
               for statement in artifact["Statement"])


def test_explicit_legacy_ecs_role_is_scoped_to_exact_role(tmp_path):
    role = f"arn:aws:iam::{ACCOUNT}:role/my-legacy-ecs-role"
    _source(tmp_path, role)
    report = scan(tmp_path, account=ACCOUNT, region=REGION)
    assert not any(x["source"] == SOURCE and x["action"] == "iam:PassRole"
                   for x in report["not_required_permissions"])
    permissions = [x for x in report["permissions"]
                   if x["source"] == SOURCE and x["action"] == "iam:PassRole"]
    assert permissions
    assert all(x["scope"] == role for x in permissions)
    assert all(x["condition"] == {
        "StringEquals": {"iam:PassedToService": "ecs.amazonaws.com"}
    } for x in permissions)


def test_unknown_legacy_ecs_role_is_not_silently_classified_as_absent():
    from tests.test_ecs_43_resource_acceptance import fixture
    data = fixture()
    for row in data["resource_changes"]:
        if row["address"] == SOURCE:
            row["change"]["after"]["iam_role"] = None
            row["change"]["after_unknown"]["iam_role"] = True
            break
    report = scan(plan=data, account=ACCOUNT, region=REGION)
    assert not any(x["source"] == SOURCE and x["action"] == "iam:PassRole"
                   for x in report["not_required_permissions"])


def test_fallback_rejects_not_required_but_preserves_other_unresolved():
    report = {
        "not_required_permissions": [{
            "source": SOURCE, "action": "iam:PassRole",
            "reason": "legacy role omitted",
        }],
        "resources": [],
        "permissions": [],
        "unresolved_permissions": [
            {"source": SOURCE, "action": "iam:PassRole", "reason": "stale"},
            {"source": "aws_ecs_task_definition.app", "action": "iam:PassRole",
             "reason": "task role unresolved"},
        ],
        "warnings": [], "scope_summary": {}, "risks": [],
    }
    include_unresolved(report)
    assert [(x["source"], x["action"]) for x in report["fallback_permissions"]] == [
        ("aws_ecs_task_definition.app", "iam:PassRole"),
    ]
