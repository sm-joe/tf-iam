"""Generated IAM candidates must never silently drop mapped lifecycle actions."""
import json
from tfiam.cli import main
from tfiam.scan import scan


def test_source_only_ecs_stack_uses_broad_fallback_without_account(tmp_path,capsys):
    config={"resource":{
        "aws_autoscaling_group":{"ecs":{"name":"ecs-asg","max_size":2,"min_size":1}},
        "aws_iam_role":{"ecs":{"name":"ecs-task-role","assume_role_policy":"{}"}},
        "aws_ecr_repository":{"app":{"name":"ecs-app"}},
        "aws_ecs_cluster":{"main":{"name":"ecs-main"}},
        "aws_lb":{"main":{"name":"ecs-alb","load_balancer_type":"application"}},
        "aws_vpc":{"main":{"cidr_block":"10.0.0.0/16"}},
    }}
    (tmp_path/"main.tf.json").write_text(json.dumps(config))
    original=scan(tmp_path,account=None,region="ap-south-1")
    assert original["unresolved_permissions"]
    destination=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--allow-partial","--aws-region","ap-south-1","--output",str(destination)])==0
    result=json.loads(destination.read_text())
    actions={action for statement in result["Statement"] for action in statement["Action"]}
    required={
        "autoscaling:CreateAutoScalingGroup",
        "iam:CreateRole",
        "ecr:CreateRepository",
        "ecs:CreateCluster",
        "elasticloadbalancing:CreateLoadBalancer",
        "ec2:CreateVpc",
    }
    assert required <= actions
    for action in required:
        assert any(action in statement["Action"] and
                   (statement["Resource"]=="*" or "*" in statement["Resource"])
                   for statement in result["Statement"])
    report=json.loads((tmp_path/"policy.json.report.json").read_text())
    assert report["candidate_status"]=="INCOMPLETE"
    assert report["fallback_permissions"]
    assert required <= {row["action"] for row in report["fallback_permissions"]}
    assert report["scope_summary"]["global"]>=len(required)
    assert "BROAD_FALLBACK" in json.dumps(report["fallback_permissions"])
    assert "broad generation fallbacks" in "\n".join(report["warnings"])
    captured=capsys.readouterr()
    assert "POLICY SUMMARY" in captured.err


def test_fallback_excludes_non_iam_actions_and_avoids_duplicates():
    from tfiam.candidate_fallback import include_unresolved
    report={
        "permissions":[{"provider":"aws","source":"a","action":"iam:PassRole","scope":"*","plane":"management"}],
        "unresolved_permissions":[
            {"source":"a","action":"iam:PassRole","reason":"unresolved"},
            {"source":"b","action":"iam:CreateRole","reason":"unknown account"},
            {"source":"b","action":"invalid action","reason":"synthetic"},
        ],
        "warnings":[],"scope_summary":{},"risks":[],
    }
    include_unresolved(report)
    assert report["fallback_permissions"]==[{
        "source":"b","action":"iam:CreateRole","scope":"*",
        "reason":"unknown account","scope_status":"BROAD_FALLBACK"
    }]
    assert len(report["permissions"])==2


def test_strict_complete_mode_still_blocks_partial_generation(tmp_path):
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{
        "aws_ecr_repository":{"app":{"name":"demo"}},
        "aws_ecs_cluster":{"main":{"name":"demo"}},
    }}))
    out=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--allow-partial","--require-complete",
                 "--aws-region","ap-south-1","--output",str(out)])==4
    assert not out.exists()


def test_conditional_global_grant_does_not_mask_unresolved_fallback():
    from tfiam.candidate_fallback import include_unresolved
    report={
        "permissions":[{
            "provider":"aws","source":"x","action":"iam:PassRole",
            "scope":"*","plane":"management",
            "condition":{"StringEquals":{"iam:PassedToService":"ecs-tasks.amazonaws.com"}},
        }],
        "unresolved_permissions":[{
            "source":"x","action":"iam:PassRole","reason":"different role context unknown",
        }],
        "warnings":[],"scope_summary":{},"risks":[],
    }
    include_unresolved(report)
    assert len(report["permissions"])==2
    assert report["fallback_permissions"][0]["action"]=="iam:PassRole"
    assert any(p["action"]=="iam:PassRole" and "condition" not in p
               for p in report["permissions"])
