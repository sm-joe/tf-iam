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
    assert "candidate fallbacks" in "\n".join(report["warnings"])
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


def test_known_account_scopes_iam_passrole_and_ec2_tag_fallbacks():
    from tfiam.candidate_fallback import include_unresolved
    def resource(address):
        return {"address": address, "provider_context": {
            "account":"638631156706", "region":"us-east-1","partition":"aws"}}
    sources = [
        ("aws_ecs_task_definition.app", "iam:PassRole"),
        ("aws_iam_instance_profile.ecs", "iam:PassRole"),
        ('module.compute.aws_subnet.public[0]', "ec2:CreateTags"),
        ('aws_security_group.ecs', "ec2:DeleteTags"),
        ("aws_ecs_service.app", "iam:PassRole"),
    ]
    report={
        "resources":[resource(src) for src,_ in sources],
        "permissions":[],
        "unresolved_permissions":[{"source":src, "action":action,"reason":"unknown"}
                                  for src,action in sources],
        "warnings":[], "scope_summary":{}, "risks":[],
    }
    include_unresolved(report)
    grants={(row["source"],row["action"]):row for row in report["permissions"]}
    assert grants[("aws_ecs_task_definition.app","iam:PassRole")]["scope"] == (
        "arn:aws:iam::638631156706:role/*")
    assert grants[("aws_ecs_task_definition.app","iam:PassRole")]["condition"] == {
        "StringEquals":{"iam:PassedToService":"ecs-tasks.amazonaws.com"}}
    assert grants[("aws_iam_instance_profile.ecs","iam:PassRole")]["condition"] == {
        "StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}
    assert grants[('module.compute.aws_subnet.public[0]',"ec2:CreateTags")]["scope"] == (
        "arn:aws:ec2:us-east-1:638631156706:subnet/*")
    assert grants[("aws_security_group.ecs","ec2:DeleteTags")]["scope"] == (
        "arn:aws:ec2:us-east-1:638631156706:security-group/*")
    assert grants[("aws_ecs_service.app","iam:PassRole")]["scope"] == (
        "arn:aws:iam::638631156706:role/*")
    assert grants[("aws_ecs_service.app","iam:PassRole")]["condition"] == {
        "StringEquals":{"iam:PassedToService":"ecs.amazonaws.com"}}
    assert sum(x["scope_status"]=="SCOPED_FALLBACK"
               for x in report["fallback_permissions"]) == 5
    assert report["scope_summary"]["global"]==0
    assert report["scope_summary"]["bounded_wildcard"]==5


def test_unknown_account_preserves_nonblocking_broad_candidate_fallback():
    from tfiam.candidate_fallback import include_unresolved
    report={
        "resources":[{"address":"aws_ecs_task_definition.app",
                      "provider_context":{"account":None,"region":"us-east-1","partition":"aws"}}],
        "permissions":[],
        "unresolved_permissions":[{"source":"aws_ecs_task_definition.app",
                                   "action":"iam:PassRole","reason":"unknown"}],
        "warnings":[],"scope_summary":{},"risks":[],
    }
    include_unresolved(report)
    assert report["permissions"][0]["scope"] == "*"
    assert "condition" not in report["permissions"][0]


def test_known_account_ecs_elb_and_network_single_resource_fallbacks():
    from tfiam.candidate_fallback import include_unresolved
    cases = {
        ("aws_ecs_service.app", "ecs:CreateService"):
            "arn:aws:ecs:us-east-1:638631156706:service/*/*",
        ("aws_ecs_service.app", "ecs:TagResource"):
            "arn:aws:ecs:us-east-1:638631156706:service/*/*",
        ("aws_lb_listener.http", "elasticloadbalancing:CreateListener"):
            "arn:aws:elasticloadbalancing:us-east-1:638631156706:loadbalancer/*/*/*",
        ("aws_lb_listener.http", "elasticloadbalancing:AddTags"):
            "arn:aws:elasticloadbalancing:us-east-1:638631156706:listener/*/*/*/*",
        ("aws_lb_target_group.app", "elasticloadbalancing:DescribeTargetGroupAttributes"):
            "arn:aws:elasticloadbalancing:us-east-1:638631156706:targetgroup/*/*",
        ("aws_lb.main", "elasticloadbalancing:DescribeLoadBalancerAttributes"):
            "arn:aws:elasticloadbalancing:us-east-1:638631156706:loadbalancer/*/*/*",
        ("aws_security_group.ecs", "ec2:AuthorizeSecurityGroupIngress"):
            "arn:aws:ec2:us-east-1:638631156706:security-group/*",
        ("aws_subnet.public[0]", "ec2:ModifySubnetAttribute"):
            "arn:aws:ec2:us-east-1:638631156706:subnet/*",
        ("aws_route.public", "ec2:CreateRoute"):
            "arn:aws:ec2:us-east-1:638631156706:route-table/*",
        ("aws_vpc.main", "ec2:ModifyVpcAttribute"):
            "arn:aws:ec2:us-east-1:638631156706:vpc/*",
    }
    report = {
        "resources": [{
            "address": source,
            "provider_context": {
                "account": "638631156706", "region": "us-east-1",
                "partition": "aws",
            },
        } for source, _ in cases],
        "permissions": [],
        "unresolved_permissions": [
            {"source": source, "action": action, "reason": "computed reference"}
            for source, action in cases
        ],
        "warnings": [], "scope_summary": {}, "risks": [],
    }
    include_unresolved(report)
    actual = {(x["source"], x["action"]): x["scope"]
              for x in report["fallback_permissions"]}
    assert actual == cases
    assert all(x["scope_status"] == "SCOPED_FALLBACK"
               for x in report["fallback_permissions"])
    assert report["scope_summary"]["global"] == 0


def test_multi_resource_ec2_fallback_remains_nonblocking_when_dependencies_unknown():
    from tfiam.candidate_fallback import include_unresolved
    actions = ["ec2:CreateSubnet", "ec2:CreateRouteTable",
               "ec2:AssociateRouteTable", "ec2:AttachInternetGateway",
               "ec2:CreateVpcEndpoint"]
    report = {
        "resources": [{"address": "aws_subnet.public[0]",
                       "provider_context": {
                           "account": "638631156706", "region": "us-east-1",
                           "partition": "aws"}}],
        "permissions": [],
        "unresolved_permissions": [
            {"source": "aws_subnet.public[0]", "action": action, "reason": "unknown"}
            for action in actions],
        "warnings": [], "scope_summary": {}, "risks": [],
    }
    include_unresolved(report)
    assert {row["action"] for row in report["permissions"]} == set(actions)
    assert all(row["scope"] == "*" for row in report["permissions"])


def test_generated_fallback_warnings_do_not_claim_action_omitted():
    from tfiam.candidate_fallback import include_unresolved
    report={
        "resources":[],
        "permissions":[],
        "unresolved_permissions":[
            {"source":"aws_ecs_service.app","action":"iam:PassRole",
             "reason":"unresolved role reference"}
        ],
        "warnings":[
            "aws_ecs_service.app: iam:PassRole omitted; unresolved role reference"
        ],
        "scope_summary":{},"risks":[],
    }
    include_unresolved(report)
    assert report["permissions"][0]["action"]=="iam:PassRole"
    assert report["warnings"][0]==(
        "aws_ecs_service.app: iam:PassRole included as unverified fallback; unresolved role reference")
    assert len(report["unresolved_permissions"])==1
