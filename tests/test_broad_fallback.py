"""Generated IAM candidates must never silently drop mapped lifecycle actions."""
import json
from tfiam.cli import main
from tfiam.scan import scan


def test_source_only_ecs_stack_uses_explicit_placeholders_without_account(tmp_path,capsys):
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
                   ("REPLACE_WITH" in statement["Resource"])
                   for statement in result["Statement"])
    report=json.loads((tmp_path/"policy.json.report.json").read_text())
    assert report["candidate_status"]=="INCOMPLETE"
    assert report["fallback_permissions"]
    assert required <= {row["action"] for row in report["fallback_permissions"]}
    assert all(row["scope"] != "*" for row in report["fallback_permissions"] if row["action"] in required)
    assert "REQUIRES_REPLACEMENT" in json.dumps(report["fallback_permissions"])
    assert "REPLACE_WITH" in "\n".join(report["warnings"])
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
        "source":"b","action":"iam:CreateRole","scope":"arn:aws:iam::<AWS_ACCOUNT_ID>:role/<REPLACE_WITH_IAM_ROLE_PATH_AND_NAME>",
        "reason":"unknown account","scope_status":"REQUIRES_REPLACEMENT",
        "replacement_instruction":"Replace placeholder with actual IAM role ARN before use"
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
        "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<REPLACE_WITH_IAM_ROLE_PATH_AND_NAME>")
    assert grants[('module.compute.aws_subnet.public[0]',"ec2:CreateTags")]["scope"] == (
        "arn:aws:ec2:<AWS_REGION>:<AWS_ACCOUNT_ID>:subnet/<REPLACE_WITH_SUBNET_ID>")
    assert grants[("aws_security_group.ecs","ec2:DeleteTags")]["scope"] == (
        "arn:aws:ec2:<AWS_REGION>:<AWS_ACCOUNT_ID>:security-group/<REPLACE_WITH_SECURITY_GROUP_ID>")
    assert grants[("aws_ecs_service.app","iam:PassRole")]["scope"] == (
        "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<REPLACE_WITH_IAM_ROLE_PATH_AND_NAME>")
    assert sum(x["scope_status"]=="REQUIRES_REPLACEMENT"
               for x in report["fallback_permissions"]) == 5
    assert report["scope_summary"]["global"]==0
    assert report["scope_summary"]["bounded_wildcard"]==0


def test_role_policy_placeholder_never_contains_specific_account():
    from tfiam.candidate_fallback import include_unresolved
    report = {"resources": [{"address": "aws_iam_role_policy.gateway",
              "provider_context": {"account": "638631156706", "region": "ap-south-1", "partition": "aws"}}],
              "permissions": [], "unresolved_permissions": [
              {"source": "aws_iam_role_policy.gateway", "action": "iam:PutRolePolicy", "reason": "unknown role"}],
              "warnings": [], "scope_summary": {}, "risks": []}
    include_unresolved(report)
    assert report["permissions"][0]["scope"] == "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<REPLACE_WITH_IAM_ROLE_PATH_AND_NAME>"
    assert "638631156706" not in report["permissions"][0]["scope"]


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
    assert report["permissions"][0]["scope"] == "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<REPLACE_WITH_IAM_ROLE_PATH_AND_NAME>"
    assert report["permissions"][0]["condition"] == {"StringEquals":{"iam:PassedToService":"ecs-tasks.amazonaws.com"}}


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
    assert set(actual)==set(cases)
    assert all("REPLACE_WITH_" in scope for scope in actual.values())
    assert all(x["scope_status"]=="REQUIRES_REPLACEMENT" for x in report["fallback_permissions"])
    assert report["scope_summary"]["global"]==0

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
    assert all("REPLACE_WITH_" in row["scope"] for row in report["permissions"])


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

def test_action_specific_iam_resource_types():
    from tfiam.fallback_resource import template
    cases = [
        ("aws_ecs_task_definition.app", "iam:PassRole", ":role/"),
        ("aws_ecs_service.app", "iam:CreateServiceLinkedRole", ":role/aws-service-role/"),
        ("aws_iam_role_policy_attachment.app", "iam:AttachRolePolicy", ":role/"),
        ("aws_iam_instance_profile.ecs", "iam:CreateInstanceProfile", ":instance-profile/"),
        ("aws_ecr_lifecycle_policy.app", "ecr:PutLifecyclePolicy", ":repository/"),
        ("aws_route.public", "ec2:CreateRoute", ":route-table/"),
        ("aws_route_table_association.public", "ec2:AssociateRouteTable", ":route-table/"),
        ("aws_lb_listener.http", "elasticloadbalancing:CreateListener", ":loadbalancer/"),
        ("aws_ecs_task_definition.app", "ecs:RegisterTaskDefinition", ":task-definition/"),
    ]
    for source, action, marker in cases:
        scope, replacement, condition = template(source, action, {})
        assert marker in scope, (source, action, scope)
        assert replacement and "<AWS_ACCOUNT_ID>" in scope

def test_describe_autoscaling_tags_is_global():
    from tfiam.fallback_resource import template
    assert template("aws_autoscaling_group.main", "autoscaling:DescribeTags", {}) == ("*", None, None)
