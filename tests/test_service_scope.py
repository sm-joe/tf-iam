import json
from tfiam.scan import scan
from tfiam.cli import main

ACCOUNT="123456789012"
REGION="us-east-1"
def write(root,resources):
    (root/"main.tf.json").write_text(json.dumps({"resource":resources}))
def check(report,action,scope,condition=None):
    assert any(p["action"]==action and p["scope"]==scope and (condition is None or p.get("condition")==condition) for p in report["permissions"]), (action,scope)
def test_expansion_across_services(tmp_path):
    role="arn:aws:iam::123456789012:role/team/runtime"
    topic="arn:aws:sns:us-east-1:123456789012:alerts"
    write(tmp_path,{
      "aws_iam_user":{"u":{"name":"dev","path":"/team/"}},
      "aws_iam_access_key":{"k":{"user":"\u0024{aws_iam_user.u.name}"}},
      "aws_iam_user_group_membership":{"g":{"user":"\u0024{aws_iam_user.u.name}","groups":["developers"]}},
      "aws_iam_instance_profile":{"p":{"name":"profile","role":"runtime"}},
      "aws_key_pair":{"k":{"key_name":"ci-key","public_key":"placeholder"}},
      "aws_s3_bucket_accelerate_configuration":{"a":{"bucket":"fixture-bucket","status":"Enabled"}},
      "aws_s3_bucket_request_payment_configuration":{"p":{"bucket":"fixture-bucket","payer":"BucketOwner"}},
      "aws_db_option_group":{"o":{"name":"fixture-options","engine_name":"mysql","major_engine_version":"8.0"}},
      "aws_sqs_queue":{"q":{"name":"events"}},
      "aws_sqs_queue_policy":{"p":{"queue_url":"\u0024{aws_sqs_queue.q.id}","policy":"{}"}},
      "aws_sqs_queue_redrive_policy":{"r":{"queue_url":"\u0024{aws_sqs_queue.q.url}","redrive_policy":"{}"}},
      "aws_sqs_queue_redrive_allow_policy":{"r":{"queue_url":"\u0024{aws_sqs_queue.q.id}","redrive_allow_policy":"{}"}},
      "aws_sns_topic":{"t":{"name":"alerts"}},
      "aws_sns_topic_policy":{"p":{"arn":"\u0024{aws_sns_topic.t.arn}","policy":"{}"}},
      "aws_sns_topic_subscription":{"s":{"topic_arn":"\u0024{aws_sns_topic.t.arn}","protocol":"sqs","endpoint":"arn:aws:sqs:us-east-1:123456789012:events"}},
      "aws_lambda_alias":{"a":{"function_name":"worker","name":"live","function_version":"1"}},
      "aws_ecs_task_definition":{"t":{"family":"worker","execution_role_arn":role}},
      "aws_eks_fargate_profile":{"p":{"cluster_name":"demo","fargate_profile_name":"apps","pod_execution_role_arn":role}},
    })
    r=scan(tmp_path,account=ACCOUNT,region=REGION)
    assert r["mapping_coverage"]["unmapped_resources"]==0
    assert not r["unresolved_permissions"],r["unresolved_permissions"]
    check(r,"iam:CreateAccessKey","arn:aws:iam::123456789012:user/team/dev")
    check(r,"iam:AddUserToGroup","arn:aws:iam::123456789012:group/developers")
    check(r,"iam:AddRoleToInstanceProfile","arn:aws:iam::123456789012:instance-profile/profile")
    check(r,"ec2:ImportKeyPair","arn:aws:ec2:us-east-1:123456789012:key-pair/ci-key")
    check(r,"s3:PutAccelerateConfiguration","arn:aws:s3:::fixture-bucket")
    check(r,"rds:CreateOptionGroup","arn:aws:rds:us-east-1:123456789012:og:fixture-options")
    check(r,"sqs:SetQueueAttributes","arn:aws:sqs:us-east-1:123456789012:events")
    check(r,"sns:Subscribe",topic,{"StringEquals":{"sns:Endpoint":"arn:aws:sqs:us-east-1:123456789012:events","sns:Protocol":"sqs"}})
    check(r,"lambda:CreateAlias","arn:aws:lambda:us-east-1:123456789012:function:worker")
    check(r,"ecs:RegisterTaskDefinition","arn:aws:ecs:us-east-1:123456789012:task-definition/worker:*")
    check(r,"ecs:DescribeTaskDefinition","*",{"StringEquals":{"aws:RequestedRegion":REGION}})
    check(r,"ecs:DeregisterTaskDefinition","*",{"StringEquals":{"aws:RequestedRegion":REGION}})
    check(r,"eks:CreateFargateProfile","arn:aws:eks:us-east-1:123456789012:cluster/demo")
    check(r,"iam:PassRole",role,{"StringEquals":{"iam:PassedToService":"eks.amazonaws.com"}})
    assert main(["generate",str(tmp_path),"--aws-account",ACCOUNT,"--aws-region",REGION,"--output",str(tmp_path/"policy.json")])==0
def test_saved_plan_operation_and_unknown_role(tmp_path):
    doc={"format_version":"1.2","terraform_version":"1.10.0","resource_changes":[
        {"address":"aws_dynamodb_table.t","mode":"managed","type":"aws_dynamodb_table","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":None,"after":{"name":"fixture"}}},
        {"address":"aws_eks_fargate_profile.p","mode":"managed","type":"aws_eks_fargate_profile","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":None,"after":{"cluster_name":"demo","fargate_profile_name":"apps"},"after_unknown":{"pod_execution_role_arn":True}}}
    ]}
    r=scan(plan=doc,account=ACCOUNT,region=REGION)
    actions={p["action"] for p in r["permissions"]}
    assert "dynamodb:CreateTable" in actions
    assert not {"dynamodb:DeleteTable","dynamodb:UpdateTimeToLive","dynamodb:UpdateContinuousBackups","eks:DeleteFargateProfile"} & actions
    assert any(p["action"]=="iam:PassRole" for p in r["unresolved_permissions"])


def test_asg_named_scope_and_describe_global(tmp_path):
    write(tmp_path,{"aws_autoscaling_group":{"main":{"name":"worker-asg","max_size":2,"min_size":0}}})
    report=scan(tmp_path,account=ACCOUNT,region=REGION)
    arn="arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:*:autoScalingGroupName/worker-asg"
    check(report,"autoscaling:CreateAutoScalingGroup",arn)
    check(report,"autoscaling:UpdateAutoScalingGroup",arn)
    check(report,"autoscaling:DescribeAutoScalingGroups","*")
    assert not report["unresolved_permissions"]


def test_asg_unknown_name_fail_closed(tmp_path):
    write(tmp_path,{"aws_autoscaling_group":{"main":{"name":"${var.missing}","max_size":1,"min_size":0}}})
    report=scan(tmp_path,account=ACCOUNT,region=REGION)
    assert any(x["action"]=="autoscaling:CreateAutoScalingGroup" for x in report["unresolved_permissions"])
    assert not any(x["action"]=="autoscaling:CreateAutoScalingGroup" for x in report["permissions"])


def test_launch_template_creation_request_tag_and_scope(tmp_path):
    write(tmp_path,{"aws_launch_template":{"main":{"name":"worker","tags":{"tfiam:scope":"worker-owned"}}}})
    report=scan(tmp_path,account=ACCOUNT,region=REGION)
    target="arn:aws:ec2:us-east-1:123456789012:launch-template/*"
    check(report,"ec2:CreateLaunchTemplate",target,{"StringEquals":{"aws:RequestTag/tfiam:scope":"worker-owned"}})
    check(report,"ec2:DeleteLaunchTemplate",target,{"StringEquals":{"ec2:ResourceTag/tfiam:scope":"worker-owned"}})
    check(report,"ec2:DescribeLaunchTemplates","*")


def test_launch_template_no_tag_or_id_fails_closed(tmp_path):
    write(tmp_path,{"aws_launch_template":{"main":{"name":"worker"}}})
    report=scan(tmp_path,account=ACCOUNT,region=REGION)
    assert any(x["action"]=="ec2:CreateLaunchTemplate" for x in report["unresolved_permissions"])
    assert not any(x["action"]=="ec2:DeleteLaunchTemplate" for x in report["permissions"])


def test_scaling_account_and_region_required(tmp_path):
    write(tmp_path,{"aws_autoscaling_group":{"a":{"name":"worker"}},"aws_launch_template":{"b":{"tags":{"tfiam:scope":"owned"}}}})
    report=scan(tmp_path)
    assert not any(p["action"]=="autoscaling:CreateAutoScalingGroup" for p in report["permissions"])
    assert not any(p["action"]=="ec2:CreateLaunchTemplate" for p in report["permissions"])


def test_asg_launch_template_requires_separate_run_instances_scope(tmp_path):
    write(tmp_path,{"aws_autoscaling_group":{"main":{"name":"workers","launch_template":[{"id":"lt-1234567890abcdef0","version":"1"}]}}})
    report=scan(tmp_path,account=ACCOUNT,region=REGION)
    assert any(x["action"]=="ec2:RunInstances" for x in report["unresolved_permissions"])
    assert not any(p["action"]=="ec2:RunInstances" for p in report["permissions"])


def test_launch_template_creation_tags_are_create_only(tmp_path):
    write(tmp_path,{"aws_launch_template":{"main":{"name":"worker","tags":{"tfiam:scope":"team-worker"}}}})
    report=scan(tmp_path,account=ACCOUNT,region=REGION)
    target="arn:aws:ec2:us-east-1:123456789012:launch-template/*"
    check(report,"ec2:CreateTags",target,{"StringEquals":{"ec2:CreateAction":"CreateLaunchTemplate"}})
