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


def test_saved_plan_counted_sns_topic_and_subscription(tmp_path):
    topic="arn:aws:sns:us-east-1:123456789012:notifications"
    plan={"format_version":"1.2","terraform_version":"1.10.0","complete":True,"resource_changes":[
        {"address":"module.sns-topic.aws_sns_topic.sns-topic[0]","mode":"managed","type":"aws_sns_topic","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":None,"after":{"name":"notifications","arn":topic}}},
        {"address":"module.sns-topic.aws_sns_topic_subscription.sns-subscription[0]","mode":"managed","type":"aws_sns_topic_subscription","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":None,"after":{"topic_arn":topic,"endpoint":"ops@example.org","protocol":"email"}}}
    ]}
    report=scan(plan=plan,account=ACCOUNT,region=REGION,provider_version="6.73.0")
    assert report["mapping_coverage"]["mapped_resources"]==2
    assert not report["unresolved_permissions"],report["unresolved_permissions"]
    check(report,"sns:CreateTopic",topic)
    check(report,"sns:Subscribe",topic,{"StringEquals":{"sns:Endpoint":"ops@example.org","sns:Protocol":"email"}})
    output=tmp_path/"sns-policy.json"
    (tmp_path/"plan.json").write_text(json.dumps(plan))
    assert main(["generate","--plan-json",str(tmp_path/"plan.json"),"--aws-account",ACCOUNT,"--aws-region",REGION,"--aws-provider-version","6.73.0","--output",str(output)])==0
    assert output.is_file()
