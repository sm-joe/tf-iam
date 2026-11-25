"""AWS IAM action resource templates, independent of Terraform resource names.

Templates are deliberately unattachable until user substitution. An AWS
resource's Terraform type is not necessarily its IAM authorization resource.
"""
import re

ACCOUNT = "<AWS_ACCOUNT_ID>"
REGION = "<AWS_REGION>"

GLOBAL_ACTIONS = {
    "kms:CreateKey", "kms:ListAliases",
    "autoscaling:DescribeAutoScalingGroups", "autoscaling:DescribeScalingActivities",
    "autoscaling:DescribeTags", "ec2:DescribeVpcs", "ec2:DescribeImages",
    "ec2:DescribeAvailabilityZones", "ec2:DescribeInternetGateways",
    "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables",
    "ec2:DescribeSecurityGroupRules", "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets", "ec2:DescribeTags", "ec2:DescribeVpcAttribute",
    "ec2:DescribeVpcEndpoints",
}

EC2_KINDS = {
    "aws_vpc": "vpc", "aws_subnet": "subnet",
    "aws_security_group": "security-group", "aws_route_table": "route-table",
    "aws_route": "route-table", "aws_route_table_association": "route-table",
    "aws_internet_gateway": "internet-gateway",
    "aws_launch_template": "launch-template", "aws_vpc_endpoint": "vpc-endpoint",
}

def template(source, action, contexts):
    context = contexts.get(source, {})
    partition = context.get("partition") or "aws"
    kind = next((part.split("[", 1)[0] for part in source.split(".") if part.startswith("aws_")), "")
    def arn(service, suffix):
        return f"arn:{partition}:{service}:{REGION}:{ACCOUNT}:{suffix}"
    def role():
        return f"arn:{partition}:iam::{ACCOUNT}:role/<REPLACE_WITH_IAM_ROLE_PATH_AND_NAME>"
    if action in GLOBAL_ACTIONS:
        return "*", None, None
    if action == "iam:PassRole":
        principal = {"aws_ecs_task_definition": "ecs-tasks.amazonaws.com",
                     "aws_iam_instance_profile": "ec2.amazonaws.com"}.get(kind)
        condition = {"StringEquals": {"iam:PassedToService": principal}} if principal else None
        return role(), "IAM role ARN", condition
    if action == "iam:CreateServiceLinkedRole":
        return (f"arn:{partition}:iam::{ACCOUNT}:role/aws-service-role/"
                "<REPLACE_WITH_SERVICE_PRINCIPAL>/<REPLACE_WITH_SERVICE_LINKED_ROLE_NAME>",
                "service-linked IAM role ARN", None)
    if action.startswith("iam:"):
        if action in {"iam:AttachRolePolicy", "iam:DetachRolePolicy",
                      "iam:ListAttachedRolePolicies", "iam:AddRoleToInstanceProfile",
                      "iam:RemoveRoleFromInstanceProfile", "iam:GetRolePolicy",
                      "iam:PutRolePolicy", "iam:DeleteRolePolicy"}:
            return role(), "IAM role ARN", None
        if "InstanceProfile" in action:
            return (f"arn:{partition}:iam::{ACCOUNT}:instance-profile/"
                    "<REPLACE_WITH_INSTANCE_PROFILE_PATH_AND_NAME>", "instance-profile ARN", None)
        return role(), "IAM role ARN", None
    if action.startswith("s3:") and kind.startswith("aws_s3_"):
        return f"arn:{partition}:s3:::<REPLACE_WITH_S3_BUCKET_NAME>", "S3 bucket name", None
    if action.startswith("ecr:") and kind.startswith("aws_ecr_"):
        return arn("ecr", "repository/<REPLACE_WITH_ECR_REPOSITORY_NAME>"), "ECR repository ARN", None
    if action.startswith("ecs:") and kind.startswith("aws_ecs_"):
        if action == "ecs:RegisterTaskDefinition":
            return "*", None, None
        if kind == "aws_ecs_cluster":
            return arn("ecs", "cluster/<REPLACE_WITH_CLUSTER_NAME>"), "ECS cluster ARN", None
        if kind == "aws_ecs_service":
            return arn("ecs", "service/<REPLACE_WITH_CLUSTER_NAME>/<REPLACE_WITH_SERVICE_NAME>"), "ECS service ARN", None
        if kind == "aws_ecs_task_definition":
            return arn("ecs", "task-definition/<REPLACE_WITH_TASK_FAMILY>:<REPLACE_WITH_REVISION>"), "ECS task-definition ARN", None
    if action.startswith("ec2:") and kind in EC2_KINDS:
        cls = EC2_KINDS[kind]
        suffix = cls + "/<REPLACE_WITH_" + cls.upper().replace("-", "_") + "_ID>"
        return arn("ec2", suffix), "EC2 " + cls + " ARN", None
    if action.startswith("elasticloadbalancing:"):
        if kind == "aws_lb":
            return arn("elasticloadbalancing", "loadbalancer/<REPLACE_WITH_LB_TYPE>/<REPLACE_WITH_LB_NAME>/<REPLACE_WITH_LB_ID>"), "load balancer ARN", None
        if kind == "aws_lb_listener":
            return arn("elasticloadbalancing", "listener/<REPLACE_WITH_LB_TYPE>/<REPLACE_WITH_LB_NAME>/<REPLACE_WITH_LB_ID>/<REPLACE_WITH_LISTENER_ID>"), "listener ARN", None
        if kind == "aws_lb_target_group":
            return arn("elasticloadbalancing", "targetgroup/<REPLACE_WITH_TARGET_GROUP_NAME>/<REPLACE_WITH_TARGET_GROUP_ID>"), "target group ARN", None
    if action.startswith("autoscaling:") and kind == "aws_autoscaling_group":
        return arn("autoscaling", "autoScalingGroup:<REPLACE_WITH_ASG_UUID>:autoScalingGroupName/<REPLACE_WITH_ASG_NAME>"), "Auto Scaling group ARN", None
    if action.startswith("logs:") and kind == "aws_cloudwatch_log_group":
        return arn("logs", "log-group:<REPLACE_WITH_LOG_GROUP_NAME>"), "CloudWatch log group ARN", None
    return "<REPLACE_WITH_RESOURCE_ARN_FOR_ACTION_" + re.sub(r"[^A-Za-z0-9]", "_", action).upper() + ">", "action-specific ARN (verify in AWS Service Authorization Reference)", None
