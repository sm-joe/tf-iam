"""Candidate-only broad fallback for actions with unresolved resource scope.

Static scan reports retain the unresolved diagnostics. Generation keeps mapped
lifecycle action names instead of silently outputting only Describe permissions.
"""
import re
from .risk import assess

IAM_ACTION = re.compile(r"^[a-z][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$")


EC2_TAG_CLASSES = {
    "aws_vpc": "vpc", "aws_subnet": "subnet",
    "aws_security_group": "security-group", "aws_route_table": "route-table",
    "aws_internet_gateway": "internet-gateway",
    "aws_vpc_endpoint": "vpc-endpoint",
    "aws_launch_template": "launch-template",
    "aws_nat_gateway": "natgateway", "aws_network_acl": "network-acl",
    "aws_eip": "elastic-ip", "aws_vpn_gateway": "vpn-gateway",
    "aws_vpc_peering_connection": "vpc-peering-connection",
    "aws_ec2_transit_gateway": "transit-gateway",
}


def _typed_source(source):
    for part in source.split("."):
        if part.startswith("aws_"):
            return part.split("[", 1)[0]
    return None


def _fallback_scope(source, action, contexts):
    context = contexts.get(source, {})
    account, region, partition = (
        context.get("account"), context.get("region"), context.get("partition")
    )
    if not (isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account)
            and isinstance(partition, str) and partition in ("aws", "aws-us-gov", "aws-cn")):
        return "*", None
    kind = _typed_source(source)
    if action == "iam:PassRole":
        service = {
            "aws_ecs_task_definition": "ecs-tasks.amazonaws.com",
            "aws_iam_instance_profile": "ec2.amazonaws.com",
        }.get(kind)
        if service:
            return (f"arn:{partition}:iam::{account}:role/*",
                    {"StringEquals": {"iam:PassedToService": service}})
    # Only single-resource authorization paths confirmed in AWS's
    # Service Authorization Reference. Multi-resource EC2 operations
    # (e.g. CreateSubnet, CreateRouteTable, AssociateRouteTable) retain
    # the original non-blocking '*' fallback until all dependencies can
    # be authorized together.
    valid_region = isinstance(region, str) and re.fullmatch(
        r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", region)
    if valid_region:
        ec2_single = {
            ("aws_vpc", "ec2:ModifyVpcAttribute"): "vpc",
            ("aws_subnet", "ec2:ModifySubnetAttribute"): "subnet",
            ("aws_security_group", "ec2:AuthorizeSecurityGroupIngress"): "security-group",
            ("aws_security_group", "ec2:AuthorizeSecurityGroupEgress"): "security-group",
            ("aws_security_group", "ec2:RevokeSecurityGroupIngress"): "security-group",
            ("aws_security_group", "ec2:RevokeSecurityGroupEgress"): "security-group",
            ("aws_route", "ec2:CreateRoute"): "route-table",
            ("aws_route_table", "ec2:CreateRoute"): "route-table",
        }
        resource_class = ec2_single.get((kind, action))
        if resource_class:
            return f"arn:{partition}:ec2:{region}:{account}:{resource_class}/*", None
        if kind == "aws_ecs_service" and action in (
            "ecs:CreateService", "ecs:DescribeServices",
            "ecs:ListTagsForResource", "ecs:TagResource"
        ):
            return f"arn:{partition}:ecs:{region}:{account}:service/*/*", None
        elbv2_resources = {
            ("aws_lb_listener", "elasticloadbalancing:CreateListener"): "loadbalancer/*/*/*",
            ("aws_lb_listener", "elasticloadbalancing:AddTags"): "listener/*/*/*/*",
            ("aws_lb_listener", "elasticloadbalancing:DescribeListenerAttributes"): "listener/*/*/*/*",
            ("aws_lb_target_group", "elasticloadbalancing:DescribeTargetGroupAttributes"): "targetgroup/*/*",
            ("aws_lb", "elasticloadbalancing:DescribeLoadBalancerAttributes"): "loadbalancer/*/*/*",
        }
        suffix = elbv2_resources.get((kind, action))
        if suffix:
            return f"arn:{partition}:elasticloadbalancing:{region}:{account}:{suffix}", None
    if action in ("ec2:CreateTags", "ec2:DeleteTags"):
        resource_class = EC2_TAG_CLASSES.get(kind)
        if resource_class and isinstance(region, str) and re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", region):
            return f"arn:{partition}:ec2:{region}:{account}:{resource_class}/*", None
    return "*", None


def include_unresolved(report):
    existing = {
        (row["source"], row["action"], row["scope"], row.get("plane", "management"))
        for row in report["permissions"] if row["provider"] == "aws" and not row.get("condition")
    }
    contexts = {
        row["address"]: row.get("provider_context", {})
        for row in report.get("resources", [])
        if isinstance(row, dict) and isinstance(row.get("address"), str)
    }
    fallbacks = []
    for missing in report.get("unresolved_permissions", []):
        source, action = missing.get("source"), missing.get("action")
        if not isinstance(source, str) or not isinstance(action, str) or not IAM_ACTION.fullmatch(action):
            continue
        scope, condition = _fallback_scope(source, action, contexts)
        key = (source, action, scope, "management")
        if key in existing and condition is None:
            continue
        existing.add(key)
        permission = {
            "provider": "aws", "action": action, "scope": scope,
            "source": source, "plane": "management"
        }
        if condition:
            permission["condition"] = condition
        report["permissions"].append(permission)
        fallbacks.append({
            "source": source, "action": action, "scope": scope,
            "reason": missing["reason"],
            "scope_status": "BROAD_FALLBACK" if scope == "*" else "SCOPED_FALLBACK",
            **({"condition": condition} if condition else {}),
        })
    report["fallback_permissions"] = sorted(fallbacks, key=lambda row: (row["source"], row["action"]))
    if fallbacks:
        report["warnings"].append(
            f"{len(fallbacks)} unresolved IAM grants included as candidate fallbacks "
            f"({sum(x['scope'] == '*' for x in fallbacks)} with Resource '*'); "
            "verify the action/resource requirements and expected Terraform "
            "lifecycle behavior before attachment."
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
