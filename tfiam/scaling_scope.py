"""Conservative scoped IAM candidates for EC2 launch templates and Auto Scaling groups.

AWS assigns launch-template IDs; never fabricate them from names. An ASG name
can be scoped by its AWS-documented wildcard UUID ARN. Describe operations
lack resource-level IAM support. Potential cross-resource permissions remain
explicitly unresolved instead of being silently granted.
"""
import re

ASG_NAME=re.compile(r"[A-Za-z0-9_-]{1,255}")
LT_ID=re.compile(r"lt-[0-9a-f]{8,32}")

ASG_DESCRIBE={
    "autoscaling:DescribeAutoScalingGroups",
    "autoscaling:DescribeScalingActivities",
    "autoscaling:DescribeTags",
}
LT_DESCRIBE={
    "ec2:DescribeLaunchTemplates",
    "ec2:DescribeLaunchTemplateVersions",
}

def scoped(typ,body,actions,account,region,partition,resolve,emit,omit,task=None):
    def value(field):
        return resolve(body.get(field))
    if not account or not region:
        for action in actions: omit(action)
        return
    if typ=="aws_autoscaling_group":
        name=value("name")
        if not name or not ASG_NAME.fullmatch(name):
            for action in actions: omit(action)
            return
        arn=f"arn:{partition}:autoscaling:{region}:{account}:autoScalingGroup:*:autoScalingGroupName/{name}"
        for action in actions:
            if action in ASG_DESCRIBE: emit(action,"*")
            elif action.startswith("autoscaling:"): emit(action,arn)
            else: omit(action)
        # Auto Scaling launch authorization can also require ec2:RunInstances,
        # instance-profile PassRole, KMS and a custom service-linked role. Such
        # unrelated grants are not inferred from an Auto Scaling group name.
        return
    if typ=="aws_launch_template":
        prefix=f"arn:{partition}:ec2:{region}:{account}:launch-template/"
        current=value("id")
        # The AWS-assigned launch template ID is trusted only from an
        # already-evaluated saved plan and is not derived from its name.
        target=prefix+current if task and isinstance(current,str) and LT_ID.fullmatch(current) else None
        tags=body.get("tags")
        tags=tags if isinstance(tags,dict) else {}
        # aws:RequestTag applies to CreateLaunchTemplate, and resource tags
        # apply to later mutations only when Terraform sets them on the LT.
        scope_tag=tags.get("tfiam:scope")
        valid_tag=isinstance(scope_tag,str) and bool(scope_tag) and re.fullmatch(r"[A-Za-z0-9_.:/+=@-]{1,128}",scope_tag)
        for action in actions:
            if action in LT_DESCRIBE:
                emit(action,"*")
            elif action=="ec2:CreateLaunchTemplate":
                if valid_tag:
                    emit(action,prefix+"*",{"StringEquals":{"aws:RequestTag/tfiam:scope":scope_tag}})
                elif target:
                    emit(action,target)
                else:
                    omit(action)
            elif action=="ec2:CreateTags":
                if task and task.get("operation")=="create" and tags:
                    emit(action,target or prefix+"*",{"StringEquals":{"ec2:CreateAction":"CreateLaunchTemplate"}})
                elif target:
                    emit(action,target)
                elif valid_tag:
                    emit(action,prefix+"*",{"StringEquals":{"ec2:ResourceTag/tfiam:scope":scope_tag}})
                else:
                    omit(action)
            elif target:
                emit(action,target)
            elif valid_tag and action.startswith("ec2:"):
                emit(action,prefix+"*",{"StringEquals":{"ec2:ResourceTag/tfiam:scope":scope_tag}})
            else:
                omit(action)
        return
    raise ValueError("Unexpected service scope type")
