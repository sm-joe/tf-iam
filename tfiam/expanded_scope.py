"""Conservative scope strategies for expanded catalog candidates.

A known ARN is not proof that all actions accept that resource type. Multi-resource
authorization remains a review item until M05; privileged unresolved actions are omitted.
"""
import re

ROLE=re.compile(r"arn:[a-z0-9-]+:iam::[0-9]{12}:role/[^\s*?]+")
KEY=re.compile(r"arn:[a-z0-9-]+:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+")
GLOBAL={
    "kms:CreateKey","kms:ListAliases","ecs:RegisterTaskDefinition",
    "logs:DescribeLogGroups","route53:CreateHostedZone","route53:ListHostedZones",
    "route53:ListHostedZonesByName","route53:ListHostedZonesByVPC",
    "ec2:DescribeAvailabilityZones","ec2:DescribeVpcs","ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups","ec2:DescribeSecurityGroupRules",
    "ec2:DescribeRouteTables","ec2:DescribeInternetGateways","ec2:DescribeNatGateways",
    "ec2:DescribeVpcEndpoints","ec2:DescribeNetworkAcls","ec2:DescribeAddresses",
    "ec2:DescribeLaunchTemplates","ec2:DescribeLaunchTemplateVersions",
    "ec2:DescribeVolumes","ec2:DescribeInstances","ec2:DescribeNetworkInterfaces",
    "ec2:DescribeVpcPeeringConnections","cloudwatch:GetDashboard",
    "cloudwatch:PutDashboard","cloudwatch:DeleteDashboards",
}
def expand(strategy, typ, body, actions, account, region, partition, resolve, add, warn, source, task=None, unresolved=None):
    def value(field):
        return resolve(body.get(field))
    def emit(action, resource, condition=None):
        add("aws",[action],resource,source,condition=condition)
    def omit(action):
        if unresolved: unresolved(action)
        else: warn(source+": "+action+" omitted; action-specific scope or dependency unresolved")
    def arn(service, suffix):
        if account and region and suffix: return f"arn:{partition}:{service}:{region}:{account}:{suffix}"
    def name_arn(service, prefix, field):
        name=value(field)
        return arn(service,prefix+name) if name and re.fullmatch(r"[A-Za-z0-9_./+=,@-]+",name) else None
    def iam_arn(kind, field):
        name=value(field)
        path=resolve(body.get("path","/"))
        if account and name and re.fullmatch(r"[\w+=,.@-]+",name) and path and path.startswith("/") and path.endswith("/"):
            return f"arn:{partition}:iam::{account}:{kind}{path}{name}"
    def role_from_field(field, service):
        role=value(field)
        if role and ROLE.fullmatch(role):
            emit("iam:PassRole",role,{"StringEquals":{"iam:PassedToService":service}})
        else: omit("iam:PassRole")
    known=value("arn") if task else None
    target=None
    expected=None
    if strategy in ("role","profile","user","group","policy"):
        kind="instance-profile" if strategy=="profile" else strategy
        expected=rf"arn:{partition}:iam::[0-9]{{12}}:{kind}/[^\s*?]+"
        if typ in ("aws_iam_role_policy","aws_iam_user_policy","aws_iam_group_policy"):
            # Inline policies authorize against the attached identity, not the policy name.
            # A bare role/user/group name does not establish its IAM path.
            target=value("_tfiam_identity_arn") if not task else None
            if not target or not re.fullmatch(expected,target): target=None
        else: target=iam_arn(kind,"name")
    elif strategy=="oidc":
        expected=rf"arn:{partition}:iam::[0-9]{{12}}:oidc-provider/[^\s*?]+"
        url=value("url")
        if account and url and url.startswith("https://") and re.fullmatch(r"https://[A-Za-z0-9./_-]+",url):
            target=f"arn:{partition}:iam::{account}:oidc-provider/{url[8:]}"
    elif strategy=="bucket":
        bucket=value("bucket")
        if bucket and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",bucket):
            target=f"arn:{partition}:s3:::{bucket}"
    elif strategy=="kms-key":
        expected=KEY.pattern
        for field in ("key_id","key_arn"):
            key=value(field)
            if key and KEY.fullmatch(key): target=key; break
            if task and key and re.fullmatch(r"(?:mrk-[a-f0-9]{32}|[a-f0-9-]{36})",key):
                target=arn("kms","key/"+key); break
    elif strategy=="kms-alias":
        expected=rf"arn:{partition}:kms:[a-z0-9-]+:[0-9]{{12}}:alias/[A-Za-z0-9/_-]+"
        alias=value("name")
        if alias and alias.startswith("alias/"): target=name_arn("kms","","name")
    elif strategy=="eks-access":
        expected=rf"arn:{partition}:eks:[a-z0-9-]+:[0-9]{{12}}:access-entry/[^\s*?]+"
        # AWS assigns an opaque UUID. Scope to exact ARN when supplied by Terraform.
        known=value("access_entry_arn") or known
        cluster=value("cluster_name")
        principal=value("principal_arn")
        if cluster and principal and re.fullmatch(r"[\w-]+",cluster):
            match=re.fullmatch(r"arn:[a-z0-9-]+:iam::([0-9]{12}):(role|user)/([A-Za-z0-9+=,.@_/-]+)",principal)
            if match:
                identity=match.group(3).rsplit("/",1)[-1]
                target=arn("eks","access-entry/"+cluster+"/"+match.group(2)+"/"+match.group(1)+"/"+identity+"/*")
    elif strategy=="ecr":
        expected=rf"arn:{partition}:ecr:[a-z0-9-]+:[0-9]{{12}}:repository/[^\s*?]+"
        target=name_arn("ecr","repository/","name" if typ=="aws_ecr_repository" else "repository")
    elif strategy=="lambda":
        expected=rf"arn:{partition}:lambda:[a-z0-9-]+:[0-9]{{12}}:function:[^\s*?]+"
        target=name_arn("lambda","function:","function_name")
        candidate=value("function_name")
        if candidate and re.fullmatch(expected,candidate): target=candidate
        if typ=="aws_lambda_permission" and value("qualifier") and target:
            target+=":"+value("qualifier")
    elif strategy=="ecs-cluster":
        expected=rf"arn:{partition}:ecs:[a-z0-9-]+:[0-9]{{12}}:cluster/[^\s*?]+"
        field="cluster_name" if typ=="aws_ecs_cluster_capacity_providers" else "name"
        target=name_arn("ecs","cluster/",field)
    elif strategy=="ecs-service":
        expected=rf"arn:{partition}:ecs:[a-z0-9-]+:[0-9]{{12}}:service/[^\s*?]+"
        cluster=value("cluster"); name=value("name")
        if cluster and ":cluster/" in cluster: cluster=cluster.split(":cluster/",1)[1]
        if cluster and name and re.fullmatch(r"[\w-]+",cluster) and re.fullmatch(r"[\w-]+",name):
            target=arn("ecs","service/"+cluster+"/"+name)
    elif strategy=="ecs-task":
        expected=rf"arn:{partition}:ecs:[a-z0-9-]+:[0-9]{{12}}:task-definition/[^\s*?]+"
    elif strategy.startswith("rds-"):
        prefix={"rds-db":"db","rds-cluster":"cluster","rds-subgrp":"subgrp","rds-pg":"pg","rds-clpg":"cluster-pg"}[strategy]
        expected=rf"arn:{partition}:rds:[a-z0-9-]+:[0-9]{{12}}:{prefix}:[^\s*?]+"
        field="identifier" if strategy=="rds-db" else "cluster_identifier" if strategy=="rds-cluster" else "name"
        target=name_arn("rds",prefix+":",field)
    elif strategy in ("log-group","log-stream"):
        field="name" if typ=="aws_cloudwatch_log_group" else "log_group_name"
        group=value(field)
        if group and re.fullmatch(r"[\w./#-]+",group):
            target=arn("logs","log-group:"+group)
            if strategy=="log-stream":
                stream=value("name")
                target=target+":log-stream:"+stream if target and stream else None
    elif strategy=="alarm":
        target=name_arn("cloudwatch","alarm:","alarm_name")
    elif strategy in ("route-zone","route-record"):
        zone=value("zone_id")
        if zone and re.fullmatch(r"Z[A-Z0-9]+",zone): target=f"arn:{partition}:route53:::hostedzone/{zone}"
    if expected and known and re.fullmatch(expected,known): target=known

    for action in actions:
        if action in GLOBAL:
            if action=="kms:CreateKey":
                warn(source+": CreateKey requires wildcard scope; review request conditions")
            emit(action,"*")
            continue
        if strategy=="dashboard":
            # Dashboard actions in GLOBAL above are account-level candidates.
            omit(action); continue
        if strategy=="eks-access":
            if action=="eks:CreateAccessEntry":
                cluster=value("cluster_name"); principal=value("principal_arn")
                cluster_arn=arn("eks","cluster/"+cluster) if cluster else None
                if cluster_arn and principal and re.fullmatch(r"arn:[a-z0-9-]+:iam::[0-9]{12}:(?:role|user)/[^\s*?]+",principal):
                    emit(action,cluster_arn,{"ArnEquals":{"eks:principalArn":principal}})
                else: omit(action)
            elif action in ("eks:AssociateAccessPolicy","eks:DisassociateAccessPolicy"):
                policy=value("policy_arn")
                if target and policy and re.fullmatch(r"arn:[a-z0-9-]+:eks::aws:cluster-access-policy/[A-Za-z0-9]+",policy):
                    condition={"ArnEquals":{"eks:policyArn":policy}}
                    principal=value("principal_arn")
                    if principal: condition["ArnEquals"]["eks:principalArn"]=principal
                    emit(action,target,condition)
                else: omit(action)
            elif target: emit(action,target,{"ArnEquals":{"eks:principalArn":value("principal_arn")}} if value("principal_arn") and action not in ("eks:TagResource","eks:UntagResource") else None)
            else: omit(action)
            continue
        if strategy=="kms-alias":
            def key_arn(raw):
                key=resolve(raw)
                if key and KEY.fullmatch(key): return key
                if key and re.fullmatch(r"(?:mrk-[a-f0-9]{32}|[a-f0-9-]{36})",key): return arn("kms","key/"+key)
                return None
            key=key_arn(body.get("target_key_id"))
            old=key_arn(task.get("before",{}).get("target_key_id")) if task else None
            if action=="kms:CreateAlias" and target and key:
                emit(action,target); emit(action,key)
            elif action=="kms:UpdateAlias" and target and key and old and task and task["operation"]=="update":
                for resource in sorted({target,key,old}): emit(action,resource)
            elif action=="kms:DeleteAlias" and target and key and task and task["operation"]=="delete":
                emit(action,target); emit(action,key)
            else: omit(action)
            continue
        if action in ("route53:GetChange",):
            omit(action); continue
        if strategy in ("manual","review"):
            # Do not silently turn an unimplemented scope strategy into a global mutation.
            omit(action); continue
        if not target:
            omit(action); continue
        if action in ("iam:AddRoleToInstanceProfile","iam:RemoveRoleFromInstanceProfile"):
            # Requires both profile and role. Explicit role ARN inference is a separate milestone.
            omit(action); continue
        if strategy=="ecs-service" and action in ("ecs:CreateService","ecs:UpdateService") and (not task or task.get("operation")!="delete"):
            task_definition=value("task_definition")
            inferred_family=body.get("_tfiam_task_definition_family")
            if task_definition or inferred_family:
                prefix=arn("ecs","task-definition/")
                if prefix and task_definition and re.fullmatch(re.escape(prefix)+r"[A-Za-z0-9_-]+:[0-9]+",task_definition):
                    task_arn=task_definition
                elif prefix and task_definition and re.fullmatch(r"[A-Za-z0-9_-]+:(?:[0-9]+|\\*)",task_definition):
                    # A graph-proven planned task-definition family has no
                    # allocated revision until Terraform registers it.
                    task_arn=prefix+task_definition
                elif prefix and task_definition and re.fullmatch(r"[A-Za-z0-9_-]+",task_definition):
                    task_arn=prefix+task_definition+":*"
                else: task_arn=None
                if not task_arn and prefix and inferred_family and re.fullmatch(r"[A-Za-z0-9_-]+",inferred_family):
                    task_arn=prefix+inferred_family+":*"
                if not task_arn: omit(action); continue
                # UpdateService also serves non-task-definition updates and scale-down.
                condition={"ArnLike":{"ecs:task-definition":task_arn}} if action=="ecs:CreateService" else {"ArnLikeIfExists":{"ecs:task-definition":task_arn}}
                emit(action,target,condition); continue
            if action=="ecs:CreateService" or "task_definition" in (task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[])):
                omit(action); continue
        if action in ("logs:DescribeLogStreams","logs:DescribeMetricFilters","logs:DescribeSubscriptionFilters") and strategy=="log-stream":
            omit(action); continue
        emit(action,target)
    # ECS service IAM role delegation is an API dependency, not part of the
    # mapped ECS service actions list. Resolve it once using configured role
    # intent rather than interpreting provider-computed unknowns as PassRole.
    if strategy=="ecs-service" and any(
        a in actions for a in ("ecs:CreateService","ecs:UpdateService")
    ):
        role=value("iam_role")
        configured=body.get("_tfiam_ecs_role_configured")
        unknown="iam_role" in (task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))
        before_role=(task or {}).get("before",{}).get("iam_role")
        changed=not task or task.get("operation")=="create" or role!=before_role or unknown
        if changed and (role or configured is True or (configured is None and unknown)):
            if role and ROLE.fullmatch(role):
                emit("iam:PassRole",role,{"StringEquals":{
                    "iam:PassedToService":"ecs.amazonaws.com"}})
            else:
                omit("iam:PassRole")
    if strategy=="lambda" and "lambda:CreateFunction" in actions:
        role_from_field("role","lambda.amazonaws.com")
    elif strategy=="lambda" and "lambda:UpdateFunctionConfiguration" in actions and (body.get("role") or "role" in (task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))):
        if not task or task.get("before",{}).get("role")!=body.get("role") or "role" in task.get("unknown_fields",[]): role_from_field("role","lambda.amazonaws.com")
    if strategy=="ecs-task" and "ecs:RegisterTaskDefinition" in actions:
        for field in ("execution_role_arn","task_role_arn"):
            if field in body: role_from_field(field,"ecs-tasks.amazonaws.com")
    if strategy in ("review","manual"):
        warn(source+": catalog actions mapped; full action-specific scope/dependency implementation pending")
