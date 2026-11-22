"""Scoped candidates for common AWS resources and explicit service dependencies."""
import re

TYPES={
    "aws_iam_access_key","aws_iam_user_group_membership","aws_iam_instance_profile",
    "aws_key_pair","aws_sqs_queue_policy","aws_sqs_queue_redrive_policy",
    "aws_sqs_queue_redrive_allow_policy","aws_sns_topic","aws_sns_topic_policy",
    "aws_sns_topic_subscription","aws_db_option_group","aws_lambda_alias",
    "aws_ecs_task_definition","aws_eks_fargate_profile",
}
NAME=re.compile(r"[A-Za-z0-9_+=,.@-]{1,128}")
def scoped(typ,body,actions,account,region,partition,resolve,emit,omit,task=None):
    def val(k): return resolve(body.get(k))
    def arn(service,suffix):
        return f"arn:{partition}:{service}:{region}:{account}:{suffix}" if account and region else None
    def grant(action,targets,condition=None):
        if not targets or any(not t for t in targets):
            omit(action); return
        for target in sorted(set(targets)): emit(action,target,condition)
    def identity(kind,name,known=None):
        if not account or not name or not NAME.fullmatch(name): return []
        stem=f"arn:{partition}:iam::{account}:{kind}/"
        if known and known.startswith(stem) and known.rsplit("/",1)[-1]==name and not any(x in known for x in ("*","?","\u0024{")): return [known]
        return [stem+name,stem+"*/"+name]
    def role_arn(value):
        return value if value and account and re.fullmatch(rf"arn:{partition}:iam::{account}:role/[^\s*?]+",value) else None
    def passed(action,role,service):
        grant(action,[role_arn(role)],{"StringEquals":{"iam:PassedToService":service}})
    op=task.get("operation") if task else None
    before=task.get("before",{}) if task else {}
    unknown=set(task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))
    def changed(field): return not task or op!="update" or field in unknown or before.get(field)!=body.get(field)
    def tagged(): return bool(body.get("tags") or body.get("tags_all") or "tags" in unknown or "tags_all" in unknown)
    if typ=="aws_iam_access_key":
        targets=identity("user",val("user"),val("_tfiam_user_arn"))
        for action in actions:
            if action=="iam:UpdateAccessKey":
                if task and op=="create" and val("status") not in ("Inactive",) and "status" not in unknown: continue
                if task and op=="update" and not changed("status"): continue
            grant(action,targets)
        return
    if typ=="aws_iam_user_group_membership":
        user=identity("user",val("user"),val("_tfiam_user_arn"))
        groups=body.get("groups")
        old=before.get("groups",[])
        def names(raw):
            if not isinstance(raw,list) or any(not isinstance(x,str) or not NAME.fullmatch(x) for x in raw): return None
            return set(raw)
        current=names(groups); previous=names(old)
        for action in actions:
            if action=="iam:ListGroupsForUser": grant(action,user); continue
            if not user or current is None or (op=="update" and previous is None): omit(action); continue
            selected=current
            if op=="update":
                selected=current-previous if action=="iam:AddUserToGroup" else previous-current
            for group in selected: grant(action,identity("group",group))
        return
    if typ=="aws_iam_instance_profile":
        name=val("name"); path=val("path") if "path" in body else "/"
        target=f"arn:{partition}:iam::{account}:instance-profile{path}{name}" if account and name and NAME.fullmatch(name) and path and path.startswith("/") and path.endswith("/") and "path" not in unknown else None
        if task and val("arn") and account and re.fullmatch(rf"arn:{partition}:iam::{account}:instance-profile/[^\s*?]+",val("arn")): target=val("arn")
        current=val("role"); previous=resolve(before.get("role"))
        current_roles=identity("role",current,val("_tfiam_profile_role_arn"))
        old_roles=identity("role",previous)
        role_unknown="role" in unknown or bool(task and task.get("all_fields_masked"))
        for action in actions:
            if action=="iam:GetRole":
                for name in sorted(set(current_roles+old_roles)): emit(action,name)
                if role_unknown: omit(action)
                continue
            if action in ("iam:AddRoleToInstanceProfile","iam:RemoveRoleFromInstanceProfile","iam:PassRole"):
                if role_unknown: omit(action); continue
                if not current and not previous: continue
                if action in ("iam:AddRoleToInstanceProfile","iam:PassRole") and op=="update" and not changed("role"): continue
                if action=="iam:RemoveRoleFromInstanceProfile" and op=="update" and not previous: continue
                if action=="iam:PassRole":
                    if current: grant(action,current_roles,{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}})
                elif action=="iam:AddRoleToInstanceProfile":
                    if current: grant(action,[target])
                else: grant(action,[target])
                continue
            grant(action,[target])
        return
    if typ=="aws_key_pair":
        name=val("key_name") or (val("id") if task else None)
        target=arn("ec2","key-pair/"+name) if name and re.fullmatch(r"[A-Za-z0-9_.@+=,-]{1,255}",name) else None
        for action in actions:
            if action=="ec2:DescribeKeyPairs":
                emit(action,"*",{"StringEquals":{"aws:RequestedRegion":region}} if region else None)
            elif action=="ec2:CreateTags" and op=="create":
                if tagged(): grant(action,[target],{"StringEquals":{"ec2:CreateAction":"ImportKeyPair"}})
            elif action in ("ec2:CreateTags","ec2:DeleteTags") and task and op=="update" and not changed("tags") and not changed("tags_all"): continue
            else: grant(action,[target])
        return
    if typ.startswith("aws_sqs_queue_"):
        url=val("queue_url")
        # Standard regional AWS queue URL; never interpret arbitrary hosts as AWS.
        suffix={"aws":"amazonaws.com","aws-cn":"amazonaws.com.cn","aws-us-gov":"amazonaws.com"}.get(partition)
        match=re.fullmatch(r"https://sqs\.([a-z0-9-]+)\."+re.escape(suffix or "!")+r"/([0-9]{12})/([A-Za-z0-9_-]+(?:\.fifo)?)",url or "")
        target=arn("sqs",match.group(3)) if match and match.group(1)==region and match.group(2)==account else None
        for action in actions: grant(action,[target])
        return
    if typ.startswith("aws_sns_"):
        topic=val("topic_arn") if typ=="aws_sns_topic_subscription" else val("arn")
        name=val("name")
        if typ=="aws_sns_topic" and not topic and name and re.fullmatch(r"[A-Za-z0-9_-]+(?:\.fifo)?",name): topic=arn("sns",name)
        if not topic or not account or not region or not re.fullmatch(rf"arn:{partition}:sns:{region}:{account}:[A-Za-z0-9_-]+(?:\.fifo)?",topic): topic=None
        for action in actions:
            if action=="iam:PassRole":
                if typ=="aws_sns_topic_subscription":
                    fields=["subscription_role_arn"]
                else:
                    fields=[k for k in body if k.endswith("_feedback_role_arn")]
                    fields+= [k for k in unknown if k.endswith("_feedback_role_arn") and k not in fields]
                for field in fields:
                    if val(field) or field in unknown:
                        if changed(field): passed(action,val(field),"sns.amazonaws.com")
                continue
            if action=="sns:Subscribe":
                endpoint=val("endpoint"); protocol=val("protocol")
                if endpoint and protocol: grant(action,[topic],{"StringEquals":{"sns:Endpoint":endpoint,"sns:Protocol":protocol}})
                else: omit(action)
                continue
            grant(action,[topic])
        return
    if typ=="aws_db_option_group":
        name=val("name")
        target=arn("rds","og:"+name.lower()) if name and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*",name) else None
        for action in actions:
            if action=="rds:ModifyOptionGroup" and task and op=="create" and not body.get("option") and "option" not in unknown: continue
            if action=="rds:ModifyOptionGroup" and task and op=="update" and not changed("option"): continue
            grant(action,[target])
        # Complex options can carry IAM, VPC and other service dependencies.
        if body.get("option") or "option" in unknown: omit("rds:ModifyOptionGroup")
        return
    if typ=="aws_lambda_alias":
        name=val("function_name")
        target=arn("lambda","function:"+name) if name and re.fullmatch(r"[A-Za-z0-9_-]+",name) else None
        if name and account and region and re.fullmatch(rf"arn:{partition}:lambda:{region}:{account}:function:[A-Za-z0-9_-]+",name): target=name
        for action in actions: grant(action,[target])
        return
    if typ=="aws_ecs_task_definition":
        family=val("family")
        prospective=arn("ecs","task-definition/"+family+":*") if family and re.fullmatch(r"[A-Za-z0-9_-]+",family) else None
        known=val("arn") if task else None
        if known and prospective and not re.fullmatch(re.escape(prospective[:-1])+r"[0-9]+",known): known=None
        for action in actions:
            if action in ("ecs:DescribeTaskDefinition","ecs:DeregisterTaskDefinition"):
                # AWS does not offer resource or service-specific condition keys for these APIs.
                # Bound the regional endpoint with a global IAM condition instead.
                if region: emit(action,"*",{"StringEquals":{"aws:RequestedRegion":region}})
                else: omit(action)
            elif action=="ecs:RegisterTaskDefinition": grant(action,[prospective])
            elif action=="ecs:TagResource" and op=="create":
                if tagged(): grant(action,[prospective],{"StringEquals":{"ecs:CreateAction":"RegisterTaskDefinition"}})
            else: grant(action,[known or prospective])
        if "ecs:RegisterTaskDefinition" in actions:
            for field in ("task_role_arn","execution_role_arn"):
                if val(field) or field in unknown: passed("iam:PassRole",val(field),"ecs-tasks.amazonaws.com")
        return
    if typ=="aws_eks_fargate_profile":
        cluster=val("cluster_name"); name=val("fargate_profile_name")
        valid=cluster and name and all(re.fullmatch(r"[A-Za-z0-9_-]+",x) for x in (cluster,name))
        parent=arn("eks","cluster/"+cluster) if valid else None
        target=arn("eks","fargateprofile/"+cluster+"/"+name+"/*") if valid else None
        known=val("arn") if task else None
        if known and target and re.fullmatch(re.escape(target[:-1])+r"[A-Za-z0-9-]+",known): target=known
        for action in actions:
            if action=="eks:CreateFargateProfile": grant(action,[parent])
            elif action=="iam:PassRole": passed(action,val("pod_execution_role_arn"),"eks.amazonaws.com")
            else: grant(action,[target])
        return
