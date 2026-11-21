"""Action-specific authorization candidates for EC2 and ELBv2.

Resource groups are atomic: missing a required identity withholds the action.
Prospective IDs are bounded to resource type, account and region, never global.
"""
import re

EC2_TYPES={
    "aws_vpc":("vpc","vpc"),"aws_subnet":("subnet","subnet"),
    "aws_instance":("instance","i"),"aws_internet_gateway":("internet-gateway","igw"),
    "aws_nat_gateway":("natgateway","nat"),"aws_route_table":("route-table","rtb"),
    "aws_security_group":("security-group","sg"),"aws_vpc_endpoint":("vpc-endpoint","vpce"),
    "aws_network_acl":("network-acl","acl"),"aws_eip":("elastic-ip","eipalloc"),
    "aws_launch_template":("launch-template","lt"),"aws_ebs_volume":("volume","vol"),
    "aws_network_interface":("network-interface","eni"),
    "aws_vpc_peering_connection":("vpc-peering-connection","pcx"),
    "aws_vpc_peering_connection_accepter":("vpc-peering-connection","pcx"),
    "aws_vpc_security_group_ingress_rule":("security-group-rule","sgr"),
    "aws_vpc_security_group_egress_rule":("security-group-rule","sgr"),
}
ELB_TYPES={"aws_lb","aws_lb_target_group","aws_lb_listener","aws_lb_listener_rule","aws_lb_target_group_attachment"}
EC2_GLOBAL={"ec2:"+s for s in (
    "DescribeVpcs DescribeVpcAttribute DescribeTags DescribeSubnets DescribeInstances DescribeInstanceAttribute "
    "DescribeVolumes DescribeInstanceStatus DescribeImages DescribeSecurityGroups DescribeSecurityGroupRules "
    "DescribeInternetGateways DescribeNatGateways DescribeRouteTables DescribeVpcEndpoints DescribeNetworkAcls "
    "DescribeAddresses DescribeLaunchTemplates DescribeLaunchTemplateVersions DescribeNetworkInterfaces DescribeVpcPeeringConnections"
).split()}
ELB_GLOBAL={"elasticloadbalancing:"+s for s in "DescribeLoadBalancers DescribeTargetGroups DescribeListeners DescribeRules DescribeTags".split()}
# Create request authorization includes the allocated resource and listed parent dependencies.
CREATE={
    "CreateVpc":("vpc",()),"CreateSubnet":("subnet",(("vpc_id","vpc","vpc"),)),
    "CreateInternetGateway":("internet-gateway",()),
    "CreateRouteTable":("route-table",(("vpc_id","vpc","vpc"),)),
    "CreateSecurityGroup":("security-group",(("vpc_id","vpc","vpc"),)),
    "CreateNetworkAcl":("network-acl",(("vpc_id","vpc","vpc"),)),
    "AllocateAddress":("elastic-ip",()),
    "CreateLaunchTemplate":("launch-template",()),
    "CreateVolume":("volume",()),
}
# Only actions whose resource types have been selected explicitly are emitted.
SELF_ACTIONS=set("ModifyVpcAttribute DeleteVpc ModifySubnetAttribute DeleteSubnet ModifyInstanceAttribute StartInstances StopInstances TerminateInstances DeleteInternetGateway DeleteNatGateway DeleteRouteTable DeleteSecurityGroup DeleteVpcEndpoints DeleteNetworkAcl ReleaseAddress CreateLaunchTemplateVersion ModifyLaunchTemplate DeleteLaunchTemplateVersions DeleteLaunchTemplate ModifyVolume DeleteVolume ModifyNetworkInterfaceAttribute DeleteNetworkInterface AcceptVpcPeeringConnection ModifyVpcPeeringConnectionOptions DeleteVpcPeeringConnection".split())
def tag_conditions(body,prefix):
    tags=body.get("tags")
    if not isinstance(tags,dict) or not tags: return {}
    # Refuse unknown or policy-variable values rather than silently weaken a condition.
    if any(not isinstance(k,str) or not re.fullmatch(r"[\w .:/=+@-]{1,128}",k) or k.lower().startswith("aws:") or not isinstance(v,str) or "\x00" in v or "\u0024{" in v for k,v in tags.items()):
        return {}
    return {"StringEquals":{prefix+k:v for k,v in sorted(tags.items())}}

def network(typ,body,actions,account,region,partition,resolve,emit,omit,task=None):
    def val(field): return resolve(body.get(field))
    def ec(kind,ident,owner=None):
        if not region or not account or not ident: return None
        return f"arn:{partition}:ec2:{region}:{account if owner is None else owner}:{kind}/{ident}"
    def ident(field,prefix):
        v=val(field)
        return v if v and re.fullmatch(re.escape(prefix)+r"-[0-9a-f]+",v) else None
    def dep(field,kind,prefix): return ec(kind,ident(field,prefix))
    def many(field,kind,prefix):
        raw=body.get(field)
        if not isinstance(raw,list) or not raw: return None
        values=[resolve(x) for x in raw]
        if any(not x or not re.fullmatch(re.escape(prefix)+r"-[0-9a-f]+",x) for x in values): return None
        out=[ec(kind,x) for x in values]
        return out if all(out) else None
    def grant(action,targets,condition=None):
        if not targets or any(t is None for t in targets):
            omit(action); return False
        for t in sorted(set(targets)): emit(action,t,condition)
        return True
    spec=EC2_TYPES.get(typ)
    own=dep("id",*spec) if spec else None
    if typ=="aws_eip": own=dep("allocation_id","elastic-ip","eipalloc") or own
    if typ in ("aws_route","aws_route_table_association"): own=dep("route_table_id","route-table","rtb")
    if typ=="aws_security_group_rule": own=dep("security_group_id","security-group","sg")
    if typ=="aws_network_acl_rule": own=dep("network_acl_id","network-acl","acl")
    if typ.startswith("aws_vpc_endpoint_"): own=dep("vpc_endpoint_id","vpc-endpoint","vpce")
    op=task.get("operation") if task else None
    creates=set()
    for action in actions:
        short=action.split(":")[1]
        if action in EC2_GLOBAL:
            emit(action,"*"); continue
        if short in CREATE and spec and spec[0]==CREATE[short][0]:
            kind,fields=CREATE[short]
            deps=[dep(*f) for f in fields]
            target=ec(kind,"*")
            if typ=="aws_ebs_volume" and body.get("snapshot_id"):
                deps.append(ec("snapshot",ident("snapshot_id","snap"),""))
            if target and all(deps):
                for d in deps: emit(action,d)
                emit(action,target,tag_conditions(body,"aws:RequestTag/") or None)
                creates.add(short)
            else: omit(action)
            continue
        if short=="RunInstances" and typ=="aws_instance":
            image=ec("image",ident("ami","ami"),"")
            subnet=dep("subnet_id","subnet","subnet")
            groups=many("vpc_security_group_ids","security-group","sg")
            # Unsupported launch-template / pre-existing ENI / key-pair combinations
            # cannot safely be approximated with global grants.
            if body.get("launch_template") or body.get("network_interface") or body.get("key_name"):
                omit(action); continue
            targets=[image,subnet,ec("instance","*"),ec("volume","*"),ec("network-interface","*")]+(groups or [None])
            if grant(action,targets): creates.add(short)
            continue
        if short in ("AttachVolume","DetachVolume"):
            grant(action,[dep("instance_id","instance","i"),dep("volume_id","volume","vol")]); continue
        if short in ("AttachInternetGateway","DetachInternetGateway"):
            grant(action,[own,dep("vpc_id","vpc","vpc")]); continue
        if short in ("CreateRoute","ReplaceRoute","DeleteRoute"):
            grant(action,[own]); continue
        if short=="AssociateRouteTable":
            parent=dep("subnet_id","subnet","subnet") or dep("gateway_id","internet-gateway","igw")
            grant(action,[own,parent]); continue
        if short in ("AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress","RevokeSecurityGroupIngress","RevokeSecurityGroupEgress","ModifySecurityGroupRules"):
            target=dep("security_group_id","security-group","sg") if "rule" in typ else own
            grant(action,[target]); continue
        if short in ("CreateNetworkAclEntry","ReplaceNetworkAclEntry","DeleteNetworkAclEntry"):
            grant(action,[own]); continue
        if short=="CreateVpcEndpoint" and typ=="aws_vpc_endpoint":
            vpc=dep("vpc_id","vpc","vpc")
            endpoint=ec("vpc-endpoint","*")
            optional=[]
            for field,kind,prefix in (("subnet_ids","subnet","subnet"),("security_group_ids","security-group","sg"),("route_table_ids","route-table","rtb")):
                if field in body and body[field]!=[]: optional.extend(many(field,kind,prefix) or [None])
            service=val("service_name")
            if vpc and endpoint and service and all(optional):
                emit(action,endpoint,{"StringEquals":{"ec2:VpceServiceName":service}})
                for d in [vpc]+optional: emit(action,d)
                creates.add(short)
            else: omit(action)
            continue
        if short=="ModifyVpcEndpoint":
            targets=[own]
            for field,kind,prefix in (("subnet_id","subnet","subnet"),("route_table_id","route-table","rtb")):
                if field in body: targets.append(dep(field,kind,prefix))
            for field,kind,prefix in (("subnet_ids","subnet","subnet"),("security_group_ids","security-group","sg"),("route_table_ids","route-table","rtb")):
                if field in body and body[field]!=[]: targets.extend(many(field,kind,prefix) or [None])
            grant(action,targets); continue
        if short in SELF_ACTIONS:
            grant(action,[own]); continue
        if short in ("CreateTags","DeleteTags"):
            if own and (op!="create"):
                emit(action,own)
            elif short=="CreateTags" and creates and spec:
                for create in sorted(creates):
                    emit(action,ec(spec[0],"*"),{"StringEquals":{"ec2:CreateAction":create}})
                    if create=="RunInstances":
                        for kind in ("volume","network-interface"): emit(action,ec(kind,"*"),{"StringEquals":{"ec2:CreateAction":create}})
            else: omit(action)
            continue
        omit(action)
    # An instance profile association is not evidence of the role path.
    if typ=="aws_instance" and "ec2:RunInstances" in actions and body.get("iam_instance_profile"):
        role=val("_tfiam_profile_role_arn") if not task else None
        if role and re.fullmatch(r"arn:[a-z0-9-]+:iam::[0-9]{12}:role/[^\s*?]+",role):
            emit("iam:PassRole",role,{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}})
        else: omit("iam:PassRole")

def elb(typ,body,actions,account,region,partition,resolve,emit,omit,task=None):
    def val(field): return resolve(body.get(field))
    prefix=f"arn:{partition}:elasticloadbalancing:{region}:{account}:" if region and account else None
    def exact(field,kinds):
        value=val(field)
        if not value or not re.fullmatch(r"arn:[a-z0-9-]+:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:(?:"+kinds+r")/[A-Za-z0-9/_-]+",value): return None
        return value
    name=val("name")
    valid_name=name and re.fullmatch(r"[A-Za-z0-9-]{1,32}",name)
    own=exact("arn","loadbalancer|targetgroup|listener|listener-rule") if task else None
    lb=exact("load_balancer_arn","loadbalancer")
    listener=exact("listener_arn","listener")
    target=exact("target_group_arn","targetgroup")
    prospective=None
    kind={"application":"app","network":"net","gateway":"gwy"}.get(val("load_balancer_type") or "application")
    if prefix and typ=="aws_lb" and valid_name and kind: prospective=prefix+"loadbalancer/"+kind+"/"+name+"/*"
    if prefix and typ=="aws_lb_target_group" and valid_name: prospective=prefix+"targetgroup/"+name+"/*"
    for action in actions:
        short=action.split(":")[1]
        if action in ELB_GLOBAL: emit(action,"*"); continue
        scope=None; condition=None
        if short in ("CreateLoadBalancer","CreateTargetGroup"): scope=prospective; condition=tag_conditions(body,"aws:RequestTag/") or None
        elif short=="CreateListener": scope=lb
        elif short=="CreateRule": scope=listener
        elif short in ("RegisterTargets","DeregisterTargets","DescribeTargetHealth"): scope=target or own
        elif short=="AddTags" and not own and prospective:
            scope=prospective
            create="CreateLoadBalancer" if typ=="aws_lb" else "CreateTargetGroup"
            condition={"StringEquals":{"elasticloadbalancing:CreateAction":create}}
        else: scope=own
        if scope: emit(action,scope,condition)
        else: omit(action)
