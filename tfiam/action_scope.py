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
    "aws_ec2_transit_gateway":("transit-gateway","tgw"),
    "aws_vpn_gateway":("vpn-gateway","vgw"),
    "aws_vpc_security_group_ingress_rule":("security-group-rule","sgr"),
    "aws_vpc_security_group_egress_rule":("security-group-rule","sgr"),
}
ELB_TYPES={"aws_lb","aws_lb_target_group","aws_lb_listener","aws_lb_listener_rule","aws_lb_target_group_attachment"}
EC2_GLOBAL={"ec2:"+s for s in (
    "DescribeVpcs DescribeVpcAttribute DescribeTags DescribeSubnets DescribeInstances DescribeInstanceAttribute "
    "DescribeVolumes DescribeInstanceStatus DescribeImages DescribeSecurityGroups DescribeSecurityGroupRules "
    "DescribeInternetGateways DescribeNatGateways DescribeRouteTables DescribeVpcEndpoints DescribeNetworkAcls "
    "DescribeAddresses DescribeLaunchTemplates DescribeLaunchTemplateVersions DescribeNetworkInterfaces DescribeVpcPeeringConnections DescribeTransitGateways DescribeVpnGateways"
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
    "CreateTransitGateway":("transit-gateway",()),
    "CreateVpnGateway":("vpn-gateway",()),
}
# Only actions whose resource types have been selected explicitly are emitted.
SELF_ACTIONS=set("ModifyVpcAttribute DeleteVpc ModifySubnetAttribute DeleteSubnet ModifyInstanceAttribute StartInstances StopInstances TerminateInstances DeleteInternetGateway DeleteNatGateway DeleteRouteTable DeleteSecurityGroup DeleteVpcEndpoints DeleteNetworkAcl ReleaseAddress CreateLaunchTemplateVersion ModifyLaunchTemplate DeleteLaunchTemplateVersions DeleteLaunchTemplate ModifyVolume DeleteVolume ModifyNetworkInterfaceAttribute DeleteNetworkInterface AcceptVpcPeeringConnection ModifyVpcPeeringConnectionOptions DeleteVpcPeeringConnection ModifyTransitGateway DeleteTransitGateway DeleteVpnGateway".split())
def tag_conditions(body,prefix):
    tags=body.get("tags")
    if not isinstance(tags,dict) or not tags: return {}
    # Refuse unknown or policy-variable values rather than silently weaken a condition.
    if any(not isinstance(k,str) or not re.fullmatch(r"[\w .:/=+@-]{1,128}",k) or k.lower().startswith("aws:") or not isinstance(v,str) or "\x00" in v or "\u0024{" in v for k,v in tags.items()):
        return {}
    return {"StringEquals":{prefix+k:v for k,v in sorted(tags.items())}}

def network(typ,body,actions,account,region,partition,resolve,emit,omit,task=None,scope_resource_tags=False,diagnose=lambda message: None):
    def val(field): return resolve(body.get(field))
    def ec(kind,ident,owner=None):
        if not region or not account or not ident: return None
        return f"arn:{partition}:ec2:{region}:{account if owner is None else owner}:{kind}/{ident}"
    def ident(field,prefix):
        v=val(field)
        return v if v and re.fullmatch(re.escape(prefix)+r"-[0-9a-f]+",v) else None
    def dep(field,kind,prefix):
        exact=ec(kind,ident(field,prefix))
        if exact: return exact
        if not scope_resource_tags: return None
        dynamic=body.get("_tfiam_dynamic_ec2",{}).get(field,{})
        if not isinstance(dynamic,dict): return None
        condition=dynamic.get("condition")
        if dynamic.get("kind")==kind and condition and ec(kind,"*"):
            return (ec(kind,"*"),condition)
        return None
    def many(field,kind,prefix):
        raw=body.get(field)
        dynamic=body.get("_tfiam_dynamic_ec2",{}).get(field,[])
        if raw is None and scope_resource_tags and isinstance(dynamic,list) and dynamic: raw=[None]*len(dynamic)
        if not isinstance(raw,list) or not raw: return None
        out=[]
        for i,item in enumerate(raw):
            value=resolve(item)
            if value and re.fullmatch(re.escape(prefix)+r"-[0-9a-f]+",value):
                out.append(ec(kind,value)); continue
            ref=dynamic[i] if scope_resource_tags and isinstance(dynamic,list) and len(dynamic)==len(raw) else None
            if isinstance(ref,dict) and ref.get("kind")==kind and ref.get("condition") and ec(kind,"*"):
                out.append((ec(kind,"*"),ref["condition"]))
            else: return None
        return out if all(out) else None
    def request_tags():
        condition=tag_conditions(body,"aws:RequestTag/")
        # Unknown unrelated tags must not erase the verified creation anchor.
        if not condition and scope_resource_tags:
            anchor=body.get("_tfiam_self_tags",{}).get("StringEquals",{}).get("ec2:ResourceTag/tfiam:scope")
            if isinstance(anchor,str) and anchor:
                condition={"StringEquals":{"aws:RequestTag/tfiam:scope":anchor}}
        return condition
    # Only documented EC2 resource-tag authorization paths are eligible.
    dynamic_actions={"CreateSubnet","CreateRouteTable","CreateSecurityGroup","CreateNetworkAcl","CreateNatGateway","CreateVpcEndpoint","AttachInternetGateway","DetachInternetGateway","AssociateRouteTable","ReplaceRouteTableAssociation","DisassociateRouteTable","CreateRoute","ReplaceRoute","DeleteRoute","AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress","RevokeSecurityGroupIngress","RevokeSecurityGroupEgress","ModifyVpcAttribute","DeleteVpc","ModifySubnetAttribute","DeleteSubnet","DeleteRouteTable","DeleteSecurityGroup","DeleteNetworkAcl","DeleteNatGateway","DeleteInternetGateway","RunInstances","ModifyInstanceAttribute","DescribeInstanceAttribute","DescribeVpcAttribute"}
    def grant(action,targets,condition=None):
        if not targets or any(t is None for t in targets):
            omit(action); return False
        if any(isinstance(t,tuple) for t in targets) and action.split(":")[1] not in dynamic_actions:
            omit(action); return False
        for t in targets:
            if isinstance(t,tuple):
                emit(action,t[0],t[1])
            else: emit(action,t,condition)
        return True
    spec=EC2_TYPES.get(typ)
    own=dep("id",*spec) if spec else None
    if not own and scope_resource_tags and spec and body.get("_tfiam_self_tags") and ec(spec[0],"*"):
        own=(ec(spec[0],"*"),body["_tfiam_self_tags"])
    if typ=="aws_eip": own=dep("allocation_id","elastic-ip","eipalloc") or own
    # AWS allocates IDs for new gateways. Scope unknown current identity to
    # the verified regional resource class without inventing an exact ID.
    if not own and typ in ("aws_ec2_transit_gateway","aws_vpn_gateway","aws_vpc_peering_connection"):
        own=ec(spec[0],"*")
        if own: diagnose(typ+": generated gateway ID unavailable; prospective resource-class wildcard requires review")
    if typ in ("aws_route","aws_route_table_association"): own=dep("route_table_id","route-table","rtb")
    if typ=="aws_security_group_rule": own=dep("security_group_id","security-group","sg")
    if typ=="aws_network_acl_rule": own=dep("network_acl_id","network-acl","acl")
    if typ.startswith("aws_vpc_endpoint_"): own=dep("vpc_endpoint_id","vpc-endpoint","vpce")
    op=task.get("operation") if task else None
    creates=set()
    for action in sorted(actions,key=lambda a:(a in ("ec2:CreateTags","ec2:DeleteTags"),a)):
        short=action.split(":")[1]
        if action in EC2_GLOBAL:
            # Preserve the lifecycle-tested region-scoped read policy for the
            # original explicit tfiam:scope workflow. The new generated-name
            # workflow can scope attribute reads to its opt-in Name anchor.
            if isinstance(own,tuple) and "ec2:ResourceTag/Name" in own[1].get("StringEquals",{}) and short in ("DescribeInstanceAttribute","DescribeVpcAttribute"):
                grant(action,[own]); continue
            emit(action,"*",{"StringEquals":{"aws:RequestedRegion":region}} if region else None); continue
        if short in CREATE and spec and spec[0]==CREATE[short][0]:
            kind,fields=CREATE[short]
            deps=[dep(*f) for f in fields]
            target=ec(kind,"*")
            if typ=="aws_ebs_volume" and body.get("snapshot_id"):
                deps.append(ec("snapshot",ident("snapshot_id","snap"),""))
            if target and all(deps):
                if deps and not grant(action,deps): continue
                emit(action,target,request_tags() or None)
                creates.add(short)
            else: omit(action)
            continue
        if short=="CreateVpcPeeringConnection" and typ=="aws_vpc_peering_connection":
            # AWS requires authorization on the requester VPC and the
            # prospective peering connection. Cross-account acceptance
            # belongs to the peer identity and is never guessed here.
            requester=dep("vpc_id","vpc","vpc")
            accepter=dep("peer_vpc_id","vpc","vpc")
            peer_account=val("peer_owner_id")
            peer_region=val("peer_region")
            if peer_account and peer_account!=account or peer_region and peer_region!=region:
                diagnose("Cross-account or cross-region peering requires peer-specific authorization evidence")
                omit(action); continue
            target=ec("vpc-peering-connection","*")
            if requester and accepter and target:
                emit(action,requester)
                emit(action,target,{"ArnEquals":{"ec2:AccepterVpc":accepter,"ec2:RequesterVpc":requester}})
                creates.add(short)
            else:
                omit(action)
            continue
        if short=="CreateNatGateway" and typ=="aws_nat_gateway":
            # Zonal NAT only; regional NAT uses different request dependencies.
            subnet=dep("subnet_id","subnet","subnet")
            allocation=dep("allocation_id","elastic-ip","eipalloc")
            connectivity=val("connectivity_type") or "public"
            if body.get("availability_mode")=="regional" or body.get("secondary_allocation_ids") or body.get("secondary_private_ip_addresses"):
                omit(action); continue
            if connectivity not in ("public","private") or (connectivity=="public" and not allocation):
                omit(action); continue
            targets=[subnet]+([allocation] if connectivity=="public" else [])
            target=ec("natgateway","*")
            if target and all(targets):
                if not grant(action,targets): continue
                emit(action,target,request_tags() or None)
                creates.add(short)
            else: omit(action)
            continue
        if short=="RunInstances" and typ=="aws_instance":
            image=ec("image",ident("ami","ami"),"")
            subnet=dep("subnet_id","subnet","subnet")
            groups=many("vpc_security_group_ids","security-group","sg")
            # Unsupported launch-template / pre-existing ENI / key-pair combinations
            # cannot safely be approximated with global grants.
            if body.get("launch_template") or body.get("network_interface"):
                diagnose('RunInstances: launch template or pre-existing network interface requires separate authorization evidence')
                omit(action); continue
            key=val("key_name")
            targets=[image,subnet,ec("instance","*"),ec("volume","*"),ec("network-interface","*")]+(groups or [None])
            if "key_name" in body and body.get("key_name") not in ("",None):
                targets.append(ec("key-pair",key) if key and re.fullmatch(r"[A-Za-z0-9_.@+=,-]{1,255}",key) else None)
            elif not body.get("_tfiam_omitted_key_name") and ("key_name" in body.get("_tfiam_unknown_fields",[]) or (task and "key_name" in task.get("unknown_fields",[]))):
                diagnose("RunInstances: configured or computed key_name unresolved")
                targets.append(None)
            if not any(t is None for t in targets):
                # A known launch tag restricts the newly allocated instance, not the AMI,
                # subnet, security group, volume or ENI authorization checks.
                instance=ec("instance","*")
                if scope_resource_tags and request_tags():
                    targets=[(t,request_tags()) if t==instance else t for t in targets]
                if grant(action,targets): creates.add(short)
            else:
                for label,value in (("AMI",image),("subnet",subnet),("security groups",groups),("account/region",ec("instance","*"))):
                    if not value: diagnose("RunInstances: "+label+" authorization scope unresolved")
                omit(action)
            continue
        if short in ("AttachVolume","DetachVolume"):
            grant(action,[dep("instance_id","instance","i"),dep("volume_id","volume","vol")]); continue
        if short in ("AttachInternetGateway","DetachInternetGateway","AttachVpnGateway","DetachVpnGateway"):
            grant(action,[own,dep("vpc_id","vpc","vpc")]); continue
        if short in ("CreateRoute","ReplaceRoute","DeleteRoute"):
            grant(action,[own]); continue
        if short in ("AssociateRouteTable","ReplaceRouteTableAssociation","DisassociateRouteTable") and typ=="aws_route_table_association":
            parent=dep("subnet_id","subnet","subnet") or dep("gateway_id","internet-gateway","igw")
            targets=[own,parent]
            if short=="ReplaceRouteTableAssociation" and task and task.get("operation")=="update":
                old=resolve(task.get("before",{}).get("route_table_id"))
                targets.append(ec("route-table",old) if old and re.fullmatch(r"rtb-[0-9a-f]+",old) else None)
            grant(action,targets); continue
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
                if not grant(action,[vpc]+optional): continue
                emit(action,endpoint,{"StringEquals":{**request_tags().get("StringEquals",{}),"ec2:VpceServiceName":service}})
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
            condition=None
            # On supported existing-resource actions, use only stable pre-existing tags.
            # A new/changed tag cannot be assumed to exist when the action runs.
            if scope_resource_tags and task and task.get("operation") in ("update","delete") and short in ("StartInstances","StopInstances","TerminateInstances","DeleteVolume","DeleteVpc","DeleteSubnet"):
                old=task.get("before",{}).get("tags",{})
                current=body.get("tags",{})
                if isinstance(old,dict) and isinstance(current,dict):
                    stable={k:v for k,v in old.items() if k in current and current[k]==v}
                    condition=tag_conditions({"tags":stable},"ec2:ResourceTag/") or None
            grant(action,[own],condition); continue
        if short in ("CreateTags","DeleteTags"):
            if own and (op!="create") and not isinstance(own,tuple):
                emit(action,own)
            elif isinstance(own,tuple) and op!="create":
                # Creation tags are authorized independently. On existing objects,
                # only known non-anchor tag keys may be changed, never the binding tag.
                if short=="CreateTags" and creates and spec:
                    for create in sorted(creates):
                        emit(action,ec(spec[0],"*"),{"StringEquals":{"ec2:CreateAction":create}})
                tags=body.get("tags",{})
                anchor_keys={k.split("/",1)[1] for k in own[1].get("StringEquals",{}) if k.startswith("ec2:ResourceTag/")}
                keys=sorted(k for k in tags if k not in anchor_keys) if isinstance(tags,dict) else []
                if keys:
                    emit(action,own[0],{**own[1],"ForAllValues:StringEquals":{"aws:TagKeys":keys}})
            elif short=="CreateTags" and creates and spec:
                for create in sorted(creates):
                    emit(action,ec(spec[0],"*"),{"StringEquals":{"ec2:CreateAction":create}})
                    if create=="RunInstances":
                        for kind in ("volume","network-interface"): emit(action,ec(kind,"*"),{"StringEquals":{"ec2:CreateAction":create}})
            else: omit(action)
            continue
        omit(action)
    # An instance profile association is not evidence of the role path.
    profile_unknown="iam_instance_profile" in (task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))
    if typ=="aws_instance" and "ec2:RunInstances" in actions and (body.get("iam_instance_profile") or profile_unknown):
        role=val("_tfiam_profile_role_arn")
        if role and account and re.fullmatch(rf"arn:{partition}:iam::{account}:role/[^\s*?]+",role):
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
