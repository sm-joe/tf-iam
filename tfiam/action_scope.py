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
        return v if isinstance(v,str) and re.fullmatch(re.escape(prefix)+r"-[0-9a-f]+",v) else None
    managed={
        "vpc":"aws_vpc","subnet":"aws_subnet",
        "route-table":"aws_route_table","security-group":"aws_security_group",
        "internet-gateway":"aws_internet_gateway","natgateway":"aws_nat_gateway",
        "elastic-ip":"aws_eip","network-acl":"aws_network_acl",
        "vpc-endpoint":"aws_vpc_endpoint","vpc-peering-connection":"aws_vpc_peering_connection",
        "transit-gateway":"aws_ec2_transit_gateway","vpn-gateway":"aws_vpn_gateway",
    }
    def managed_reference(value,kind):
        # A Terraform resource attribute is computed at creation. It is
        # not an arbitrary var, an external ID, or a user-created IAM tag.
        return bool(isinstance(value,str) and re.fullmatch(
            r"\$\{"+re.escape(managed.get(kind,"<none>"))+
            r"\.[A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?\.(?:id|allocation_id)\}",value))
    def prospective(kind):
        candidate=ec(kind,"*")
        if candidate:
            diagnose("AWS-generated "+kind+" ID unknown until create; scoped to account, region and resource class "+candidate)
        return candidate
    def dep(field,kind,prefix):
        exact=ec(kind,ident(field,prefix))
        if exact: return exact
        if task is None and managed_reference(body.get(field),kind):
            return prospective(kind)
        dynamic=body.get("_tfiam_dynamic_ec2",{}).get(field,{})
        if not isinstance(dynamic,dict) or dynamic.get("kind")!=kind: return None
        condition=dynamic.get("condition")
        if scope_resource_tags and condition and ec(kind,"*"):
            return (ec(kind,"*"),condition)
        if dynamic.get("prospective"):
            return prospective(kind)
        return None
    def many(field,kind,prefix):
        raw=body.get(field)
        dynamic=body.get("_tfiam_dynamic_ec2",{}).get(field,[])
        if raw is None and isinstance(dynamic,list) and dynamic: raw=[None]*len(dynamic)
        if not isinstance(raw,list) or not raw: return None
        out=[]
        for i,item in enumerate(raw):
            value=resolve(item)
            if isinstance(value,str) and re.fullmatch(re.escape(prefix)+r"-[0-9a-f]+",value):
                out.append(ec(kind,value)); continue
            if task is None and managed_reference(item,kind):
                out.append(prospective(kind)); continue
            ref=dynamic[i] if isinstance(dynamic,list) and len(dynamic)==len(raw) else None
            if isinstance(ref,dict) and ref.get("kind")==kind:
                if scope_resource_tags and ref.get("condition") and ec(kind,"*"):
                    out.append((ec(kind,"*"),ref["condition"]))
                elif ref.get("prospective"):
                    out.append(prospective(kind))
                else: return None
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
    # Source-only generation cannot know resource IDs before creation.
    # Use a declared stable tag to limit operations on existing resources.
    # Name is not globally unique: this is a resource-tag boundary, not
    # proof of Terraform ownership. Prefer a dedicated tfiam:scope anchor.
    declared_tags=body.get("tags")
    tag_keys=sorted(declared_tags) if isinstance(declared_tags,dict) and declared_tags and all(
        isinstance(k,str) and re.fullmatch(r"[\w .:/=+@-]{1,128}",k)
        and not k.lower().startswith("aws:") for k in declared_tags
    ) else []
    anchor=None
    for key in ("tfiam:scope","Name"):
        candidate=declared_tags.get(key) if isinstance(declared_tags,dict) else None
        if isinstance(candidate,str) and candidate and "\x00" not in candidate and "${" not in candidate:
            anchor=(key,candidate)
            break
    def existing_tag_condition():
        if not anchor: return None
        return {"StringEquals":{"ec2:ResourceTag/"+anchor[0]:anchor[1]}}
    def tag_keys_condition(keys=None):
        selected=tag_keys if keys is None else keys
        if not selected: return {}
        # IAM ForAllValues is true for absent context keys; explicitly
        # require the aws:TagKeys key for both tag-add and tag-delete calls.
        return {"ForAllValues:StringEquals":{"aws:TagKeys":selected},
                "Null":{"aws:TagKeys":"false"}}
    # EC2 actions confirmed to accept ec2:ResourceTag in AWS's Service
    # Authorization Reference. Do not generically tag-scope other actions.
    tagged_delete_actions={
        "DeleteVpc","DeleteSubnet","DeleteInternetGateway","DeleteNatGateway",
        "DeleteNetworkAcl","DeleteRouteTable","DeleteSecurityGroup",
        "DeleteTransitGateway","DeleteVpnGateway","DeleteVpcEndpoints",
        "DeleteVpcPeeringConnection","ReleaseAddress",
    }
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
    if not own and spec and (
        (task is None and (body.get("id") is None or managed_reference(body.get("id"),spec[0])))
        or (task is not None and task.get("operation")=="create"
            and body.get("id") is None and not task.get("all_fields_masked"))
    ) and (typ!="aws_vpc_endpoint" or bool(
        body.get("vpc_id") or body.get("_tfiam_dynamic_ec2",{}).get("vpc_id")
    )):
        # A fresh static configuration has no AWS-assigned ID. Authorize
        # the prospective resource class; never claim this identifies only
        # one resource, and preserve exact IDs when supplied by a saved plan.
        own=prospective(spec[0])
    if typ in ("aws_route","aws_route_table_association"): own=dep("route_table_id","route-table","rtb")
    if typ=="aws_security_group_rule": own=dep("security_group_id","security-group","sg")
    if typ=="aws_network_acl_rule": own=dep("network_acl_id","network-acl","acl")
    if typ.startswith("aws_vpc_endpoint_"): own=dep("vpc_endpoint_id","vpc-endpoint","vpce")
    # Only narrow source-only wildcard resource scopes; an exact saved-plan
    # ARN already identifies the target and should retain its semantics.
    anchor_wildcard=(
        task is None and isinstance(own,str) and own.endswith("/*")
        and anchor is not None and bool(tag_keys)
    )
    if anchor_wildcard and anchor[0]=="Name":
        diagnose("Name-tag resource binding is not unique or immutable; generated ARN wildcard plus ec2:ResourceTag/Name matches other resources with the same Name. Supply a saved plan for exact existing IDs.")
    op=task.get("operation") if task else None
    # Optional Terraform lifecycle branches must not force unrelated
    # privileges or unresolved findings when the feature is not configured.
    uncertain=set(task.get("unknown_fields",[])) if task else set(body.get("_tfiam_unknown_fields",[]))
    if typ=="aws_vpn_gateway" and not body.get("vpc_id") and "vpc_id" not in uncertain:
        actions=[action for action in actions if action not in ("ec2:AttachVpnGateway","ec2:DetachVpnGateway")]
    if typ=="aws_vpc_peering_connection" and body.get("auto_accept") is not True and "auto_accept" not in uncertain:
        actions=[action for action in actions if action!="ec2:AcceptVpcPeeringConnection"]
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
            # AWS VPC peering IAM documentation explicitly supports a
            # requester VPC ARN and an AccepterVpc condition that identifies
            # the other account and region. The accepter account separately
            # authorizes acceptance; never grant that role implicitly.
            requester=dep("vpc_id","vpc","vpc")
            peer_account=val("peer_owner_id") if "peer_owner_id" in body else account
            peer_region=val("peer_region") if "peer_region" in body else region
            peer_id=ident("peer_vpc_id","vpc")
            peer_context_known=(
                isinstance(peer_account,str)
                and re.fullmatch(r"[0-9]{12}",peer_account)
                and isinstance(peer_region,str)
                and re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]",peer_region)
            )
            accepter=(
                f"arn:{partition}:ec2:{peer_region}:{peer_account}:vpc/{peer_id}"
                if peer_id and peer_context_known
                else dep("peer_vpc_id","vpc","vpc")
                if peer_account==account and peer_region==region else None
            )
            prospective_accepter=False
            if not accepter and peer_context_known:
                # The peer VPC ID may be supplied only at apply time (e.g.
                # var.peer_vpc_id). The peer account and region still bound
                # the AccepterVpc condition to one specific AWS context.
                # Never infer this from a missing peer_vpc_id declaration.
                raw_peer=body.get("peer_vpc_id")
                computed_peer=(
                    isinstance(raw_peer,str) and
                    re.fullmatch(r"\$\{[^{}]+\}",raw_peer) is not None
                ) or "peer_vpc_id" in body.get("_tfiam_unknown_fields",[]) or (task is not None and "peer_vpc_id" in task.get("unknown_fields",[]))
                if computed_peer:
                    accepter=f"arn:{partition}:ec2:{peer_region}:{peer_account}:vpc/*"
                    prospective_accepter=True
                    diagnose("Peer VPC ID is computed; ec2:AccepterVpc is scoped to peer account and region, but permits any VPC in that context: "+accepter)
            target=ec("vpc-peering-connection","*")
            if requester and accepter and target:
                emit(action,requester)
                emit(action,target,{
                    "ArnLike" if prospective_accepter else "ArnEquals":{"ec2:AccepterVpc":accepter}
                })
                creates.add(short)
            elif requester and target:
                # The accepter identity is NOT a required resource for AWS
                # requester-side IAM authorization. The optional AccepterVpc
                # condition must not prevent generating the two required
                # requester-side grants when a for_each instance could not be
                # statically expanded (or peer_vpc_id is absent).
                # Do not claim this is restricted to a particular peer.
                emit(action,requester)
                emit(action,target)
                declared=body.get("_tfiam_declared_fields",[])
                if "peer_vpc_id" not in declared and "peer_vpc_id" not in body:
                    diagnose("peer_vpc_id absent from statically evaluated peering declaration; Terraform may reject creation. IAM requester-side grant is still valid without an accepter constraint.")
                diagnose("Peer account/region or peer VPC identity unresolved; ec2:CreateVpcPeeringConnection scoped to requester VPC and local peering resource, without optional ec2:AccepterVpc restriction. This permits requests to other accepter VPCs; use a saved plan or exact peer values to constrain it.")
                creates.add(short)
            else:
                omit(action,"requester VPC identity unresolved; provide a managed VPC reference or known VPC ID")
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
            if anchor_wildcard and short in tagged_delete_actions:
                condition=existing_tag_condition()
            grant(action,[own],condition); continue
        if short in ("CreateTags","DeleteTags"):
            if anchor_wildcard:
                if short=="CreateTags" and creates and spec:
                    # Create-time tagging is explicitly authorized only as
                    # part of the corresponding EC2 create operation.
                    for create in sorted(creates):
                        emit(action,ec(spec[0],"*"),{
                            "StringEquals":{"ec2:CreateAction":create},
                            **tag_keys_condition(),
                        })
                        if create=="RunInstances":
                            for kind in ("volume","network-interface"):
                                emit(action,ec(kind,"*"),{
                                    "StringEquals":{"ec2:CreateAction":create},
                                    **tag_keys_condition(),
                                })
                # Never grant changes to the ownership key itself while
                # using its current value to select resource-class wildcards.
                # Otherwise the same identity can change the boundary used
                # by future delete and mutation operations. Exact-ID saved
                # plans can authorize an intentional anchor rotation.
                mutable_keys=[key for key in tag_keys if key!=anchor[0]]
                if mutable_keys:
                    emit(action,own,{**existing_tag_condition(),**tag_keys_condition(mutable_keys)})
            elif own and (op!="create") and not isinstance(own,tuple):
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
    # A graph-proven, newly created load balancer has an unallocated AWS ID.
    # Its prospective ARN is valid as a scoped CreateListener authorization.
    prospective_lb=body.get("_tfiam_parent_lb_arn")
    if not lb and prefix and isinstance(prospective_lb,str) and re.fullmatch(
        re.escape(prefix)+r"loadbalancer/(?:app|net|gwy)/[A-Za-z0-9-]{1,32}/\*",prospective_lb
    ):
        lb=prospective_lb
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
