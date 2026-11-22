import json, re
from pathlib import Path
from .catalog_loader import get_rule, actions_for, operation_actions, attribute_values, CATALOG
from .plan import parse_plan
from .plan_roles import recover_role_arn
from .plan_buckets import recover_bucket, source_only_resources
from .risk import assess
from .resolver import discover
from .versioning import selected_version, evidence_status
from .authorization import audit
from .expanded_scope import expand
from .action_scope import network, elb, EC2_TYPES, ELB_TYPES, EC2_GLOBAL

def blocks(doc, key):
    value=doc.get(key, [])
    return value if isinstance(value,list) else [value]

def literal(v):
    return v if isinstance(v,str) and v and not any(c in v for c in ('${','%{','*','?')) else None

def scan(root=None, phase='apply', account=None, region=None, partition='aws', backend_config=None, plan=None, var_files=None, variables=None, scope_resource_tags=False, provider_version=None, authorization_metadata=None):
    if root is None and plan is None: raise ValueError('Provide a Terraform directory or saved plan JSON')
    has_root=root is not None
    root=Path(root or '.').resolve()
    if not root.is_dir(): raise ValueError('Terraform directory does not exist')
    report={'schema_version':1,'phase':phase,'coverage':'PARTIAL','resources':[], 'permissions':[], 'warnings':[], 'information':[], 'resolved_dependencies':[], 'backends':[], 'unresolved_permissions':[]}
    report['catalog']={'schema_version':CATALOG['schema_version'],'provider':CATALOG['provider'],'provider_version':None}
    provider_selection=selected_version(root if has_root else None,provider_version)
    version=provider_selection['version']
    report['catalog']['provider_version']=version
    report['catalog']['provider_selection']=provider_selection
    visited=set(); records=set()
    def warn(msg):
        if msg not in report['warnings']: report['warnings'].append(msg)
    def info(message):
        if message not in report['information']: report['information'].append(message)
    def unresolved(source,action):
        row={'source':source,'action':action,'reason':'action-specific scope or dependency unresolved'}
        if row not in report['unresolved_permissions']: report['unresolved_permissions'].append(row)
        warn(source+': '+action+' omitted; action-specific scope or dependency unresolved')
    def add(p,a,s,source,plane='management',condition=None):
        for action in a:
            key=(p,action,s,source,plane,json.dumps(condition,sort_keys=True))
            if key not in records:
                records.add(key); report['permissions'].append(dict(provider=p,action=action,scope=s,source=source,plane=plane, **({"condition":condition} if condition else {})))
    plan_tasks=[]
    if plan is not None:
        entries,plan_tasks,plan_warnings,meta=parse_plan(plan,phase)
        report['input']='terraform-plan-json'; report['plan']=meta; report['resources']=entries
        for message in plan_warnings: warn(message)
        unknown=sum(e['unknown_values'] for e in entries)
        sensitive=sum(e['sensitive_values'] for e in entries)
        if unknown: info(f'{unknown} planned resources contain computed or unknown values; masked values are not used for permission inference.')
        if sensitive: info(f'{sensitive} planned resources contain marked sensitive values; those values are withheld.')
        info('Saved-plan analysis uses planned operations, not a provider API trace.')
    else: report['input']='terraform-config'
    def backend(kind,b,src,readonly=False):
        if not readonly: b={**b,**(backend_config or {})}
        report['backends'].append({'type':kind,'source':src})
        if kind=='s3':
            bucket,key=literal(b.get('bucket')),literal(b.get('key'))
            if not bucket or not key: warn(src+': unresolved S3 bucket/key; backend omitted'); return
            arn=f'arn:{partition}:s3:::{bucket}'
            add('aws',['s3:ListBucket'],arn,src)
            add('aws',['s3:GetObject']+([] if readonly or phase=='plan' else ['s3:PutObject']),arn+'/'+key,src)
            if not readonly and b.get('use_lockfile') is True: add('aws',['s3:GetObject','s3:PutObject','s3:DeleteObject'],arn+'/'+key+'.tflock',src)
            if not readonly and b.get('dynamodb_table'):
                table=literal(b['dynamodb_table'])
                if table and account and region: add('aws',['dynamodb:DescribeTable','dynamodb:GetItem','dynamodb:PutItem','dynamodb:DeleteItem'],f'arn:{partition}:dynamodb:{region}:{account}:table/{table}',src)
                else: warn(src+': DynamoDB locking needs literal table, --aws-account and --aws-region')
            if b.get('kms_key_id'):
                kms=literal(b['kms_key_id'])
                if kms and kms.startswith(f'arn:{partition}:kms:'): add('aws',['kms:Decrypt']+([] if readonly else ['kms:Encrypt','kms:GenerateDataKey']),kms,src)
                else: warn(src+': unresolved KMS key ARN')
            warn(src+': default workspace only; verify workspace prefix and optional bucket policy conditions')
        elif kind not in ('local',): warn(src+': unsupported backend '+kind)
    resolved_docs=[]
    if plan is None:
        resolved_docs,report['modules'],report['dependencies']=discover(root,account,region,partition,var_files,variables,warn)
    elif var_files or variables: raise ValueError('Variable overrides cannot be used with an already evaluated saved plan')
    def visit(folder,is_root=False):
        folder=folder.resolve()
        if folder in visited: return
        visited.add(folder)
        files=sorted(set(folder.glob('*.tf'))|set(folder.glob('*.tf.json'))) if has_root else []
        if not files and plan is None: warn(str(folder)+': no Terraform files')
        docs=[]
        for f in files:
            src=str(f.relative_to(root)) if f.is_relative_to(root) else str(f)
            try:
                if f.name.endswith('.json'): doc=json.loads(f.read_text())
                else:
                    import hcl2
                    with f.open() as handle: doc=hcl2.load(handle)
            except Exception as e:
                warn(src+': parse failed ('+type(e).__name__+'); file not analyzed'); continue
            if not isinstance(doc,dict): warn(src+': invalid document'); continue
            docs.append((src,doc))
        definitions={}
        for _,doc in docs:
            for category in ('resource','variable','locals'):
                for group in blocks(doc,category):
                    for typ,instances in group.items():
                        if category=='resource':
                            for name,body in instances.items(): definitions[f'{typ}.{name}']=body
                        elif category=='variable': definitions['var.'+typ]=instances
                        else: definitions['local.'+typ]={'value':instances}
        def resolve(value,seen=()):
            if plan is not None: return literal(value)
            if not isinstance(value,str): return None
            def lookup(match):
                ref=match.group(1)
                if ref in seen: return None
                if ref.startswith('var.'):
                    warn('Variable defaults used for static inference; verify tfvars, TF_VAR and CI overrides before deployment')
                    base,attr=ref,'default'
                elif ref.startswith('local.'): base,attr=ref,'value'
                else: base,_,attr=ref.rpartition('.')
                obj=definitions.get(base,{})
                if attr=='arn' and base.startswith('aws_iam_role.'):
                    return role_arn(obj,seen+(ref,))
                return resolve(obj.get(attr),seen+(ref,))
            # Resolve only whole direct references, never evaluate arbitrary HCL.
            m=re.fullmatch(r'\$\{([\w.-]+)\}',value)
            return lookup(m) if m else literal(value)
        def role_arn(body,seen=()):
            known=resolve(body.get('arn'),seen) if plan is not None else None
            if known and re.fullmatch(r'arn:[a-z0-9-]+:iam::[0-9]{12}:role/[^\s*?]+',known): return known
            name=resolve(body.get('name'),seen)
            path=resolve(body.get('path','/'),seen)
            return f'arn:{partition}:iam::{account}:role{path}{name}' if account and name and path else None
        task_lookup={}
        if plan is not None and has_root:
            report["source_only_resources"]=source_only_resources(plan,definitions)
            if report["source_only_resources"]:
                warn("Current root configuration contains AWS declarations absent from saved plan configuration; regenerate the plan before policy generation.")
        analysis_docs=[]
        module_paths={}
        if plan is None:
            for i,(source,module_path,doc) in enumerate(resolved_docs):
                key='resolved:'+str(i); module_paths[key]=(source,module_path); analysis_docs.append((key,doc))
        role_targets={}
        if plan is not None:
            analysis_docs=[]
            for i,task in enumerate(plan_tasks):
                key='plan:'+str(i); task_lookup[key]=task
                entry=task['entry']; body=task['body']
                analysis_docs.append((key,{entry['mode']:{entry['type']:{'instance':body}}}))
                if entry['type']=='aws_iam_role' and entry['mode'] in ('resource','data'):
                    role=resolve(body.get('name')); arn=role_arn(body)
                    if role and arn: role_targets.setdefault(role,set()).add(arn)
        for src,doc in analysis_docs:
            for category in ('resource','data'):
                for group in blocks(doc,category):
                    for typ,instances in group.items():
                        for name,body in instances.items():
                            task=task_lookup.get(src)
                            source,module_path=module_paths.get(src,(src,''))
                            address=task['entry']['address'] if task else ((module_path+'.' if module_path else '')+('data.' if category=='data' else '')+typ+'.'+name)

                            unknown_fields=set(task.get('unknown_fields',[])) if task else set(body.get('_tfiam_unknown_fields',[]))
                            def unknown_field(field):
                                return field in unknown_fields or bool(task and task.get('all_fields_masked'))
                            operation=task['operation'] if task else None
                            resource_phase=('plan' if operation=='read' else 'destroy' if operation=='delete' else 'apply') if task else phase
                            if typ=='terraform_remote_state' and category=='data':
                                backend(body.get('backend','unknown'),body.get('config',{}),address,True); continue
                            rule=get_rule(category,typ,version)
                            entry=task['entry'] if task else {'address':address,'type':typ,'mode':category,'status':'PARTIAL' if rule else 'UNSUPPORTED'}
                            if not task: entry['file']=source; report['resources'].append(entry)
                            if not rule: entry['status']='UNSUPPORTED'
                            if not rule: warn(address+': no AWS '+category+' permission mapping'); continue
                            entry['validation']=rule['validation']; entry['reference']=rule['reference']
                            if not task and unknown_fields:
                                entry['unevaluated_fields']=sorted(unknown_fields)
                                entry['unknown_values']=True
                            p='aws'; acts=operation_actions(rule,operation) if task else actions_for(rule, 'plan' if category=='data' else phase)
                            def emit(action,target,condition=None):
                                add('aws',[action],target,address,condition=condition)
                            def omit(action):
                                unresolved(address,action)
                            if typ in EC2_TYPES or typ in ('aws_route','aws_route_table_association','aws_main_route_table_association','aws_security_group_rule','aws_network_acl_rule','aws_network_acl_association','aws_eip_association','aws_volume_attachment','aws_vpc_endpoint_route_table_association','aws_vpc_endpoint_subnet_association'):
                                network(typ,body,acts,account,region,partition,resolve,emit,omit,task,scope_resource_tags=scope_resource_tags)
                                continue
                            if typ in ELB_TYPES:
                                elb(typ,body,acts,account,region,partition,resolve,emit,omit,task)
                                continue
                            if rule.get('scope_strategy'):
                                expand(rule['scope_strategy'],typ,body,acts,account,region,partition,resolve,add,warn,address,task,unresolved=omit)
                                continue
                            # v6.73.0 role description uses a separate SDK API.
                            # A saved plan can omit it when the description is unchanged.
                            if typ=='aws_iam_role' and task and operation=='update' and 'iam:UpdateRoleDescription' in acts:
                                previous=task.get('before',{}).get('description')
                                current=body.get('description')
                                if previous==current and current is not None:
                                    acts=[a for a in acts if a!='iam:UpdateRoleDescription']
                            attr_rules=[]
                            for attr in rule['attributes']:
                                values=attribute_values(body,attr['path'])
                                if resource_phase not in attr['phases']: continue
                                if not values and unknown_field(attr['path'].split('.')[0]):
                                    if attr['scope']=='resource': acts=sorted(set(acts+attr['actions']))
                                    else:
                                        for action in attr['actions']: unresolved(address,action)
                                    continue
                                if not values: continue
                                if attr['scope']=='resource':
                                    acts=sorted(set(acts+attr['actions']))
                                    if task and any(v is None for v in values):
                                        info(address+': '+attr['path']+' values are computed or masked; catalog actions included without inferring their values.')
                                else: attr_rules.append((attr,values))
                            if category=='resource':
                                for attr,values in attr_rules:
                                    for value in values:
                                        arn=resolve(value)
                                        if arn and arn.startswith(f'arn:{partition}:kms:') and ':key/' in arn:
                                            add(p,[a for a in attr['actions'] if a!='kms:CreateGrant'],arn,address)
                                            if 'kms:CreateGrant' in attr['actions']: add(p,['kms:CreateGrant'],arn,address,condition={'Bool':{'kms:GrantIsForAWSResource':'true'}})
                                        else:
                                            for action in attr['actions']: unresolved(address,action)
                            scope='*'
                            if p=='aws' and typ.startswith('aws_s3_'):
                                bucket=resolve(body.get('bucket'))
                                if not bucket and task and operation in ('create','update') and has_root:
                                    bucket=recover_bucket(plan,address,definitions)
                                    if bucket:
                                        item={'source':address,'action':'S3 bucket dependency','scope':f'arn:{partition}:s3:::{bucket}','method':'direct source and saved-plan bucket identity'}
                                        if item not in report['resolved_dependencies']: report['resolved_dependencies'].append(item)
                                if bucket and typ=='aws_s3_object':
                                    key=resolve(body.get('key')); scope=f'arn:{partition}:s3:::{bucket}/{key}' if key else '*'
                                elif bucket: scope=f'arn:{partition}:s3:::{bucket}'
                            if p=='aws' and typ=='aws_dynamodb_table' and account and region and literal(body.get('name')): scope=f'arn:{partition}:dynamodb:{region}:{account}:table/{body["name"]}'
                            if p=='aws' and typ=='aws_sqs_queue' and account and region and literal(body.get('name')): scope=f'arn:{partition}:sqs:{region}:{account}:{body["name"]}'
                            if typ=='aws_iam_role': scope=role_arn(body) or '*'
                            if typ=='aws_iam_policy':
                                known=resolve(body.get('arn')); policy_name=resolve(body.get('name')); policy_path=resolve(body.get('path','/'))
                                if known and re.fullmatch(r'arn:[a-z0-9-]+:iam::(?:[0-9]{12}|aws):policy/[^\s*?]+',known): scope=known
                                elif account and policy_name and policy_path: scope=f'arn:{partition}:iam::{account}:policy{policy_path}{policy_name}'
                                if scope=='*':
                                    for action in acts: unresolved(address,action)
                                    acts=[]
                            if typ=='aws_iam_role_policy_attachment':
                                role=resolve(body.get('role'))
                                # Resolve role paths from direct references when possible.
                                ref=re.fullmatch(r'\$\{(aws_iam_role\.[\w-]+)\.name\}',str(body.get('role')))
                                scope=(role_arn(definitions.get(ref.group(1),{})) if ref else None) or (f'arn:{partition}:iam::{account}:role/{role}' if role and account and not ref else '*') or '*'
                                if not task:
                                    inferred=resolve(body.get('_tfiam_role_arn'))
                                    scope=inferred if inferred else '*'
                                if task:
                                    targets=role_targets.get(role,set())
                                    scope=next(iter(targets)) if len(targets)==1 else '*'
                                policy_arn=resolve(body.get('policy_arn'))
                                for action in acts:
                                    if action in ('iam:AttachRolePolicy','iam:DetachRolePolicy'):
                                        if scope=='*' or not policy_arn or not policy_arn.startswith('arn:'):
                                            unresolved(address,action); continue
                                        add(p,[action],scope,address,condition={'ArnEquals':{'iam:PolicyARN':policy_arn}})
                                    elif scope!='*': add(p,[action],scope,address)
                                    else: unresolved(address,action)
                                continue
                            if typ in ('aws_eks_cluster','aws_eks_node_group','aws_eks_addon','aws_eks_pod_identity_association'):
                                cluster=resolve(body.get('name' if typ=='aws_eks_cluster' else 'cluster_name'))
                                prefix=f'arn:{partition}:eks:{region}:{account}:' if region and account and cluster else None
                                cluster_arn=prefix+'cluster/'+cluster if prefix else '*'
                                kind={'aws_eks_cluster':'cluster','aws_eks_node_group':'nodegroup','aws_eks_addon':'addon','aws_eks_pod_identity_association':'podidentityassociation'}[typ]
                                name=resolve(body.get('node_group_name' if kind=='nodegroup' else 'addon_name'))
                                if kind=='cluster': scope=cluster_arn
                                elif prefix and kind=='podidentityassociation':
                                    association=resolve(body.get('association_id')) if task else None
                                    scope=prefix+kind+'/'+cluster+'/'+(association if association and re.fullmatch(r'[A-Za-z0-9-]+',association) else '*')
                                elif prefix and name: scope=prefix+kind+'/'+cluster+'/'+name+'/*'
                                else: scope='*'
                                known=resolve(body.get('association_arn') or body.get('arn')) if task else None
                                if known and re.fullmatch(r'arn:[a-z0-9-]+:eks:[a-z0-9-]+:[0-9]{12}:'+kind+r'/[^\s*?]+',known):
                                    scope=known
                                    if kind=='cluster': cluster_arn=known
                                for action in acts:
                                    target='*' if action in ('eks:CreateCluster','eks:DescribeAddonVersions') else cluster_arn if action in ('eks:CreateNodegroup','eks:CreateAddon','eks:CreatePodIdentityAssociation') else scope
                                    if target=='*' and action not in ('eks:CreateCluster','eks:DescribeAddonVersions'): unresolved(address,action); continue
                                    if action=='eks:AssociateEncryptionConfig' and task and (operation!='update' or task.get('before',{}).get('encryption_config')): continue
                                    condition={'StringEquals':{'aws:RequestedRegion':region}} if action in ('eks:CreateCluster','eks:DescribeAddonVersions') and region else None
                                    add(p,[action],target,address,condition=condition)
                                if resource_phase=='apply' and category=='resource' and operation not in ('read','no-op'):
                                    if kind in ('cluster','nodegroup') and (not task or operation=='create'):
                                        service,role_name={'cluster':('eks.amazonaws.com','AWSServiceRoleForAmazonEKS'),'nodegroup':('eks-nodegroup.amazonaws.com','AWSServiceRoleForAmazonEKSNodegroup')}[kind]
                                        if account:
                                            add(p,['iam:CreateServiceLinkedRole'],f'arn:{partition}:iam::{account}:role/aws-service-role/{service}/{role_name}',address,condition={'StringEquals':{'iam:AWSServiceName':service}})
                                            info(address+': service-linked role creation grant is only needed when the role does not already exist.')
                                        else: unresolved(address,'iam:CreateServiceLinkedRole')
                                    if kind=='cluster':
                                        access=attribute_values(body,'access_config.authentication_mode')
                                        old_access=attribute_values(task.get('before',{}),'access_config.authentication_mode') if task else []
                                        if any(v in ('API','API_AND_CONFIG_MAP') for v in access) and (not task or operation=='create' or operation=='update' and access!=old_access):
                                            if cluster_arn!='*': add(p,['eks:CreateAccessEntry'],cluster_arn,address)
                                            else: unresolved(address,'eks:CreateAccessEntry')
                                        elif unknown_field('access_config') or any(v is None or isinstance(v,str) and v.startswith('${') for v in access):
                                            unresolved(address,'eks:CreateAccessEntry')
                                    if kind in ('addon','podidentityassociation') and (body.get('pod_identity_association') or body.get('target_role_arn') or unknown_field('pod_identity_association') or unknown_field('target_role_arn')):
                                        unresolved(address,'iam:PassRole (additional pod identity role)')
                                        if kind=='addon': unresolved(address,'eks:CreatePodIdentityAssociation')
                                    field,service={'cluster':('role_arn','eks.amazonaws.com'),'nodegroup':('node_role_arn','eks.amazonaws.com'),'addon':('service_account_role_arn','eks.amazonaws.com'),'podidentityassociation':('role_arn','pods.eks.amazonaws.com')}[kind]
                                    recovered=None
                                    if task and has_root and not body.get(field):
                                        recovered=recover_role_arn(plan,address,field,definitions,account,partition)
                                    if kind!='addon' or body.get(field) or recovered or unknown_field(field):
                                        arn=resolve(body.get(field)) or recovered
                                        if recovered:
                                            item={'source':address,'action':'iam:PassRole','scope':recovered,'method':'direct source and saved-plan role dependency'}
                                            if item not in report['resolved_dependencies']: report['resolved_dependencies'].append(item)
                                        if arn and re.fullmatch(r'arn:[a-z0-9-]+:iam::[0-9]{12}:role/[^\s*?]+',arn): add(p,['iam:PassRole'],arn,address,condition={'StringEquals':{'iam:PassedToService':service}})
                                        else: unresolved(address,'iam:PassRole')
                                    if kind=='cluster' and (unknown_field('compute_config') or any(v is True or v is None for v in attribute_values(body,'compute_config.enabled'))):
                                        unresolved(address,'iam:PassRole (EKS Auto Mode compute role)')
                                if scope=='*': warn(address+': provide account, region and resolvable resource names')
                                continue
                            if typ=='aws_iam_role' and scope!='*' and category=='resource' and resource_phase=='apply' and operation not in ('read','no-op'):
                                boundary=resolve(body.get('permissions_boundary'))
                                old_boundary=resolve(task.get('before',{}).get('permissions_boundary')) if task else None
                                if unknown_field('permissions_boundary') or body.get('permissions_boundary') and not boundary:
                                    unresolved(address,'iam:PutRolePermissionsBoundary')
                                    if 'iam:CreateRole' in acts:
                                        acts=[a for a in acts if a!='iam:CreateRole']
                                        unresolved(address,'iam:CreateRole')
                                elif boundary and not re.fullmatch(r'arn:[a-z0-9-]+:iam::(?:[0-9]{12}|aws):policy/[^\s*?]+',boundary):
                                    unresolved(address,'iam:PutRolePermissionsBoundary')
                                elif boundary:
                                    if 'iam:CreateRole' in acts:
                                        acts=[a for a in acts if a!='iam:CreateRole']
                                        add(p,['iam:CreateRole'],scope,address,condition={'ArnEquals':{'iam:PermissionsBoundary':boundary}})
                                    if not task or operation=='update' and boundary!=old_boundary:
                                        add(p,['iam:PutRolePermissionsBoundary'],scope,address,condition={'ArnEquals':{'iam:PermissionsBoundary':boundary}})
                                elif task and operation=='update' and old_boundary and 'permissions_boundary' in body and body['permissions_boundary'] in ('',None):
                                    add(p,['iam:DeleteRolePermissionsBoundary'],scope,address)
                            if typ=='aws_iam_role' and scope=='*':
                                for action in acts: unresolved(address,action)
                                acts=[]
                            if scope=='*' and (typ.startswith('aws_s3_') or typ in ('aws_dynamodb_table','aws_sqs_queue')):
                                for action in acts: unresolved(address,action)
                                acts=[]
                            add(p,acts,scope,address)
                            # Delegation and boundary approval appear in the risk inventory.
                            if typ=='aws_instance' and body.get('iam_instance_profile'): warn(address+': instance profile PassRole dependency unresolved; permission omitted')
                            if scope=='*': warn(address+': exact resource scope not inferred')
        for src,doc in docs:
            if is_root:
                for group in blocks(doc,'terraform'):
                    for item in blocks(group,'backend'):
                        for kind,b in item.items(): backend(kind,b,src)
            for group in blocks(doc,'provider'):
                if not isinstance(group,dict): continue
                for provider_name,cfg in group.items():
                    if provider_name!='aws': continue
                    for item in cfg if isinstance(cfg,list) else [cfg]:
                        if isinstance(item,dict) and any(k in item for k in ('alias','assume_role','assume_role_with_web_identity','endpoints','default_tags')):
                            warn(src+': AWS provider alias, assumed identity, custom endpoint or default tags requires explicit context review')
        if is_root and not report['backends']:
            if backend_config: backend('s3',backend_config,'explicit-backend')
            elif has_root and docs and not any('cloud' in group for _,doc in docs for group in blocks(doc,'terraform')) and len(docs)==len(files): backend('local',{},'implicit-local')
            else: warn('Backend could not be determined; supply the Terraform directory or explicit S3 backend config')
    visit(root,True)
    mapped=0; eligible=0; verified=0; reviewed=0
    used_actions=set()
    for entry in report['resources']:
        if entry['status']=='SKIPPED':
            entry['mapping_status']='SKIPPED'
            continue
        eligible+=1
        rule=get_rule(entry['mode'],entry['type'],version) if entry['status']!='UNSUPPORTED' else None
        entry['mapping_status']='MAPPED' if rule else 'UNMAPPED'
        status=evidence_status(rule,version)
        entry['validation_level']=status
        entry['provider_version_validated']=status=='lifecycle-verified'
        if rule:
            mapped+=1
            for field in ('read','write','delete'): used_actions.update(rule[field])
            for attr in rule['attributes']: used_actions.update(attr['actions'])
            entry['validation_evidence']=[e for e in rule.get('evidence',[]) if e['provider_version']==version]
        verified+=status=='lifecycle-verified'
        reviewed+=status=='provider-source-reviewed'
    for entry in report['resources']:
        fields=entry.get('unevaluated_fields',[])
        if fields and not any(p['source']==entry['address'] for p in report['unresolved_permissions']):
            info(entry['address']+': unevaluated configuration fields ('+', '.join(fields)+'); no omitted mapped permission identified. Values withheld.')
    report['mapping_coverage']={'eligible_resources':eligible,'mapped_resources':mapped,'unmapped_resources':eligible-mapped,'mapping_percent':round(100*mapped/eligible,2) if eligible else None}
    report['authorization_confidence']={'provider_version':version,'lifecycle_verified_resources':verified,'source_reviewed_resources':reviewed,'unvalidated_mapped_resources':mapped-verified-reviewed,'status':'lifecycle-verified' if eligible and verified==eligible else 'partial-evidence' if verified else 'source-reviewed' if reviewed else 'unvalidated'}
    if not version: warn('AWS provider version unknown; supply the Terraform lockfile or --aws-provider-version')
    if provider_selection['lockfile_status']=='invalid-lockfile': warn('AWS provider lockfile could not be parsed')
    if mapped>verified: warn(f'AWS provider {version or "unknown"}: {mapped-verified} mapped resources lack exact-version lifecycle authorization evidence.')
    from .authorization import bundled_metadata
    explicit_metadata=authorization_metadata is not None
    if not explicit_metadata: authorization_metadata=bundled_metadata()
    if authorization_metadata is not None:
        report['authorization_metadata']=audit(used_actions,report['permissions'],authorization_metadata)
        report['authorization_metadata']['metadata_source']='explicit-offline-snapshot' if explicit_metadata else 'packaged'
        if report['authorization_metadata']['status']!='compatible': warn('AWS authorization metadata audit contains findings; review authorization_metadata before generating a policy')
    else: report['authorization_metadata']={'status':'not-run','metadata_source':'not-packaged-in-source-checkout'}

    report['permissions'].sort(key=lambda p:(p['provider'],p['action'],p['scope'],p['source']))
    report['scope_summary']={'global':sum(p['scope']=='*' for p in report['permissions']),'bounded_wildcard':sum(p['scope']!='*' and '*' in p['scope'] for p in report['permissions']),'exact':sum('*' not in p['scope'] and '?' not in p['scope'] for p in report['permissions']),'conditional':sum(bool(p.get('condition')) for p in report['permissions']),'unresolved':len(report['unresolved_permissions'])}
    report['unresolved_permissions'].sort(key=lambda x:(x['source'],x['action']))
    report['risks'] = assess(report['permissions'])
    return report
