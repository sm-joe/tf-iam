import json, re
from pathlib import Path
from .catalog_loader import get_rule, actions_for, operation_actions, attribute_values, CATALOG
from .plan import parse_plan
from .provider_context import validate as validate_contexts, plan_contexts
from .plan_roles import recover_role_arn
from .plan_buckets import recover_bucket, source_only_resources, recover_random_bucket_pattern
from .risk import assess
from .resolver import discover
from .versioning import selected_version, evidence_status
from .authorization import audit
from .expanded_scope import expand
from .dependencies import dependencies, object_dependencies
from .service_scope import TYPES as SERVICE_TYPES, scoped
from .scaling_scope import scoped as scaling_scoped
from .glue_scope import scoped as glue_scoped
from .route53_scope import scoped as route53_scoped
from .action_scope import network, elb, EC2_TYPES, ELB_TYPES, EC2_GLOBAL

def blocks(doc, key):
    value=doc.get(key, [])
    return value if isinstance(value,list) else [value]

def literal(v):
    return v if isinstance(v,str) and v and not any(c in v for c in ('${','%{','*','?')) else None

def scan(root=None, phase='apply', account=None, region=None, partition='aws', backend_config=None, plan=None, var_files=None, variables=None, scope_resource_tags=False, provider_version=None, authorization_metadata=None, provider_contexts=None, scope_generated_names=False):
    provider_contexts=validate_contexts(provider_contexts)
    if scope_generated_names and plan is not None: scope_resource_tags=True
    default_context=provider_contexts.get("aws",(account,region,partition))
    if root is None and plan is None: raise ValueError('Provide a Terraform directory or saved plan JSON')
    has_root=root is not None
    root=Path(root or '.').resolve()
    if not root.is_dir(): raise ValueError('Terraform directory does not exist')
    report={'schema_version':1,'phase':phase,'coverage':'PARTIAL','resources':[], 'permissions':[], 'warnings':[], 'information':[], 'resolved_dependencies':[], 'backends':[], 'unresolved_permissions':[], 'input_blockers':[]}
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
    def unresolved(source,action,reason='action-specific scope or dependency unresolved'):
        row={'source':source,'action':action,'reason':reason}
        if row not in report['unresolved_permissions']: report['unresolved_permissions'].append(row)
        warn(source+': '+action+' omitted; '+reason)
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
        if meta.get('complete') is False or meta.get('deferred'): report['input_blockers'].append('Incomplete or deferred saved plan')
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
        resolved_docs,report['modules'],report['dependencies']=discover(root,account,region,partition,var_files,variables,warn,provider_contexts=provider_contexts)
        for module in report['modules']:
            if module.get('status')=='UNRESOLVED': report['input_blockers'].append('Unresolved static module')
    elif var_files or variables: raise ValueError('Variable overrides cannot be used with an already evaluated saved plan')
    def visit(folder,is_root=False):
        account,region,partition=default_context
        select_context=plan_contexts(plan,default_context,provider_contexts) if plan is not None else None
        folder=folder.resolve()
        if folder in visited: return
        visited.add(folder)
        files=sorted(set(folder.glob('*.tf'))|set(folder.glob('*.tf.json'))) if has_root else []
        if not files and plan is None: warn(str(folder)+': no Terraform files')
        docs=[]
        for f in files:
            src=str(f.relative_to(root)) if f.is_relative_to(root) else str(f)
            if not f.resolve().is_relative_to(root):
                warn(src+': source outside scan root'); report['input_blockers'].append('Source outside scan root'); continue
            try:
                if f.name.endswith('.json'): doc=json.loads(f.read_text())
                else:
                    import hcl2
                    with f.open() as handle: doc=hcl2.load(handle)
            except Exception as e:
                warn(src+': parse failed ('+type(e).__name__+'); file not analyzed'); report['input_blockers'].append('Source parse failure'); continue
            if not isinstance(doc,dict): warn(src+': invalid document'); report['input_blockers'].append('Invalid source document'); continue
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
        network_sources=None
        if plan is not None and has_root:
            # Terraform's plan references are authorization evidence even when
            # callers have not opted in to resource-tag restrictions.
            from .plan_network import source_index
            network_sources=source_index(root,plan,definitions)
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
        profile_targets={}
        current_role_targets={}
        identity_targets={}
        if plan is not None:
            analysis_docs=[]
            for i,task in enumerate(plan_tasks):
                key='plan:'+str(i); task_lookup[key]=task
                entry=task['entry']; body={k:v for k,v in task['body'].items() if not k.startswith('_tfiam_')}
                context=select_context(entry['address'])
                account,region,partition=context or (None,None,None)
                analysis_docs.append((key,{entry['mode']:{entry['type']:{'instance':body}}}))
                if entry['type']=='aws_iam_role' and entry['mode'] in ('resource','data'):
                    role=resolve(body.get('name')); arn=role_arn(body)
                    if role and arn and context:
                        role_targets.setdefault((account,partition,role),set()).add(arn)
                        if task['operation'] in ('create','update','read'): current_role_targets.setdefault((account,partition,role),set()).add(arn)
                if entry['type'] in ('aws_iam_user','aws_iam_group') and entry['mode'] in ('resource','data'):
                    kind=entry['type'].split('_')[-1]
                    identity_name=resolve(body.get('name') or body.get('user_name') or body.get('group_name'))
                    known=resolve(body.get('arn'))
                    path=resolve(body.get('path','/'))
                    expected=rf'arn:{partition}:iam::{account}:{kind}/[^\s*?]+' if account else None
                    # Do not guess the path of an external identity.
                    if known and expected and re.fullmatch(expected,known) and known.rsplit('/',1)[-1]==identity_name:
                        target=known
                    elif account and entry['mode']=='resource' and identity_name and re.fullmatch(r'[\w+=,.@-]+',identity_name) and path and path.startswith('/') and path.endswith('/'):
                        target=f'arn:{partition}:iam::{account}:{kind}{path}{identity_name}'
                    else: target=None
                    if target and context: identity_targets.setdefault((account,partition,kind,identity_name),set()).add(target)
            # Named IAM identities are unique within the account. Use a single
            # current managed profile/role candidate only; never guess its path.
            for task in plan_tasks:
                entry=task['entry']; body=task['body']
                if entry['type']!='aws_iam_instance_profile' or entry['mode']!='resource' or task['operation'] not in ('create','update','read'): continue
                context=select_context(entry['address'])
                if context is None: continue
                a,rg,p=context
                name=literal(body.get('name')); role=literal(body.get('role'))
                targets=current_role_targets.get((a,p,role),set())
                if name and len(targets)==1:
                    profile_targets.setdefault((a,p,name),set()).update(targets)
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
                            if not task and typ=='random_id' and category=='resource' and body.get('_tfiam_local_random_id') is True:
                                report['resources'].append({'address':address,'type':typ,'mode':category,'status':'SKIPPED','file':source,'skip_reason':'Local random identifier; no AWS IAM permissions'})
                                continue
                            rule=get_rule(category,typ,version)
                            entry=task['entry'] if task else {'address':address,'type':typ,'mode':category,'status':'PARTIAL' if rule else 'UNSUPPORTED'}
                            if not task: entry['file']=source; report['resources'].append(entry)
                            if not rule: entry['status']='UNSUPPORTED'
                            if not rule: warn(address+': no AWS '+category+' permission mapping'); continue
                            entry['validation']=rule['validation']; entry['reference']=rule['reference']
                            context=select_context(address) if task else body.get('_tfiam_context',default_context)
                            if context is None:
                                unresolved(address,'AWS provider context')
                                continue
                            account,region,partition=context
                            entry['provider_context']={'account':account,'region':region,'partition':partition}
                            if body.get('region') and typ.startswith('aws_') and body.get('region')!=region:
                                unresolved(address,'AWS resource region differs from provider context')
                                continue
                            if not task and unknown_fields:
                                entry['unevaluated_fields']=sorted(unknown_fields)
                                entry['unknown_values']=True
                            p='aws'; acts=operation_actions(rule,operation) if task else actions_for(rule, 'plan' if category=='data' else phase)
                            if task and category=='resource':
                                from .optimization import minimize
                                acts=minimize(typ,acts,body,task)
                            # Inline network rules are provider operations, not separate
                            # Terraform resources. Retain their action candidates.
                            if category=='resource' and resource_phase=='apply':
                                extras=set()
                                if typ=='aws_route_table' and (body.get('route') or unknown_field('route') or task and task.get('before',{}).get('route')):
                                    if not task or operation=='create': extras.add('ec2:CreateRoute')
                                    if not task or operation=='update' and (unknown_field('route') or body.get('route')!=task.get('before',{}).get('route')):
                                        extras.update(('ec2:CreateRoute','ec2:ReplaceRoute','ec2:DeleteRoute'))
                                if typ=='aws_security_group' and operation=='create':
                                    extras.add('ec2:RevokeSecurityGroupEgress')
                                    for field,action in (('ingress','ec2:AuthorizeSecurityGroupIngress'),('egress','ec2:AuthorizeSecurityGroupEgress')):
                                        if body.get(field) or unknown_field(field): extras.add(action)
                                acts=sorted(set(acts)|extras)
                            def emit(action,target,condition=None):
                                add('aws',[action],target,address,condition=condition)
                            def omit(action,reason='action-specific scope or dependency unresolved'):
                                # Missing identity is one root cause, not dozens of
                                # independent AWS authorization catalog failures.
                                if reason=='action-specific scope or dependency unresolved' and action.startswith('ec2:'):
                                    if not account:
                                        reason='AWS target account unknown; resolve AWS STS identity, AWS_ACCOUNT_ID, or a literal Terraform assume_role target'
                                    elif not region:
                                        reason='AWS target region unknown; set a Terraform provider region or AWS_REGION'
                                unresolved(address,action,reason)
                            if task and (
                                typ in EC2_TYPES or typ in (
                                    'aws_route','aws_route_table_association',
                                    'aws_vpc_endpoint_route_table_association',
                                    'aws_vpc_endpoint_subnet_association',
                                )
                            ):
                                from .plan_network import recover, anchor
                                body={**body,'_tfiam_dynamic_ec2':recover(
                                    plan,address,definitions,select_context,body,task,
                                    network_sources,allow_name=scope_generated_names)}
                                if scope_resource_tags and operation=='create' and typ in EC2_TYPES and not body.get('id'):
                                    body['_tfiam_self_tags']=anchor(body,scope_generated_names)
                                    if scope_generated_names and 'ec2:ResourceTag/Name' in body['_tfiam_self_tags'].get('StringEquals',{}):
                                        info(address+': opt-in EC2 Name tag scope; names are not unique and tag mutation must be controlled independently.')
                            if task and operation in ('create','update','read') and typ in ('aws_instance','aws_iam_instance_profile'):
                                # Only current role identities from same account/partition.
                                if typ=='aws_instance':
                                    targets=profile_targets.get((account,partition,resolve(body.get('iam_instance_profile'))),set())
                                else:
                                    targets=current_role_targets.get((account,partition,resolve(body.get('role'))),set())
                                if len(targets)==1:
                                    body['_tfiam_profile_role_arn']=next(iter(targets))
                            if typ in ('aws_route53_zone','aws_route53_record') and category=='resource':
                                route53_scoped(typ,body,acts,account,region,partition,resolve,emit,omit,task,diagnose=lambda msg: info(address+': '+msg))
                                continue
                            if typ in ('aws_glue_catalog_database','aws_glue_job') and category=='resource':
                                if typ=='aws_glue_catalog_database' and body.get('name') is None and account and region:
                                    info(address+': database name not statically resolved; using prospective database/* ARN in the selected account and region. This grants access to other databases in the same resource class; inspect scan coverage before deployment.')
                                glue_scoped(typ,body,acts,account,region,partition,resolve,emit,omit,task)
                                continue
                            if typ in ('aws_autoscaling_group','aws_launch_template') and category=='resource':
                                scaling_scoped(typ,body,acts,account,region,partition,resolve,emit,omit,task,diagnose=lambda message: info(address+': '+message),phase=resource_phase)
                                continue
                            if typ in EC2_TYPES or typ in ('aws_route','aws_route_table_association','aws_main_route_table_association','aws_security_group_rule','aws_network_acl_rule','aws_network_acl_association','aws_eip_association','aws_volume_attachment','aws_vpc_endpoint_route_table_association','aws_vpc_endpoint_subnet_association'):
                                if task and typ=='aws_instance' and operation=='create' and has_root:
                                    from .plan_network import omitted_instance_key
                                    if omitted_instance_key(plan,address,network_sources,version):
                                        body['_tfiam_omitted_key_name']=True
                                        info(address+': optional computed key_name is absent from source and plan configuration; no key-pair authorization required for direct creation.')
                                network(typ,body,acts,account,region,partition,resolve,emit,omit,task,scope_resource_tags=scope_resource_tags,diagnose=lambda message: warn(address+': '+message))
                                continue
                            if typ in ELB_TYPES:
                                elb(typ,body,acts,account,region,partition,resolve,emit,omit,task)
                                continue
                            if typ in SERVICE_TYPES and category=='resource':
                                scoped(typ,body,acts,account,region,partition,resolve,emit,omit,task)
                                continue
                            if category=='resource':
                                if resource_phase=='apply':
                                    from .dependencies import rds_create_actions
                                    acts,blocked=rds_create_actions(typ,body,acts,task)
                                    for action in blocked: omit(action)
                                dependencies(typ,body,acts,account,region,partition,resolve,emit,omit,task,resource_phase)
                            if rule.get('scope_strategy'):
                                expand(rule['scope_strategy'],typ,body,acts,account,region,partition,resolve,add,warn,address,task,unresolved=omit)
                                continue
                            if typ=='aws_dynamodb_table' and task:
                                # Provider only invokes these optional APIs when requested or changed.
                                for action,field in (('dynamodb:UpdateTimeToLive','ttl'),('dynamodb:UpdateContinuousBackups','point_in_time_recovery')):
                                    if action in acts and not unknown_field(field):
                                        previous=task.get('before',{}).get(field)
                                        current=body.get(field)
                                        if (operation=='create' and not current) or (operation=='update' and previous==current):
                                            acts=[a for a in acts if a!=action]
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
                            generated_bucket=False
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
                                elif scope_generated_names and task and has_root and operation=='create' and account:
                                    pattern=recover_random_bucket_pattern(plan,address,definitions,select_context)
                                    if pattern:
                                        scope=f'arn:{partition}:s3:::{pattern}'
                                        generated_bucket=True
                                        info(address+': opt-in bounded bucket name pattern; matches other names of the same length and prefix. Review namespace ownership.')
                                        report['resolved_dependencies'].append({'source':address,'action':'S3 generated bucket name','scope':scope,'method':'fixed-width random_id hex pattern from saved plan and source'})
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
                            if typ in ('aws_iam_user_policy_attachment','aws_iam_group_policy_attachment'):
                                kind=typ.split('_')[2]
                                identity_name=resolve(body.get(kind))
                                target=resolve(body.get('_tfiam_identity_arn')) if not task else None
                                if task:
                                    targets=identity_targets.get((account,partition,kind,identity_name),set())
                                    target=next(iter(targets)) if len(targets)==1 else None
                                if not account or not identity_name or not target or not re.fullmatch(rf'arn:{partition}:iam::{account}:{kind}/[^\s*?]+',target) or target.rsplit('/',1)[-1]!=identity_name:
                                    target=None
                                # IAM identity names are unique within an account regardless of path.
                                # Cover the root and any path, keeping the final identity name literal.
                                # Never fall back to user/*, group/* or another account.
                                targets=[target] if target else []
                                if not target and account and re.fullmatch(r'[0-9]{12}',account) and identity_name and re.fullmatch(r'[A-Za-z0-9_+=,.@-]{1,128}',identity_name):
                                    stem=f'arn:{partition}:iam::{account}:{kind}/'
                                    targets=[stem+identity_name,stem+'*/'+identity_name]
                                    info(address+': external identity path unknown; scope restricted to the exact configured identity name across IAM paths.')
                                policy_arn=resolve(body.get('policy_arn'))
                                valid_policy=bool(policy_arn and re.fullmatch(rf'arn:{partition}:iam::(?:aws|{account}):policy/[^\s*?]+',policy_arn))
                                for action in acts:
                                    if not targets: unresolved(address,action); continue
                                    if action in ('iam:AttachUserPolicy','iam:DetachUserPolicy','iam:AttachGroupPolicy','iam:DetachGroupPolicy'):
                                        if not valid_policy: unresolved(address,action); continue
                                        for target in targets: add(p,[action],target,address,condition={'ArnEquals':{'iam:PolicyARN':policy_arn}})
                                    else:
                                        for target in targets: add(p,[action],target,address)
                                continue
                            if typ=='aws_iam_role_policy_attachment':
                                role=resolve(body.get('role'))
                                # Resolve role paths from direct references when possible.
                                ref=re.fullmatch(r'\$\{(aws_iam_role\.[\w-]+)\.name\}',str(body.get('role')))
                                scope=(role_arn(definitions.get(ref.group(1),{})) if ref else None) or (f'arn:{partition}:iam::{account}:role/{role}' if role and account and not ref else '*') or '*'
                                if not task:
                                    inferred=resolve(body.get('_tfiam_role_arn'))
                                    scope=inferred if inferred else '*'
                                if task:
                                    targets=role_targets.get((account,partition,role),set())
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
                                    if kind=='addon' and (body.get('pod_identity_association') or unknown_field('pod_identity_association')):
                                        roles=attribute_values(body,'pod_identity_association.role_arn')
                                        if roles and all(isinstance(v,str) and account and re.fullmatch(rf'arn:{partition}:iam::{account}:role/[^\s*?]+',v) for v in roles) and cluster_arn!='*':
                                            for v in roles: add(p,['iam:PassRole'],v,address,condition={'StringEquals':{'iam:PassedToService':'pods.eks.amazonaws.com'}})
                                            if not task or operation=='create' or body.get('pod_identity_association')!=task.get('before',{}).get('pod_identity_association'):
                                                add(p,['eks:CreatePodIdentityAssociation'],cluster_arn,address)
                                                if not task or operation=='update':
                                                    add(p,['eks:DeletePodIdentityAssociation','eks:UpdatePodIdentityAssociation'],prefix+'podidentityassociation/'+cluster+'/*',address)
                                        else:
                                            unresolved(address,'iam:PassRole')
                                            unresolved(address,'eks:CreatePodIdentityAssociation')
                                    if kind=='podidentityassociation' and (body.get('target_role_arn') or unknown_field('target_role_arn')):
                                        target_role=resolve(body.get('target_role_arn'))
                                        if not target_role or not re.fullmatch(rf'arn:{partition}:iam::[0-9]{{12}}:role/[^\s*?]+',target_role):
                                            unresolved(address,'eks:CreatePodIdentityAssociation')
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
                                        roles=attribute_values(body,'compute_config.node_role_arn')
                                        if roles and all(isinstance(v,str) and account and re.fullmatch(rf'arn:{partition}:iam::{account}:role/[^\s*?]+',v) for v in roles):
                                            for v in roles: add(p,['iam:PassRole'],v,address,condition={'StringEquals':{'iam:PassedToService':'eks.amazonaws.com'}})
                                        else: unresolved(address,'iam:PassRole')
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
                            if typ=='aws_s3_object' and category=='resource':
                                object_dependencies(body,acts,scope,account,region,partition,resolve,emit,omit,task)
                            if typ=='aws_iam_role' and scope=='*':
                                for action in acts: unresolved(address,action)
                                acts=[]
                            if scope=='*' and (typ.startswith('aws_s3_') or typ in ('aws_dynamodb_table','aws_sqs_queue')):
                                for action in acts: unresolved(address,action)
                                acts=[]
                            if generated_bucket:
                                for action in acts:
                                    add(p,[action],scope,address,condition={'StringEquals':{'s3:ResourceAccount':account}} if action!='s3:CreateBucket' else None)
                            else: add(p,acts,scope,address)
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
    report['scope_summary']={'global':sum(p['scope']=='*' for p in report['permissions']),'bounded_wildcard':sum(p['scope']!='*' and ('*' in p['scope'] or '?' in p['scope']) for p in report['permissions']),'exact':sum('*' not in p['scope'] and '?' not in p['scope'] for p in report['permissions']),'conditional':sum(bool(p.get('condition')) for p in report['permissions']),'unresolved':len(report['unresolved_permissions'])}
    report['unresolved_permissions'].sort(key=lambda x:(x['source'],x['action']))
    report['risks'] = assess(report['permissions'])
    return report
