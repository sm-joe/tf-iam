import json, re
from pathlib import Path
from .catalog_loader import get_rule, actions_for, operation_actions, attribute_values, CATALOG
from .plan import parse_plan
from .risk import assess
from .resolver import discover

def blocks(doc, key):
    value=doc.get(key, [])
    return value if isinstance(value,list) else [value]

def literal(v):
    return v if isinstance(v,str) and v and not any(c in v for c in ('${','%{','*','?')) else None

def scan(root=None, phase='apply', account=None, region=None, partition='aws', backend_config=None, plan=None, var_files=None, variables=None):
    if root is None and plan is None: raise ValueError('Provide a Terraform directory or saved plan JSON')
    has_root=root is not None
    root=Path(root or '.').resolve()
    if not root.is_dir(): raise ValueError('Terraform directory does not exist')
    report={'schema_version':1,'phase':phase,'coverage':'PARTIAL','resources':[], 'permissions':[], 'warnings':[], 'backends':[]}
    report['catalog']={'schema_version':CATALOG['schema_version'],'provider':CATALOG['provider'],'provider_version':None}
    visited=set(); records=set()
    def warn(msg):
        if msg not in report['warnings']: report['warnings'].append(msg)
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
        warn('Saved-plan analysis is operation-specific, not a complete provider API trace; aliases and cross-account contexts require review')
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

                            operation=task['operation'] if task else None
                            resource_phase=('plan' if operation=='read' else 'destroy' if operation=='delete' else 'apply') if task else phase
                            if typ=='terraform_remote_state' and category=='data':
                                backend(body.get('backend','unknown'),body.get('config',{}),address,True); continue
                            rule=get_rule(category,typ)
                            entry=task['entry'] if task else {'address':address,'type':typ,'mode':category,'status':'PARTIAL' if rule else 'UNSUPPORTED'}
                            if not task: entry['file']=source; report['resources'].append(entry)
                            if not rule: entry['status']='UNSUPPORTED'
                            if not rule: warn(address+': no AWS '+category+' permission mapping'); continue
                            entry['validation']=rule['validation']; entry['reference']=rule['reference']
                            p='aws'; acts=operation_actions(rule,operation) if task else actions_for(rule, 'plan' if category=='data' else phase)
                            attr_rules=[]
                            for attr in rule['attributes']:
                                values=attribute_values(body,attr['path'])
                                if resource_phase not in attr['phases'] or not values: continue
                                if task and any(v is None for v in values): warn(address+': unknown or sensitive '+attr['path']+'; dependent actions may be incomplete')
                                if attr['scope']=='resource': acts=sorted(set(acts+attr['actions']))
                                else: attr_rules.append((attr,values))
                            if category=='resource':
                                for attr,values in attr_rules:
                                    for value in values:
                                        arn=resolve(value)
                                        if arn and arn.startswith(f'arn:{partition}:kms:') and ':key/' in arn:
                                            add(p,[a for a in attr['actions'] if a!='kms:CreateGrant'],arn,address)
                                            if 'kms:CreateGrant' in attr['actions']: add(p,['kms:CreateGrant'],arn,address,condition={'Bool':{'kms:GrantIsForAWSResource':'true'}})
                                        else: warn(address+': unresolved '+attr['path']+' ARN; dependent actions omitted')
                            scope='*'
                            if p=='aws' and typ.startswith('aws_s3_'):
                                bucket=resolve(body.get('bucket'))
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
                                if scope=='*': warn(address+': unresolved IAM policy ARN; actions omitted'); acts=[]
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
                                            warn(address+': unresolved role or policy ARN; attachment mutation omitted'); continue
                                        add(p,[action],scope,address,condition={'ArnEquals':{'iam:PolicyARN':policy_arn}})
                                    elif scope!='*': add(p,[action],scope,address)
                                if scope=='*': warn(address+': exact role scope not inferred')
                                continue
                            if typ in ('aws_eks_cluster','aws_eks_node_group','aws_eks_addon','aws_eks_pod_identity_association'):
                                cluster=resolve(body.get('name' if typ=='aws_eks_cluster' else 'cluster_name'))
                                prefix=f'arn:{partition}:eks:{region}:{account}:' if region and account and cluster else None
                                cluster_arn=prefix+'cluster/'+cluster if prefix else '*'
                                kind={'aws_eks_cluster':'cluster','aws_eks_node_group':'nodegroup','aws_eks_addon':'addon','aws_eks_pod_identity_association':'podidentityassociation'}[typ]
                                name=resolve(body.get('node_group_name' if kind=='nodegroup' else 'addon_name'))
                                if kind=='cluster': scope=cluster_arn
                                elif prefix and kind=='podidentityassociation': scope=prefix+kind+'/'+cluster+'/*'
                                elif prefix and name: scope=prefix+kind+'/'+cluster+'/'+name+'/*'
                                else: scope='*'
                                known=resolve(body.get('arn')) if task else None
                                if known and re.fullmatch(r'arn:[a-z0-9-]+:eks:[a-z0-9-]+:[0-9]{12}:'+kind+r'/[^\s*?]+',known):
                                    scope=known
                                    if kind=='cluster': cluster_arn=known
                                for action in acts:
                                    target='*' if action in ('eks:CreateCluster','eks:DescribeAddonVersions') else cluster_arn if action in ('eks:CreateNodegroup','eks:CreateAddon','eks:CreatePodIdentityAssociation') else scope
                                    if target=='*' and action not in ('eks:CreateCluster','eks:DescribeAddonVersions'): warn(address+': unresolved EKS scope; '+action+' omitted'); continue
                                    add(p,[action],target,address)
                                if resource_phase=='apply' and category=='resource':
                                    field,service={'cluster':('role_arn','eks.amazonaws.com'),'nodegroup':('node_role_arn','eks.amazonaws.com'),'addon':('service_account_role_arn','eks.amazonaws.com'),'podidentityassociation':('role_arn','pods.eks.amazonaws.com')}[kind]
                                    if kind!='addon' or body.get(field):
                                        arn=resolve(body.get(field))
                                        if arn and re.fullmatch(r'arn:[a-z0-9-]+:iam::[0-9]{12}:role/[^\s*?]+',arn): add(p,['iam:PassRole'],arn,address,condition={'StringEquals':{'iam:PassedToService':service}})
                                        else: warn(address+': unresolved PassRole target; permission omitted')
                                    if kind in ('cluster','nodegroup'): warn(address+': verify first-use service-linked roles, optional encryption, access entries and provider-specific dependencies')
                                if scope=='*': warn(address+': provide account, region and resolvable resource names')
                                continue
                            if typ=='aws_iam_role' and scope=='*':
                                if resource_phase=='apply' or resource_phase=='destroy': warn(address+': unresolved role ARN; IAM mutations omitted')
                                acts=[]
                            if scope=='*' and (typ.startswith('aws_s3_') or typ in ('aws_dynamodb_table','aws_sqs_queue')):
                                warn(address+': named resource scope unresolved; actions omitted'); acts=[]
                            add(p,acts,scope,address)
                            if resource_phase!='plan' and typ in ('aws_iam_role','aws_iam_policy'): warn(address+': review privilege delegation and permissions boundaries')
                            if typ=='aws_instance' and body.get('iam_instance_profile'): warn(address+': instance profile PassRole dependency unresolved; permission omitted')
                            if scope=='*': warn(address+': exact resource scope not inferred')
            for group in blocks(doc,'module'):
                for name,body in group.items():
                    source=literal(body.get('source'))
                    if source and source.startswith(('./','../')):
                        target=(folder/source).resolve()
                        if target.is_relative_to(root) and target.is_dir(): visit(target)
                        else: warn(src+': module '+name+' outside scan root or missing')
                    else: warn(src+': remote or dynamic module '+name+' not analyzed')
        for src,doc in docs:
            if is_root:
                for group in blocks(doc,'terraform'):
                    for item in blocks(group,'backend'):
                        for kind,b in item.items(): backend(kind,b,src)
            if doc.get('provider'): warn(src+': provider initialization, aliases, impersonation and registration require review')
        if is_root and not report['backends']:
            if backend_config: backend('s3',backend_config,'explicit-backend')
            elif has_root and docs and not any('cloud' in group for _,doc in docs for group in blocks(doc,'terraform')) and len(docs)==len(files): backend('local',{},'implicit-local')
            else: warn('Backend could not be determined; supply the Terraform directory or explicit S3 backend config')
    lock=root/'.terraform.lock.hcl'
    if has_root and lock.is_file():
        try:
            import hcl2
            with lock.open() as handle: locked=hcl2.load(handle)
            for group in blocks(locked,'provider'):
                if CATALOG['provider'] in group: report['catalog']['provider_version']=group[CATALOG['provider']].get('version')
        except Exception: warn('AWS provider lockfile could not be parsed')
    visit(root,True)
    for entry in report['resources']:
        rule=get_rule(entry['mode'],entry['type'])
        if rule: entry['provider_version_validated']=rule['validation']=='validated' and report['catalog']['provider_version'] in rule['provider_versions']
    warn('Starter catalog is not provider-version validated; review all permissions with cloud audit evidence before production use.')
    report['permissions'].sort(key=lambda p:(p['provider'],p['action'],p['scope'],p['source']))
    report['risks'] = assess(report['permissions'])
    return report
