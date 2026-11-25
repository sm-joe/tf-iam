import argparse, json, sys
from pathlib import Path
from .scan import scan
from .authorization import catalog_actions, download_snapshot, audit
from .versioning import selected_version
from .risk import gate, LEVELS
from . import cloud
from .table_output import render

def policy(report,provider,name,scope):
    rows=[r for r in report['permissions'] if r['provider']==provider]
    if not rows: raise ValueError('No mapped permissions for '+provider)
    if provider=='aws':
        groups={}
        for r in rows: groups.setdefault((r['scope'],json.dumps(r.get('condition'),sort_keys=True)),set()).add(r['action'])
        raw={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':sorted(a),'Resource':s, **({'Condition':json.loads(c)} if c!='null' else {})} for (s,c),a in sorted(groups.items())]}
        from .policy_size import optimize, grants
        compact=optimize(raw)
        if grants(compact)!=grants(raw):
            raise ValueError('Generated policy optimization changed effective action/resource/condition grants')
        return compact
    raise ValueError('Only AWS is supported')

def terraform(p,provider,name,scope):
    if provider=='aws': typ='aws_iam_policy'; body={'name':name,'policy':json.dumps(p)}
    else: raise ValueError('Only AWS is supported')
    return {'resource':{typ:{'candidate':body}}}

from .comparison import compare

def read_plan_json(path):
    """Read a saved JSON plan, including BOM-encoded Windows exports."""
    try:
        raw=path.read_bytes()
    except FileNotFoundError:
        raise ValueError(f"Plan JSON file not found: {path.absolute()} (paths are relative to the current working directory)") from None
    except IsADirectoryError:
        raise ValueError(f"Plan JSON path is a directory: {path.absolute()}") from None
    except OSError as exc:
        raise ValueError(f"Cannot open plan JSON file: {path.absolute()} (OS error {exc.errno})") from None
    if not raw.strip():
        raise ValueError("Plan JSON file is empty; regenerate with terraform show -json tfplan > plan.json")
    try:
        # json.loads(bytes) detects UTF-8, UTF-16 and UTF-32, including BOMs.
        plan=json.loads(raw)
    except UnicodeError:
        raise ValueError("Plan file is not valid JSON text; export with terraform show -json tfplan > plan.json") from None
    except json.JSONDecodeError as exc:
        # Do not echo input or excerpts: plans can contain secrets.
        raise ValueError(f"Invalid plan JSON at line {exc.lineno}, column {exc.colno}; regenerate with terraform show -json tfplan > plan.json (not terraform plan -json)") from None
    if not isinstance(plan,dict):
        raise ValueError("Expected a saved Terraform plan JSON object")
    return plan

def main(argv=None, *, maintainer=False):
    parser=argparse.ArgumentParser(prog='tfiam',description='Terraform IAM candidate policy analyzer')
    sub=parser.add_subparsers(dest='command',required=True)
    catalog=sub.add_parser('catalog-audit',help='Audit catalog action names using AWS service authorization snapshots')
    catalog.add_argument('--metadata-dir',type=Path,help='Optional offline snapshot override; defaults to packaged metadata')
    if maintainer: catalog.add_argument('--refresh',action='store_true',help='Maintainer only: refresh AWS public metadata')
    catalog.add_argument('--aws-provider-version')
    catalog.add_argument('--output',type=Path)
    catalog.add_argument('--strict',action='store_true')
    validate=sub.add_parser('validate-policy',help='AWS IAM Access Analyzer identity policy validation')
    validate.add_argument('policy',type=Path); validate.add_argument('--aws-profile'); validate.add_argument('--aws-region'); validate.add_argument('--strict',action='store_true'); validate.add_argument('--output',type=Path)
    pack=sub.add_parser('pack-policy',help='Optimize and partition generated AWS policies without changing grants')
    pack.add_argument('policy',type=Path); pack.add_argument('--policy-type',choices=['managed','inline-role','inline-user','inline-group'],default='managed'); pack.add_argument('--max-chars',type=int); pack.add_argument('--max-policies',type=int,default=10); pack.add_argument('--name',default='TerraformPipeline'); pack.add_argument('--output-dir',type=Path,required=True)
    runtime=sub.add_parser('runtime-audit',help='Compare observed CloudTrail management operations with candidate actions')
    runtime.add_argument('--role-arn',required=True); runtime.add_argument('--events',type=Path); runtime.add_argument('--start'); runtime.add_argument('--end'); runtime.add_argument('--aws-profile'); runtime.add_argument('--aws-region'); runtime.add_argument('--candidate',type=Path,required=True); runtime.add_argument('--output',type=Path); runtime.add_argument('--session-name',action='append',default=[],help='Exact known STS session name; repeat for multiple sessions'); runtime.add_argument('--max-pages',type=int,default=100); runtime.add_argument('--max-seconds',type=int,default=120); runtime.add_argument('--quiet',action='store_true')
    for cmd in ('scan','generate','compare','split'):
        p=sub.add_parser(cmd); p.add_argument('directory',type=Path,nargs='?'); p.add_argument('--plan-json',type=Path,help='Saved terraform show -json output; optional directory supplies backend, lockfile and direct source evidence for computed EKS role ARNs'); p.add_argument('--phase',choices=['plan','apply','destroy'],default='apply'); p.add_argument('--var-file',action='append',type=Path,default=[]); p.add_argument('--var',action='append',default=[],metavar='NAME=VALUE'); p.add_argument('--scope-resource-tags',action='store_true',help='Restrict supported existing-resource EC2 mutations to stable saved-plan tags'); p.add_argument('--scope-generated-names',action='store_true',help='Opt in to bounded generated-name scopes from corroborated source and saved plans; review name collisions'); p.add_argument('--aws-provider-version',help='Exact provider version if lockfile unavailable'); p.add_argument('--authorization-metadata',type=Path,help='Local AWS service authorization metadata'); p.add_argument('--provider-contexts',type=Path,help='JSON map of AWS provider configuration keys to account, region and partition'); p.add_argument('--aws-account'); p.add_argument('--aws-region'); p.add_argument('--aws-partition',default='aws'); p.add_argument('--backend-config',type=Path,help='JSON backend overrides'); p.add_argument('--output',type=Path); p.add_argument('--strict',action='store_true',help='Exit 2 when analysis is partial'); p.add_argument('--fail-on-risk',choices=list(LEVELS)); p.add_argument('--fail-on-unresolved',action='store_true'); p.add_argument('--fail-on-unmapped',action='store_true'); p.add_argument('--require-compatible-metadata',action='store_true'); p.add_argument('--require-lifecycle-verified',action='store_true',help='Block unless every applicable resource has exact-version lifecycle evidence and no unresolved permissions')
        p.add_argument('--show-table',action='store_true',help='Print table in addition to an output file')
        if cmd=='scan': p.add_argument('--format',choices=['text','json','table'],default='table')
        elif cmd in ('compare','split'): p.add_argument('--format',choices=['json','table'],default='json'); p.add_argument('--provider',default='aws',choices=['aws'])
        else: p.add_argument('--provider',default='aws',choices=['aws'])
        if cmd=='generate':
            p.add_argument('--format',choices=['json','terraform','table'],default='json'); p.add_argument('--name',default='TerraformPipeline'); p.add_argument('--scope'); p.add_argument('--allow-partial',action='store_true',help='Permit generation despite unresolved permissions or unmapped resources; review before use')
        if cmd=='compare':
            source=p.add_mutually_exclusive_group(required=True); source.add_argument('--existing',type=Path); source.add_argument('--role-name'); p.add_argument('--aws-profile'); p.add_argument('--fail-on-missing',action='store_true')
        if cmd=='split': p.add_argument('--allow-partial',action='store_true'); p.add_argument('--acknowledge-break-glass',action='store_true',help='Include destructive/delegation grants in a separately gated policy')
    for p in (catalog,validate,runtime):
        p.add_argument('--format',choices=['json','table'],default='json')
        p.add_argument('--show-table',action='store_true',help='Print table in addition to an output file')
    if maintainer:
        provider=sub.add_parser('provider-audit',help='Reconcile pinned AWS provider source with AWS operation metadata')
        provider.add_argument('--source-dir',type=Path,required=True); provider.add_argument('--aws-provider-version',required=True); provider.add_argument('--metadata-dir',type=Path,required=True); provider.add_argument('--resource',action='append'); provider.add_argument('--format',choices=['json','table'],default='table'); provider.add_argument('--output',type=Path); provider.add_argument('--show-table',action='store_true'); provider.add_argument('--strict',action='store_true')
        evidence=sub.add_parser('evidence-audit',help='Reconcile completed S3 fixture, pinned source and CloudTrail evidence')
        evidence.add_argument('--lifecycle',type=Path,required=True); evidence.add_argument('--source-report',type=Path,required=True); evidence.add_argument('--policy',type=Path,required=True); evidence.add_argument('--lockfile',type=Path,required=True); evidence.add_argument('--metadata-dir',type=Path,required=True); evidence.add_argument('--events',type=Path); evidence.add_argument('--aws-profile'); evidence.add_argument('--max-pages',type=int,default=100); evidence.add_argument('--max-seconds',type=int,default=120); evidence.add_argument('--format',choices=['json','table'],default='table'); evidence.add_argument('--output',type=Path); evidence.add_argument('--show-table',action='store_true'); evidence.add_argument('--strict',action='store_true')
    args=parser.parse_args(argv)
    def write_result(result,output=None):
        if args.format=='table': output=render(args.command,result,compact=args.command=='compare' and not args.show_table)
        elif output is None: output=json.dumps(result,indent=2)
        if args.output:
            args.output.write_text(output+'\n',encoding='utf-8')
            if args.show_table and args.format!='table': print(render(args.command,result),file=sys.stderr)
        else: print(output)
    try:
        if args.command=='pack-policy':
            from .policy_size import partition
            from .policy_size import compact
            result=partition(json.loads(args.policy.read_bytes()),args.policy_type,args.max_chars,args.max_policies,args.name)
            # One parseable JSON document contains all IAM policy documents.
            # Individual JSON files remain the attachable AWS IAM documents.
            bundle={
                'schema_version':result['schema_version'],
                'policy_type':result['policy_type'],
                'policy_count':result['policy_count'],
                'managed_policy_character_limit':result['limit'],
                'policies':[{'name':item['name'],'document':item['document']} for item in result['policies']],
            }
            # Never overwrite a previous policy set or leave a half-written set.
            import os, tempfile, shutil
            target=args.output_dir.absolute()
            if target.exists() or target.is_symlink(): raise ValueError('Output directory already exists; choose a new directory')
            stage=Path(tempfile.mkdtemp(prefix='.tfiam-pack-',dir=target.parent))
            try:
                for item in result['policies']:
                    path=stage/(item['name']+'.json')
                    path.write_text(json.dumps(item['document'],indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
                    item['file']=path.name
                    del item['document']
                (stage/'bundle.json').write_text(json.dumps(bundle,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
                (stage/'manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
                # Reserve destination exclusively, then move the completed files.
                target.mkdir(mode=0o700)
                try:
                    for path in stage.iterdir(): os.rename(path,target/path.name)
                except OSError:
                    shutil.rmtree(target)
                    raise
            finally: shutil.rmtree(stage)
            print(json.dumps({
                'status':'PACKED',
                'output_directory':str(target),
                'bundle_file':str(target/'bundle.json'),
                'manifest_file':str(target/'manifest.json'),
                'policy_count':result['policy_count'],
                'policies':[{'name':item['name'],'file':item['file'],'characters':item['characters']} for item in result['policies']],
            },indent=2))
            return 0
        if args.command=='evidence-audit':
            from .evidence_audit import reconcile,read_events
            run=json.loads(args.lifecycle.read_bytes()); source=json.loads(args.source_report.read_bytes())
            retrieval={}
            if args.events: events=read_events(args.events)
            else:
                events=cloud.lookup_events(cloud.client('cloudtrail',args.aws_profile,run['region']),run['role_arn'],cloud.parse_time(run['start']),cloud.parse_time(run['end']),max_pages=args.max_pages,max_seconds=args.max_seconds,stats=retrieval)
            result=reconcile(run,args.policy.read_bytes(),args.lockfile,source,args.metadata_dir,events)
            if retrieval:
                result['retrieval']=retrieval
                if not retrieval['complete']:
                    result['status']='review'; result['blockers'].append('cloudtrail-retrieval-incomplete')
            write_result(result)
            return 2 if args.strict and result['status']!='fixture-evidence-reconciled' else 0
        if args.command=='provider-audit':
            from .provider_audit import audit_provider
            result=audit_provider(args.source_dir,args.aws_provider_version,args.metadata_dir,args.resource)
            write_result(result)
            return 2 if args.strict and result['status']!='direct-calls-matched' else 0
        if args.command in ('validate-policy','runtime-audit'):
            if args.command=='validate-policy':
                result=cloud.validate_policy(cloud.client('accessanalyzer',args.aws_profile,args.aws_region),json.loads(args.policy.read_bytes()))
                status=2 if args.strict and result['status']!='no-findings' else 0
            else:
                retrieval={}
                if args.events:
                    if args.start or args.end or args.session_name: raise ValueError('Offline events cannot be combined with live interval')
                    raw=json.loads(args.events.read_bytes()); events=raw.get('Records',[]) if isinstance(raw,dict) else raw
                    if not isinstance(events,list): raise ValueError('Expected CloudTrail event list or Records object')
                else:
                    if not args.start or not args.end or not args.aws_region: raise ValueError('Live runtime audit requires start, end and AWS region')
                    if not args.quiet: print('CloudTrail: retrieving regional management events (bounded scan)...',file=sys.stderr,flush=True)
                    def progress(s):
                        if not args.quiet: print(f"CloudTrail: {s['pages']} pages | {s['events_scanned']} events searched | {s['matched']} role matches",file=sys.stderr,flush=True)
                    events=cloud.lookup_events(cloud.client('cloudtrail',args.aws_profile,args.aws_region),args.role_arn,cloud.parse_time(args.start),cloud.parse_time(args.end),session_names=args.session_name,max_pages=args.max_pages,max_seconds=args.max_seconds,progress=progress,stats=retrieval)
                candidate=json.loads(args.candidate.read_bytes())
                actions={r['action'] for r in candidate['permissions']}
                result=cloud.refine(events,args.role_arn,actions); status=0
                if retrieval:
                    result['retrieval']=retrieval
                    result['coverage']='PARTIAL' if not retrieval['complete'] or args.session_name else 'REGIONAL_MANAGEMENT_HISTORY'
                    if not retrieval['complete']:
                        status=2
                        print('REVIEW: CloudTrail retrieval stopped at '+retrieval['stop_reason']+'; report is partial.',file=sys.stderr)
                else: result['coverage']='OFFLINE_EXPORT'
            write_result(result)
            return status
        if args.command=='catalog-audit':
            version=selected_version(None,args.aws_provider_version)['version']
            actions=catalog_actions(version)
            from .authorization import bundled_metadata
            folder=args.metadata_dir or bundled_metadata()
            if getattr(args,'refresh',False):
                if not args.metadata_dir: raise ValueError('Maintainer refresh requires an explicit writable --metadata-dir')
                download_snapshot(args.metadata_dir,{a.split(':',1)[0] for a in actions})
                folder=args.metadata_dir
            if folder is None: raise ValueError('No packaged AWS metadata in this source checkout; use an official built distribution or an existing offline snapshot')
            result=audit(actions,[],folder)
            result['metadata_source']='explicit-offline-snapshot' if args.metadata_dir else 'packaged'
            write_result(result)
            return 2 if args.strict and result['status']!='compatible' else 0
        config=json.loads(args.backend_config.read_text()) if args.backend_config else None
        if args.directory is None and args.plan_json is None: raise ValueError('Provide a Terraform directory or --plan-json')
        plan=read_plan_json(args.plan_json) if args.plan_json else None
        variables=[]
        for item in args.var:
            key,sep,value=item.partition('=')
            if not sep or not key: raise ValueError('--var requires NAME=VALUE')
            variables.append((key,value))
        account,region,partition=args.aws_account,args.aws_region,args.aws_partition
        contexts=json.loads(args.provider_contexts.read_text()) if args.provider_contexts else None
        if args.command in ('generate','split') and not args.allow_partial:
            from .provider_context import discover_aws_identity, discover_profile_contexts
            if (account is None or region is None) and not (contexts and "aws" in contexts):
                account,region,partition=discover_aws_identity(account,region,partition)
            contexts=discover_profile_contexts(args.directory,contexts)
        report=scan(args.directory,args.phase,account,region,partition,config,plan=plan,var_files=args.var_file,variables=variables,scope_resource_tags=args.scope_resource_tags,scope_generated_names=args.scope_generated_names,provider_version=args.aws_provider_version,authorization_metadata=args.authorization_metadata,provider_contexts=contexts)
        status=2 if args.strict and report['coverage']!='COMPLETE' else 0
        require_complete_mapping=args.command in ('generate','split') and not args.allow_partial
        report['gate_failures']=gate(report,args.fail_on_risk,args.fail_on_unresolved or require_complete_mapping,args.fail_on_unmapped or require_complete_mapping,args.require_compatible_metadata,args.require_lifecycle_verified)
        if report['gate_failures']: status=4
        if args.command in ('generate','split') and (report['gate_failures'] or (args.strict and report['coverage']!='COMPLETE')):
            print(render('generate',{**report,'generation_status':'BLOCKED','policy_output':'Not written'},compact=True),file=sys.stderr); return status
        if args.command in ('generate','split') and report.get('source_only_resources'):
            report['gate_failures'].append({'kind':'stale-plan','count':len(report['source_only_resources'])})
            print(render('generate',{**report,'generation_status':'BLOCKED','policy_output':'Not written'},compact=True),file=sys.stderr); return 4
        if args.command in ('generate','split') and report['authorization_metadata']['status']=='issues':
            report['gate_failures'].append({'kind':'metadata','status':'issues'})
            print(render('generate',{**report,'generation_status':'BLOCKED','policy_output':'Not written'},compact=True),file=sys.stderr); return 1
        if args.command=='split':
            if not args.acknowledge_break_glass: raise ValueError('Split requires --acknowledge-break-glass to emit a separate destructive/delegation policy')
            from .lifecycle import split_policies
            result=split_policies(report,policy); output=json.dumps(result,indent=2)
        elif args.command=='scan' and args.format=='text':
            result=report
            lines=[f'tf-iam | {report["phase"]} | {report["coverage"]}',f'Resources: {len(report["resources"])} | Permission observations: {len(report["permissions"])}']
            mc=report['mapping_coverage']; ac=report['authorization_confidence']; lines.append(f"AWS provider: {ac['provider_version'] or 'unknown'} | Mappings: {mc['mapped_resources']}/{mc['eligible_resources']} | Lifecycle verified: {ac['lifecycle_verified_resources']} | Metadata: {report['authorization_metadata']['status']}")
            if report.get('plan'): lines.append('Input: Terraform plan JSON | Terraform '+report['plan']['terraform_version'])
            for r in report['resources']: lines.append(f'{r["status"]:11} {r["address"]}'+(' ('+' → '.join(r['operations'])+')' if 'operations' in r else ''))
            groups={}
            for r in report['permissions']:
                key=(r['provider'],r['action'],r['scope'],json.dumps(r.get('condition'),sort_keys=True))
                groups.setdefault(key,set()).add(r['source'])
            lines[1]+=f' | Unique grants: {len(groups)}'
            ss=report['scope_summary']; lines.append(f"Scopes: {ss['exact']} exact | {ss['bounded_wildcard']} bounded wildcard | {ss['global']} global | {ss['conditional']} conditional | {ss['unresolved']} unresolved")
            for (provider,action,scope,condition),sources in sorted(groups.items()):
                lines.append(f'{provider:5} {action} [{scope}] ({len(sources)} sources)'+(' '+condition if condition!='null' else ''))
            lines.extend('RISK ['+r['severity']+']: '+r['provider']+' '+', '.join(r['actions'])+' — '+r['message'] for r in report['risks'])
            lines.extend('GATE: '+json.dumps(g,sort_keys=True) for g in report['gate_failures']); lines.extend('REVIEW: '+w for w in report['warnings']); output='\n'.join(lines)
        elif args.command=='scan': result=report; output=json.dumps(report,indent=2)
        elif args.command=='generate':
            result=policy(report,args.provider,args.name,args.scope)
            from .policy_size import size as policy_characters, LIMITS
            candidate_size=policy_characters(result)
            if candidate_size>LIMITS['managed']:
                print(
                    f'NOTICE: Generated policy contains {candidate_size} IAM characters, '
                    f'exceeding the {LIMITS["managed"]}-character customer-managed policy limit. '
                    'The candidate is not attachable as one managed policy. '
                    'Run: tfiam pack-policy policy.json --output-dir policy-bundle',
                    file=sys.stderr,
                )
            if args.format=='terraform': output=json.dumps(terraform(result,args.provider,args.name,args.scope),indent=2)
            else: output=json.dumps(result,indent=2)
        else:
            existing,identity=cloud.role_policies(cloud.client('iam',args.aws_profile,args.aws_region),args.role_name) if args.role_name else (json.loads(args.existing.read_text()),None)
            result=compare(report,args.provider,existing); result['identity']=identity; result['gate_failures']=report['gate_failures']; result['scan_warnings']=report['warnings']; result['information']=report['information']; result['resolved_dependencies']=report['resolved_dependencies']; result['unresolved_permissions']=report['unresolved_permissions']; result['scope_summary']=report['scope_summary']; result['mapping_coverage']=report['mapping_coverage']; result['authorization_confidence']=report['authorization_confidence']; result['authorization_metadata']=report['authorization_metadata']; result['input']=report['input']; result['plan']=report.get('plan'); result['risks']=[r for r in report['risks'] if r['provider']==args.provider]; output=json.dumps(result,indent=2)
            if args.fail_on_missing and (result['missing_or_unverified'] or result['explicitly_denied']) and status!=4: status=3
        if args.command=='generate':
            display={**report,**result,'policy_output':str(args.output) if args.output else 'stdout','generation_status':'GENERATED'}
            if args.format=='table':
                write_result(display)
            else:
                if args.output: args.output.write_text(output+'\n',encoding='utf-8')
                else: print(output)
                print(render('generate',display,compact=not args.show_table),file=sys.stderr)
        else: write_result(result,output)
        return status
    except (ValueError,OSError,TypeError,AttributeError,KeyError) as e:
        print('ERROR: '+str(e),file=sys.stderr); return 1
    except Exception as e:
        # AWS SDK errors can contain request or identity details; avoid echoing them.
        print('ERROR: operation failed ('+type(e).__name__+')',file=sys.stderr); return 1
if __name__=='__main__': sys.exit(main())
