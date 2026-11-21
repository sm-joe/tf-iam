import argparse, json, sys, fnmatch
from pathlib import Path
from .scan import scan
from .authorization import catalog_actions, download_snapshot, audit
from .versioning import selected_version

def policy(report,provider,name,scope):
    rows=[r for r in report['permissions'] if r['provider']==provider]
    if not rows: raise ValueError('No mapped permissions for '+provider)
    if provider=='aws':
        groups={}
        for r in rows: groups.setdefault((r['scope'],json.dumps(r.get('condition'),sort_keys=True)),set()).add(r['action'])
        return {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':sorted(a),'Resource':s, **({'Condition':json.loads(c)} if c!='null' else {})} for (s,c),a in sorted(groups.items())]}
    raise ValueError('Only AWS is supported')

def terraform(p,provider,name,scope):
    if provider=='aws': typ='aws_iam_policy'; body={'name':name,'policy':json.dumps(p)}
    else: raise ValueError('Only AWS is supported')
    return {'resource':{typ:{'candidate':body}}}

def matches(pattern,value): return fnmatch.fnmatchcase(value.lower(),pattern.lower())
def arr(x): return x if isinstance(x,list) else [x]
def compare(report,provider,existing):
    rows=[r for r in report['permissions'] if r['provider']==provider]; grants=[]; uncertain=[]; denies=[]
    if provider=='aws':
        for s in arr(existing.get('Statement',[])):
            if s.get('Condition') or 'NotAction' in s or 'NotResource' in s or 'Principal' in s:
                uncertain.append('Complex AWS statement requires manual evaluation'); continue
            target=grants if s.get('Effect')=='Allow' else denies
            for a in arr(s.get('Action',[])):
                for r in arr(s.get('Resource',[])): target.append((a,r,'management'))
    else: raise ValueError('Only AWS is supported')
    def covers(g,r):
        a,s,p=g
        return p==r['plane'] and matches(a,r['action']) and (provider!='aws' or (s=='*' or s==r['scope'] or ('*' not in r['scope'] and fnmatch.fnmatchcase(r['scope'],s))))
    missing=[]; blocked=[]
    for r in rows:
        if any(covers(g,r) for g in denies): blocked.append(r)
        elif not any(covers(g,r) for g in grants): missing.append(r)
    excess=[{'action':a,'scope':s,'plane':p} for a,s,p in grants if '*' in a or '?' in a or not any(covers((a,s,p),r) for r in rows) or (provider=='aws' and s=='*' and any(covers((a,s,p),r) and r['scope']!='*' for r in rows))]
    return {'coverage':'PARTIAL','missing_or_unverified':missing,'explicitly_denied':blocked,'potentially_excessive':excess,'warnings':uncertain+['Static comparison only; inherited policies, conditions, boundaries, SCPs, assignments and unknown resources are not evaluated. Do not automatically revoke permissions.']}

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

def main(argv=None):
    parser=argparse.ArgumentParser(prog='tfiam',description='Terraform IAM candidate policy analyzer')
    sub=parser.add_subparsers(dest='command',required=True)
    catalog=sub.add_parser('catalog-audit',help='Audit catalog action names using AWS service authorization snapshots')
    catalog.add_argument('--metadata-dir',type=Path,required=True)
    catalog.add_argument('--refresh',action='store_true',help='Download public AWS service metadata')
    catalog.add_argument('--aws-provider-version')
    catalog.add_argument('--output',type=Path)
    catalog.add_argument('--strict',action='store_true')
    for cmd in ('scan','generate','compare'):
        p=sub.add_parser(cmd); p.add_argument('directory',type=Path,nargs='?'); p.add_argument('--plan-json',type=Path,help='Saved terraform show -json output; optional directory supplies backend and lockfile'); p.add_argument('--phase',choices=['plan','apply','destroy'],default='apply'); p.add_argument('--var-file',action='append',type=Path,default=[]); p.add_argument('--var',action='append',default=[],metavar='NAME=VALUE'); p.add_argument('--scope-resource-tags',action='store_true',help='Restrict supported existing-resource EC2 mutations to stable saved-plan tags'); p.add_argument('--aws-provider-version',help='Exact provider version if lockfile unavailable'); p.add_argument('--authorization-metadata',type=Path,help='Local AWS service authorization metadata'); p.add_argument('--aws-account'); p.add_argument('--aws-region'); p.add_argument('--aws-partition',default='aws'); p.add_argument('--backend-config',type=Path,help='JSON backend overrides'); p.add_argument('--output',type=Path); p.add_argument('--strict',action='store_true',help='Exit 2 when analysis is partial')
        if cmd=='scan': p.add_argument('--format',choices=['text','json'],default='text')
        else: p.add_argument('--provider',default='aws',choices=['aws'])
        if cmd=='generate':
            p.add_argument('--format',choices=['json','terraform'],default='json'); p.add_argument('--name',default='TerraformPipeline'); p.add_argument('--scope'); p.add_argument('--allow-partial',action='store_true',required=True,help='Explicitly accept candidate-only policy generation')
        if cmd=='compare': p.add_argument('--existing',required=True,type=Path); p.add_argument('--fail-on-missing',action='store_true')
    args=parser.parse_args(argv)
    try:
        if args.command=='catalog-audit':
            version=selected_version(None,args.aws_provider_version)['version']
            actions=catalog_actions(version)
            if args.refresh: download_snapshot(args.metadata_dir,{a.split(':',1)[0] for a in actions})
            result=audit(actions,[],args.metadata_dir)
            output=json.dumps(result,indent=2)
            if args.output: args.output.write_text(output+'\n',encoding='utf-8')
            else: print(output)
            return 2 if args.strict and result['status']!='compatible' else 0
        config=json.loads(args.backend_config.read_text()) if args.backend_config else None
        if args.directory is None and args.plan_json is None: raise ValueError('Provide a Terraform directory or --plan-json')
        plan=read_plan_json(args.plan_json) if args.plan_json else None
        variables=[]
        for item in args.var:
            key,sep,value=item.partition('=')
            if not sep or not key: raise ValueError('--var requires NAME=VALUE')
            variables.append((key,value))
        report=scan(args.directory,args.phase,args.aws_account,args.aws_region,args.aws_partition,config,plan=plan,var_files=args.var_file,variables=variables,scope_resource_tags=args.scope_resource_tags,provider_version=args.aws_provider_version,authorization_metadata=args.authorization_metadata)
        status=2 if args.strict and report['coverage']!='COMPLETE' else 0
        if args.command=='generate' and report['authorization_metadata']['status']=='issues': raise ValueError('AWS authorization metadata audit reports invalid actions or resource scopes; review scan findings before generating')
        if args.command=='scan' and args.format=='text':
            lines=[f'TF IAM Scope | {report["phase"]} | {report["coverage"]}',f'Resources: {len(report["resources"])} | Permission observations: {len(report["permissions"])}']
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
            lines.extend('RISK: '+r['provider']+' '+', '.join(r['actions'])+' — '+r['message'] for r in report['risks'])
            lines.extend('REVIEW: '+w for w in report['warnings']); output='\n'.join(lines)
        elif args.command=='scan': output=json.dumps(report,indent=2)
        elif args.command=='generate':
            print(f'REVIEW: {len(report["warnings"])} scan warnings; run scan for details.',file=sys.stderr)
            for risk in report['risks']:
                if risk['provider']==args.provider: print('RISK: '+', '.join(risk['actions'])+' — '+risk['message'],file=sys.stderr)
            result=policy(report,args.provider,args.name,args.scope)
            if args.format=='terraform': result=terraform(result,args.provider,args.name,args.scope)
            output=json.dumps(result,indent=2)
        else:
            result=compare(report,args.provider,json.loads(args.existing.read_text())); result['scan_warnings']=report['warnings']; result['unresolved_permissions']=report['unresolved_permissions']; result['scope_summary']=report['scope_summary']; result['mapping_coverage']=report['mapping_coverage']; result['authorization_confidence']=report['authorization_confidence']; result['authorization_metadata']=report['authorization_metadata']; result['input']=report['input']; result['plan']=report.get('plan'); result['risks']=[r for r in report['risks'] if r['provider']==args.provider]; output=json.dumps(result,indent=2)
            if args.fail_on_missing and (result['missing_or_unverified'] or result['explicitly_denied']): status=3
        if args.output: args.output.write_text(output+'\n',encoding='utf-8')
        else: print(output)
        return status
    except (ValueError,OSError,TypeError,AttributeError,KeyError) as e:
        print('ERROR: '+str(e),file=sys.stderr); return 1
if __name__=='__main__': sys.exit(main())
