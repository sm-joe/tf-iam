import argparse, json, sys, fnmatch, re
from pathlib import Path
from .scan import scan

def policy(report,provider,name,scope):
    rows=[r for r in report['permissions'] if r['provider']==provider]
    if not rows: raise ValueError('No mapped permissions for '+provider)
    if provider=='aws':
        groups={}
        for r in rows: groups.setdefault((r['scope'],json.dumps(r.get('condition'),sort_keys=True)),set()).add(r['action'])
        return {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':sorted(a),'Resource':s, **({'Condition':json.loads(c)} if c!='null' else {})} for (s,c),a in sorted(groups.items())]}
    if provider=='gcp':
        return {'title':name,'description':'Candidate Terraform deployment permissions; review report before use','stage':'GA','includedPermissions':sorted({r['action'] for r in rows})}
    if not scope: raise ValueError('--scope required for Azure role definition')
    return {'Name':name,'IsCustom':True,'Description':'Candidate Terraform deployment permissions','Actions':sorted({r['action'] for r in rows if r['plane']=='management'}),'NotActions':[],'DataActions':sorted({r['action'] for r in rows if r['plane']=='data'}),'NotDataActions':[],'AssignableScopes':[scope]}

def terraform(p,provider,name,scope):
    if provider=='aws': typ='aws_iam_policy'; body={'name':name,'policy':json.dumps(p)}
    elif provider=='gcp':
        if not scope: raise ValueError('--scope must be GCP project ID')
        if not re.fullmatch(r'[a-zA-Z0-9_.]{3,64}',name): raise ValueError('GCP Terraform role ID must be 3–64 letters, digits, underscores or dots')
        typ='google_project_iam_custom_role'; body={'project':scope,'role_id':name,'title':name,'permissions':p['includedPermissions'],'stage':'GA'}
    else:
        typ='azurerm_role_definition'; body={'name':name,'scope':scope,'assignable_scopes':[scope],'permissions':[{'actions':p['Actions'],'not_actions':[],'data_actions':p['DataActions'],'not_data_actions':[]}]}
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
    elif provider=='gcp':
        if 'includedPermissions' not in existing: raise ValueError('Expected GCP custom role definition, not IAM bindings')
        grants=[(a,'*','management') for a in existing['includedPermissions']]
    else:
        props=existing.get('properties',existing)
        perms=props.get('permissions',[props])
        for p in perms:
            for key,exclude,plane in [('actions','notActions','management'),('dataActions','notDataActions','data')]:
                def get(k): return p.get(k,p.get(k[0].upper()+k[1:],[]))
                if get(exclude): uncertain.append('Azure exclusions present; affected grant coverage requires review'); continue
                grants.extend((a,'*',plane) for a in get(key))
    def covers(g,r):
        a,s,p=g
        return p==r['plane'] and matches(a,r['action']) and (provider!='aws' or (s=='*' or s==r['scope'] or ('*' not in r['scope'] and matches(s,r['scope']))))
    missing=[]; blocked=[]
    for r in rows:
        if any(covers(g,r) for g in denies): blocked.append(r)
        elif not any(covers(g,r) for g in grants): missing.append(r)
    excess=[{'action':a,'scope':s,'plane':p} for a,s,p in grants if '*' in a or '?' in a or not any(covers((a,s,p),r) for r in rows) or (provider=='aws' and s=='*' and any(covers((a,s,p),r) and r['scope']!='*' for r in rows))]
    return {'coverage':'PARTIAL','missing_or_unverified':missing,'explicitly_denied':blocked,'potentially_excessive':excess,'warnings':uncertain+['Static comparison only; inherited policies, conditions, boundaries, SCPs, assignments and unknown resources are not evaluated. Do not automatically revoke permissions.']}

def main(argv=None):
    parser=argparse.ArgumentParser(prog='tfiam',description='Terraform IAM candidate policy analyzer')
    sub=parser.add_subparsers(dest='command',required=True)
    for cmd in ('scan','generate','compare'):
        p=sub.add_parser(cmd); p.add_argument('directory',type=Path); p.add_argument('--phase',choices=['plan','apply','destroy'],default='apply'); p.add_argument('--aws-account'); p.add_argument('--aws-region'); p.add_argument('--aws-partition',default='aws'); p.add_argument('--backend-config',type=Path,help='JSON backend overrides'); p.add_argument('--output',type=Path); p.add_argument('--strict',action='store_true',help='Exit 2 when analysis is partial')
        if cmd=='scan': p.add_argument('--format',choices=['text','json'],default='text')
        else: p.add_argument('--provider',required=True,choices=['aws','gcp','azure'])
        if cmd=='generate':
            p.add_argument('--format',choices=['json','terraform'],default='json'); p.add_argument('--name',default='TerraformPipeline'); p.add_argument('--scope'); p.add_argument('--allow-partial',action='store_true',required=True,help='Explicitly accept candidate-only policy generation')
        if cmd=='compare': p.add_argument('--existing',required=True,type=Path); p.add_argument('--fail-on-missing',action='store_true')
    args=parser.parse_args(argv)
    try:
        config=json.loads(args.backend_config.read_text()) if args.backend_config else None
        report=scan(args.directory,args.phase,args.aws_account,args.aws_region,args.aws_partition,config)
        status=2 if args.strict and report['coverage']!='COMPLETE' else 0
        if args.command=='scan' and args.format=='text':
            lines=[f'TF IAM Scope | {report["phase"]} | {report["coverage"]}',f'Resources: {len(report["resources"])} | Permission observations: {len(report["permissions"])}']
            for r in report['resources']: lines.append(f'{r["status"]:11} {r["address"]}')
            groups={}
            for r in report['permissions']:
                key=(r['provider'],r['action'],r['scope'],json.dumps(r.get('condition'),sort_keys=True))
                groups.setdefault(key,set()).add(r['source'])
            lines[1]+=f' | Unique grants: {len(groups)}'
            for (provider,action,scope,condition),sources in sorted(groups.items()):
                lines.append(f'{provider:5} {action} [{scope}] ({len(sources)} sources)'+(' '+condition if condition!='null' else ''))
            lines.extend('RISK: '+r['provider']+' '+', '.join(r['actions'])+' — '+r['message'] for r in report['risks'])
            lines.extend('REVIEW: '+w for w in report['warnings']); output='\n'.join(lines)
        elif args.command=='scan': output=json.dumps(report,indent=2)
        elif args.command=='generate':
            print(f'REVIEW: {len(report["warnings"])} scan warnings; run scan for details.',file=sys.stderr)
            if args.provider!='aws': print('REVIEW: role definition combines permissions across scopes; split backend and infrastructure roles before assigning.',file=sys.stderr)
            for risk in report['risks']:
                if risk['provider']==args.provider: print('RISK: '+', '.join(risk['actions'])+' — '+risk['message'],file=sys.stderr)
            result=policy(report,args.provider,args.name,args.scope)
            if args.format=='terraform': result=terraform(result,args.provider,args.name,args.scope)
            output=json.dumps(result,indent=2)
        else:
            result=compare(report,args.provider,json.loads(args.existing.read_text())); result['scan_warnings']=report['warnings']; result['risks']=[r for r in report['risks'] if r['provider']==args.provider]; output=json.dumps(result,indent=2)
            if args.fail_on_missing and (result['missing_or_unverified'] or result['explicitly_denied']): status=3
        if args.output: args.output.write_text(output+'\n',encoding='utf-8')
        else: print(output)
        return status
    except (ValueError,OSError,TypeError,AttributeError,KeyError) as e:
        print('ERROR: '+str(e),file=sys.stderr); return 1
if __name__=='__main__': sys.exit(main())
