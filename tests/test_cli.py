import json
from pathlib import Path
import pytest
from tfiam.scan import scan
from tfiam.cli import policy,compare,terraform,main
ROOT=Path(__file__).resolve().parents[1]/'examples'
def test_backend_and_scope():
    r=scan(ROOT/'aws'); p=policy(r,'aws','test',None)
    resources=lambda row: row['Resource'] if isinstance(row['Resource'],list) else [row['Resource']]
    assert any(any(resource.endswith('.tflock') for resource in resources(s)) and 's3:DeleteObject' in s['Action'] for s in p['Statement'])
    assert not any(any(resource.endswith('.tfstate') for resource in resources(s)) and 's3:DeleteObject' in s['Action'] for s in p['Statement'])
    assert any(x['status']=='UNSUPPORTED' for x in r['resources'])
    assert r['coverage']=='PARTIAL'
def test_plan():
    r=scan(ROOT/'aws','plan'); a={x['action'] for x in r['permissions']}; assert 's3:CreateBucket' not in a; assert 's3:PutObject' in a
def test_compare():
    r=scan(ROOT/'aws'); c=compare(r,'aws',json.loads((ROOT/'existing-aws.json').read_text())); assert not c['missing_or_unverified']; assert c['potentially_excessive']
def test_deny():
    r=scan(ROOT/'aws'); c=compare(r,'aws',{'Statement':[{'Effect':'Deny','Action':'s3:*','Resource':'*'}]}); assert c['explicitly_denied']
def test_outputs():
    r=scan(ROOT/'aws'); p=policy(r,'aws','Test',None); assert 'aws_iam_policy' in terraform(p,'aws','Test',None)['resource']
def test_strict(tmp_path):
    assert main(['scan',str(ROOT/'aws'),'--strict','--output',str(tmp_path/'report')])==2
    assert (tmp_path/'report').exists()
def test_local_module(tmp_path):
    (tmp_path/'main.tf.json').write_text(json.dumps({'module':{'child':{'source':'./child'}}})); (tmp_path/'child').mkdir(); (tmp_path/'child'/'main.tf.json').write_text(json.dumps({'resource':{'aws_s3_bucket':{'x':{'bucket':'test'}}}})); assert scan(tmp_path)['resources'][0]['type']=='aws_s3_bucket'
def test_hcl():
    pytest.importorskip('hcl2'); assert scan(ROOT/'aws-hcl')['resources'][0]['type']=='aws_s3_bucket'

def test_eks_regression(capsys):
    r=scan(ROOT/'eks','apply','123456789012','us-east-1'); assert len(r['resources'])==13; assert not any(x['status']=='UNSUPPORTED' for x in r['resources'])
    p=policy(r,'aws','test',None); statements=p['Statement']; actions={a for s in statements for a in s['Action']}
    assert {'eks:CreateCluster','eks:CreateNodegroup','eks:CreateAddon','eks:CreatePodIdentityAssociation','iam:PassRole'} <= actions
    assert all(s['Resource']!='*' and 'Condition' in s for s in statements if 'iam:PassRole' in s['Action'] or 'iam:AttachRolePolicy' in s['Action'])
    assert all(s['Resource']!='*' for s in statements if 'iam:CreateRole' in s['Action'])
    plan=scan(ROOT/'eks','plan','123456789012','us-east-1'); assert not any('Create' in x['action'] or x['action']=='iam:PassRole' for x in plan['permissions'])
    assert main(['scan',str(ROOT/'eks'),'--phase','plan','--format','text','--aws-account','123456789012','--aws-region','us-east-1'])==0
    output=capsys.readouterr().out; assert 'Unique grants:' in output; assert len([l for l in output.splitlines() if 'iam:ListAttachedRolePolicies [' in l])==3

def test_unresolved_eks_no_wildcard_passrole():
    r=scan(ROOT/'eks'); assert not any(x['action'] in ('iam:PassRole','iam:AttachRolePolicy','iam:CreateRole') for x in r['permissions'])

def test_table_output_and_json_side_by_side(tmp_path,capsys):
    report=tmp_path/"report.json"
    assert main(["scan",str(ROOT/"aws"),"--format","json","--show-table","--output",str(report)])==0
    assert json.loads(report.read_text())["permissions"]
    assert "PERMISSIONS" in capsys.readouterr().err
    assert main(["scan",str(ROOT/"aws"),"--format","table"])==0
    out=capsys.readouterr().out
    assert "SUMMARY" in out and "Unique grants" in out and "PERMISSIONS" in out and "+---" in out
    assert main(["generate",str(ROOT/"aws"),"--allow-partial","--format","table"])==0
    assert "POLICY GRANTS" in capsys.readouterr().out
    assert main(["compare",str(ROOT/"aws"),"--existing",str(ROOT/"existing-aws.json"),"--format","table"])==0
    assert "SUMMARY" in capsys.readouterr().out

def test_review_and_validation_are_tables(capsys,monkeypatch,tmp_path):
    from tfiam import cloud
    from tfiam.table_output import render
    out=render("validate-policy",{"status":"no-findings","counts":{"ERROR":0},"findings":[],"limitation":"Syntax only"})
    assert "INFORMATION AND LIMITATIONS" in out and "| INFO" in out and "REVIEW:" not in out
    assert "FINDINGS" in out and "| None" in out
    target=tmp_path/"policy.json"
    assert main(["generate",str(ROOT/"aws"),"--allow-partial","--format","json","--show-table","--output",str(target)])==0
    assert set(json.loads(target.read_text()))=={"Version","Statement"}
    output=capsys.readouterr().err
    assert "REVIEW REQUIREMENTS" in output and "REVIEW:" not in output

def test_table_borders_each_logical_row():
    from tfiam.table_output import table
    output=table(["Action","Scope"],[("Read","first"),("Write","second"),("Delete","third")],[20,20])
    lines=output.splitlines()
    assert len(lines)==9
    assert all(lines[i]==lines[0] for i in (0,2,4,6,8))
    assert all(lines[i].startswith("|") and lines[i].endswith("|") for i in (1,3,5,7))

def test_table_wrapped_row_has_single_enclosing_border():
    from tfiam.table_output import table
    lines=table(["Action","Scope"],[("Read","abcdefghijklmnopqrstuvwxyz"),("Write","short")],[8,8]).splitlines()
    borders=[i for i,line in enumerate(lines) if line.startswith("+")]
    assert borders==[0,2,7,9]
    assert all(len(line)==len(lines[0]) for line in lines)
    assert "Read" in lines[3] and "Write" in lines[8]
    assert all(line.startswith("|") and line.endswith("|") for line in lines[3:7])

def test_empty_table_has_enclosed_placeholder():
    from tfiam.table_output import table
    lines=table(["Source","Reason"],[],[10,10]).splitlines()
    assert len(lines)==5 and lines[0]==lines[2]==lines[4]
    assert "None" in lines[3]

def test_generation_default_decision_grid(tmp_path,capsys):
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_s3_bucket_versioning":{"x":{"bucket":"fixture-bucket","versioning_configuration":{"status":"Enabled"}}}}}))
    dest=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--output",str(dest)])==0
    captured=capsys.readouterr()
    assert not captured.out
    assert set(json.loads(dest.read_text()))=={"Version","Statement"}
    assert "POLICY SUMMARY" in captured.err and "GENERATED" in captured.err
    assert "Sensitive permission findings" in captured.err
    assert "RISKS" not in captured.err
    assert "RISK:" not in captured.err and "REVIEW:" not in captured.err
    assert "POLICY GRANTS" not in captured.err
    assert main(["generate",str(tmp_path)])==0
    captured=capsys.readouterr()
    assert json.loads(captured.out)["Statement"]
    assert "POLICY SUMMARY" in captured.err

def test_generation_blocked_decision_grid(tmp_path,capsys):
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_unknown_fixture":{"x":{}}}}))
    dest=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--output",str(dest)])==0
    assert json.loads(dest.read_text())=={"Version":"2012-10-17","Statement":[]}
    report=json.loads((tmp_path/"policy.json.report.json").read_text())
    assert report["candidate_status"]=="INCOMPLETE"
    assert report["mapping_coverage"]["unmapped_resources"]==1
    out=capsys.readouterr().err
    assert "GENERATED" in out and "BLOCKED" not in out
    dest.unlink()
    assert main(["generate",str(tmp_path),"--require-complete","--output",str(dest)])==4
    assert not dest.exists()
