import json
from pathlib import Path
import pytest
from tfiam.scan import scan
from tfiam.cli import policy,compare,terraform,main
ROOT=Path(__file__).resolve().parents[1]/'examples'
def test_backend_and_scope():
    r=scan(ROOT/'multicloud'); p=policy(r,'aws','test',None)
    assert any(s['Resource'].endswith('.tflock') and 's3:DeleteObject' in s['Action'] for s in p['Statement'])
    assert not any(s['Resource'].endswith('.tfstate') and 's3:DeleteObject' in s['Action'] for s in p['Statement'])
    assert any(x['status']=='UNSUPPORTED' for x in r['resources'])
    assert r['coverage']=='PARTIAL'
def test_plan():
    r=scan(ROOT/'multicloud','plan'); a={x['action'] for x in r['permissions']}; assert 's3:CreateBucket' not in a; assert 's3:PutObject' in a
def test_compare():
    r=scan(ROOT/'multicloud'); c=compare(r,'aws',json.loads((ROOT/'existing-aws.json').read_text())); assert not c['missing_or_unverified']; assert c['potentially_excessive']
def test_deny():
    r=scan(ROOT/'multicloud'); c=compare(r,'aws',{'Statement':[{'Effect':'Deny','Action':'s3:*','Resource':'*'}]}); assert c['explicitly_denied']
def test_outputs():
    r=scan(ROOT/'multicloud'); assert 'includedPermissions' in policy(r,'gcp','Test',None); p=policy(r,'azure','Test','/subscriptions/example'); assert 'azurerm_role_definition' in terraform(p,'azure','Test','/subscriptions/example')['resource']
def test_strict(tmp_path):
    assert main(['scan',str(ROOT/'multicloud'),'--strict','--output',str(tmp_path/'report')])==2
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
    assert main(['scan',str(ROOT/'eks'),'--phase','plan','--aws-account','123456789012','--aws-region','us-east-1'])==0
    output=capsys.readouterr().out; assert 'Unique grants:' in output; assert len([l for l in output.splitlines() if 'iam:ListAttachedRolePolicies [' in l])==3

def test_unresolved_eks_no_wildcard_passrole():
    r=scan(ROOT/'eks'); assert not any(x['action'] in ('iam:PassRole','iam:AttachRolePolicy','iam:CreateRole') for x in r['permissions'])
