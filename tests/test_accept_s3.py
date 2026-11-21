import importlib.util
import json
from pathlib import Path
import pytest

SPEC=importlib.util.spec_from_file_location("accept_s3",Path(__file__).resolve().parents[1]/"scripts"/"accept-s3.py")
M=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)

def test_prepare_fixture(tmp_path):
    from argparse import Namespace
    root=tmp_path/"fixture"
    M.prepare(Namespace(directory=root,version="6.73.0",account="123456789012",region="us-east-1"))
    data=json.loads((root/"prepare.json").read_text())
    policy=json.loads((root/"candidate-policy.json").read_text())
    grants=M.grants(policy)
    assert len({r for _,r in grants})==2
    assert all(("s3:PutBucketVersioning","arn:aws:s3:::"+b) in grants for b in data["buckets"])
    assert data["candidate_sha256"]==M.digest(root/"candidate-policy.json")
    assert json.loads((root/"main.tf.json").read_text())["terraform"]["required_providers"]["aws"]["version"]=="=6.73.0"

def test_lifecycle_shape_fail_closed():
    doc={"resource_changes":[{"address":a,"mode":"managed","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create","delete"]}} for a in M.RESOURCES]}
    assert len(M.check_operations(doc,["create","delete"]))==3
    with pytest.raises(ValueError): M.check_operations(doc,["delete","create"])
    doc["resource_changes"].pop()
    with pytest.raises(ValueError): M.check_operations(doc,["create","delete"])

def test_role_policy_rejects_wildcards():
    with pytest.raises(ValueError): M.grants({"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]})
