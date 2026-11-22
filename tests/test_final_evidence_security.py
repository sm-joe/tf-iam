import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path
import pytest
from tfiam.risk import gate, assess

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/(name+".py"))
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def test_dynamodb_fixture(tmp_path):
    mod=load("accept-dynamodb")
    dest=tmp_path/"fixture"
    mod.prepare(Namespace(directory=dest,version="6.73.0",account="123456789012",region="us-east-1"))
    info=json.loads((dest/"prepare.json").read_text())
    candidate=json.loads((dest/"candidate-policy.json").read_text())
    grants=mod.grants(candidate)
    assert len(grants)==33
    assert grants==mod.grants(mod.candidate_for(info))
    assert all(a.startswith("dynamodb:") and "table/tfiam-test-" in r for a,r in grants)

def test_release_gate_rejects_symlink(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT/"scripts"))
    mod=load("check-release")
    proof=tmp_path/"proof"
    proof.write_text("test")
    alias=tmp_path/"alias"
    alias.symlink_to(proof)
    import hashlib
    row={"status":"passed","artifact":"alias","sha256":hashlib.sha256(proof.read_bytes()).hexdigest()}
    path=tmp_path/"manifest.json"
    path.write_text(json.dumps({"commit":"a"*40,"provider_version":"6.73.0","checks":{"create":row}}))
    result=mod.check(path,"a"*40)
    assert not result["ready"] and "create" in result["missing_or_invalid"]

def test_lifecycle_gate_rejects_incomplete_inputs():
    report={"authorization_confidence":{"provider_version":"6.73.0","lifecycle_verified_resources":1},"mapping_coverage":{"eligible_resources":1},"input_blockers":["Incomplete plan"]}
    assert gate(report,lifecycle_verified=True)[0]["kind"]=="lifecycle-evidence"

def test_new_sensitive_operations_require_review():
    for action in ("kms:CreateGrant","secretsmanager:CreateSecret","rds:PromoteReadReplica"):
        findings=assess([{"provider":"aws","action":action,"scope":"arn:aws:example","source":"test"}])
        assert any(f["severity"]=="HIGH" for f in findings)
