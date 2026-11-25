"""Private release tooling only; fixtures below are synthetic, not AWS evidence."""
import importlib.util
import json
import tarfile
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("assemble_release_evidence",ROOT/"scripts"/"assemble-release-evidence.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def fixture(tmp_path):
    base=tmp_path/"release"
    base.mkdir()
    evidence=base/"lifecycle.json"
    evidence.write_text(json.dumps({"synthetic":True}))
    sha=mod.digest(evidence)
    draft={"commit":"a"*40,"provider_version":"6.73.0",
           "checks":{"restricted-role-lifecycle":{"status":"review","artifact":"lifecycle.json","sha256":sha}},
           "supplemental":{"lifecycle.json":sha}}
    mod.write(base/"release-review-draft.json",draft)
    args=Namespace(source_commit="a"*40,provider_version="6.73.0",confirm_reviewed=True)
    life=SimpleNamespace(check_bundle=lambda *args:None)
    gate=SimpleNamespace(REQUIRED=("restricted-role-lifecycle",),check=lambda *args:{"ready":True})
    return base,args,life,gate

def test_seal_requires_review_confirmation(tmp_path):
    base,args,life,gate=fixture(tmp_path)
    args.confirm_reviewed=False
    with pytest.raises(ValueError,match="review confirmation"):
        mod.seal(args,base,life,gate)
    assert not (base/"manifest.json").exists()

def test_seal_rejects_changed_evidence(tmp_path):
    base,args,life,gate=fixture(tmp_path)
    (base/"lifecycle.json").write_text("changed")
    with pytest.raises(ValueError,match="Reviewed evidence changed"):
        mod.seal(args,base,life,gate)

def test_seal_archives_only_reviewed_files(tmp_path):
    base,args,life,gate=fixture(tmp_path)
    (base/"unreviewed-private-file.txt").write_text("synthetic private file")
    mod.seal(args,base,life,gate)
    archive=tmp_path/"release-evidence.tar.gz"
    with tarfile.open(archive,"r:gz") as tar:
        assert set(tar.getnames())=={"lifecycle.json","manifest.json"}
        doc=json.load(tar.extractfile("manifest.json"))
        assert doc["review_confirmed"] is True
        assert doc["checks"]["restricted-role-lifecycle"]["status"]=="passed"

def test_private_evidence_path_rejects_symlinks_and_traversal(tmp_path):
    source=tmp_path/"proof"
    source.write_text("test")
    alias=tmp_path/"alias"
    try:
    alias.symlink_to(source)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink creation requires Developer Mode or SeCreateSymbolicLinkPrivilege")
        raise
    with pytest.raises(ValueError,match="symlinks"):
        mod.ordinary(tmp_path,"alias")
    with pytest.raises(ValueError,match="Unsafe"):
        mod.ordinary(tmp_path,"../proof")
