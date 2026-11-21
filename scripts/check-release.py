"""Fail closed on missing release evidence. Manifest attestation is not empirical proof."""
import argparse,json,hashlib,re
from pathlib import Path
REQUIRED=("create","update","delete","replace-create-first","replace-delete-first","restricted-role-lifecycle","provider-source-review","module-resolution","authorization-metadata","access-analyzer","cloudtrail","secret-redaction","backend-locking","risk-gates","linux-binary")
def check(path, expected_commit=None):
    path=Path(path)
    data=json.loads(path.read_bytes())
    if not isinstance(data,dict) or not re.fullmatch(r"\d+\.\d+\.\d+",data.get("provider_version","")): raise ValueError("Exact AWS provider version required")
    if not re.fullmatch(r"[a-f0-9]{40}",data.get("commit","")): raise ValueError("Exact tested commit required")
    if expected_commit and data["commit"]!=expected_commit: raise ValueError("Evidence commit does not match release target")
    items=data.get("checks",{})
    if not isinstance(items,dict): raise ValueError("Invalid acceptance checks")
    missing=[]
    for name in REQUIRED:
        row=items.get(name,{})
        if row.get("status")!="passed" or not row.get("artifact") or not re.fullmatch(r"[a-f0-9]{64}",row.get("sha256","")):
            missing.append(name); continue
        artifact=(path.parent/row["artifact"]).resolve()
        if not artifact.is_relative_to(path.parent.resolve()) or not artifact.is_file():
            missing.append(name); continue
        if hashlib.sha256(artifact.read_bytes()).hexdigest()!=row["sha256"]: missing.append(name)
    return {"ready":not missing,"missing_or_invalid":missing,"commit":data["commit"],"provider_version":data["provider_version"]}
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("manifest",type=Path)
    parser.add_argument("--expected-commit")
    args=parser.parse_args()
    result=check(args.manifest,args.expected_commit)
    print(json.dumps(result,indent=2))
    return 0 if result["ready"] else 2
if __name__=="__main__": raise SystemExit(main())
