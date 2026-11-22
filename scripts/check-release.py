"""Fail closed on missing release evidence. Manifest attestation is not empirical proof."""
import argparse,json,hashlib,re,os
from lifecycle_evidence import check_bundle, collect_bundle, artifact as checked_artifact
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
        if not isinstance(row,dict) or row.get("status")!="passed":
            missing.append(name); continue
        try: artifact=checked_artifact(path.parent,row)
        except (ValueError,TypeError,OSError):
            missing.append(name); continue
        if name=="restricted-role-lifecycle":
            try: check_bundle(artifact,data["commit"],data["provider_version"])
            except (ValueError,TypeError,KeyError,OSError): missing.append(name)
    return {"ready":not missing,"missing_or_invalid":missing,"commit":data["commit"],"provider_version":data["provider_version"]}
def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument("manifest",type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--collect-lifecycle",action="store_true",help="Collect and validate the four fixture directories into the output bundle")
    parser.add_argument("--fixture-dir",action="append",type=Path,default=[])
    parser.add_argument("--provider-version")
    args=parser.parse_args()
    if args.collect_lifecycle:
        if not args.expected_commit or not args.provider_version: parser.error("Collection requires exact commit and provider version")
        try: collect_bundle(args.manifest,args.fixture_dir,args.expected_commit,args.provider_version)
        except (ValueError,TypeError,KeyError,OSError) as exc: parser.exit(2,"Lifecycle evidence rejected: "+str(exc)+"\n")
        print("Lifecycle evidence bundle collected; independent AWS evidence review required")
        return 0
    result=check(args.manifest,args.expected_commit)
    print(json.dumps(result,indent=2))
    return 0 if result["ready"] else 2
if __name__=="__main__": raise SystemExit(main())
