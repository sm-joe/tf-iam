#!/usr/bin/env python3
"""Prepare and seal a compact, private release evidence archive.

Run against the exact accepted source checkout. No AWS calls or Terraform
mutations are made. Review the draft before sealing; the manifest is an
attestation of that review, not a new claim of full catalog verification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO="sm-joe/tf-iam"
SERVICES={
    "s3":"s3-general-purpose-empty",
    "sqs":"sqs-standard-empty",
    "vpc":"vpc-private-subnet",
    "dynamodb":"dynamodb-ondemand-empty",
}
TESTS=(
    "tests/test_resolver.py",
    "tests/test_plan.py::test_sensitive_unknown_and_foreign_provider",
    "tests/test_plan.py::test_directory_only_supplies_backend",
    "tests/test_cli.py::test_backend_and_scope",
    "tests/test_integrations.py::test_gate_blocks_policy_output",
    "tests/test_integrations.py::test_split_preserves_grants",
    "tests/test_final_evidence_security.py::test_lifecycle_gate_rejects_incomplete_inputs",
    "tests/test_release_readiness.py",
)
LIMITS=[
    "Lifecycle proof covers only the four isolated representative fixtures, not every mapped service or configuration.",
    "S3 provider v6.73.0 falls back from denied ListTagsForResource to GetBucketTagging and from TagResource to ordinary bucket tagging.",
    "VPC provider v6.73.0 tolerates discovery failures for default NACL, route table and security group; those computed IDs may be unavailable. Configurations depending on them are not verified by this fixture.",
    "CloudTrail session-filtered management events are partial authorization evidence; a direct runner denial may not appear in that history.",
    "Catalog/metadata and direct source matches are not certification of effective IAM authorization.",
]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_bytes())

def write(path,value):
    path.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8")
    path.chmod(0o600)

def require(condition,message):
    if not condition:
        raise ValueError(message)

def run(source,*args):
    result=subprocess.run(args,cwd=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
    if result.returncode:
        raise ValueError(f"Command failed ({result.returncode}): {args[0]} {args[1] if len(args)>1 else ''}; inspect locally")
    return result.stdout

def ordinary(base,name):
    rel=Path(name)
    require(not rel.is_absolute() and ".." not in rel.parts and bool(rel.parts),"Unsafe evidence path")
    for n in range(1,len(rel.parts)+1):
        require(not base.joinpath(*rel.parts[:n]).is_symlink(),"Evidence symlinks are not accepted")
    path=base/rel
    require(path.is_file(),"Missing evidence file: "+str(rel))
    return path

def modules(source):
    sys.path.insert(0,str(source/"scripts"))
    import lifecycle_evidence
    spec=importlib.util.spec_from_file_location("tfiam_release_check",source/"scripts/check-release.py")
    gate=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return lifecycle_evidence,gate

def ci_run(source,run_id,commit,name):
    fields="headSha,headBranch,status,conclusion,workflowName,url"
    data=json.loads(run(source,"gh","run","view",str(run_id),"--repo",REPO,"--json",fields))
    require(data.get("headSha")==commit and data.get("headBranch")=="main" and data.get("status")=="completed"
            and data.get("conclusion")=="success" and data.get("workflowName")==name,"CI does not match successful exact-source main run: "+name)
    return data

def prepare(args,source,base,life,gate):
    bundle_path=ordinary(base,"lifecycle.json")
    life.check_bundle(bundle_path,args.source_commit,args.provider_version)
    bundle=read(bundle_path)
    supplemental={"lifecycle.json"}
    for records in bundle["fixtures"].values():
        for record in records.values():
            supplemental.add(record["artifact"])
    summary={"source_commit":args.source_commit,"provider_version":args.provider_version,"limitations":LIMITS,
             "services":{},"source_review":{}}
    for service,fixture in SERVICES.items():
        records=bundle["fixtures"][fixture]
        evidence=read(ordinary(base,records["evidence"]["artifact"]))
        validation_name=f"{service}-validation.json"
        runtime_name=f"{service}-runtime-audit.json"
        validation=read(ordinary(base,validation_name))
        runtime=read(ordinary(base,runtime_name))
        supplemental.update((validation_name,runtime_name))
        require(validation.get("status")=="no-findings" and not validation.get("findings"),service+" Access Analyzer findings require review")
        retrieval=runtime.get("retrieval",{})
        session=evidence["session_arn"].rsplit("/",1)[1]
        require(retrieval.get("complete") is True and retrieval.get("mode")=="session-filtered"
                and retrieval.get("session_names")==[session] and runtime.get("matched_events",0)>0
                and retrieval.get("matched")==runtime["matched_events"],service+" CloudTrail retrieval or session mismatch")
        require(runtime.get("unmapped_operations")==[],service+" has unmapped CloudTrail operations")
        observations=runtime.get("observations",[])
        prefix={"s3":"s3:","sqs":"sqs:","vpc":"ec2:","dynamodb":"dynamodb:"}[service]
        require(any(x.get("action","").startswith(prefix) and x.get("successful",0)>0 for x in observations),
                service+" has no positive service operation evidence")
        outside=runtime.get("observed_outside_candidates",[])
        require(not any(x.get("successful",0)>0 and x.get("action")!="sts:GetCallerIdentity" for x in outside),
                service+" has unexplained successful operations outside the candidate")
        expected_denials={
            "s3":{"s3:ListAllMyBuckets","s3:ListTagsForResource","s3:TagResource","s3:UntagResource"},
            "sqs":{"sqs:ListQueues"},
            "vpc":{"ec2:CreateInternetGateway","ec2:DescribeNetworkAcls","ec2:DescribeRouteTables","ec2:DescribeSecurityGroups"},
            "dynamodb":{"dynamodb:ListTables"},
        }[service]
        require(not any((x.get("denied",0)>0 and x.get("action") not in expected_denials) or x.get("other_errors",0)>0 for x in outside),
                service+" has additional outside-candidate errors requiring source review")
        summary["services"][service]={
            "fixture":fixture,"lifecycle_status":evidence["status"],"access_analyzer":validation["status"],
            "matched_events":runtime["matched_events"],"coverage":runtime.get("coverage"),
            "outside_candidates":outside,"conditional_operations":runtime.get("conditional_operations",[]),
            "direct_denial":evidence["negative_action"],
            "direct_denial_observed_in_cloudtrail":any(x.get("action")==evidence["negative_action"] and x.get("denied",0)>0 for x in observations),
            "validation_sha256":digest(base/validation_name),"runtime_sha256":digest(base/runtime_name),
        }
    ci=ci_run(source,args.ci_run_id,args.source_commit,"CLI tests")
    linux=ci_run(source,args.linux_run_id,args.source_commit,"Linux binary build")
    write(base/"ci-run.json",ci)
    write(base/"linux-run.json",linux)
    with tempfile.TemporaryDirectory() as tmp:
        run(source,"gh","run","download",str(args.ci_run_id),"--repo",REPO,"--name","provider-source-audit-"+args.provider_version,"--dir",tmp)
        report=read(Path(tmp)/"provider-source-audit.json")
    require(report.get("provider_version")==args.provider_version and report.get("pin_verified") is True,"Provider report is not pinned to the tested version")
    reviewed={r["resource"] for r in report["resources"] if r.get("source_review_record_matched")}
    require({"aws_s3_bucket_versioning","aws_s3_bucket_public_access_block"}<=reviewed,"Missing reviewed provider mappings")
    write(base/"provider-source-audit.json",report)
    summary["source_review"]={"report_status":report.get("status"),"counts":report.get("counts"),"reviewed_resources":sorted(reviewed),
        "provider_commit":report.get("provider_commit"),"report_sha256":digest(base/"provider-source-audit.json"),
        "additional_source_paths":["internal/service/s3/bucket.go","internal/service/s3/tags.go","internal/service/ec2/vpc_.go"],
        "scope":"Review unresolved calls and limitations; do not treat a direct-call inventory as full provider coverage."}
    output=run(source,sys.executable,"-m","pytest","-q",*TESTS)
    (base/"regression-review.txt").write_text("Commit: "+args.source_commit+"\nTests: "+" ".join(TESTS)+"\n"+output,encoding="utf-8")
    binpath=source/"dist/tfiam"
    require(binpath.is_file(),"Build the accepted source Linux binary first")
    fields=(source/"dist/SHA256SUMS").read_text().strip().split()
    require(len(fields)==2 and fields[1]=="tfiam" and fields[0]==digest(binpath),"Local binary checksum mismatch")
    run(source,str(binpath),"--help")
    run(source,str(binpath),"catalog-audit","--strict","--aws-provider-version",args.provider_version,"--format","json","--output",str(base/"authorization-metadata.json"))
    audit=read(base/"authorization-metadata.json")
    require(audit.get("status")=="compatible" and not audit.get("findings"),"Packaged authorization metadata audit failed")
    with tempfile.TemporaryDirectory() as tmp:
        scan=Path(tmp)/"scan.json"
        run(source,str(binpath),"scan","examples/aws-hcl","--format","json","--output",str(scan))
        require(read(scan).get("authorization_metadata",{}).get("metadata_source")=="packaged","Binary does not use packaged metadata")
        scan_hash=digest(scan)
    write(base/"binary-review.json",{"source_commit":args.source_commit,"local_sha256":fields[0],"size":binpath.stat().st_size,
        "smoke_test":"passed","example_scan_sha256":scan_hash,"ci_run":linux["url"],
        "limitation":"Signed workflow independently rebuilds twice and verifies repeatability."})
    write(base/"review-summary.json",summary)
    supplemental.update(("ci-run.json","linux-run.json","provider-source-audit.json","regression-review.txt",
                         "authorization-metadata.json","binary-review.json","review-summary.json"))
    paths={
        **{k:"lifecycle.json" for k in ("create","update","delete","replace-create-first","replace-delete-first","restricted-role-lifecycle")},
        "provider-source-review":"review-summary.json",
        "module-resolution":"regression-review.txt",
        "authorization-metadata":"authorization-metadata.json",
        "access-analyzer":"review-summary.json","cloudtrail":"review-summary.json",
        "secret-redaction":"regression-review.txt","backend-locking":"regression-review.txt",
        "risk-gates":"regression-review.txt","linux-binary":"binary-review.json",
    }
    require(set(paths)==set(gate.REQUIRED),"Evidence gate inventory changed")
    draft={"commit":args.source_commit,"provider_version":args.provider_version,
           "checks":{k:{"status":"review","artifact":v,"sha256":digest(ordinary(base,v))} for k,v in paths.items()},
           "supplemental":{name:digest(ordinary(base,name)) for name in sorted(supplemental)}}
    write(base/"release-review-draft.json",draft)
    print("Review draft prepared. Read review-summary.json, provider-source-audit.json and the referenced evidence before sealing.")
    print(output.strip())

def seal(args,base,life,gate):
    require(args.confirm_reviewed,"Independent maintainer review confirmation required")
    draft=read(ordinary(base,"release-review-draft.json"))
    require(draft.get("commit")==args.source_commit and draft.get("provider_version")==args.provider_version,"Draft source mismatch")
    require(set(draft["checks"])==set(gate.REQUIRED),"Draft check inventory mismatch")
    files=set(draft["supplemental"])
    for name,expected in draft["supplemental"].items():
        require(re.fullmatch(r"[a-f0-9]{64}",expected) and digest(ordinary(base,name))==expected,"Reviewed evidence changed: "+name)
    for row in draft["checks"].values():
        require(row["status"]=="review" and row["artifact"] in files and digest(ordinary(base,row["artifact"]))==row["sha256"],"Draft check changed")
        row["status"]="passed"
    life.check_bundle(ordinary(base,"lifecycle.json"),args.source_commit,args.provider_version)
    draft["review_confirmed"]=True
    manifest=base/"manifest.json"
    write(manifest,draft)
    require(gate.check(manifest,args.source_commit)["ready"],"Final manifest rejected")
    archive=base.parent/"release-evidence.tar.gz"
    temp=archive.with_suffix(".tmp")
    require(not archive.is_symlink() and not temp.exists(),"Unsafe archive path")
    try:
        with tarfile.open(temp,"w:gz") as out:
            for name in sorted(files|{"manifest.json"}):
                p=ordinary(base,name)
                out.add(p,arcname=name,recursive=False)
        require(temp.stat().st_size<=36_000,"Private evidence archive exceeds Actions secret size; do not upload raw evidence")
        temp.chmod(0o600)
        temp.replace(archive)
    finally:
        if temp.exists(): temp.unlink()
    print("READY: private release evidence verified and sealed")
    print("Archive:",archive)
    print("SHA256:",digest(archive))

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("prepare","seal"))
    parser.add_argument("--source-dir",type=Path,default=Path.cwd())
    parser.add_argument("--evidence-dir",type=Path,required=True)
    parser.add_argument("--source-commit",required=True)
    parser.add_argument("--provider-version",required=True)
    parser.add_argument("--ci-run-id",type=int)
    parser.add_argument("--linux-run-id",type=int)
    parser.add_argument("--confirm-reviewed",action="store_true")
    args=parser.parse_args()
    try:
        source=args.source_dir.resolve()
        base=args.evidence_dir.resolve()/"release"
        require(base.is_dir() and not base.stat().st_mode & 0o077,"Use a private release evidence directory (0700)")
        require(re.fullmatch(r"[a-f0-9]{40}",args.source_commit) and re.fullmatch(r"\d+\.\d+\.\d+",args.provider_version),"Use exact source commit and provider version")
        require(run(source,"git","rev-parse","HEAD").strip()==args.source_commit and not run(source,"git","status","--porcelain","--untracked-files=no").strip(),
                "Use the exact clean accepted source checkout")
        life,gate=modules(source)
        if args.mode=="prepare":
            require(args.ci_run_id and args.linux_run_id,"Exact-source CI and Linux run IDs required")
            prepare(args,source,base,life,gate)
        else:
            seal(args,base,life,gate)
    except (ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError) as exc:
        parser.exit(2,"Release evidence rejected: "+str(exc)+"\n")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
