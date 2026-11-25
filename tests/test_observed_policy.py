"""Reconcile IAM Live observations without changing or hiding IAM grants."""
import json
import pytest
from tfiam.observed import reconcile
from tfiam.policy_size import grants, size
from tfiam.cli import main


def doc(*rows):
    return {"Version":"2012-10-17","Statement":list(rows)}


def row(action,resource,condition=None,sid=None):
    out={"Effect":"Allow","Action":action,"Resource":resource}
    if condition: out["Condition"]=condition
    if sid: out["Sid"]=sid
    return out


def test_observed_comparison_preserves_broad_and_conditioned_grants():
    generated=doc(row(["s3:GetObject"],"arn:aws:s3:::sample/*",{
        "StringEquals":{"aws:ResourceAccount":"123456789012"}
    }))
    observed=doc(row("s3:GetObject","*",sid="FromIamLive"),row("s3:ListBucket","arn:aws:s3:::sample"))
    result=reconcile(generated,observed)
    report=result["report"]
    assert report["status"]=="DIFFERENCES"
    assert len(report["observed_not_in_generated"])==2
    assert report["observed_not_in_generated"][0]["resource"]=="*" or report["observed_not_in_generated"][1]["resource"]=="*"
    assert report["generated_grants"]==1
    assert grants(result["merged_policy"])==grants(doc(row("s3:GetObject","arn:aws:s3:::sample/*",{
        "StringEquals":{"aws:ResourceAccount":"123456789012"}
    }),row("s3:GetObject","*"),row("s3:ListBucket","arn:aws:s3:::sample")))
    assert report["merged_policy_characters"]==size(result["merged_policy"])


def test_reconcile_accepts_single_statement_and_rejects_denies_and_notaction():
    observed=doc(row("ec2:DescribeVpcs","*"))
    observed["Statement"]=observed["Statement"][0]
    report=reconcile(doc(row("ec2:DescribeVpcs","*")),observed)["report"]
    assert report["status"]=="MATCHED"
    with pytest.raises(ValueError,match="Allow identity"):
        reconcile(doc(row("ec2:DescribeVpcs","*")),doc({"Effect":"Deny","Action":"*","Resource":"*"}))
    with pytest.raises(ValueError,match="unsupported IAM fields"):
        reconcile(doc(row("ec2:DescribeVpcs","*")),doc({"Effect":"Allow","NotAction":"s3:DeleteObject","Resource":"*"}))


def test_cli_reconcile_observed_reports_differences_and_writes_opt_in_union(tmp_path,capsys):
    generated=tmp_path/"generated.json"
    observed=tmp_path/"iamlive.json"
    output=tmp_path/"difference.json"
    merged=tmp_path/"merged.json"
    candidate=doc(row("ec2:DescribeVpcs","*"))
    runtime=doc(row("ec2:DescribeVpcs","*"),row("ec2:DescribeSubnets","*"))
    generated.write_text(json.dumps(candidate))
    observed.write_text(json.dumps(runtime))
    assert main(["reconcile-observed","--generated",str(generated),
                 "--observed",str(observed),"--output",str(output),
                 "--merged-policy",str(merged)])==0
    assert not capsys.readouterr().out
    report=json.loads(output.read_text())
    assert report["status"]=="DIFFERENCES"
    assert report["observed_not_in_generated"]==[{"action":"ec2:DescribeSubnets","resource":"*"}]
    assert grants(json.loads(merged.read_text()))==grants(runtime)
    assert main(["reconcile-observed","--generated",str(generated),
                 "--observed",str(observed)])==0
    assert json.loads(capsys.readouterr().out)["status"]=="DIFFERENCES"
    assert main(["reconcile-observed","--generated",str(generated),
                 "--observed",str(observed),"--merged-policy",str(generated)])==1
    assert json.loads(generated.read_text())==candidate
