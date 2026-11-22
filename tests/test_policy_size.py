import json
import pytest
from tfiam.policy_size import grants, size, partition, optimize
from tfiam.cli import main

def doc(rows):
    return {"Version":"2012-10-17","Statement":rows}

def row(a,r,c=None):
    return {"Effect":"Allow","Action":a,"Resource":r,**({"Condition":c} if c else {})}

def test_policy_size_equivalence():
    cond={"StringEquals":{"aws:ResourceTag/Name":"demo"}}
    original=doc([row(["ec2:StartInstances","ec2:StopInstances"],"arn:aws:ec2:us-east-1:123456789012:instance/i-aaa",cond),
                  row(["ec2:StartInstances","ec2:StopInstances"],"arn:aws:ec2:us-east-1:123456789012:instance/i-bbb",cond),
                  row("ec2:StartInstances","arn:aws:ec2:us-east-1:123456789012:instance/i-ccc"),
                  row("ec2:StartInstances","arn:aws:ec2:us-east-1:123456789012:instance/i-aaa")])
    optimized=optimize(original)
    assert size(optimized)<size(original)
    assert grants(optimized)==grants(original)
    assert partition(original)==partition(original)

def test_large_policy_partition_and_budget():
    original=doc([row("s3:GetBucketTagging",f"arn:aws:s3:::fixture-{i:04d}-"+"a"*40,{"StringEquals":{"s3:ResourceAccount":"123456789012"}}) for i in range(230)])
    result=partition(original)
    assert result["policy_count"]>1
    assert all(p["characters"]<=6144 for p in result["policies"])
    assert set().union(*(grants(p["document"]) for p in result["policies"]))==grants(original)
    with pytest.raises(ValueError,match="attachment budget"): partition(original,max_policies=1)
    with pytest.raises(ValueError,match="Aggregate inline"): partition(original,"inline-role")
    with pytest.raises(ValueError,match="quota"): partition(original,max_chars=6145)
    with pytest.raises(ValueError,match="single grant"): partition(original,max_chars=60)
    with pytest.raises(ValueError): partition(doc([{"Effect":"Deny","Action":"*","Resource":"*"}]))

def test_cli_pack_policy(tmp_path):
    source=tmp_path/"policy.json"; target=tmp_path/"bundle"
    original=doc([row("s3:ListBucket","arn:aws:s3:::fixture")])
    source.write_text(json.dumps(original))
    args=["pack-policy",str(source),"--output-dir",str(target)]
    assert main(args)==0
    manifest=json.loads((target/"manifest.json").read_text())
    packed=json.loads((target/manifest["policies"][0]["file"]).read_text())
    assert grants(packed)==grants(original)
    assert main(args)!=0
    assert main(["pack-policy",str(source),"--output-dir",str(tmp_path/"bad"),"--max-chars","1"])!=0
    assert not (tmp_path/"bad").exists()
