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


def test_generate_default_is_grant_equivalent_and_groups_compatible_resources():
    from tfiam.cli import policy
    source={
        "permissions":[
            {"provider":"aws","action":action,"scope":resource,"source":"test"}
            for action in ("ec2:CreateTags","ec2:DeleteTags")
            for resource in (
                "arn:aws:ec2:ap-south-1:123456789012:vpc/vpc-aabbccdd",
                "arn:aws:ec2:ap-south-1:123456789012:vpc/vpc-11223344",
            )
        ],
    }
    generated=policy(source,"aws","test",None)
    unoptimized=doc([
        row(["ec2:CreateTags","ec2:DeleteTags"],r)
        for r in (
            "arn:aws:ec2:ap-south-1:123456789012:vpc/vpc-aabbccdd",
            "arn:aws:ec2:ap-south-1:123456789012:vpc/vpc-11223344",
        )
    ])
    assert grants(generated)==grants(unoptimized)
    assert len(generated["Statement"])==1
    assert size(generated)<size(unoptimized)


def test_optimized_generation_preserves_peer_and_tag_conditions_exactly():
    from tfiam.cli import policy
    records=[
        {"provider":"aws","action":"ec2:CreateVpcPeeringConnection",
         "scope":"arn:aws:ec2:ap-south-1:123456789012:vpc-peering-connection/*",
         "condition":{"ArnEquals":{"ec2:AccepterVpc":"arn:aws:ec2:us-west-2:999999999999:vpc/vpc-aabbccdd"}},
         "source":"peer"},
        {"provider":"aws","action":"ec2:CreateTags",
         "scope":"arn:aws:ec2:ap-south-1:123456789012:vpc/*",
         "condition":{"StringEquals":{"ec2:CreateAction":"CreateVpc"},
                      "ForAllValues:StringEquals":{"aws:TagKeys":["Name"]},
                      "Null":{"aws:TagKeys":"false"}},
         "source":"vpc"}
    ]
    result=policy({"permissions":records},"aws","test",None)
    assert grants(result)=={
        (p["action"],p["scope"],json.dumps(p["condition"],sort_keys=True,separators=(",",":"),ensure_ascii=True))
        for p in records
    }
