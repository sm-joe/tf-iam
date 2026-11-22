"""Generated identities regression based on a mixed infrastructure topology."""
import copy
import json
from tfiam.scan import scan
from tfiam.cli import main

ACCOUNT="123456789012"
REGION="us-east-1"
AWS="registry.terraform.io/hashicorp/aws"

def fixture(tmp_path):
    config={"variable":{"prefix":{"default":"fixture-infra"}},
            "terraform":{"required_providers":{"random":{"source":"hashicorp/random"}}},
            "resource":{
              "random_id":{"suffix":{"byte_length":4}},
              "aws_s3_bucket":{"storage":{"bucket":"\u0024{var.prefix}-storage-\u0024{random_id.suffix.hex}"}},
              "aws_s3_bucket_public_access_block":{"storage":{"bucket":"\u0024{aws_s3_bucket.storage.id}"}},
              "aws_s3_bucket_versioning":{"storage":{"bucket":"\u0024{aws_s3_bucket.storage.id}"}},
              "aws_vpc":{"main":{"tags":{"Name":"fixture-infra-vpc"}}},
              "aws_subnet":{"public":{"count":2,"vpc_id":"\u0024{aws_vpc.main.id}"}},
              "aws_internet_gateway":{"main":{"vpc_id":"\u0024{aws_vpc.main.id}"}},
              "aws_route_table":{"public":{"vpc_id":"\u0024{aws_vpc.main.id}","route":[{"gateway_id":"\u0024{aws_internet_gateway.main.id}","cidr_block":"0.0.0.0/0"}]}},
              "aws_route_table_association":{"public":{"count":2,"subnet_id":"\u0024{aws_subnet.public[count.index].id}","route_table_id":"\u0024{aws_route_table.public.id}"}},
              "aws_security_group":{"web":{"vpc_id":"\u0024{aws_vpc.main.id}"}},
              "aws_iam_role":{"runner":{"name":"fixture-runner","path":"/ci/"}},
              "aws_iam_instance_profile":{"runner":{"name":"fixture-profile","role":"\u0024{aws_iam_role.runner.name}"}},
              "aws_instance":{"worker":{"ami":"ami-1234abcd","subnet_id":"\u0024{aws_subnet.public[0].id}","vpc_security_group_ids":["\u0024{aws_security_group.web.id}"],"iam_instance_profile":"\u0024{aws_iam_instance_profile.runner.name}"}}
            }}
    (tmp_path/"main.tf.json").write_text(json.dumps(config))
    changes=[]; sources={}
    def create(addr,after,unknown=None,refs=None,provider=AWS):
        base=addr.split("[",1)[0]; typ=base.split(".")[0]
        changes.append({"address":addr,"type":typ,"mode":"managed","provider_name":provider,
                        "change":{"actions":["create"],"before":None,"after":after,
                                  "after_unknown":unknown or {},"after_sensitive":{}}})
        sources[base]={"address":base,"mode":"managed","type":typ,
                       "provider_config_key":"aws" if provider==AWS else "random",
                       "expressions":{k:{"references":v} for k,v in (refs or {}).items()}}
    create("random_id.suffix",{"byte_length":4,"prefix":""},{"hex":True},provider="registry.terraform.io/hashicorp/random")
    create("aws_s3_bucket.storage",{},{"bucket":True,"id":True},{"bucket":["var.prefix","random_id.suffix.hex","random_id.suffix"]})
    for typ in ("aws_s3_bucket_public_access_block","aws_s3_bucket_versioning"):
        create(typ+".storage",{},{"bucket":True},{"bucket":["aws_s3_bucket.storage.id","aws_s3_bucket.storage"]})
    create("aws_vpc.main",{"tags":{"Name":"fixture-infra-vpc"}},{"id":True})
    for i in range(2):
        create("aws_subnet.public["+str(i)+"]",{"tags":{"Name":"fixture-infra-public-"+str(i)}},{"id":True,"vpc_id":True},{"vpc_id":["aws_vpc.main.id","aws_vpc.main"]})
    create("aws_internet_gateway.main",{"tags":{"Name":"fixture-infra-igw"}},{"id":True,"vpc_id":True},{"vpc_id":["aws_vpc.main.id","aws_vpc.main"]})
    create("aws_route_table.public",{"tags":{"Name":"fixture-infra-rt"},"route":[{"cidr_block":"0.0.0.0/0"}]},{"id":True,"vpc_id":True,"route":[{"gateway_id":True}]},{"vpc_id":["aws_vpc.main.id","aws_vpc.main"]})
    for i in range(2):
        create("aws_route_table_association.public["+str(i)+"]",{},{"subnet_id":True,"route_table_id":True},{"subnet_id":["aws_subnet.public","count.index"],"route_table_id":["aws_route_table.public.id","aws_route_table.public"]})
    create("aws_security_group.web",{"tags":{"Name":"fixture-infra-web"},"ingress":[{"from_port":80}],"egress":[{"protocol":"-1"}]},{"id":True,"vpc_id":True},{"vpc_id":["aws_vpc.main.id","aws_vpc.main"]})
    create("aws_iam_role.runner",{"name":"fixture-runner","path":"/ci/"},{"arn":True})
    create("aws_iam_instance_profile.runner",{"name":"fixture-profile","path":"/","role":"fixture-runner"},{"arn":True})
    create("aws_instance.worker",{"ami":"ami-1234abcd","iam_instance_profile":"fixture-profile","tags":{"Name":"fixture-infra-worker"}},{"id":True,"subnet_id":True,"vpc_security_group_ids":[True]},{"subnet_id":["aws_subnet.public[0].id","aws_subnet.public[0]","aws_subnet.public"],"vpc_security_group_ids":["aws_security_group.web.id","aws_security_group.web"]})
    return {"format_version":"1.2","terraform_version":"1.10.5",
            "variables":{"prefix":{"value":"fixture-infra"}},
            "configuration":{"root_module":{"resources":list(sources.values())},"provider_config":{"aws":{"full_name":AWS}}},
            "resource_changes":changes}

def test_mixed_generated_infrastructure(tmp_path):
    plan=fixture(tmp_path)
    baseline=scan(tmp_path,account=ACCOUNT,region=REGION,plan=plan)
    assert baseline["unresolved_permissions"]
    report=scan(tmp_path,account=ACCOUNT,region=REGION,plan=plan,scope_generated_names=True)
    assert report["mapping_coverage"]["unmapped_resources"]==0
    assert not report["unresolved_permissions"],report["unresolved_permissions"]
    rows=report["permissions"]
    bucket="arn:aws:s3:::fixture-infra-storage-????????"
    for action in ("s3:CreateBucket","s3:PutBucketPublicAccessBlock","s3:PutBucketVersioning"):
        assert any(p["action"]==action and p["scope"]==bucket for p in rows)
    assert any(p["action"]=="s3:PutBucketVersioning" and p["condition"]=={"StringEquals":{"s3:ResourceAccount":ACCOUNT}} for p in rows)
    for action in ("ec2:CreateSubnet","ec2:AttachInternetGateway","ec2:AssociateRouteTable","ec2:RunInstances","ec2:CreateRoute","ec2:AuthorizeSecurityGroupIngress","ec2:RevokeSecurityGroupEgress"):
        assert any(p["action"]==action and p["scope"]!="*" for p in rows),action
    pass_roles=[p for p in rows if p["action"]=="iam:PassRole"]
    assert {p["source"] for p in pass_roles}=={"aws_instance.worker","aws_iam_instance_profile.runner"}
    assert all(p["scope"]=="arn:aws:iam::"+ACCOUNT+":role/ci/fixture-runner" for p in pass_roles)
    assert all("?" not in p["scope"] or p["scope"]==bucket for p in rows)
    plan_file=tmp_path/"plan.json"; plan_file.write_text(json.dumps(plan))
    dest=tmp_path/"policy.json"
    assert main(["generate",str(tmp_path),"--plan-json",str(plan_file),"--aws-account",ACCOUNT,"--aws-region",REGION,"--scope-generated-names","--output",str(dest)])==0
    assert dest.exists()

def test_generated_name_safety(tmp_path):
    plan=fixture(tmp_path)
    # Sensitive random output, unverified direct reference or masked prefix must
    # never turn into an inferred bucket wildcard.
    for mode in ("sensitive","wrong-provider","wrong-reference"):
        bad=copy.deepcopy(plan)
        if mode=="sensitive": bad["resource_changes"][0]["change"]["after_sensitive"]={"hex":True}
        elif mode=="wrong-provider": bad["resource_changes"][0]["provider_name"]="registry.terraform.io/example/random"
        else:
            row=next(r for r in bad["configuration"]["root_module"]["resources"] if r["address"]=="aws_s3_bucket.storage")
            row["expressions"]["bucket"]["references"]=["var.prefix"]
        report=scan(tmp_path,account=ACCOUNT,region=REGION,plan=bad,scope_generated_names=True)
        assert any(p["source"]=="aws_s3_bucket.storage" for p in report["unresolved_permissions"])
        assert not any(p["action"].startswith("s3:") and ("?" in p["scope"] or p["scope"]=="*") for p in report["permissions"])
