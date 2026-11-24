"""Zero-configuration IAM generation must work with AWS CLI caller discovery."""
import json
from types import SimpleNamespace

from tfiam.cli import main
from tfiam.provider_context import configured


def test_generate_from_current_directory_without_context_flags(tmp_path,monkeypatch):
    config={
        "provider":{"aws":{"region":"us-east-1"}},
        "resource":{
            "aws_vpc":{"main":{"cidr_block":"10.0.0.0/16"}},
            "aws_subnet":{"private":{
                "vpc_id":"${aws_vpc.main.id}",
                "cidr_block":"10.0.1.0/24",
            }},
            "aws_route_table":{"private":{"vpc_id":"${aws_vpc.main.id}"}},
            "aws_eip":{"nat":{"domain":"vpc"}},
            "aws_nat_gateway":{"nat":{
                "subnet_id":"${aws_subnet.private.id}",
                "allocation_id":"${aws_eip.nat.id}",
            }},
        },
    }
    (tmp_path/"main.tf.json").write_text(json.dumps(config))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AWS_REGION",raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION",raising=False)
    monkeypatch.setattr("shutil.which",lambda command:"/usr/bin/aws" if command=="aws" else None)
    calls=[]
    def fake_run(args,**kwargs):
        calls.append(args)
        if args[:3]==["aws","configure","get"]:
            return SimpleNamespace(returncode=0,stdout="us-east-1\n")
        assert args[:3]==["aws","sts","get-caller-identity"]
        return SimpleNamespace(returncode=0,stdout=json.dumps({
            "Account":"123456789012",
            "Arn":"arn:aws:sts::123456789012:assumed-role/ci/session"
        }))
    monkeypatch.setattr("subprocess.run",fake_run)
    assert main(["generate",".","--output","policy.json"])==0
    policy=json.loads((tmp_path/"policy.json").read_text())
    assert policy["Version"]=="2012-10-17"
    actions={a for statement in policy["Statement"] for a in statement["Action"]}
    assert {"ec2:CreateVpc","ec2:CreateSubnet","ec2:CreateNatGateway"}<=actions
    assert any(statement["Resource"]=="arn:aws:ec2:us-east-1:123456789012:vpc/*"
               for statement in policy["Statement"])
    assert any(x[:3]==["aws","sts","get-caller-identity"] for x in calls)


def test_assume_role_alias_uses_destination_account_not_caller():
    actual=configured("aws.west",{
        "region":"us-west-2",
        "assume_role":{"role_arn":"arn:aws:iam::999999999999:role/deploy"},
    },("123456789012","us-east-1","aws"),{})
    assert actual==("999999999999","us-west-2","aws")


def test_ambiguous_assume_role_stays_unresolved():
    actual=configured("aws.west",{
        "region":"us-west-2",
        "assume_role":{"role_arn":None},
    },("123456789012","us-east-1","aws"),{})
    assert actual is None


def test_named_profile_alias_generates_without_manual_context(tmp_path,monkeypatch):
    config={
        "provider":{"aws":[
            {"region":"us-east-1"},
            {"alias":"west","region":"us-west-2","profile":"production"},
        ]},
        "resource":{"aws_sqs_queue":{
            "main":{"name":"main"},
            "west":{"provider":"aws.west","name":"west"},
        }},
    }
    (tmp_path/"main.tf.json").write_text(json.dumps(config))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("shutil.which",lambda command:"/usr/bin/aws" if command=="aws" else None)
    def fake_run(args,**kwargs):
        if args[-2:]==["get","region"]:
            return SimpleNamespace(returncode=0,stdout="us-east-1\n")
        if "--profile" in args:
            assert args[args.index("--profile")+1]=="production"
            return SimpleNamespace(returncode=0,stdout=json.dumps({
                "Account":"999999999999",
                "Arn":"arn:aws:iam::999999999999:user/builder",
            }))
        return SimpleNamespace(returncode=0,stdout=json.dumps({
            "Account":"123456789012",
            "Arn":"arn:aws:iam::123456789012:user/builder",
        }))
    monkeypatch.setattr("subprocess.run",fake_run)
    assert main(["generate",".","--output","policy.json"])==0
    policy=json.loads((tmp_path/"policy.json").read_text())
    scopes={s["Resource"] for s in policy["Statement"]}
    assert "arn:aws:sqs:us-east-1:123456789012:main" in scopes
    assert "arn:aws:sqs:us-west-2:999999999999:west" in scopes


def test_explicit_provider_contexts_do_not_require_network(tmp_path,monkeypatch):
    (tmp_path/"main.tf.json").write_text(json.dumps({
        "provider":{"aws":{"region":"us-east-1"}},
        "resource":{"aws_vpc":{"main":{"cidr_block":"10.0.0.0/16"}}},
    }))
    (tmp_path/"contexts.json").write_text(json.dumps({
        "aws":{"account":"123456789012","region":"us-east-1","partition":"aws"}
    }))
    monkeypatch.setattr("subprocess.run",lambda *a,**kw:(_ for _ in ()).throw(AssertionError("Network attempt")))
    assert main(["generate",str(tmp_path),"--provider-contexts",str(tmp_path/"contexts.json"),
                 "--output",str(tmp_path/"policy.json")])==0
    assert json.loads((tmp_path/"policy.json").read_text())["Statement"]
