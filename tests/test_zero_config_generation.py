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


def test_full_networking_project_writes_policy_without_context_flags(tmp_path,monkeypatch):
    vpc="${aws_vpc.main.id}"
    public="${aws_subnet.public.id}"
    private="${aws_subnet.private.id}"
    routes_public="${aws_route_table.public.id}"
    routes_private="${aws_route_table.private.id}"
    config={"provider":{"aws":{"region":"us-east-1"}},"resource":{
        "aws_vpc":{"main":{"cidr_block":"10.60.0.0/16"}},
        "aws_subnet":{
            "public":{"vpc_id":vpc,"cidr_block":"10.60.1.0/24"},
            "private":{"vpc_id":vpc,"cidr_block":"10.60.2.0/24"},
        },
        "aws_internet_gateway":{"main":{"vpc_id":vpc}},
        "aws_eip":{"nat":{"domain":"vpc"}},
        "aws_nat_gateway":{"main":{"subnet_id":public,"allocation_id":"${aws_eip.nat.id}"}},
        "aws_route_table":{
            "public":{"vpc_id":vpc},
            "private":{"vpc_id":vpc},
        },
        "aws_route_table_association":{
            "public":{"route_table_id":routes_public,"subnet_id":public},
            "private":{"route_table_id":routes_private,"subnet_id":private},
        },
        "aws_security_group":{"main":{"vpc_id":vpc,"name":"network-main"}},
        "aws_network_acl":{"main":{"vpc_id":vpc}},
        "aws_ec2_transit_gateway":{"main":{"description":"transit"}},
        "aws_vpc_endpoint":{"s3":{
            "vpc_id":vpc,"service_name":"com.amazonaws.us-east-1.s3",
            "vpc_endpoint_type":"Gateway",
            "route_table_ids":[routes_public,routes_private],
        }},
        "aws_route53_zone":{"main":{"name":"example.com"}},
        "aws_route53_record":{"app":{
            "zone_id":"${aws_route53_zone.main.zone_id}","name":"app.example.com",
            "type":"A","ttl":60,"records":["192.0.2.10"],
        }},
        "aws_vpc_peering_connection":{"peer":{
            "vpc_id":vpc,"peer_vpc_id":"vpc-aabbccdd",
            "peer_owner_id":"999999999999","peer_region":"us-east-1",
        }},
        "aws_vpn_gateway":{"main":{"vpc_id":vpc}},
    }}
    (tmp_path/"main.tf.json").write_text(json.dumps(config))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AWS_REGION","us-east-1")
    monkeypatch.setattr("shutil.which",lambda command:"/usr/bin/aws" if command=="aws" else None)
    def fake_run(args,**kwargs):
        return SimpleNamespace(returncode=0,stdout=json.dumps({
            "Account":"123456789012",
            "Arn":"arn:aws:iam::123456789012:user/runner",
        }))
    monkeypatch.setattr("subprocess.run",fake_run)
    assert main(["generate",".","--output","policy.json"])==0
    policy=json.loads((tmp_path/"policy.json").read_text())
    actions={a for row in policy["Statement"] for a in row["Action"]}
    assert {"ec2:CreateVpc","ec2:CreateSubnet","ec2:CreateNatGateway",
            "ec2:CreateVpcEndpoint","ec2:CreateVpcPeeringConnection",
            "route53:ChangeResourceRecordSets","ec2:CreateTransitGateway",
            "ec2:CreateVpnGateway"}<=actions
    assert policy["Statement"]


def test_account_from_validated_environment_produces_policy_without_network(tmp_path,monkeypatch):
    (tmp_path/"main.tf.json").write_text(json.dumps({
        "provider":{"aws":{"region":"us-east-1"}},
        "resource":{
            "aws_vpc":{"main":{"cidr_block":"10.20.0.0/16"}},
            "aws_subnet":{"private":{"vpc_id":"${aws_vpc.main.id}","cidr_block":"10.20.1.0/24"}},
        },
    }))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AWS_ACCOUNT_ID","123456789012")
    monkeypatch.setenv("AWS_REGION","us-east-1")
    monkeypatch.setattr("subprocess.run",lambda *a,**k: (_ for _ in ()).throw(
        AssertionError("Explicit AWS account context must not trigger AWS CLI")))
    assert main(["generate",".","--output","policy.json"])==0
    doc=json.loads((tmp_path/"policy.json").read_text())
    assert any("ec2:CreateSubnet" in statement["Action"] for statement in doc["Statement"])


def test_failed_aws_cli_sts_falls_back_to_sdk(monkeypatch):
    import sys
    from types import ModuleType
    from tfiam.provider_context import discover_aws_identity
    monkeypatch.delenv("AWS_ACCOUNT_ID",raising=False)
    monkeypatch.delenv("TFIAM_AWS_ACCOUNT_ID",raising=False)
    monkeypatch.delenv("AWS_REGION",raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION",raising=False)
    monkeypatch.setattr("shutil.which",lambda command:"/usr/bin/aws" if command=="aws" else None)
    def failing_cli(args,**kwargs):
        if args[-2:]==["get","region"]:
            return SimpleNamespace(returncode=0,stdout="us-east-1\n")
        return SimpleNamespace(returncode=255,stdout="",stderr="expired CLI credentials")
    monkeypatch.setattr("subprocess.run",failing_cli)
    class FakeSession:
        region_name="us-east-1"
        def client(self,*args,**kwargs):
            return SimpleNamespace(get_caller_identity=lambda:{
                "Account":"123456789012",
                "Arn":"arn:aws:sts::123456789012:assumed-role/test/test"
            })
    boto3=ModuleType("boto3")
    boto3.Session=lambda **kwargs:FakeSession()
    botocore=ModuleType("botocore")
    botocore.__path__=[]
    config=ModuleType("botocore.config")
    config.Config=lambda **kwargs:kwargs
    monkeypatch.setitem(sys.modules,"boto3",boto3)
    monkeypatch.setitem(sys.modules,"botocore",botocore)
    monkeypatch.setitem(sys.modules,"botocore.config",config)
    assert discover_aws_identity()==("123456789012","us-east-1","aws")


def test_missing_context_has_explicit_root_cause(tmp_path):
    (tmp_path/"main.tf.json").write_text(json.dumps({
        "resource":{"aws_vpc":{"main":{"cidr_block":"10.0.0.0/16"}}},
    }))
    from tfiam.scan import scan
    report=scan(tmp_path)
    assert any(
        row["action"]=="ec2:CreateVpc" and
        "AWS target account unknown" in row["reason"]
        for row in report["unresolved_permissions"]
    )


def test_full_networking_generation_with_unexpanded_peer_missing_destination(tmp_path,monkeypatch):
    # Reproduces the reported 18/18 mapped, 1 unresolved peering blocker.
    from pathlib import Path
    fixture=Path(__file__).resolve().parents[1]/"examples"/"networking-18"/"main.tf.json"
    project=json.loads(fixture.read_text())
    peer=project["resource"]["aws_vpc_peering_connection"]["peer"]
    peer.pop("peer_vpc_id")
    peer["for_each"]="${var.remote_peers}"
    project["variable"]["remote_peers"]={"type":"map(string)"}
    (tmp_path/"main.tf.json").write_text(json.dumps(project))
    monkeypatch.setenv("AWS_ACCOUNT_ID","123456789012")
    monkeypatch.setenv("AWS_REGION","us-east-1")
    monkeypatch.chdir(tmp_path)
    assert main(["generate",".","--output","policy.json"])==0
    policy=json.loads((tmp_path/"policy.json").read_text())
    actions={action for statement in policy["Statement"] for action in statement["Action"]}
    assert "ec2:CreateVpcPeeringConnection" in actions
    assert "ec2:CreateVpc" in actions
    assert "ec2:CreateNatGateway" in actions
    assert "route53:ChangeResourceRecordSets" in actions
