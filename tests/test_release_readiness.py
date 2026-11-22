import copy
import importlib.util
import json
from argparse import Namespace
from pathlib import Path
import pytest
from tfiam.scan import scan
from tfiam.cli import main

A="123456789012"
R="us-east-1"
AWS="registry.terraform.io/hashicorp/aws"
ROOT=Path(__file__).resolve().parents[1]

def write(path,doc):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(doc))

def resource(address,kind,after,unknown=None):
    return {"address":address,"mode":"managed","type":kind,"provider_name":AWS,
        "change":{"actions":["create"],"before":None,"after":after,
                  "after_unknown":unknown or {},"after_sensitive":{}}}

def config_resource(address,kind,refs=None,key="aws"):
    return {"address":address,"mode":"managed","type":kind,"provider_config_key":key,
            "expressions":{k:{"references":v} for k,v in (refs or {}).items()}}

def plan(config,rows):
    return {"format_version":"1.2","terraform_version":"1.10.0","complete":True,
            "configuration":{"provider_config":{"aws":{"full_name":AWS}},"root_module":config},
            "resource_changes":rows}

def scopes(report,action,source=None):
    return {(p["scope"],json.dumps(p.get("condition"),sort_keys=True)) for p in report["permissions"]
            if p["action"]==action and (source is None or p["source"]==source)}

def test_count_same_index_resolves_only_matching_tag(tmp_path):
    expr="\x24{aws_vpc.v[count.index].id}"
    write(tmp_path/"main.tf.json",{"resource":{
        "aws_vpc":{"v":{"count":2,"tags":{"tfiam:scope":"dynamic"}}},
        "aws_subnet":{"s":{"count":2,"vpc_id":expr,"tags":{"tfiam:scope":"dynamic-subnet"}}}}})
    cfg={"resources":[config_resource("aws_vpc.v","aws_vpc"),
                      config_resource("aws_subnet.s","aws_subnet",{"vpc_id":["aws_vpc.v.id","aws_vpc.v","count.index"]})]}
    rows=[]
    for i in range(2):
        rows.extend([resource(f"aws_vpc.v[{i}]","aws_vpc",{"tags":{"tfiam:scope":f"vpc-{i}"}},{"id":True}),
                     resource(f"aws_subnet.s[{i}]","aws_subnet",{"tags":{"tfiam:scope":f"subnet-{i}"}},{"id":True,"vpc_id":True})])
    data=plan(cfg,rows)
    report=scan(tmp_path,plan=data,account=A,region=R,scope_resource_tags=True)
    for i in range(2):
        actual=scopes(report,"ec2:CreateSubnet",f"aws_subnet.s[{i}]")
        assert (f"arn:aws:ec2:{R}:{A}:vpc/*",json.dumps({"StringEquals":{"ec2:ResourceTag/tfiam:scope":f"vpc-{i}"}},sort_keys=True)) in actual
        assert not any(f"vpc-{1-i}" in cond for _,cond in actual)
    data["configuration"]["root_module"]["resources"][1]["expressions"]["vpc_id"]["references"].remove("count.index")
    report=scan(tmp_path,plan=data,account=A,region=R,scope_resource_tags=True)
    assert not scopes(report,"ec2:CreateSubnet")

def test_nested_for_each_module_input_and_output(tmp_path):
    write(tmp_path/"main.tf.json",{"module":{
        "vpcs":{"source":"./vpcs","for_each":{"blue":1,"green":2}},
        "subnets":{"source":"./subnets","for_each":{"blue":1,"green":2},"vpc_id":"\x24{module.vpcs[each.key].vpc_id}"}}})
    write(tmp_path/"vpcs/main.tf.json",{"resource":{"aws_vpc":{"v":{"tags":{"tfiam:scope":"dynamic"}}}},
        "output":{"vpc_id":{"value":"\x24{aws_vpc.v.id}"}}})
    write(tmp_path/"subnets/main.tf.json",{"variable":{"vpc_id":{}},
        "resource":{"aws_subnet":{"s":{"vpc_id":"\x24{var.vpc_id}","tags":{"tfiam:scope":"dynamic-subnet"}}}}})
    cfg={"module_calls":{
        "vpcs":{"source":"./vpcs","module":{"resources":[config_resource("aws_vpc.v","aws_vpc")],
            "outputs":{"vpc_id":{"expression":{"references":["aws_vpc.v.id","aws_vpc.v"]}}}}},
        "subnets":{"source":"./subnets","expressions":{"vpc_id":{"references":["module.vpcs.vpc_id","module.vpcs","each.key"]}},
            "module":{"resources":[config_resource("aws_subnet.s","aws_subnet",{"vpc_id":["var.vpc_id"]})]}}}}
    rows=[]
    for key in ("blue","green"):
        rows.extend([resource(f'module.vpcs["{key}"].aws_vpc.v',"aws_vpc",{"tags":{"tfiam:scope":f"vpc-{key}"}},{"id":True}),
                     resource(f'module.subnets["{key}"].aws_subnet.s',"aws_subnet",{"tags":{"tfiam:scope":f"subnet-{key}"}},{"vpc_id":True,"id":True})])
    data=plan(cfg,rows)
    report=scan(tmp_path,plan=data,account=A,region=R,scope_resource_tags=True)
    for key in ("blue","green"):
        assert any("vpc-"+key in cond for scope,cond in scopes(report,"ec2:CreateSubnet",f'module.subnets["{key}"].aws_subnet.s') if scope.endswith(":vpc/*"))
    data["resource_changes"][0]["change"]["after_sensitive"]={"tags":{"tfiam:scope":True}}
    report=scan(tmp_path,plan=data,account=A,region=R,scope_resource_tags=True)
    assert not scopes(report,"ec2:CreateSubnet",'module.subnets["blue"].aws_subnet.s')
    assert scopes(report,"ec2:CreateSubnet",'module.subnets["green"].aws_subnet.s')

def test_endpoint_wholly_unknown_generated_subnet_list(tmp_path):
    write(tmp_path/"main.tf.json",{"resource":{
        "aws_subnet":{"s":{"tags":{"tfiam:scope":"s"},"vpc_id":"vpc-abc"}},
        "aws_vpc_endpoint":{"e":{"vpc_id":"vpc-abc","subnet_ids":["\x24{aws_subnet.s.id}"]}}}})
    cfg={"resources":[config_resource("aws_subnet.s","aws_subnet"),config_resource("aws_vpc_endpoint.e","aws_vpc_endpoint",{"subnet_ids":["aws_subnet.s","aws_subnet.s.id"]})]}
    rows=[resource("aws_subnet.s","aws_subnet",{"vpc_id":"vpc-abc","tags":{"tfiam:scope":"s"}},{"id":True}),
          resource("aws_vpc_endpoint.e","aws_vpc_endpoint",{"vpc_id":"vpc-abc","service_name":"com.amazonaws.us-east-1.sqs","subnet_ids":None,"tags":{"tfiam:scope":"endpoint"}},{"subnet_ids":True,"id":True})]
    report=scan(tmp_path,plan=plan(cfg,rows),account=A,region=R,scope_resource_tags=True)
    assert any(scope.endswith(":subnet/*") and "ResourceTag/tfiam:scope" in cond for scope,cond in scopes(report,"ec2:CreateVpcEndpoint"))
    assert any(scope.endswith(":vpc-endpoint/*") and "RequestTag/tfiam:scope" in cond for scope,cond in scopes(report,"ec2:CreateVpcEndpoint"))

@pytest.mark.parametrize("typ,body,action,source",[
    ("aws_db_instance",{"identifier":"target","replicate_source_db":"source"},"rds:CreateDBInstanceReadReplica","db:source"),
    ("aws_db_instance",{"identifier":"target","restore_to_point_in_time":[{"source_db_instance_identifier":"source","use_latest_restorable_time":True}]},"rds:RestoreDBInstanceToPointInTime","db:source"),
    ("aws_rds_cluster",{"cluster_identifier":"target","restore_to_point_in_time":[{"source_cluster_identifier":"source","use_latest_restorable_time":True}]},"rds:RestoreDBClusterToPointInTime","cluster:source"),
])
def test_named_rds_operations(tmp_path,typ,body,action,source):
    write(tmp_path/"main.tf.json",{"resource":{typ:{"d":body}}})
    out=scan(tmp_path,account=A,region=R)
    targets={x[0] for x in scopes(out,action)}
    assert f"arn:aws:rds:{R}:{A}:{source}" in targets
    assert f"arn:aws:rds:{R}:{A}:{source.split(':')[0]}:target" in targets
    assert not scopes(out,"rds:CreateDBInstance")
    assert not scopes(out,"rds:CreateDBCluster")

def test_cross_region_and_ambiguous_rds_operations_block(tmp_path):
    f=tmp_path/"main.tf.json"
    write(f,{"resource":{"aws_db_instance":{"d":{"identifier":"target","replicate_source_db":"arn:aws:rds:us-west-2:"+A+":db:source"}}}})
    r=scan(tmp_path,account=A,region=R)
    assert any(x["action"]=="rds:CreateDBInstanceReadReplica" for x in r["unresolved_permissions"])
    assert not scopes(r,"rds:CreateDBInstance")
    write(f,{"resource":{"aws_db_instance":{"d":{"identifier":"target","replicate_source_db":"source","snapshot_identifier":"snap"}}}})
    r=scan(tmp_path,account=A,region=R)
    assert {x["action"] for x in r["unresolved_permissions"]}>={"rds:CreateDBInstanceReadReplica","rds:RestoreDBInstanceFromDBSnapshot"}
    assert not scopes(r,"rds:CreateDBInstance")

def test_managed_secret_scope_and_unknown_key(tmp_path):
    key=f"arn:aws:kms:{R}:{A}:key/12345678-1234-1234-1234-123456789012"
    f=tmp_path/"main.tf.json"
    body={"identifier":"target","manage_master_user_password":True,"master_user_secret_kms_key_id":key}
    write(f,{"resource":{"aws_db_instance":{"d":body}}})
    r=scan(tmp_path,account=A,region=R)
    for action in ("secretsmanager:CreateSecret","secretsmanager:TagResource"):
        assert {s for s,_ in scopes(r,action)}=={f"arn:aws:secretsmanager:{R}:{A}:secret:rds!db-*"}
    assert {s for s,_ in scopes(r,"kms:Decrypt")}=={key}
    assert not scopes(r,"secretsmanager:GetSecretValue")
    assert not scopes(r,"secretsmanager:DeleteSecret")
    body["master_user_secret_kms_key_id"]="alias/unknown"
    write(f,{"resource":{"aws_db_instance":{"d":body}}})
    r=scan(tmp_path,account=A,region=R)
    assert any(x["action"]=="kms:DescribeKey" for x in r["unresolved_permissions"])
    assert not scopes(r,"kms:Decrypt")

def test_vpc_fixture_candidate_is_conditioned(tmp_path):
    spec=importlib.util.spec_from_file_location("accept_vpc",ROOT/"scripts"/"accept-vpc.py")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    dest=tmp_path/"fixture"
    mod.prepare(Namespace(directory=dest,version="6.73.0",account=A,region=R))
    candidate=json.loads((dest/"candidate-policy.json").read_text())
    grants=mod.grants(candidate)
    assert any(a=="ec2:CreateVpc" and "aws:RequestTag/tfiam:scope" in c for a,s,c in grants)
    assert all(a.startswith("ec2:Describe") for a,s,c in grants if s=="*")
    assert ("ec2:DescribeNetworkInterfaces","*",json.dumps({"StringEquals":{"aws:RequestedRegion":R}},sort_keys=True,separators=(",",":"))) in grants
    changed=copy.deepcopy(candidate)
    changed["Statement"].append({"Effect":"Allow","Action":"ec2:DeleteVpc","Resource":"*"})
    with pytest.raises(ValueError): mod.grants(changed)

def test_subnet_delete_discovers_enis_only_in_destroy_lifecycle(tmp_path):
    body={"id":"subnet-123abc","vpc_id":"vpc-123abc","tags":{"tfiam:scope":"subnet"}}
    cfg={"resources":[config_resource("aws_subnet.s","aws_subnet")]}
    row=resource("aws_subnet.s","aws_subnet",body)
    expected={("*",json.dumps({"StringEquals":{"aws:RequestedRegion":R}},sort_keys=True))}
    for ops in (["delete"],["delete","create"],["create","delete"]):
        row["change"]={"actions":ops,"before":body,"after":None if ops==["delete"] else body,"after_unknown":{},"after_sensitive":{}}
        report=scan(tmp_path,plan=plan(cfg,[row]),account=A,region=R)
        assert scopes(report,"ec2:DescribeNetworkInterfaces")==expected
        assert not scopes(report,"ec2:DeleteNetworkInterface")
        assert not any("ec2:DescribeNetworkInterfaces" in f["actions"] for f in report["risks"] if f["kind"]=="destructive")
    row=resource("aws_subnet.s","aws_subnet",body)
    report=scan(tmp_path,plan=plan(cfg,[row]),account=A,region=R)
    assert not scopes(report,"ec2:DescribeNetworkInterfaces")
