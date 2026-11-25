"""Representative 43-resource ECS and VPC plan acceptance fixture.

This fixture exercises the same Terraform resource families and instance
shapes as the reported ECS example; it is not the user's original plan.
"""
import json

from tfiam.cli import main
from tfiam.scan import scan
from tfiam.plan_network import clean
from tfiam.policy_size import grants

AWS="registry.terraform.io/hashicorp/aws"
ACCOUNT="638631156706"
REGION="us-east-1"

ADDRESSES=[
    "aws_autoscaling_group.ecs",
    "aws_cloudwatch_log_group.ecs",
    "aws_ecr_lifecycle_policy.app",
    "aws_ecr_repository.app",
    "aws_ecs_cluster.main",
    "aws_ecs_service.app",
    "aws_ecs_task_definition.app",
    "aws_iam_instance_profile.ecs",
    "aws_iam_role.ecs_execution_role",
    "aws_iam_role.ecs_instance_role",
    "aws_iam_role_policy_attachment.ecs_execution_policy",
    "aws_iam_role_policy_attachment.ecs_instance_policy",
    "aws_iam_role_policy_attachment.ssm_instance_policy",
    "aws_internet_gateway.main",
    "aws_launch_template.ecs",
    "aws_lb.main",
    "aws_lb_listener.http",
    "aws_lb_target_group.app",
    "aws_route.public_internet",
    "aws_route_table.private[0]",
    "aws_route_table.private[1]",
    "aws_route_table.public",
    "aws_route_table_association.private[0]",
    "aws_route_table_association.private[1]",
    "aws_route_table_association.public[0]",
    "aws_route_table_association.public[1]",
    "aws_security_group.alb",
    "aws_security_group.ecs",
    "aws_security_group.vpc_endpoints",
    "aws_subnet.private[0]",
    "aws_subnet.private[1]",
    "aws_subnet.public[0]",
    "aws_subnet.public[1]",
    "aws_vpc.main",
    'aws_vpc_endpoint.interface["ecr.api"]',
    'aws_vpc_endpoint.interface["ecr.dkr"]',
    'aws_vpc_endpoint.interface["ecs"]',
    'aws_vpc_endpoint.interface["ecs-agent"]',
    'aws_vpc_endpoint.interface["ecs-telemetry"]',
    'aws_vpc_endpoint.interface["logs"]',
    'aws_vpc_endpoint.interface["ssm"]',
    'aws_vpc_endpoint.interface["ssmmessages"]',
    "aws_vpc_endpoint.s3",
]

def fixture():
    rows=[]
    config={}
    for address in ADDRESSES:
        base=clean(address)
        kind=base.split(".",1)[0]
        name=base.split(".",1)[1]
        after={}
        unknown={"id":True}
        refs={}
        if kind=="aws_vpc":
            after={"cidr_block":"10.0.0.0/16"}
        elif kind in {"aws_subnet","aws_route_table","aws_security_group",
                      "aws_internet_gateway","aws_vpc_endpoint"}:
            after["vpc_id"]=None
            unknown["vpc_id"]=True
            refs["vpc_id"]=["aws_vpc.main.id","aws_vpc.main"]
        if kind=="aws_subnet":
            after["cidr_block"]="10.0.1.0/24"
        if kind=="aws_ecs_cluster": after["name"]="ecs-demo-dev-cluster"
        if kind=="aws_ecs_task_definition":
            after.update({"family":"ecs-demo-dev","execution_role_arn":None})
            unknown["execution_role_arn"]=True
            refs["execution_role_arn"]=[
                "aws_iam_role.ecs_execution_role.arn","aws_iam_role.ecs_execution_role"]
        if kind=="aws_ecs_service":
            after.update({"name":"ecs-demo-dev-service","cluster":None,"task_definition":None})
            unknown.update({"cluster":True,"task_definition":True})
            refs.update({
                "cluster":["aws_ecs_cluster.main.id","aws_ecs_cluster.main"],
                "task_definition":["aws_ecs_task_definition.app.arn","aws_ecs_task_definition.app"]})
        if kind=="aws_iam_role":
            after.update({"name":"ecs-demo-"+name.replace("_","-"),"path":"/"})
        if kind=="aws_lb":
            after.update({"name":"ecs-demo-dev-alb","load_balancer_type":"application"})
        if kind=="aws_lb_target_group": after.update({"name":"ecs-demo-dev-tg","port":80,"protocol":"HTTP"})
        if kind=="aws_lb_listener":
            after.update({"port":80,"protocol":"HTTP","load_balancer_arn":None})
            unknown["load_balancer_arn"]=True
            refs["load_balancer_arn"]=["aws_lb.main.arn","aws_lb.main"]
        if kind=="aws_ecr_repository": after["name"]="ecs-demo-dev"
        if kind=="aws_ecr_lifecycle_policy": after["repository"]="ecs-demo-dev"
        if kind=="aws_cloudwatch_log_group": after["name"]="/ecs/ecs-demo-dev"
        if kind=="aws_autoscaling_group":
            after.update({"name":"ecs-demo-dev-asg","min_size":1,"max_size":2})
        if kind=="aws_launch_template": after["name"]="ecs-demo-dev-lt"
        if kind=="aws_iam_instance_profile":
            after.update({"name":"ecs-demo-instance-profile","role":"ecs-demo-ecs-instance-role"})
        if kind=="aws_vpc_endpoint":
            after["service_name"]="com.amazonaws.us-east-1.s3" if name=="s3" else "com.amazonaws.us-east-1.ecr.api"
        rows.append({
            "address":address,"type":kind,"mode":"managed","provider_name":AWS,
            "change":{"actions":["create"],"before":None,"after":after,
                      "after_unknown":unknown}})
        if base not in config:
            config[base]={
                "address":base,"type":kind,"mode":"managed",
                "provider_config_key":"aws",
                "expressions":{key:{"references":value} for key,value in refs.items()}
            }
    return {"format_version":"1.2","terraform_version":"1.17.1",
            "resource_changes":rows,
            "configuration":{"root_module":{"resources":list(config.values())}}}


def test_43_resource_ecs_saved_plan_generation_and_reconciliation(tmp_path):
    assert len(ADDRESSES)==43
    data=fixture()
    report=scan(plan=data,account=ACCOUNT,region=REGION)
    coverage=report["mapping_coverage"]
    assert coverage["eligible_resources"]==43
    assert coverage["mapped_resources"]==43
    assert coverage["unmapped_resources"]==0
    expected={
        "ec2:CreateVpc","ec2:CreateSubnet","ec2:CreateRouteTable",
        "ec2:CreateSecurityGroup","ec2:CreateVpcEndpoint",
        "ecs:CreateCluster","ecs:RegisterTaskDefinition","ecs:CreateService",
        "iam:CreateRole","elasticloadbalancing:CreateLoadBalancer",
        "elasticloadbalancing:CreateListener","ecr:CreateRepository",
    }
    plan_path=tmp_path/"plan.json"
    plan_path.write_text(json.dumps(data))
    target=tmp_path/"policy.json"
    assert main(["generate","--plan-json",str(plan_path),
                 "--aws-account",ACCOUNT,"--aws-region",REGION,
                 "--output",str(target)])==0
    policy=json.loads(target.read_text())
    actions={action for row in policy["Statement"] for action in row["Action"]}
    assert expected <= actions
    assert grants(policy)
    assert any(row["action"]=="ec2:CreateSubnet"
               and row["scope"].endswith(":vpc/*")
               for row in report["permissions"])
    assert any(row["action"]=="elasticloadbalancing:CreateListener"
               and ":loadbalancer/app/ecs-demo-dev-alb/*" in row["scope"]
               for row in report["permissions"])
    assert not any(x["source"]=="aws_ecs_service.app" and
                   x["action"]=="ecs:CreateService"
                   for x in report["unresolved_permissions"])
