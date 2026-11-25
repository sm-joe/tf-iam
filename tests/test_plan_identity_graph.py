"""Acceptance tests for IAM, ECS and ALB dependency inference."""
from tfiam.scan import scan
from tfiam.plan_identity import enrich

AWS="registry.terraform.io/hashicorp/aws"
ACCOUNT="638631156706"
REGION="us-east-1"


def resource(kind,name,values,unknown=None,refs=None):
    address=kind+"."+name
    expr={key:{"references":[reference,reference.rsplit(".",1)[0]]}
          for key,reference in (refs or {}).items()}
    return (
        {"address":address,"type":kind,"mode":"managed",
         "provider_name":AWS,"change":{"actions":["create"],"before":None,
              "after":values,"after_unknown":{"id":True,**(unknown or {})}}},
        {"address":address,"type":kind,"mode":"managed",
         "provider_config_key":"aws","expressions":expr}
    )


def plan(*rows):
    return {"format_version":"1.2","terraform_version":"1.17.1",
            "resource_changes":[x[0] for x in rows],
            "configuration":{"root_module":{"resources":[x[1] for x in rows]}}}


def test_iam_ecs_elb_plan_references_no_unscoped_passrole(monkeypatch):
    roles=[
        resource("aws_iam_role","task",{"name":"ecs-task-role","path":"/"}),
        resource("aws_iam_role","execution",{"name":"ecs-execution-role","path":"/"}),
    ]
    cluster=resource("aws_ecs_cluster","main",{"name":"ecs-demo-cluster"})
    task=resource("aws_ecs_task_definition","app",
                  {"family":"ecs-demo","execution_role_arn":None,"task_role_arn":None},
                  {"execution_role_arn":True,"task_role_arn":True},
                  {"execution_role_arn":"aws_iam_role.execution.arn",
                   "task_role_arn":"aws_iam_role.task.arn"})
    service=resource("aws_ecs_service","app",
                     {"name":"ecs-demo-service","cluster":None,"task_definition":None},
                     {"cluster":True,"task_definition":True},
                     {"cluster":"aws_ecs_cluster.main.id",
                      "task_definition":"aws_ecs_task_definition.app.arn"})
    lb=resource("aws_lb","main",{"name":"ecs-demo-alb","load_balancer_type":"application"})
    listener=resource("aws_lb_listener","http",{"load_balancer_arn":None,"port":80,"protocol":"HTTP"},
                      {"load_balancer_arn":True},
                      {"load_balancer_arn":"aws_lb.main.arn"})
    p=plan(*roles,cluster,task,service,lb,listener)
    direct=enrich(
        p,"aws_lb_listener.http",listener[0]["change"]["after"],
        {"entry":{"type":"aws_lb_listener"},"operation":"create",
         "unknown_fields":["load_balancer_arn"],"all_fields_masked":False},
        lambda _: (ACCOUNT,REGION,"aws")
    )
    assert direct.get("_tfiam_parent_lb_arn")==(
        f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/ecs-demo-alb/*")
    import importlib
    module=importlib.import_module("tfiam.scan")
    original=module.elb
    seen=[]
    def capture(typ,body,*args,**kwargs):
        if typ=="aws_lb_listener":
            seen.append((body.get("_tfiam_parent_lb_arn"),args[0]))
            import re
            prefix=f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:"
            assert re.fullmatch(re.escape(prefix)+r"loadbalancer/(?:app|net|gwy)/[A-Za-z0-9-]{1,32}/\*",body["_tfiam_parent_lb_arn"])
        return original(typ,body,*args,**kwargs)
    monkeypatch.setattr(module,"elb",capture)
    report=scan(plan=p,account=ACCOUNT,region=REGION)
    assert seen and seen[0][0]==f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/ecs-demo-alb/*"
    assert "elasticloadbalancing:CreateListener" in seen[0][1]
    def rows(source,action):
        return [row for row in report["permissions"]
                if row["source"]==source and row["action"]==action]
    passed=rows("aws_ecs_task_definition.app","iam:PassRole")
    assert {row["scope"] for row in passed} == {
        f"arn:aws:iam::{ACCOUNT}:role/ecs-task-role",
        f"arn:aws:iam::{ACCOUNT}:role/ecs-execution-role"
    }
    assert all(row["condition"]=={
        "StringEquals":{"iam:PassedToService":"ecs-tasks.amazonaws.com"}
    } for row in passed)
    ecs=rows("aws_ecs_service.app","ecs:CreateService")
    assert len(ecs)==1
    assert ecs[0]["scope"]==f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/ecs-demo-cluster/ecs-demo-service"
    assert ecs[0]["condition"]=={
        "ArnLike":{"ecs:task-definition":
                   f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/ecs-demo:*"}}
    alb=rows("aws_lb_listener.http","elasticloadbalancing:CreateListener")
    assert len(alb)==1
    assert alb[0]["scope"]==f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/ecs-demo-alb/*"
    for source,action in (
        ("aws_ecs_task_definition.app","iam:PassRole"),
        ("aws_ecs_service.app","ecs:CreateService"),
        ("aws_lb_listener.http","elasticloadbalancing:CreateListener"),
    ):
        assert not any(x["source"]==source and x["action"]==action
                       for x in report["unresolved_permissions"])


def test_sensitive_iam_parent_cannot_be_inferred():
    task_role=resource("aws_iam_role","task",{"name":"secret-role","path":"/"})
    task_role[0]["change"]["after_sensitive"]={"name":True}
    task=resource("aws_ecs_task_definition","app",
                  {"family":"demo","task_role_arn":None},
                  {"task_role_arn":True},
                  {"task_role_arn":"aws_iam_role.task.arn"})
    report=scan(plan=plan(task_role,task),account=ACCOUNT,region=REGION)
    assert not any("secret-role" in str(x) for x in report["permissions"])
    assert any(x["source"]=="aws_ecs_task_definition.app" and x["action"]=="iam:PassRole"
               for x in report["unresolved_permissions"])


def test_mixed_parents_do_not_produce_role_guess():
    execution=resource("aws_iam_role","execution",{"name":"execution","path":"/"})
    taskrole=resource("aws_iam_role","task",{"name":"task","path":"/"})
    definition=resource("aws_ecs_task_definition","app",
                        {"family":"demo","task_role_arn":None},{"task_role_arn":True},
                        {"task_role_arn":"aws_iam_role.task.arn"})
    definition[1]["expressions"]["task_role_arn"]["references"]=[
        "aws_iam_role.task.arn","aws_iam_role.execution.arn"
    ]
    report=scan(plan=plan(execution,taskrole,definition),account=ACCOUNT,region=REGION)
    assert not any(row["source"]=="aws_ecs_task_definition.app"
                   and row["action"]=="iam:PassRole"
                   for row in report["permissions"])
