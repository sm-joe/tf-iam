"""Recover tag-bounded generated EC2 references from matching source and plan."""
import re
from .action_scope import EC2_TYPES, tag_conditions
from .plan import AWS, masked

def anchor(body):
    tags=body.get("tags",{})
    value=tags.get("tfiam:scope") if isinstance(tags,dict) else None
    if not isinstance(value,str) or not value: return {}
    return tag_conditions({"tags":{"tfiam:scope":value}},"ec2:ResourceTag/")

def recover(plan,address,definitions,select,body,task):
    out={}
    if not re.fullmatch(r"aws_[a-z_]+\.[A-Za-z0-9_-]+",address) or task.get("operation")!="create": return out
    configs=plan.get("configuration",{}).get("root_module",{}).get("resources",[])
    changes=[r for r in plan.get("resource_changes",[]) if not r.get("deposed")]
    def one(rows,addr):
        found=[r for r in rows if r.get("address")==addr]
        return found[0] if len(found)==1 else {}
    consumer=one(configs,address); change=one(changes,address).get("change",{})
    if not consumer or not change: return out
    for field,expr in definitions.get(address,{}).items():
        match=re.fullmatch(r"\$\{(aws_[a-z_]+\.[A-Za-z0-9_-]+)\.id\}",expr) if isinstance(expr,str) else None
        if not match or body.get(field) is not None: continue
        target=match.group(1); kind=target.split(".")[0]
        if kind not in EC2_TYPES or select(target)!=select(address) or select(target) is None: continue
        if not isinstance(change.get("after_unknown"),dict) or change["after_unknown"].get(field) is not True: continue
        sensitive=change.get("after_sensitive")
        if sensitive is True or isinstance(sensitive,dict) and sensitive.get(field): continue
        refs=consumer.get("expressions",{}).get(field,{}).get("references",[])
        if not isinstance(refs,list) or target+".id" not in refs or any(x not in (target,target+".id") for x in refs): continue
        parent=one(changes,target); parent_cfg=one(configs,target)
        if not parent_cfg or parent.get("provider_name")!=AWS or parent.get("mode")!="managed" or parent.get("type")!=kind: continue
        pc=parent.get("change",{})
        if pc.get("actions")!=["create"]: continue
        parent_body=masked(pc.get("after") or {},pc.get("after_sensitive"),pc.get("after_unknown"))
        condition=anchor(parent_body) if isinstance(parent_body,dict) else {}
        if condition: out[field]={"kind":EC2_TYPES[kind][0],"condition":condition}
    return out
