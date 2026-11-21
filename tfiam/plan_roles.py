"""Conservative recovery of computed EKS role ARNs in saved plans.

Terraform JSON references alone do not identify a direct expression. Require
the matching root source expression as well as the saved plan dependency.
"""
import re
from .plan import AWS, masked

FIELDS={"aws_eks_cluster":"role_arn","aws_eks_node_group":"node_role_arn",
        "aws_eks_pod_identity_association":"role_arn","aws_eks_addon":"service_account_role_arn"}
DIRECT=re.compile(r"\$\{(aws_iam_role\.[A-Za-z0-9_-]+)\.arn\}")
ROLE_NAME=re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}")
ROLE_PATH=re.compile(r"/(?:[A-Za-z0-9_+=,.@-]+/)*")

def recover_role_arn(plan,address,field,definitions,account,partition):
    if not isinstance(account,str) or not re.fullmatch(r"[0-9]{12}",account): return None
    if partition not in ("aws","aws-cn","aws-us-gov"): return None
    # Deliberately exclude indexed/module/deposed instances until exact
    # instance-to-configuration binding is available.
    if not re.fullmatch(r"aws_eks_[a-z_]+\.[A-Za-z0-9_-]+",address): return None
    expr=definitions.get(address,{}).get(field)
    match=DIRECT.fullmatch(expr) if isinstance(expr,str) else None
    if not match: return None
    target=match.group(1)
    cfg=plan.get("configuration",{}).get("root_module",{}).get("resources",[])
    def one(items,addr):
        found=[r for r in items if isinstance(r,dict) and r.get("address")==addr]
        return found[0] if len(found)==1 else None
    consumer=one(cfg,address); role=one(cfg,target)
    if not consumer or not role: return None
    # Alias/cross-account provider contexts cannot be inferred from an account flag.
    if consumer.get("provider_config_key")!="aws" or role.get("provider_config_key")!="aws": return None
    references=consumer.get("expressions",{}).get(field,{}).get("references",[])
    if not isinstance(references,list) or not all(isinstance(x,str) for x in references): return None
    if target+".arn" not in references or set(references)-{target,target+".arn"}: return None
    changes=[r for r in plan.get("resource_changes",[]) if isinstance(r,dict) and not r.get("deposed")]
    c=one(changes,address); r=one(changes,target)
    if not c or not r or c.get("provider_name")!=AWS or r.get("provider_name")!=AWS or r.get("type")!="aws_iam_role" or r.get("mode")!="managed": return None
    cc=c.get("change",{}); rc=r.get("change",{})
    if not any(x in cc.get("actions",[]) for x in ("create","update")): return None
    unknown=cc.get("after_unknown"); sensitive=cc.get("after_sensitive")
    if not isinstance(unknown,dict) or unknown.get(field) is not True: return None
    if sensitive is True or isinstance(sensitive,dict) and sensitive.get(field): return None
    if rc.get("actions") not in (["create"],["update"],["no-op"],["delete","create"],["create","delete"]): return None
    values=masked(rc.get("after") or {},rc.get("after_sensitive"),rc.get("after_unknown"))
    if not isinstance(values,dict): return None
    name=values.get("name"); path=values.get("path")
    if not isinstance(name,str) or not ROLE_NAME.fullmatch(name) or not isinstance(path,str) or not ROLE_PATH.fullmatch(path): return None
    arn=f"arn:{partition}:iam::{account}:role{path}{name}"
    if values.get("arn") is not None and values["arn"]!=arn: return None
    if len(arn)>2048: return None
    return arn
