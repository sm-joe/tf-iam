"""Resolve explicit S3 bucket identity without predicting provider-generated names."""
import re
from .plan import AWS, masked

def valid_bucket(value):
    return isinstance(value,str) and bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",value)) and ".." not in value

def recover_bucket(plan,address,definitions):
    # Only matching direct root references; no ambiguous module/instance guessing.
    if not re.fullmatch(r"aws_s3_[a-z_]+\.[A-Za-z0-9_-]+",address): return None
    expr=definitions.get(address,{}).get("bucket")
    match=re.fullmatch(r"\$\{(aws_s3_bucket\.[A-Za-z0-9_-]+)\.(id|bucket)\}",expr) if isinstance(expr,str) else None
    if not match: return None
    target,attribute=match.groups()
    def one(items,addr):
        matches=[x for x in items if isinstance(x,dict) and x.get("address")==addr]
        return matches[0] if len(matches)==1 else None
    config=plan.get("configuration",{}).get("root_module",{}).get("resources",[])
    consumer=one(config,address); bucket=one(config,target)
    if not consumer or not bucket or consumer.get("provider_config_key")!="aws" or bucket.get("provider_config_key")!="aws": return None
    refs=consumer.get("expressions",{}).get("bucket",{}).get("references",[])
    if not isinstance(refs,list) or not all(isinstance(x,str) for x in refs): return None
    if target+"."+attribute not in refs or set(refs)-{target,target+"."+attribute}: return None
    changes=[x for x in plan.get("resource_changes",[]) if isinstance(x,dict) and not x.get("deposed")]
    c=one(changes,address); b=one(changes,target)
    if not c or not b or any(x.get("provider_name")!=AWS or x.get("mode")!="managed" for x in (c,b)) or b.get("type")!="aws_s3_bucket": return None
    cc=c.get("change",{}); bc=b.get("change",{})
    if not any(x in cc.get("actions",[]) for x in ("create","update")): return None
    if not isinstance(cc.get("after_unknown"),dict) or cc["after_unknown"].get("bucket") is not True: return None
    sensitive=cc.get("after_sensitive")
    if sensitive is True or isinstance(sensitive,dict) and sensitive.get("bucket"): return None
    if bc.get("actions") not in (["create"],["update"],["no-op"],["delete","create"],["create","delete"]): return None
    values=masked(bc.get("after") or {},bc.get("after_sensitive"),bc.get("after_unknown"))
    if not isinstance(values,dict): return None
    value=values.get("bucket")
    if not valid_bucket(value) or values.get("id") not in (None,value): return None
    return value

def source_only_resources(plan,definitions):
    # Compare declarations rather than changed instances: no-op/targeted
    # plans can omit change rows. Missing configuration is not proof of drift.
    config=plan.get("configuration",{}).get("root_module",{}).get("resources")
    if not isinstance(config,list): return []
    known={x.get("address") for x in config if isinstance(x,dict)}
    return sorted(k for k in definitions if k.startswith("aws_") and k not in known)
