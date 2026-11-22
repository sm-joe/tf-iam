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


def recover_random_bucket_pattern(plan,address,definitions,select):
    """An opt-in, fixed-length name candidate; never invent the random value."""
    if not re.fullmatch(r"aws_s3_(?:bucket|bucket_public_access_block|bucket_versioning)\.[A-Za-z0-9_-]+",address): return None
    cfg=plan.get("configuration",{}).get("root_module",{})
    resources=cfg.get("resources",[])
    changes=[x for x in plan.get("resource_changes",[]) if not x.get("deposed")]
    def one(rows,addr):
        found=[x for x in rows if isinstance(x,dict) and x.get("address")==addr]
        return found[0] if len(found)==1 else {}
    def unknown_bucket(addr):
        row=one(changes,addr); c=row.get("change",{})
        return (row.get("provider_name")==AWS and row.get("mode")=="managed"
                and c.get("actions") in (["create"],["delete","create"],["create","delete"])
                and isinstance(c.get("after_unknown"),dict) and c["after_unknown"].get("bucket") is True
                and c.get("after_sensitive") is not True
                and not (isinstance(c.get("after_sensitive"),dict) and c["after_sensitive"].get("bucket")))
    if not unknown_bucket(address) or not select(address): return None
    target=address
    if not address.startswith("aws_s3_bucket."):
        raw=definitions.get(address,{}).get("bucket")
        m=re.fullmatch(r"\$\{(aws_s3_bucket\.[A-Za-z0-9_-]+)\.(id|bucket)\}",raw or "") if isinstance(raw,str) else None
        if not m: return None
        target,attr=m.groups()
        refs=one(resources,address).get("expressions",{}).get("bucket",{}).get("references",[])
        if target+"."+attr not in refs or set(refs)-{target,target+"."+attr}: return None
        if select(target)!=select(address) or not unknown_bucket(target): return None
    raw=definitions.get(target,{}).get("bucket")
    if not isinstance(raw,str): return None
    m=re.fullmatch(r"(.*)\$\{(random_id\.[A-Za-z0-9_-]+)\.hex\}",raw)
    if not m: return None
    prefix,random=m.groups()
    refs={random+".hex"}
    def var(m):
        name=m.group(1); refs.add("var."+name)
        declared=definitions.get("var."+name,{})
        config=cfg.get("variables",{}).get(name,{})
        value=plan.get("variables",{}).get(name,{}).get("value")
        if declared.get("sensitive") or declared.get("ephemeral") or config.get("sensitive") or config.get("ephemeral") or not isinstance(value,str):
            return "\x00"
        return value
    prefix=re.sub(r"\$\{var\.([A-Za-z0-9_-]+)\}",var,prefix)
    actual=one(resources,target).get("expressions",{}).get("bucket",{}).get("references",[])
    if not isinstance(actual,list) or not all(isinstance(x,str) for x in actual) or not refs.issubset(actual) or set(actual)-refs-{random}: return None
    rr=one(changes,random); rc=rr.get("change",{})
    if rr.get("provider_name")!="registry.terraform.io/hashicorp/random" or rr.get("type")!="random_id" or rr.get("mode")!="managed" or rc.get("actions") not in (["create"],["delete","create"],["create","delete"]): return None
    if not isinstance(rc.get("after_unknown"),dict) or rc["after_unknown"].get("hex") is not True: return None
    values=masked(rc.get("after") or {},rc.get("after_sensitive"),rc.get("after_unknown"))
    if not isinstance(values,dict) or values.get("prefix") not in (None,""): return None
    size=values.get("byte_length")
    if type(size) is not int or not 2<=size<=16 or not re.fullmatch(r"[a-z0-9][a-z0-9-]{4,}-",prefix) or len(prefix)+2*size>63: return None
    if rc.get("after_sensitive") is True or (isinstance(rc.get("after_sensitive"),dict) and rc["after_sensitive"].get("hex")): return None
    return prefix+"?"*(2*size)
