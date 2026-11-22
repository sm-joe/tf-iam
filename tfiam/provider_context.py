"""Explicit offline AWS provider identity contexts; never infer assumed accounts."""
import re

def normalize(value):
    if not isinstance(value,str): return None
    if value.startswith("\u0024{") and value.endswith("}"): value=value[2:-1]
    return value if re.fullmatch(r"aws(?:\.[A-Za-z0-9_-]+)?",value) else None

def validate(raw):
    if raw is None: return {}
    if not isinstance(raw,dict): raise ValueError("Provider contexts must be an object")
    out={}
    for name,ctx in raw.items():
        if not isinstance(name,str) or not isinstance(ctx,dict) or set(ctx)-{"account","region","partition"}: raise ValueError("Invalid provider context")
        a,r,p=ctx.get("account"),ctx.get("region"),ctx.get("partition","aws")
        if not isinstance(a,str) or not re.fullmatch(r"[0-9]{12}",a) or not isinstance(r,str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",r) or p not in ("aws","aws-cn","aws-us-gov"): raise ValueError("Invalid provider account, region or partition")
        if (r.startswith("cn-"))!=(p=="aws-cn") or (r.startswith("us-gov-"))!=(p=="aws-us-gov"): raise ValueError("Provider partition and region disagree")
        out[name]=(a,r,p)
    return out

def configured(key,cfg,default,overrides):
    if key in overrides: return overrides[key]
    if key!="aws" or any(k in cfg for k in ("assume_role","assume_role_with_web_identity","profile","access_key","secret_key","token","endpoints")): return None
    a,r,p=default
    if "region" in cfg:
        value=cfg["region"]
        if not isinstance(value,str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",value): return None
        if r and r!=value: return None
        r=value
    return a,r,p

def plan_contexts(plan,default,overrides):
    config=plan.get("configuration",{})
    providers=config.get("provider_config",{})
    by_address={}
    def walk(module,prefix=""):
        for resource in module.get("resources",[]):
            addr=resource.get("address")
            if isinstance(addr,str):
                by_address[prefix+addr]=resource.get("provider_config_key")
        for name,call in module.get("module_calls",{}).items():
            walk(call.get("module",{}),prefix+"module."+name+".")
    walk(config.get("root_module",{}))
    def select(address):
        # Terraform configuration addresses omit count/for_each indices.
        clean=re.sub(r'\[(?:[0-9]+|"(?:[^"\\]|\\.)*")\]',"",address.split(" (deposed ",1)[0])
        key=by_address.get(clean)
        if key is None:
            return default if not providers and not by_address else None
        if key in overrides: return overrides[key]
        if key=="aws" and not providers: return default
        cfg=providers.get(key)
        if not isinstance(cfg,dict): return None
        if cfg.get("full_name","registry.terraform.io/hashicorp/aws")!="registry.terraform.io/hashicorp/aws": return None
        if cfg.get("alias") or key!="aws": return None
        expressions=cfg.get("expressions",{})
        values={k:v.get("constant_value") if isinstance(v,dict) else None for k,v in expressions.items()}
        return configured(key,values,default,overrides)
    return select
