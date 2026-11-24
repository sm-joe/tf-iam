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
    """Determine the target of a Terraform AWS provider, not its caller's identity.

    A constant assume_role ARN selects the destination account. Never substitute
    the caller's account for an unresolved assumed role or a different profile.
    """
    if key in overrides: return overrides[key]
    if not normalize(key) or not isinstance(cfg,dict): return None
    if any(k in cfg for k in ("access_key","secret_key","token","endpoints")): return None
    a,r,p=default
    region=cfg.get("region")
    if region is not None:
        if not isinstance(region,str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",region): return None
        r=region  # Explicit Terraform provider region takes precedence over AWS CLI defaults.
    profile=cfg.get("profile")
    if profile is not None:
        import os
        if not isinstance(profile,str) or profile != os.environ.get("AWS_PROFILE"): return None
    assumption=cfg.get("assume_role",cfg.get("assume_role_with_web_identity"))
    if assumption is not None:
        if isinstance(assumption,list) and len(assumption)==1: assumption=assumption[0]
        if not isinstance(assumption,dict): return None
        role=assumption.get("role_arn")
        match=re.fullmatch(r"arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/[^*?\\s]+",role) if isinstance(role,str) else None
        if not match: return None
        p,a=match.group(1),match.group(2)
    if r is not None and ((str(r).startswith("cn-")) != (p=="aws-cn") or (str(r).startswith("us-gov-")) != (p=="aws-us-gov")): return None
    return a,r,p


def discover_aws_identity(account=None,region=None,partition="aws"):
    """Read-only best-effort caller discovery for zero-config CLI invocations.

    This never modifies AWS, assumes a role, or fabricates an AWS account ID.
    The identity is the *caller*, and configured() handles target assume_role.
    """
    import json
    import os
    import shutil
    import subprocess

    region=region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not shutil.which("aws"):
        return account,region,partition
    env=dict(os.environ, AWS_EC2_METADATA_DISABLED="true")
    if not region:
        try:
            configured_region=subprocess.run(
                ["aws","configure","get","region"],capture_output=True,text=True,
                timeout=3,env=env,check=False,
            )
            candidate=configured_region.stdout.strip()
            if configured_region.returncode==0 and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",candidate):
                region=candidate
        except (OSError,subprocess.TimeoutExpired):
            pass
    if account is not None:
        return account,region,partition
    try:
        cmd=["aws","sts","get-caller-identity","--output","json"]
        if region: cmd.extend(["--region",region])
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=5,env=env,check=False)
        if result.returncode!=0: return account,region,partition
        identity=json.loads(result.stdout)
        arn=identity.get("Arn","")
        matched=re.match(r"arn:(aws|aws-cn|aws-us-gov):",arn)
        candidate=identity.get("Account")
        if matched and isinstance(candidate,str) and re.fullmatch(r"[0-9]{12}",candidate):
            return candidate,region,matched.group(1)
    except (OSError,ValueError,subprocess.TimeoutExpired):
        pass
    return account,region,partition

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
        if key=="aws" and not providers: return overrides.get(key,default)
        cfg=providers.get(key)
        if not isinstance(cfg,dict): return None
        if cfg.get("full_name","registry.terraform.io/hashicorp/aws")!="registry.terraform.io/hashicorp/aws": return None
        if key in overrides: return overrides[key]
        if cfg.get("alias") or key!="aws": return None
        expressions=cfg.get("expressions",{})
        values={k:v.get("constant_value") if isinstance(v,dict) else None for k,v in expressions.items()}
        return configured(key,values,default,overrides)
    return select
