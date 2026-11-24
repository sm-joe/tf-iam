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
    assumption=cfg.get("assume_role",cfg.get("assume_role_with_web_identity"))
    if profile is not None:
        import os
        # For a known destination role, the profile selects source credentials,
        # not the account in which Terraform will create the resources.
        if not isinstance(profile,str) or (assumption is None and profile != os.environ.get("AWS_PROFILE")): return None
    if assumption is not None:
        if isinstance(assumption,list) and len(assumption)==1: assumption=assumption[0]
        if not isinstance(assumption,dict): return None
        role=assumption.get("role_arn")
        match=re.fullmatch(r"arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/[^*?\s]+",role) if isinstance(role,str) else None
        if not match: return None
        p,a=match.group(1),match.group(2)
    if r is not None and ((str(r).startswith("cn-")) != (p=="aws-cn") or (str(r).startswith("us-gov-")) != (p=="aws-us-gov")): return None
    return a,r,p


def discover_aws_identity(account=None,region=None,partition="aws",profile=None):
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
        # Standalone/Python installs may ship boto3 without the separate AWS CLI.
        # Short timeouts prevent credential-discovery hangs on non-AWS hosts.
        try:
            import boto3
            from botocore.config import Config
            session=boto3.Session(profile_name=profile)
            region=region or session.region_name
            sts_region=region or {"aws":"us-east-1","aws-cn":"cn-north-1",
                                  "aws-us-gov":"us-gov-west-1"}[partition]
            identity=session.client("sts",region_name=sts_region,config=Config(
                connect_timeout=2,read_timeout=2,retries={"max_attempts":1}
            )).get_caller_identity()
            arn=identity.get("Arn","")
            matched=re.match(r"arn:(aws|aws-cn|aws-us-gov):",arn)
            candidate=identity.get("Account")
            if matched and isinstance(candidate,str) and re.fullmatch(r"[0-9]{12}",candidate):
                return candidate,region,matched.group(1)
        except Exception:
            pass  # No usable AWS identity; the resolver will surface the omission.
        return account,region,partition
    env=dict(os.environ, AWS_EC2_METADATA_DISABLED="true")
    if not region:
        try:
            configured_region=subprocess.run(
                ["aws"]+(["--profile",profile] if profile else [])+["configure","get","region"],capture_output=True,text=True,
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
        cmd=["aws"]+(["--profile",profile] if profile else [])+["sts","get-caller-identity","--output","json"]
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


def discover_profile_contexts(root,contexts=None):
    """Resolve named AWS provider profiles for zero-config generation only.

    Only literal provider/profile declarations are eligible. Arbitrary
    expressions, credentials, or unknown identities are not guessed.
    """
    from pathlib import Path
    from .resolver import read_document,groups
    out=dict(contexts or {})
    if root is None: return out
    folder=Path(root)
    if not folder.is_dir(): return out
    for path in sorted(set(folder.glob("*.tf"))|set(folder.glob("*.tf.json"))):
        try:
            doc=read_document(path)
        except (ValueError,OSError,ImportError):
            continue
        for group in groups(doc,"provider"):
            for cfg in group.get("aws",[]) if isinstance(group.get("aws",[]),list) else [group.get("aws",{})]:
                if not isinstance(cfg,dict): continue
                alias=cfg.get("alias")
                key="aws."+alias if isinstance(alias,str) else "aws"
                if key in out: continue
                profile=cfg.get("profile")
                if not isinstance(profile,str) or not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}",profile): continue
                if cfg.get("assume_role") or cfg.get("assume_role_with_web_identity"): continue
                region=cfg.get("region")
                if region is not None and (not isinstance(region,str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",region)): continue
                a,r,p=discover_aws_identity(region=region,profile=profile)
                if a and r: out[key]={"account":a,"region":r,"partition":p}
    return out
