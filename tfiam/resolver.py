"""Restricted static Terraform evaluation. Never executes expressions, providers or modules."""
import json
import os
import re
from pathlib import Path

UNKNOWN = object()
EXPR = re.compile(r"\$\{([^{}]+)\}")
REF = re.compile(r"[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)+")
MODULE_META = {"source","version","providers","depends_on","count","for_each"}

def read_document(path):
    if path.name.endswith(".json"):
        value=json.loads(path.read_bytes())
    else:
        import hcl2
        with path.open(encoding="utf-8-sig") as handle:
            value=hcl2.load(handle)
    if not isinstance(value,dict):
        raise ValueError("Expected object")
    return value

def groups(doc, key):
    value=doc.get(key,[])
    return value if isinstance(value,list) else [value]

def static(value):
    if isinstance(value,str):
        return not EXPR.search(value) and "${" not in value and "%{" not in value
    if isinstance(value,list):
        return all(static(v) for v in value)
    if isinstance(value,dict):
        return all(static(v) for v in value.values())
    return True

def env_value(raw, declaration):
    kind=declaration.get("type")
    if kind in ("string","${string}") or (kind is None and isinstance(declaration.get("default"),str)):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return raw

def root_inputs(root, declarations, files, overrides, warn, environ=None):
    env=os.environ if environ is None else environ
    values={}
    for name,decl in declarations.items():
        if "default" in decl:
            values[name]=decl["default"]
        key="TF_VAR_"+name
        if key in env:
            values[name]=env_value(env[key],decl)
    automatic=[p for p in (root/"terraform.tfvars",root/"terraform.tfvars.json") if p.is_file()]
    automatic+=sorted(set(root.glob("*.auto.tfvars"))|set(root.glob("*.auto.tfvars.json")))
    for path in automatic+list(files or []):
        try:
            supplied=read_document(Path(path))
        except Exception:
            raise ValueError("Unable to read Terraform variable file: "+str(path)) from None
        for name,value in supplied.items():
            if name in declarations: values[name]=value
            else: warn("Undeclared variable in input file ignored")
    for name,raw in overrides or []:
        if name not in declarations:
            raise ValueError("Explicit variable is not declared: "+name)
        values[name]=env_value(raw,declarations[name])
    for name,decl in declarations.items():
        if decl.get("sensitive") is True or decl.get("ephemeral") is True:
            values[name]=UNKNOWN
        elif name in values and not static(values[name]):
            values[name]=UNKNOWN
        elif values.get(name,UNKNOWN) is None and decl.get("nullable") is False:
            values[name]=decl.get("default",UNKNOWN)
    return values

class Context:
    def __init__(self, docs, inputs, account, region, partition, warn, path=""):
        self.inputs=inputs
        self.account=account
        self.region=region
        self.partition=partition
        self.warn=warn
        self.path=path
        self.resources={}
        self.locals={}
        self.outputs={}
        self.children={}
        self.declarations={}
        for _,doc in docs:
            for group in groups(doc,"variable"):
                self.declarations.update(group)
            for group in groups(doc,"locals"):
                self.locals.update(group)
            for group in groups(doc,"output"):
                self.outputs.update(group)
            for group in groups(doc,"resource"):
                for kind,instances in group.items():
                    for name,body in instances.items():
                        self.resources[kind+"."+name]=body

    def evaluate(self,value,seen=()):
        if value is UNKNOWN: return UNKNOWN
        if isinstance(value,list): return [self.evaluate(v,seen) for v in value]
        if isinstance(value,dict): return {k:self.evaluate(v,seen) for k,v in value.items()}
        if not isinstance(value,str): return value
        if "$${" in value or "%%{" in value or "%{" in value: return UNKNOWN
        match=EXPR.fullmatch(value)
        if match: return self.reference(match.group(1).strip(),seen)
        if "${" not in value: return value
        parts=[]; end=0
        for match in EXPR.finditer(value):
            parts.append(value[end:match.start()])
            resolved=self.reference(match.group(1).strip(),seen)
            if not isinstance(resolved,(str,int,float,bool)): return UNKNOWN
            parts.append(str(resolved).lower() if isinstance(resolved,bool) else str(resolved))
            end=match.end()
        parts.append(value[end:])
        result="".join(parts)
        return UNKNOWN if "${" in result or "%{" in result else result

    def reference(self,ref,seen):
        key=(id(self),ref)
        if key in seen or len(seen)>=64 or not REF.fullmatch(ref): return UNKNOWN
        seen=seen+(key,)
        parts=ref.split(".")
        if parts[0]=="var":
            value=self.inputs.get(parts[1],UNKNOWN)
            rest=parts[2:]
        elif parts[0]=="local":
            value=self.evaluate(self.locals.get(parts[1],UNKNOWN),seen)
            rest=parts[2:]
        elif parts[0]=="module" and len(parts)>=3:
            child=self.children.get(parts[1])
            if child is None: return UNKNOWN
            output=child.outputs.get(parts[2],{})
            if output.get("sensitive") is True or output.get("ephemeral") is True: return UNKNOWN
            value=child.evaluate(output.get("value",UNKNOWN),seen)
            rest=parts[3:]
        elif len(parts)==3:
            kind,name,attr=parts
            body=self.resources.get(kind+"."+name)
            if body is None or "count" in body or "for_each" in body: return UNKNOWN
            if attr=="arn" and kind in ("aws_iam_role","aws_iam_policy","aws_iam_user","aws_iam_group"):
                name=self.evaluate(body.get("name",UNKNOWN),seen)
                path=self.evaluate(body.get("path","/"),seen)
                if not self.account or not isinstance(name,str) or not isinstance(path,str): return UNKNOWN
                if not re.fullmatch(r"[\w+=,.@-]+",name) or not path.startswith("/") or not path.endswith("/"): return UNKNOWN
                if any(c in path for c in "*?"): return UNKNOWN
                return f"arn:{self.partition}:iam::{self.account}:{kind.removeprefix('aws_iam_')}{path}{name}"
            # The AWS provider documents the S3 bucket ID as the bucket name.
            # Do not infer random names, prefix-generated names or arbitrary IDs.
            if attr=="id" and kind=="aws_s3_bucket":
                from .plan_buckets import valid_bucket
                bucket=self.evaluate(body.get("bucket",UNKNOWN),seen)
                return bucket if valid_bucket(bucket) else UNKNOWN
            # Only explicit config attributes, never pretend to know provider-generated values.
            if attr not in ("name","bucket","key","cluster_name","node_group_name","addon_name","path","policy_arn","role_arn"): return UNKNOWN
            return self.evaluate(body.get(attr,UNKNOWN),seen)
        else:
            return UNKNOWN
        for part in rest:
            if not isinstance(value,dict): return UNKNOWN
            value=value.get(part,UNKNOWN)
        return value

def sanitize(value):
    if value is UNKNOWN: return None
    if isinstance(value,dict): return {k:sanitize(v) for k,v in value.items()}
    if isinstance(value,list): return [sanitize(v) for v in value]
    return value

def dependencies(value):
    refs=set()
    if isinstance(value,str):
        for match in EXPR.finditer(value):
            ref=match.group(1).strip()
            if REF.fullmatch(ref): refs.add(ref)
    elif isinstance(value,dict):
        for v in value.values(): refs.update(dependencies(v))
    elif isinstance(value,list):
        for v in value: refs.update(dependencies(v))
    return refs

def discover(root,account,region,partition,var_files,overrides,warn,environ=None):
    """Resolve each module call independently, with installed module manifest only."""
    root=Path(root).resolve()
    manifest={}
    manifest_path=root/".terraform/modules/modules.json"
    if manifest_path.exists():
        try:
            data=read_document(manifest_path)
            for row in data["Modules"]:
                if not isinstance(row,dict) or not isinstance(row.get("Key"),str): raise ValueError()
                key=row["Key"]
                if key in manifest: raise ValueError()
                manifest[key]=row
        except Exception:
            manifest={}
            warn("Installed module manifest invalid; remote module discovery disabled")
    inventory=[]; contexts=[]; edges=[]
    def collect(folder,path,parent_inputs,stack,root_call=False):
        folder=folder.resolve()
        if folder in stack or len(stack)>=64:
            warn((path or "root")+": module cycle or depth limit; skipped")
            return None
        if not folder.is_relative_to(root) or not folder.is_dir():
            warn((path or "root")+": module outside scan root or missing; skipped")
            return None
        docs=[]
        files=sorted(set(folder.glob("*.tf"))|set(folder.glob("*.tf.json")))
        for file in files:
            try:
                if not file.resolve().is_relative_to(root): raise ValueError()
                docs.append((str(file.relative_to(root)),read_document(file)))
            except Exception:
                warn((path or "root")+": Terraform file parse failed: "+file.name)
        if not files: warn((path or "root")+": no Terraform files")
        ctx=Context(docs,{},account,region,partition,warn,path)
        if root_call:
            ctx.inputs=root_inputs(root,ctx.declarations,var_files,overrides,warn,environ)
        else:
            for name,decl in ctx.declarations.items():
                value=parent_inputs.get(name,decl.get("default",UNKNOWN))
                ctx.inputs[name]=UNKNOWN if decl.get("sensitive") is True or decl.get("ephemeral") is True else value
        contexts.append((ctx,docs))
        calls={}
        for _,doc in docs:
            for group in groups(doc,"module"):
                calls.update(group)
        # Retry calls whose inputs refer to sibling outputs once siblings are available.
        # Resolve in topological order where simple module references are visible.
        pending=dict(calls)
        while pending:
            ready=[name for name,body in pending.items() if not any(ref.split(".")[1] in pending for ref in dependencies(body) if ref.startswith("module."))]
            if not ready:
                warn((path or "root")+": module input dependency cycle or unresolved sibling references")
                ready=list(pending)
            for name in sorted(ready):
                body=pending.pop(name)
                child_path=(path+"." if path else "")+"module."+name
                source=body.get("source")
                record={"address":child_path,"status":"UNRESOLVED"}
                inventory.append(record)
                edges.extend({"source":child_path,"reference":r} for r in sorted(dependencies(body)))
                if "count" in body or "for_each" in body:
                    warn(child_path+": module count/for_each not expanded; use saved plan")
                    continue
                if not isinstance(source,str) or not static(source):
                    warn(child_path+": dynamic module source unsupported"); continue
                if source.startswith(("./","../")):
                    target=folder/source
                else:
                    key=child_path.replace("module.","")
                    row=manifest.get(key,{})
                    if row.get("Source")!=source or not isinstance(row.get("Dir"),str):
                        warn(child_path+": remote module not installed or manifest source mismatch; run terraform init separately")
                        continue
                    target=root/row["Dir"]
                    if not target.resolve().is_relative_to((root/".terraform/modules").resolve()):
                        warn(child_path+": installed module outside cache; skipped"); continue
                inputs={k:ctx.evaluate(v) for k,v in body.items() if k not in MODULE_META}
                child=collect(target,child_path,inputs,stack+(folder,))
                if child:
                    ctx.children[name]=child
                    record["status"]="RESOLVED"
        return ctx
    collect(root,"",{},(),True)
    result=[]
    for ctx,docs in contexts:
        for src,doc in docs:
            transformed={}
            for category in ("resource","data"):
                mapped={}
                for group in groups(doc,category):
                    for kind,instances in group.items():
                        for name,body in instances.items():
                            addr=(ctx.path+"." if ctx.path else "")+("data." if category=="data" else "")+kind+"."+name
                            if "count" in body or "for_each" in body:
                                warn(addr+": static resource instances not expanded; use saved plan")
                            refs=dependencies(body)
                            edges.extend({"source":addr,"reference":r} for r in sorted(refs))
                            evaluated=ctx.evaluate(body)
                            if (body.get("count") is not None and evaluated.get("count")==0):
                                continue
                            if not static(sanitize(evaluated)) or contains_unknown(evaluated):
                                warn(addr+": unresolved or sensitive attributes; candidate permissions may be incomplete")
                            if kind=="aws_iam_role_policy_attachment":
                                original=body.get("role")
                                match=EXPR.fullmatch(original) if isinstance(original,str) else None
                                if match and match.group(1).endswith(".name"):
                                    arn=ctx.reference(match.group(1)[:-5]+".arn",())
                                    if arn is not UNKNOWN: evaluated["_tfiam_role_arn"]=arn
                            if kind in ("aws_iam_role_policy","aws_iam_user_policy","aws_iam_group_policy"):
                                field=kind.split("_")[2]
                                original=body.get(field)
                                match=EXPR.fullmatch(original) if isinstance(original,str) else None
                                if match and match.group(1).endswith(".name"):
                                    resolved=ctx.reference(match.group(1)[:-5]+".arn",())
                                    if resolved is not UNKNOWN: evaluated["_tfiam_identity_arn"]=resolved
                            mapped.setdefault(kind,{})[name]=sanitize(evaluated)
                if mapped: transformed[category]=mapped
            result.append((src,ctx.path,transformed))
    return result,inventory,edges

def contains_unknown(value):
    if value is UNKNOWN: return True
    if isinstance(value,dict): return any(contains_unknown(v) for v in value.values())
    if isinstance(value,list): return any(contains_unknown(v) for v in value)
    return False
