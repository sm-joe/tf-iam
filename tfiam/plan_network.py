"""Recover EC2 generated IDs using direct source/plan references only."""
import re
import json
from pathlib import Path
from .action_scope import EC2_TYPES, tag_conditions
from .plan import AWS, masked, marked
from .resolver import groups, read_document

KEY=r'\[(?:[0-9]+|"(?:[^"\\]|\\.)*")\]'
INDEX=re.compile(KEY)
NAME=r'[A-Za-z0-9_-]+'
RESOURCE=re.compile(r'(aws_[a-z0-9_]+\.'+NAME+r')('+KEY+r')?')
MODULE=re.compile(r'module\.('+NAME+r')('+KEY+r')?\.')
DIRECT=re.compile(r'\x24\{(.+)\}')

def anchor(body,allow_name=False):
    tags=body.get("tags",{})
    value=tags.get("tfiam:scope") if isinstance(tags,dict) else None
    if isinstance(value,str) and value: return tag_conditions({"tags":{"tfiam:scope":value}},"ec2:ResourceTag/")
    name=tags.get("Name") if isinstance(tags,dict) else None
    if allow_name and isinstance(name,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{7,127}",name):
        return tag_conditions({"tags":{"Name":name}},"ec2:ResourceTag/")
    return {}

def clean(address):
    return INDEX.sub("",address)

def split_address(address):
    prefix=""
    while (m:=MODULE.match(address)):
        prefix+=m.group()
        address=address[m.end():]
    m=RESOURCE.fullmatch(address)
    return (prefix,m.group(1),m.group(2)) if m else None

def source_index(root,plan,definitions):
    """Load only matching local module sources inside root, never remote code."""
    root=Path(root).resolve()
    result={}
    def walk(folder,prefix,cfg,stack):
        if len(stack)>=64 or folder in stack or not folder.is_relative_to(root): return
        resources={}; calls={}; outputs={}; variables={}
        try:
            for path in sorted(set(folder.glob("*.tf"))|set(folder.glob("*.tf.json"))):
                if not path.resolve().is_relative_to(root): return
                doc=read_document(path)
                for kind,target in (("module",calls),("output",outputs),("variable",variables)):
                    for group in groups(doc,kind):
                        if set(target)&set(group): return
                        target.update(group)
                for group in groups(doc,"resource"):
                    for typ,instances in group.items():
                        for name,body in instances.items():
                            addr=typ+"."+name
                            if addr in resources: return
                            resources[addr]=body
        except (OSError,ValueError,TypeError,AttributeError): return
        except Exception: return
        if not prefix:
            resources={k:v for k,v in resources.items() if k in definitions}
        result[prefix]=(resources,calls,outputs,variables,cfg)
        for name,call in cfg.get("module_calls",{}).items():
            actual=calls.get(name,{})
            source=actual.get("source")
            if isinstance(source,str) and source.startswith(("./","../")) and call.get("source")==source:
                walk((folder/source).resolve(),prefix+"module."+name+".",call.get("module",{}),stack+(folder,))
    walk(root,"",plan.get("configuration",{}).get("root_module",{}),())
    return result

def one(rows,address):
    found=[r for r in rows if isinstance(r,dict) and r.get("address")==address]
    return found[0] if len(found)==1 else {}

def expression(raw,index):
    m=DIRECT.fullmatch(raw.strip()) if isinstance(raw,str) else None
    if not m: return None
    value=m.group(1).strip()
    # Substitute only the instance's own selector, not arbitrary arithmetic.
    for token in ("count.index","each.key"):
        if "["+token+"]" in value:
            if not index: return None
            if (token=="each.key") != index.startswith('["'): return None
            value=value.replace("["+token+"]",index)
    return value

def allowed_refs(meta,raw,concrete,base):
    refs=meta.get("references",[]) if isinstance(meta,dict) else []
    if not isinstance(refs,list) or not refs or not all(isinstance(x,str) for x in refs): return False
    allowed={concrete,base,concrete.rsplit(".",1)[0],base.rsplit(".",1)[0]}
    tokens={token for token in ("count.index","each.key") if "["+token+"]" in raw}
    allowed.update(tokens)
    if not tokens.issubset(refs): return False
    # A literal selector must itself be present in the configuration reference;
    # a reference to the unindexed collection cannot verify its chosen element.
    required={concrete,concrete.rsplit(".",1)[0]} if concrete!=base and not tokens else {concrete,base}
    if tokens: required.add(base.rsplit(".",1)[0])
    return bool(set(refs)&required) and set(refs)<=allowed

def resolve_source(raw,meta,prefix,index,sources,depth=0):
    if depth>=32: return None
    row=sources.get(clean(prefix))
    if not row: return None
    resources,calls,outputs,variables,cfg=row
    value=expression(raw,index)
    if not value: return None
    if value.endswith(".id"):
        parsed=RESOURCE.fullmatch(value[:-3])
        if parsed:
            base,selector=parsed.groups()
            parent=resources.get(base,{})
            if not parent or bool(selector)!=("count" in parent or "for_each" in parent): return None
            if not allowed_refs(meta,raw,value,base+".id"): return None
            return prefix+value[:-3]
    module=MODULE.match(value)
    if module:
        name,selector=module.groups()
        output=value[module.end():]
        if not re.fullmatch(NAME,output): return None
        call=calls.get(name,{})
        if not call or bool(selector)!=("count" in call or "for_each" in call): return None
        if not allowed_refs(meta,raw,value,"module."+name+"."+output): return None
        child=prefix+module.group()
        child_row=sources.get(clean(child))
        if not child_row: return None
        out=child_row[2].get(output,{})
        cfg_out=child_row[4].get("outputs",{}).get(output,{})
        if out.get("sensitive") or out.get("ephemeral") or cfg_out.get("sensitive"): return None
        return resolve_source(out.get("value"),cfg_out.get("expression",{}),child,None,sources,depth+1)
    if value.startswith("var.") and re.fullmatch(NAME,value[4:]) and prefix:
        name=value[4:]
        decl=variables.get(name,{})
        if name not in variables or decl.get("sensitive") or decl.get("ephemeral"): return None
        if not allowed_refs(meta,raw,value,value): return None
        parts=list(MODULE.finditer(prefix))
        if not parts or parts[-1].end()!=len(prefix): return None
        last=parts[-1]; parent_prefix=prefix[:last.start()]
        parent=sources.get(clean(parent_prefix))
        if not parent: return None
        call=parent[1].get(last.group(1),{})
        call_cfg=parent[4].get("module_calls",{}).get(last.group(1),{})
        return resolve_source(call.get(name),call_cfg.get("expressions",{}).get(name,{}),parent_prefix,last.group(2),sources,depth+1)
    return None

def recover(plan,address,definitions,select,body,task,sources=None,allow_name=False):
    out={}
    parsed=split_address(address)
    if not parsed or task.get("operation")!="create" or task.get("all_fields_masked"): return out
    prefix,base,index=parsed
    if sources is None:
        sources={"":(definitions,{}, {},{},plan.get("configuration",{}).get("root_module",{}))}
    row=sources.get(clean(prefix))
    if not row: return out
    changes=[r for r in plan.get("resource_changes",[]) if not r.get("deposed")]
    consumer=one(row[4].get("resources",[]),base)
    change=one(changes,address).get("change",{})
    if not consumer or not change or select(address) is None: return out
    unknown=change.get("after_unknown",{})
    sensitive=change.get("after_sensitive")
    if not isinstance(unknown,dict) or sensitive is True: return out
    def parent_ref(target):
        if not target or select(target)!=select(address): return None
        parent=one(changes,target)
        kind=parent.get("type")
        if kind not in EC2_TYPES or parent.get("provider_name")!=AWS or parent.get("mode")!="managed": return None
        pc=parent.get("change",{})
        if pc.get("actions") not in (["create"],["delete","create"],["create","delete"]): return None
        parent_body=masked(pc.get("after") or {},pc.get("after_sensitive"),pc.get("after_unknown"))
        condition=anchor(parent_body,allow_name) if isinstance(parent_body,dict) else {}
        if condition: return {"kind":EC2_TYPES[kind][0],"condition":condition}
        return None
    for field,raw in row[0].get(base,{}).items():
        if isinstance(sensitive,dict) and marked(sensitive.get(field)): continue
        meta=consumer.get("expressions",{}).get(field,{})
        if unknown.get(field) is True and body.get(field) is None and not isinstance(raw,list):
            ref=parent_ref(resolve_source(raw,meta,prefix,index,sources))
            if ref: out[field]=ref
        # All elements must be proven generated references. Do not guess set order
        # or match unknown entries against a partially known list.
        elif isinstance(raw,list) and raw:
            flags=unknown.get(field)
            fully_unknown=flags is True and body.get(field) is None
            element_unknown=isinstance(flags,list) and len(flags)==len(raw) and all(x is True for x in flags) and (body.get(field) is None or isinstance(body.get(field),list) and len(raw)==len(body[field]) and all(x is None for x in body[field]))
            if not (fully_unknown or element_unknown): continue
            refs=meta.get("references",[])
            if not isinstance(refs,list): continue
            resolved=[]; allowed=set()
            for item in raw:
                value=expression(item,index)
                if not value: break
                subset={value,clean(value),value.rsplit(".",1)[0],clean(value).rsplit(".",1)[0]}
                if "count.index" in item: subset.add("count.index")
                if "each.key" in item: subset.add("each.key")
                allowed.update(subset)
                target=resolve_source(item,{"references":[r for r in refs if isinstance(r,str) and r in subset]},prefix,index,sources)
                ref=parent_ref(target)
                if not ref: break
                resolved.append(ref)
            if len(resolved)==len(raw) and all(isinstance(r,str) and r in allowed for r in refs): out[field]=resolved
    return out
