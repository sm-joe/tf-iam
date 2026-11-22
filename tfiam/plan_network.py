"""Recover direct generated EC2 IDs using matching local source and saved plan."""
import re
from pathlib import Path
from .action_scope import EC2_TYPES, tag_conditions
from .plan import AWS, masked, marked

INDEX=r'\[(?:[0-9]+|"(?:[^"\\]|\\.)*")\]'
NAME=r'[A-Za-z0-9_-]+'
ADDR=re.compile(r'(?P<modules>(?:module\.'+NAME+r'(?:'+INDEX+r')?\.)*)(?P<base>aws_[a-z0-9_]+\.'+NAME+r')(?P<index>'+INDEX+r')?')
MODULE=re.compile(r'module\.('+NAME+r')(?:'+INDEX+r')?\.')
DIRECT=re.compile(r'\$\{(aws_[a-z0-9_]+\.'+NAME+r')(\[(?:[0-9]+|"(?:[^"\\]|\\.)*"|count\.index|each\.key)\])?\.id\}')

def anchor(body):
    tags=body.get("tags",{})
    value=tags.get("tfiam:scope") if isinstance(tags,dict) else None
    if not isinstance(value,str) or not value: return {}
    return tag_conditions({"tags":{"tfiam:scope":value}},"ec2:ResourceTag/")

def one(rows,address):
    found=[r for r in rows if isinstance(r,dict) and r.get("address")==address]
    return found[0] if len(found)==1 else {}

def read_source(folder,root):
    from .resolver import read_document, groups
    definitions={}; calls={}
    for file in sorted(set(folder.glob("*.tf"))|set(folder.glob("*.tf.json"))):
        if not file.resolve().is_relative_to(root): raise ValueError("Source outside root")
        doc=read_document(file)
        for group in groups(doc,"resource"):
            for kind,instances in group.items():
                for name,body in instances.items():
                    k=kind+"."+name
                    if k in definitions: raise ValueError("Duplicate resource")
                    definitions[k]=body
        for group in groups(doc,"module"):
            for name,body in group.items():
                if name in calls: raise ValueError("Duplicate module")
                calls[name]=body
    return definitions,calls

def locate(plan,match,definitions,root):
    cfg=plan.get("configuration",{}).get("root_module",{})
    prefix=match.group("modules")
    if not prefix: return cfg,definitions
    if root is None: return {},{}
    root=Path(root).resolve(); folder=root
    for name in MODULE.findall(prefix):
        try:
            _,calls=read_source(folder,root)
            call=cfg.get("module_calls",{}).get(name,{})
            source=calls.get(name,{}).get("source")
            if not isinstance(source,str) or not source.startswith(("./","../")) or call.get("source")!=source: return {},{}
            folder=(folder/source).resolve()
            if not folder.is_relative_to(root) or not folder.is_dir(): return {},{}
            cfg=call.get("module",{})
        except (OSError,ValueError,TypeError,AttributeError): return {},{}
    try: return cfg,read_source(folder,root)[0]
    except (OSError,ValueError,TypeError,AttributeError): return {},{}

def recover(plan,address,definitions,select,body,task,root=None):
    out={}
    consumer_address=ADDR.fullmatch(address)
    if not consumer_address or task.get("operation")!="create" or select(address) is None: return out
    cfg,defs=locate(plan,consumer_address,definitions,root)
    base=consumer_address.group("base")
    prefix=consumer_address.group("modules")
    index=consumer_address.group("index")
    configs=cfg.get("resources",[])
    changes=[r for r in plan.get("resource_changes",[]) if not r.get("deposed")]
    consumer=one(configs,base); row=one(changes,address)
    if not consumer or not row or row.get("provider_name")!=AWS or row.get("mode")!="managed": return out
    change=row.get("change",{})
    source=defs.get(base,{})
    def bind(expr,refs):
        m=DIRECT.fullmatch(expr) if isinstance(expr,str) else None
        if not m: return None
        target,idx=m.groups()
        kind=target.split(".")[0]
        if kind not in EC2_TYPES: return None
        if idx=="[count.index]":
            if not index or not re.fullmatch(r'\[[0-9]+\]',index) or "count" not in source or "count_expression" not in consumer: return None
            idx=index
        elif idx=="[each.key]":
            if not index or not index.startswith('["') or "for_each" not in source or "for_each_expression" not in consumer: return None
            idx=index
        addr=prefix+target+(idx or "")
        target_cfg=one(configs,target)
        if not target_cfg or target not in defs or select(addr)!=select(address): return None
        parent=one(changes,addr)
        if parent.get("provider_name")!=AWS or parent.get("mode")!="managed" or parent.get("type")!=kind: return None
        pc=parent.get("change",{})
        if pc.get("actions")!=["create"]: return None
        # References may be reported as either the instance traversal or its declaration.
        traversal=target+(idx or "")
        allowed={target,target+".id",traversal,traversal+".id"}
        if m.group(2)=="[count.index]": allowed.add("count.index")
        if m.group(2)=="[each.key]": allowed.add("each.key")
        if not any(x in refs for x in (target,target+".id",traversal,traversal+".id")): return None
        parent_body=masked(pc.get("after") or {},pc.get("after_sensitive"),pc.get("after_unknown"))
        condition=anchor(parent_body) if isinstance(parent_body,dict) else {}
        return ({"kind":EC2_TYPES[kind][0],"condition":condition},allowed) if condition else None
    for field,expr in source.items():
        unknown=change.get("after_unknown",{})
        sensitive=change.get("after_sensitive",{})
        if not isinstance(unknown,dict) or sensitive is True or isinstance(sensitive,dict) and marked(sensitive.get(field)): continue
        refs=consumer.get("expressions",{}).get(field,{}).get("references",[])
        if not isinstance(refs,list) or not all(isinstance(x,str) for x in refs): continue
        if isinstance(expr,list):
            # Only all-unknown direct-reference collections; ordering of Terraform sets is not trusted.
            raw=body.get(field); mask=unknown.get(field)
            if not isinstance(raw,list) or not raw or len(raw)!=len(expr) or any(x is not None for x in raw) or not (isinstance(mask,list) and len(mask)==len(raw) and all(x is True for x in mask)): continue
            bindings=[bind(item,refs) for item in expr]
            if all(bindings) and set(refs)<=set().union(*(b[1] for b in bindings)):
                out[field]=[b[0] for b in bindings]
        elif body.get(field) is None and unknown.get(field) is True:
            binding=bind(expr,refs)
            if binding and set(refs)<=binding[1]: out[field]=binding[0]
    return out
