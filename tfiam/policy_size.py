"""Offline sizing and partitioning for generated Allow identity policies only."""
import json
import re

LIMITS={"managed":6144,"inline-role":10240,"inline-user":2048,"inline-group":5120}

def compact(doc):
    return json.dumps(doc,ensure_ascii=True,separators=(",",":"),sort_keys=True)

def size(doc):
    # Serialization whitespace is excluded. Preserve whitespace within values
    # for a conservative count; ASCII escaping is conservative for Unicode.
    return len(compact(doc))

def document(rows):
    return {"Version":"2012-10-17","Statement":rows}

def grants(doc):
    if not isinstance(doc,dict) or set(doc)!={"Version","Statement"} or doc["Version"]!="2012-10-17" or not isinstance(doc["Statement"],list):
        raise ValueError("Expected generated IAM identity policy")
    out=set()
    for row in doc["Statement"]:
        if not isinstance(row,dict) or row.get("Effect")!="Allow" or set(row)-{"Effect","Action","Resource","Condition"}:
            raise ValueError("Only generated Allow statements with explicit Action and Resource are supported")
        def strings(key):
            val=row.get(key)
            val=[val] if isinstance(val,str) else val
            if not isinstance(val,list) or not val or not all(isinstance(x,str) and x for x in val):
                raise ValueError("Invalid policy "+key)
            return val
        condition=row.get("Condition")
        if "Condition" in row and (not isinstance(condition,dict) or not condition):
            raise ValueError("Invalid policy condition")
        c=compact(condition)
        for a in strings("Action"):
            for resource in strings("Resource"): out.add((a,resource,c))
    return out

def statement(actions,resources,c):
    actions=sorted(actions); resources=sorted(resources)
    # Keep the generator's stable Action-array contract. IAM accepts both
    # scalar and list syntax, but changing this shape breaks existing users
    # who consume generated policies programmatically.
    row={"Effect":"Allow","Action":actions,"Resource":resources[0] if len(resources)==1 else resources}
    if c!="null": row["Condition"]=json.loads(c)
    return row

def optimize(doc):
    original=grants(doc)
    # First group actions by resource and exact condition; then group only
    # identical action sets. Never create a new action-resource cross product.
    grouped={}
    for a,r,c in original: grouped.setdefault((r,c),set()).add(a)
    combined={}
    for (r,c),actions in grouped.items(): combined.setdefault((tuple(sorted(actions)),c),set()).add(r)
    result=document([statement(actions,resources,c) for (actions,c),resources in sorted(combined.items())])
    if grants(result)!=original: raise ValueError("Policy grant equivalence failed")
    return result

def partition(doc,kind="managed",max_chars=None,max_policies=10,name="TerraformPipeline"):
    if kind not in LIMITS: raise ValueError("Unknown IAM policy type")
    limit=LIMITS[kind] if max_chars is None else max_chars
    if type(limit) is not int or not 1<=limit<=LIMITS[kind]: raise ValueError("Size limit must be within AWS quota")
    if type(max_policies) is not int or not 1<=max_policies<=20: raise ValueError("Policy count must be between 1 and 20")
    if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,115}",name): raise ValueError("Invalid policy name prefix")
    original=grants(doc)
    if not original: raise ValueError("No permission grants to partition")
    optimized=optimize(doc)
    if kind!="managed":
        # Inline limits are cumulative per IAM identity, not per document.
        if size(optimized)>limit: raise ValueError("Aggregate inline IAM policy limit exceeded; use managed policies")
        bins=[optimized["Statement"]]
    else:
        pieces=[]
        for row in optimized["Statement"]:
            if size(document([row]))<=limit:
                pieces.append(row); continue
            # Split only at grant boundaries, preserving the identical condition.
            for a,r,c in sorted(grants(document([row]))):
                atom=statement([a],[r],c)
                if size(document([atom]))>limit: raise ValueError("A single grant exceeds the policy size limit")
                pieces.append(atom)
        bins=[]
        for row in sorted(pieces,key=lambda x:(-size(document([x])),compact(x))):
            for bucket in bins:
                if size(document(bucket+[row]))<=limit:
                    bucket.append(row); break
            else: bins.append([row])
        if len(bins)>max_policies: raise ValueError("Managed policy attachment budget exceeded; review scope or request quota increase")
    policies=[document(rows) for rows in bins]
    if set().union(*(grants(p) for p in policies))!=original or any(size(p)>limit for p in policies):
        raise ValueError("Partition equivalence or size verification failed")
    return {"schema_version":1,"policy_type":kind,"limit":limit,"original_characters":size(doc),"optimized_characters":size(optimized),"grant_count":len(original),"policy_count":len(policies),"policies":[{"name":f"{name}-{i:02d}","characters":size(p),"document":p} for i,p in enumerate(policies,1)],"limitations":["Exact generated grant union preserved; not a proof of effective AWS authorization.","Attachment budget is caller-supplied and must account for existing policies.","Inline limits are aggregate per identity; existing inline policy usage must be considered."]}
