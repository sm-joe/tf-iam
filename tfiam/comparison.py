"""Conservative identity-policy comparison with unique findings and provenance."""
import json
from collections import Counter

def arr(value):
    return value if isinstance(value,list) else [value]

def matches(pattern,value):
    # IAM recognizes '*' and '?' wildcards, not fnmatch's bracket expressions.
    import re
    pattern=re.escape(pattern).replace(r"\*",r".*").replace(r"\?",r".")
    return re.fullmatch(pattern,value,re.DOTALL) is not None

def action_matches(pattern,value):
    return matches(pattern.lower(),value.lower())

def covers(g,r):
    action,scope,plane=g
    target=r["scope"]
    return plane==r["plane"] and action_matches(action,r["action"]) and (
        scope=="*" or scope==target or ("*" not in target and "?" not in target and matches(scope,target)))

def compare(report,provider,existing):
    if provider!="aws": raise ValueError("Only AWS is supported")
    if not isinstance(existing,dict) or "Statement" not in existing: raise ValueError("Expected IAM identity policy")
    rows=[r for r in report["permissions"] if r["provider"]==provider]
    # Keep the representative source for backwards compatibility and all sources
    # for traceability. Conditions participate in identity; never merge them away.
    unique={}
    for r in rows:
        key=(r["action"].lower(),r["scope"],r["plane"],json.dumps(r.get("condition"),sort_keys=True))
        if key not in unique: unique[key]={**r,"sources":[],"observations":0}
        item=unique[key]; item["observations"]+=1
        if r["source"] not in item["sources"]: item["sources"].append(r["source"])
    for r in unique.values():
        r["sources"].sort(); r["source"]=r["sources"][0]
    grants=set(); denies=set(); conditional=[]; conditional_keys={}; conditional_statements=0; uncertain=[]; complex_denies=False
    for index,s in enumerate(arr(existing["Statement"])):
        if not isinstance(s,dict) or s.get("Effect") not in ("Allow","Deny"): raise ValueError("Invalid IAM statement")
        if s.get("Condition") or any(k in s for k in ("NotAction","NotResource","Principal","NotPrincipal")):
            if s["Effect"]=="Allow" and s.get("Condition") and not any(k in s for k in ("NotAction","NotResource","Principal","NotPrincipal")):
                actions=arr(s.get("Action",[])); scopes=arr(s.get("Resource",[]))
                if not actions or not scopes or not all(isinstance(x,str) and x for x in actions+scopes): raise ValueError("Invalid IAM action or resource")
                conditional_statements+=1
                if any("${" in x for x in scopes):
                    conditional.append((None,None))
                    uncertain.append("Statement "+str(index+1)+": policy variables require manual evaluation")
                else:
                    for a in actions:
                        for scope in scopes:
                            grant=(a.lower(),scope,"management")
                            conditional_keys[(grant,json.dumps(s["Condition"],sort_keys=True))]=s["Condition"]
                continue
            uncertain.append("Statement "+str(index+1)+": complex AWS statement requires manual evaluation")
            if s["Effect"]=="Deny": complex_denies=True
            else: conditional.append((None,None))
            continue
        actions=arr(s.get("Action",[])); scopes=arr(s.get("Resource",[]))
        if not actions or not scopes or not all(isinstance(x,str) and x for x in actions+scopes): raise ValueError("Invalid IAM action or resource")
        if any("\u0024{" in x for x in scopes):
            uncertain.append("Statement "+str(index+1)+": policy variables require manual evaluation")
            if s["Effect"]=="Deny": complex_denies=True
            else: conditional.append((None,None))
            continue
        target=grants if s["Effect"]=="Allow" else denies
        for a in actions:
            for scope in scopes: target.add((a.lower(),scope,"management"))
    conditional.extend((g,c) for (g,_),c in conditional_keys.items())
    missing=[]; unverified=[]; blocked=[]; covered=[]
    for _,r in sorted(unique.items()):
        # A complex deny may intersect an otherwise covered grant; fail closed.
        if any(covers(g,r) for g in denies): blocked.append(r)
        elif complex_denies: unverified.append({**r,"comparison_reason":"complex-deny"})
        elif any(covers(g,r) for g in grants) or any(g and covers(g,r) and r.get("condition")==c for g,c in conditional): covered.append(r)
        elif any(g is None or covers(g,r) for g,c in conditional): unverified.append({**r,"comparison_reason":"conditional-or-complex-allow"})
        else: missing.append({**r,"comparison_reason":"no-matching-identity-allow"})
    excess=[]
    for a,s,p in sorted(grants):
        matching=[r for r in unique.values() if covers((a,s,p),r)]
        reasons=[]
        if "*" in a or "?" in a: reasons.append("action-wildcard")
        if not matching: reasons.append("not-required-by-candidates")
        if any(s!=r["scope"] for r in matching): reasons.append("broader-resource")
        if any(r.get("condition") for r in matching): reasons.append("missing-candidate-condition")
        if reasons: excess.append({"action":a,"scope":s,"plane":p,"reasons":reasons})
    # Conditional grants are counted, and flag only excess that can be
    # identified without guessing the effect of arbitrary IAM conditions.
    for (a,s,p),encoded in sorted(conditional_keys):
        condition=conditional_keys[((a,s,p),encoded)]
        matching=[r for r in unique.values() if covers((a,s,p),r)]
        exact=any(a==r["action"].lower() and s==r["scope"] and condition==r.get("condition") for r in matching)
        if exact: continue
        reasons=[]
        if "*" in a or "?" in a: reasons.append("action-wildcard")
        if not matching: reasons.append("not-matched-to-candidates")
        if any(s!=r["scope"] for r in matching): reasons.append("broader-resource")
        if reasons: excess.append({"action":a,"scope":s,"plane":p,"condition":condition,"reasons":reasons})
    def services(items):
        return dict(sorted(Counter(r["action"].split(":",1)[0] for r in items).items()))
    return {"coverage":"PARTIAL","missing":missing,"unverified":unverified,"missing_or_unverified":missing+unverified,"explicitly_denied":blocked,
            "potentially_excessive":excess,"summary":{"candidate_observations":len(rows),"unique_candidates":len(unique),
            "covered_candidates":len(covered),"missing":len(missing),"unverified":len(unverified),"missing_or_unverified":len(missing)+len(unverified),"explicitly_denied":len(blocked),
            "unique_existing_grants":len(grants)+len(conditional_keys),"conditional_statements":conditional_statements,"potentially_excessive":len(excess),"complex_statements":len(uncertain),
            "by_service":{"missing_or_unverified":services(missing+unverified),"explicitly_denied":services(blocked),"potentially_excessive":services(excess)}},
            "warnings":uncertain,"limitations":["Static identity-policy comparison; effective authorization, arbitrary condition relationships, boundaries, SCPs and resource policies are not established. Do not automatically revoke permissions."]}
