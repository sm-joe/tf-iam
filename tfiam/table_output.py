"""Dependency-free terminal reports. JSON remains the complete machine format."""
import json
import textwrap

def clean(value):
    if isinstance(value,(dict,list)): value=json.dumps(value,sort_keys=True,ensure_ascii=True)
    if value is None: return "-"
    return "".join(c if c.isprintable() else " " for c in str(value))

def table(headers,rows,limits):
    rows=[list(map(clean,r)) for r in rows]
    if not rows:
        rows=[["None"]+["-"]*(len(headers)-1)]
    widths=[min(limit,max(len(h),*(len(r[i]) for r in rows))) for i,(h,limit) in enumerate(zip(headers,limits))]
    sep="+"+"+".join("-"*(w+2) for w in widths)+"+"
    def line(values):
        chunks=[textwrap.wrap(v,width=w,break_long_words=True,break_on_hyphens=False) or [""] for v,w in zip(values,widths)]
        return ["| "+" | ".join((c[i] if i<len(c) else "").ljust(w) for c,w in zip(chunks,widths))+" |" for i in range(max(map(len,chunks)))]
    # Keep wrapped lines together inside a distinct border for each logical row.
    return "\n".join([sep,*line(headers),sep,*(s for r in rows for s in (*line(r),sep))])

def render(command,r,compact=False):
    parts=["tf-iam | "+command.upper()]
    def section(title,headers,rows,widths,limit=None):
        rows=list(rows)
        parts.extend(["",title,table(headers,rows if limit is None else rows[:limit],widths)])
        if limit is not None and len(rows)>limit: parts.append(f"Showing {limit} of {len(rows)} rows; use JSON for the full report.")
    def metrics(title,m):
        section(title,["Metric","Value"],m.items(),[40,76])
    def grant_rows(rows):
        return [(x["action"],x["scope"],x.get("condition") or "-",x.get("sources",x.get("source","-"))) for x in rows]
    def policy_rows(p):
        return [(a,s["Resource"],s.get("Condition") or "-") for s in p.get("Statement",[]) for a in s["Action"]]
    def decision():
        mapping=r.get("mapping_coverage",{})
        auth=r.get("authorization_confidence",{})
        metadata=r.get("authorization_metadata",{})
        total=mapping.get("eligible_resources",0)
        unmapped=mapping.get("unmapped_resources",0)
        unresolved=len(r.get("unresolved_permissions",[]))
        blocked=r.get("generation_status")=="BLOCKED" or bool(r.get("gate_failures")) or bool(r.get("source_only_resources")) or metadata.get("status")=="issues"
        risks=r.get("risks",[])
        rows=[
            ("Resource mapping","REVIEW" if unmapped or not total else "PASS",f'{mapping.get("mapped_resources",0)}/{total} mapped',"Add mappings or exclude unsupported resources." if unmapped else "No mapping gap reported." if total else "Check Terraform input."),
            ("Permission scopes","REVIEW" if unresolved else "PASS",f"{unresolved} unresolved","Resolve listed permissions before deploying." if unresolved else "No unresolved permission reported."),
            ("AWS metadata","FAIL" if metadata.get("status")=="issues" else "PASS" if metadata.get("status")=="compatible" else "REVIEW",metadata.get("status","not-run"),"Fix listed action or scope errors." if metadata.get("status")=="issues" else "Action/scope metadata compatible; not a deployment test." if metadata.get("status")=="compatible" else "Review metadata findings or use the packaged binary."),
            ("Lifecycle authorization","PASS" if total and auth.get("lifecycle_verified_resources")==total else "UNVERIFIED",f'{auth.get("lifecycle_verified_resources",0)}/{total} verified',"Do not infer effective access from mapping coverage."),
            ("Security approval","REVIEW" if risks else "NONE REPORTED",f"{len(risks)} risk findings","Review privileged and destructive grants with the deployment owner." if risks else "No listed risk rule triggered; not a security certification."),
        ]
        section("ENGINEER DECISION",["Check","Status","Result","Next action"],rows,[25,17,30,65])
        if blocked: recommendation="DO NOT DEPLOY - resolve blocking checks before generating a new policy."
        elif unmapped or unresolved: recommendation="INCOMPLETE CANDIDATE - resolve mapping/scope gaps before deployment."
        else: recommendation="CANDIDATE FOR REVIEW - validate against intended deployment identity and approve sensitive grants before use."
        metrics("RECOMMENDATION",{"Decision":recommendation})
    if command=="scan":
        decision()
        groups={}
        for x in r["permissions"]:
            key=(x["action"],x["scope"],json.dumps(x.get("condition"),sort_keys=True))
            groups.setdefault(key,set()).add(x["source"])
        metrics("SUMMARY",{"Phase":r["phase"],"Coverage":r["coverage"],"Input":r["input"],"AWS provider":r["authorization_confidence"]["provider_version"],"Resources mapped":str(r["mapping_coverage"]["mapped_resources"])+"/"+str(r["mapping_coverage"]["eligible_resources"]),"Permission observations":len(r["permissions"]),"Unique grants":len(groups),"Metadata":r["authorization_metadata"]["status"],"Authorization":r["authorization_confidence"]["status"],"Source reviewed":r["authorization_confidence"]["source_reviewed_resources"],"Lifecycle verified":r["authorization_confidence"]["lifecycle_verified_resources"],**r["scope_summary"]})
        section("RESOURCES",["Mapping","Resource","Authorization","Operations","Computed","Sensitive"],[(x.get("mapping_status",x["status"]),x["address"],x.get("validation_level","-"),", ".join(x.get("operations",[])) or r["phase"],"Yes" if x.get("unknown_values") else "-","Yes" if x.get("sensitive_values") else "-") for x in r["resources"]],[14,60,26,20,10,10])
        section("PERMISSIONS",["Action","Resource scope","Condition","Sources"],[(a,s,json.loads(c),len(v)) for (a,s,c),v in sorted(groups.items())],[38,63,48,8])
    elif command=="generate":
        metrics("SUMMARY",{"Generation":r.get("generation_status","GENERATED"),"Policy output":r.get("policy_output","-"),"Statements":len(r.get("Statement",[])),"Action grants":len(policy_rows(r)),"Phase":r.get("phase","-"),"Input":r.get("input","-")})
        if "mapping_coverage" in r: decision()
        if not compact and r.get("Statement"): section("POLICY GRANTS",["Action","Resource scope","Condition"],policy_rows(r),[40,70,55])
    elif command=="split":
        metrics("PARTITIONS",r["counts"])
        for name,p in r["policies"].items():
            section(name.upper(),["Action","Resource scope","Condition"],policy_rows(p),[40,70,55])

    elif command=="compare":
        summary=r["summary"]
        metrics("SUMMARY",{k:v for k,v in summary.items() if k!="by_service"})
        by=summary["by_service"]
        services=sorted(set().union(*(x.keys() for x in by.values())))
        section("BY AWS SERVICE",["Service","Missing / unverified","Denied","Potentially excessive"],[(s,by["missing_or_unverified"].get(s,0),by["explicitly_denied"].get(s,0),by["potentially_excessive"].get(s,0)) for s in services],[28,22,12,22])
        for k in ("missing_or_unverified","explicitly_denied"):
            section(k.replace("_"," ").upper(),["Action","Resource scope","Condition","Source"],grant_rows(r[k]),[38,60,45,45],100)
        section("POTENTIALLY EXCESSIVE",["Action","Resource scope","Reasons"],[(x["action"],x["scope"],", ".join(x["reasons"])) for x in r["potentially_excessive"]],[40,60,60],25)
    elif command=="evidence-audit":
        metrics("FIXTURE EVIDENCE",{"Fixture":r["fixture"],"Provider":r["provider_version"],"Status":r["status"],"Matched events":r["matched_events"],"Expected denial observed":r["negative_observed"]})
        section("OBSERVATIONS",["API operation","IAM actions","Status","Count"],[(x["operation"],", ".join(x["actions"]),x["status"],x["count"]) for x in r["observations"]],[36,62,27,8])
        section("BLOCKERS",["Reason"],[(x,) for x in r["blockers"]],[90])
        section("MISSING POSITIVE OBSERVATIONS",["Action"],[(x,) for x in r["missing_required_observations"]],[55])
    elif command=="provider-audit":
        metrics("SOURCE RECONCILIATION",{"Provider":r["provider_version"],"Commit":r["provider_commit"],"Official pin":r["pin_verified"],"Status":r["status"],**r["counts"]})
        section("SDK OPERATIONS",["Resource","API operation","IAM actions","Status"],[(item["resource"],op["operation"],", ".join(op["actions"]) or "-",op["status"]) for item in r["resources"] for op in item["operations"]],[48,35,66,24])
    elif command=="catalog-audit":
        metrics("CATALOG AUDIT",{k:r[k] for k in ("status","actions_total","actions_recognized","permission_observations_checked","missing_services")})
        section("FINDINGS",["Severity","Action","Code"],[(x["severity"],x["action"],x["code"]) for x in r["findings"]],[14,48,48],100)
    elif command=="validate-policy":
        metrics("VALIDATION",{"Status":r["status"],**r["counts"]})
        section("FINDINGS",["Type","Code","Details"],[(x.get("findingType"),x.get("issueCode"),x.get("findingDetails")) for x in r["findings"]],[20,40,75])
    elif command=="runtime-audit":
        metrics("RUNTIME AUDIT",{"Coverage":r.get("coverage"),"Matched events":r["matched_events"],"Unobserved candidates":len(r["unobserved_candidates"]),**r.get("retrieval",{})})
        section("OBSERVED ACTIONS",["Action","Successful","Denied","Other errors"],[(x["action"],x["successful"],x["denied"],x["other_errors"]) for x in r["observations"]],[50,14,12,14])
        section("OBSERVED OUTSIDE STATIC CANDIDATES",["Action","Successful","Denied","Other errors"],[(x["action"],x["successful"],x["denied"],x["other_errors"]) for x in r.get("observed_outside_candidates",[])],[50,14,12,14])
        section("CONDITIONAL API MAPPINGS",["Operation","Possible IAM actions"],[(x["service"]+":"+x["operation"],", ".join(x["possible_actions"])) for x in r.get("conditional_operations",[])],[55,65])
        section("UNOBSERVED CANDIDATES",["Action"],[(a,) for a in r["unobserved_candidates"]],[62])
        section("UNMAPPED OPERATIONS",["Service","Operation"],[(x["service"],x["operation"]) for x in r["unmapped_operations"]],[40,55])
    if "risks" in r:
        def risk_decision(x):
            a=set(x["actions"])
            if x["kind"]=="combination": return "Privilege combination","Review together; restrict role/policy targets and separate planner from applier."
            if "iam:PassRole" in a: return "Service role delegation","Approve only intended roles and iam:PassedToService conditions."
            if "iam:AttachRolePolicy" in a: return "Policy attachment","Approve exact target role and allowed policy ARNs."
            if "iam:UpdateAssumeRolePolicy" in a: return "Trust change","Review trusted principals and conditions in Terraform."
            if "s3:PutBucketPublicAccessBlock" in a: return "Public access settings","Confirm public access stays blocked; restrict changes to approved buckets."
            if "s3:PutBucketVersioning" in a: return "Versioning settings","Confirm suspension/deletion behavior meets retention requirements."
            if x["kind"]=="destructive": return "Destroy / replacement capability","Approve only intended deletion or replacement; use saved plan to narrow grants."
            return "Privileged change","Review target identity, conditions and independent approval."
        section("RISKS",["Severity","IAM actions","Impact","Affected resources","Engineer action"],[(x["severity"],", ".join(x["actions"]),risk_decision(x)[0],", ".join(x.get("sources",[])),risk_decision(x)[1]) for x in r["risks"]],[10,38,30,45,55])
    if "unresolved_permissions" in r:
        section("UNRESOLVED PERMISSIONS",["Source","Action","Reason"],[(x["source"],x["action"],x["reason"]) for x in r["unresolved_permissions"]],[60,40,60])
    if r.get("gate_failures"):
        fixes={"unresolved":"Resolve missing scope or dependency.","unmapped":"Add supported mapping or remove unsupported input.","metadata":"Review AWS metadata findings.","risk-threshold":"Review risk findings with security owner; narrow the plan or policy.","lifecycle-evidence":"Exact-version verification is not available for all resources.","stale-plan":"Create and export a fresh Terraform plan."}
        section("BLOCKING CHECKS",["Check","Details","Next action"],[(x["kind"],{k:v for k,v in x.items() if k!="kind"},fixes.get(x["kind"],"Review configured gate.")) for x in r["gate_failures"]],[24,50,65])
    if r.get("source_only_resources"):
        section("RESOURCES NOT IN SAVED PLAN",["Resource","Status"],[(x,"REPLAN REQUIRED") for x in r["source_only_resources"]],[70,20])
    if "resolved_dependencies" in r:
        section("RESOLVED DEPENDENCIES",["Resource","Action","Resolved scope","Status"],[(x["source"],x["action"],x["scope"],"RESOLVED") for x in r["resolved_dependencies"]],[52,30,63,12])
    metadata=r.get("authorization_metadata",{})
    if metadata.get("findings"):
        section("AUTHORIZATION METADATA FINDINGS",["Severity","Action","Code"],[(x["severity"],x["action"],x["code"]) for x in metadata["findings"]],[14,48,48])
    notes=list(dict.fromkeys(r.get("warnings",[])+r.get("scan_warnings",[])+r.get("diagnostics",[])))
    if notes:
        def next_step(n):
            if "lack exact-version lifecycle" in n: return "Maintainer evidence gap; not a resource mapping failure."
            if "privilege delegation" in n: return "See RISKS for approval targets."
            if "unresolved or sensitive" in n: return "Use a saved plan; check UNRESOLVED PERMISSIONS for omitted grants."
            if "first-use service-linked" in n: return "Check account prerequisites and optional EKS features."
            if "provider initialization" in n: return "Confirm target account, region and assumed role."
            if "metadata" in n: return "Review metadata findings."
            return "Check the named input or configuration."
        section("REVIEW REQUIREMENTS",["Status","Details","Next action"],[("REVIEW",n,next_step(n)) for n in notes],[12,66,58])
    informational=r.get("information",[])+r.get("limitations",[])+([r["limitation"]] if r.get("limitation") else [])
    if informational: section("INFORMATION AND LIMITATIONS",["Type","Details"],[("INFO",n) for n in dict.fromkeys(informational)],[12,100])
    return "\n".join(parts)
