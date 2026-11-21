"""Opt-in read-only AWS integrations. No policy attachment or infrastructure mutations."""
import json
import re
from urllib.parse import unquote
from datetime import datetime, timezone, timedelta
import time

def client(service,profile=None,region=None):
    try:
        import boto3
    except ImportError:
        raise ValueError("Install the AWS extra: pip install 'tf-iam[aws]'") from None
    return boto3.Session(profile_name=profile,region_name=region).client(service)

def policy_object(value):
    if isinstance(value,str): value=json.loads(unquote(value))
    if not isinstance(value,dict) or "Statement" not in value: raise ValueError("Invalid IAM policy document")
    return value

def statements(doc):
    s=policy_object(doc)["Statement"]
    if isinstance(s,dict): s=[s]
    if not isinstance(s,list) or not all(isinstance(x,dict) for x in s): raise ValueError("Invalid IAM statements")
    return s

def role_policies(iam,name):
    if not re.fullmatch(r"[\w+=,.@-]{1,64}",name): raise ValueError("Expected IAM role name, not ARN")
    role=iam.get_role(RoleName=name)["Role"]
    attached=[]; inline=[]; combined=[]
    for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
        for item in page["AttachedPolicies"]:
            arn=item["PolicyArn"]
            policy=iam.get_policy(PolicyArn=arn)["Policy"]
            version=policy["DefaultVersionId"]
            doc=iam.get_policy_version(PolicyArn=arn,VersionId=version)["PolicyVersion"]["Document"]
            combined.extend(statements(doc))
            attached.append({"arn":arn,"version":version})
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=name):
        for item in page["PolicyNames"]:
            doc=iam.get_role_policy(RoleName=name,PolicyName=item)["PolicyDocument"]
            combined.extend(statements(doc)); inline.append(item)
    return {"Version":"2012-10-17","Statement":combined},{"role_arn":role["Arn"],"managed_policies":attached,"inline_policies":inline,"permissions_boundary":role.get("PermissionsBoundary"),"limitations":"Identity policies only; SCPs, session policies, resource policies and permissions boundary effects not evaluated."}

def validate_policy(analyzer,doc):
    policy_object(doc)
    findings=[]
    for page in analyzer.get_paginator("validate_policy").paginate(policyDocument=json.dumps(doc,separators=(",",":")),policyType="IDENTITY_POLICY"):
        findings.extend(page.get("findings",[]))
    counts={k:sum(f.get("findingType")==k for f in findings) for k in ("ERROR","SECURITY_WARNING","WARNING","SUGGESTION")}
    return {"status":"issues" if counts["ERROR"] or counts["SECURITY_WARNING"] else "review" if findings else "no-findings","counts":counts,"findings":findings,"limitation":"Syntax and policy best-practice checks, not proof of effective authorization."}

def parse_time(value):
    try:
        out=datetime.fromisoformat(value.replace("Z","+00:00"))
        if out.tzinfo is None: raise ValueError()
        return out.astimezone(timezone.utc)
    except (TypeError,ValueError,AttributeError): raise ValueError("Use an ISO 8601 timestamp with timezone") from None

def lookup_events(trail,role_arn,start,end,*,session_names=None,max_pages=100,max_seconds=120,progress=None,stats=None):
    if not re.fullmatch(r"arn:[a-z0-9-]+:iam::[0-9]{12}:role/[^\s*?]+",role_arn): raise ValueError("Expected exact IAM role ARN")
    if start>=end or end-start>timedelta(days=90): raise ValueError("Invalid CloudTrail interval (maximum 90 days)")
    if max_pages<1 or max_seconds<1: raise ValueError("CloudTrail limits must be positive")
    session_names=list(dict.fromkeys(session_names or []))
    if any(not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}",n) for n in session_names):
        raise ValueError("Invalid STS role session name")
    stats=stats if stats is not None else {}
    stats.update({"pages":0,"events_scanned":0,"matched":0,"complete":False,"stop_reason":None,
                  "mode":"session-filtered" if session_names else "regional-management-history",
                  "session_names":session_names,"max_pages":max_pages,"max_seconds":max_seconds})
    started=time.monotonic()
    # Username is a session name for assumed-role events, not the IAM role ARN.
    # Never infer a session name from the role name. Exact issuer ARN is still checked.
    for name in session_names or [None]:
        request={"StartTime":start,"EndTime":end,"MaxResults":50}
        if name: request["LookupAttributes"]=[{"AttributeKey":"Username","AttributeValue":name}]
        token=None
        while True:
            if stats["pages"]>=max_pages or time.monotonic()-started>=max_seconds:
                stats["stop_reason"]="page-limit" if stats["pages"]>=max_pages else "time-limit"
                return
            if token: request["NextToken"]=token
            if stats["pages"]: time.sleep(0.55)
            page=trail.lookup_events(**request)
            stats["pages"]+=1
            for item in page.get("Events",[]):
                stats["events_scanned"]+=1
                try: event=json.loads(item["CloudTrailEvent"])
                except (KeyError,TypeError,ValueError): continue
                if event.get("userIdentity",{}).get("sessionContext",{}).get("sessionIssuer",{}).get("arn")==role_arn:
                    stats["matched"]+=1
                    yield event
            if progress and (stats["pages"]==1 or stats["pages"]%5==0):
                progress(stats)
            token=page.get("NextToken")
            if not token: break
    stats["complete"]=True
    stats["stop_reason"]="exhausted"

# API operation names need not equal IAM action names. Only explicit exceptions and
# exact catalog-name candidates are accepted; observations never remove permissions.
API_ALIASES={("s3.amazonaws.com","DeleteBucketOwnershipControls"):"s3:PutBucketOwnershipControls",
             ("s3.amazonaws.com","DeleteBucketLifecycle"):"s3:PutLifecycleConfiguration"}
def refine(events,role_arn,actions):
    known={a.lower():a for a in actions}
    observations={}; unknown=set(); seen=set(); count=0
    for event in events:
        if not isinstance(event,dict): continue
        if event.get("userIdentity",{}).get("sessionContext",{}).get("sessionIssuer",{}).get("arn")!=role_arn: continue
        event_id=event.get("eventID")
        if event_id and event_id in seen: continue
        if event_id: seen.add(event_id)
        count+=1
        source=event.get("eventSource",""); name=event.get("eventName","")
        if not isinstance(source,str) or not isinstance(name,str) or not re.fullmatch(r"[a-z0-9-]+\.amazonaws\.com",source) or not re.fullmatch(r"[A-Za-z0-9]+",name): continue
        candidate=API_ALIASES.get((source,name),source.split(".")[0]+":"+name)
        action=known.get(candidate.lower())
        if not action:
            unknown.add((source,name)); continue
        item=observations.setdefault(action,{"action":action,"successful":0,"denied":0,"other_errors":0})
        error=event.get("errorCode")
        if not error: item["successful"]+=1
        elif "denied" in str(error).lower() or "unauthorized" in str(error).lower(): item["denied"]+=1
        else: item["other_errors"]+=1
    return {"matched_events":count,"observations":sorted(observations.values(),key=lambda x:x["action"]),
            "unmapped_operations":[{"service":s,"operation":n} for s,n in sorted(unknown)],
            "unobserved_candidates":sorted(set(actions)-set(observations)),
            "limitation":"Observed API events are not complete IAM authorization evidence. Unobserved permissions are not safe to remove. CloudTrail history omits data events and can be delayed."}
