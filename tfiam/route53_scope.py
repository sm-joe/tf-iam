"""Action-specific Route 53 hosted-zone and record authorization scopes.

Hosted-zone IDs are assigned by AWS; never infer them from DNS names.
For records, restrict write operations to the normalized record name and type.
"""
import re

ZONE_ID=re.compile(r"Z[A-Z0-9]{5,}")
DNS=re.compile(r"^[A-Za-z0-9_-]+(?:[.][A-Za-z0-9_-]+)*[.]?$",re.I)
TYPES={"A","AAAA","CAA","CNAME","DS","HTTPS","MX","NAPTR","NS","PTR","SOA","SPF","SRV","SSHFP","SVCB","TLSA","TXT"}

def scoped(typ,body,actions,account,region,partition,resolve,emit,omit,task=None,diagnose=lambda msg:None):
    if typ not in ("aws_route53_zone","aws_route53_record"):
        raise ValueError("Unsupported Route53 resource")
    value=lambda field:resolve(body.get(field))
    raw=(value("zone_id") or value("id")) if typ=="aws_route53_zone" else value("zone_id")
    zone=f"arn:{partition}:route53:::hostedzone/{raw}" if isinstance(raw,str) and ZONE_ID.fullmatch(raw) else f"arn:{partition}:route53:::hostedzone/*"
    if not isinstance(raw,str) or not ZONE_ID.fullmatch(raw):
        diagnose("AWS-generated hosted-zone ID unresolved; prospective hostedzone/* scope may affect other hosted zones")
    name=value("name")
    record_type=value("type")
    if typ=="aws_route53_record":
        if not isinstance(name,str) or not DNS.fullmatch(name) or record_type not in TYPES:
            for action in actions:omit(action)
            return
        record=name.lower().rstrip(".")
        request_condition={
            "ForAllValues:StringEquals":{
                "route53:ChangeResourceRecordSetsNormalizedRecordNames":[record],
                "route53:ChangeResourceRecordSetsRecordTypes":[record_type],
                "route53:ChangeResourceRecordSetsActions":["CREATE","UPSERT","DELETE"],
            }
        }
    for action in actions:
        if action=="route53:CreateHostedZone":
            emit(action,"*")
        elif action in ("route53:GetHostedZone","route53:ListTagsForResource","route53:ChangeTagsForResource","route53:UpdateHostedZoneComment","route53:DeleteHostedZone","route53:ListResourceRecordSets"):
            emit(action,zone)
        elif action=="route53:ChangeResourceRecordSets" and typ=="aws_route53_record":
            emit(action,zone,request_condition)
        elif action=="route53:GetChange":
            emit(action,f"arn:{partition}:route53:::change/*")
        else:
            omit(action)
