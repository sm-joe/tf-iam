"""Narrow only reviewed, field-specific saved-plan actions."""
def minimize(typ,actions,body,task):
    op=task.get("operation")
    if op not in ("create","update") or task.get("all_fields_masked") or task.get("all_before_fields_masked"): return actions
    before=task.get("before",{})
    unknown=set(task.get("unknown_fields",[])) | set(task.get("before_masked_fields",[]))
    def changed(*fields):
        return any(f in unknown or before.get(f)!=body.get(f) for f in fields)
    out=set(actions)
    if typ=="aws_s3_object" and op=="update":
        # Do not omit upload on arbitrary content attributes. Only a known tags-only diff.
        delta={k for k in set(before)|set(body) if before.get(k)!=body.get(k)}|unknown
        if delta and delta <= {"tags","tags_all"}:
            out.discard("s3:PutObject")
    if typ=="aws_iam_user" and op=="update" and not changed("name","path"):
        out.discard("iam:UpdateUser")
    if typ=="aws_iam_group" and op=="update" and not changed("name","path"):
        out.discard("iam:UpdateGroup")
    if typ=="aws_sqs_queue" and op=="update":
        delta={k for k in set(before)|set(body) if before.get(k)!=body.get(k)}|unknown
        if delta and delta <= {"tags","tags_all"}: out.discard("sqs:SetQueueAttributes")
        if not changed("tags","tags_all"): out-={"sqs:TagQueue","sqs:UntagQueue"}
    if typ=="aws_dynamodb_table" and op=="update" and not changed("tags","tags_all"):
        out-={"dynamodb:TagResource","dynamodb:UntagResource"}
    if typ=="aws_eks_cluster" and op=="update" and not changed("version"):
        out.discard("eks:UpdateClusterVersion")
    return sorted(out)
