"""Partition candidate permissions without recombining privileged policies."""
from .risk import assess
def split_policies(report,render):
    if report["phase"]!="apply":
        raise ValueError("Split requires an apply-phase scan")
    # Read discovery candidates are classified conservatively; unknown actions stay
    # in applier, never planner. Backend lock writes stay in applier pending
    # dedicated planning evidence.
    read_prefixes=("Describe","Get","List","Head")
    risky={a.lower() for f in assess(report["permissions"]) if f["kind"] in ("delegation","destructive") for a in f["actions"]}
    groups={"planner":[],"applier":[],"break_glass":[]}
    for row in report["permissions"]:
        action=row["action"]
        if action.lower() in risky: group="break_glass"
        elif action.split(":",1)[1].startswith(read_prefixes): group="planner"
        else: group="applier"
        groups[group].append(row)
    policies={k:render({"permissions":v},"aws",k,None) if v else {"Version":"2012-10-17","Statement":[]} for k,v in groups.items()}
    return {"coverage":report["coverage"],"policies":policies,"counts":{k:len(v) for k,v in groups.items()},
            "unresolved_permissions":report.get("unresolved_permissions",[]),
            "limitations":["Candidate partition, not independently sufficient lifecycle roles.","Applier may require planner reads and explicitly approved delegated operations.","Planner backend locking and service-specific non-read-prefixed discovery require separate review.","Shared update/delete permissions are conservatively classified as break-glass, even when needed for an ordinary update.","Break-glass is not automatically attached or deployed."]}
