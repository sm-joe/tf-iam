"""Parse saved Terraform show -json plans without invoking Terraform."""
import re

AWS = "registry.terraform.io/hashicorp/aws"
BUILTIN = "terraform.io/builtin/terraform"
SUPPORTED = {
    ("create",), ("update",), ("delete",), ("read",), ("no-op",),
    ("delete", "create"), ("create", "delete"), ("forget",), ("create", "forget"),
}

def masked(value, *masks):
    if any(m is True for m in masks):
        return None
    if isinstance(value, dict) or any(isinstance(m, dict) for m in masks):
        obj = value if isinstance(value, dict) else {}
        keys = set(obj)
        for m in masks:
            if isinstance(m, dict):
                keys.update(m)
        return {k: masked(obj.get(k), *(m.get(k) if isinstance(m, dict) else None for m in masks)) for k in sorted(keys)}
    if isinstance(value, list):
        return [masked(v, *(m[i] if isinstance(m, list) and i < len(m) else None for m in masks)) for i, v in enumerate(value)]
    return value

def marked(mask):
    if mask is True:
        return True
    if isinstance(mask, dict):
        return any(marked(v) for v in mask.values())
    if isinstance(mask, list):
        return any(marked(v) for v in mask)
    return False

def parse_plan(doc, phase):
    if not isinstance(doc, dict):
        raise ValueError("Expected a saved Terraform plan JSON object")
    version = doc.get("format_version")
    if not isinstance(version, str) or not re.fullmatch(r"1\.\d+", version):
        raise ValueError("Unsupported Terraform plan JSON format version; expected 1.x")
    terraform_version = doc.get("terraform_version")
    if not isinstance(terraform_version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", terraform_version):
        raise ValueError("Missing or invalid Terraform version")
    if doc.get("errored") is True:
        raise ValueError("Terraform plan is errored and cannot be analyzed for deployment")
    changes = doc.get("resource_changes")
    if changes is None and ("configuration" in doc and "planned_values" in doc):
        changes = []
    if not isinstance(changes, list):
        raise ValueError("Expected terraform show -json of a saved plan, not state or UI output")
    warnings = []
    if doc.get("complete") is False or doc.get("deferred_changes"):
        warnings.append("Terraform plan is incomplete or deferred; deferred resources are not analyzed")
    if doc.get("applyable") is False:
        warnings.append("Terraform reports this plan is not applyable; it may contain no changes")
    if doc.get("resource_drift"):
        warnings.append("Terraform reports resource drift; drift records are not additional apply operations")
    if phase == "plan":
        warnings.append("Plan-phase output is a retrospective read candidate, not proof of all permissions needed to create the plan")
    entries, tasks = [], []
    seen = set()
    for row in changes:
        if not isinstance(row, dict):
            raise ValueError("Invalid resource change entry")
        address, kind, mode = row.get("address"), row.get("type"), row.get("mode")
        if not all(isinstance(v, str) and v and "\n" not in v and "\r" not in v for v in (address, kind, mode)):
            raise ValueError("Invalid resource change identity")
        deposed = row.get("deposed")
        if deposed is not None and (not isinstance(deposed, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", deposed)):
            raise ValueError("Invalid deposed resource identity")
        source = address + (" (deposed " + deposed + ")" if deposed else "")
        if source in seen:
            raise ValueError("Duplicate resource change identity")
        seen.add(source)
        change = row.get("change")
        if not isinstance(change, dict):
            raise ValueError("Missing resource change object")
        actions = change.get("actions")
        if not isinstance(actions, list) or not actions or not all(isinstance(a, str) for a in actions):
            raise ValueError("Invalid Terraform resource action list")
        before_raw, after_raw = change.get("before"), change.get("after")
        if any(v is not None and not isinstance(v, dict) for v in (before_raw, after_raw)):
            raise ValueError("Invalid Terraform resource value object")
        entry = {"address":source, "type":kind, "mode":"resource" if mode=="managed" else mode,
                 "status":"PARTIAL", "operations":actions, "replacement":set(actions)=={"delete","create"},
                 "unknown_values":marked(change.get("after_unknown")),
                 "sensitive_values":marked(change.get("before_sensitive")) or marked(change.get("after_sensitive"))}
        entries.append(entry)
        if tuple(actions) not in SUPPORTED or mode not in ("managed","data"):
            entry["status"]="UNSUPPORTED"
            warnings.append(source+": unsupported Terraform operation or resource mode")
            continue
        if mode == "data" and actions not in (["read"],["no-op"],["delete"],["forget"]):
            entry["status"]="UNSUPPORTED"
            warnings.append(source+": unsupported data-source operation")
            continue
        if phase == "destroy" and mode == "managed" and any(a in actions for a in ("create","update")):
            raise ValueError("Destroy phase requires a destroy-only saved plan")
        if row.get("provider_name") != AWS and not (kind=="terraform_remote_state" and mode=="data" and row.get("provider_name")==BUILTIN):
            entry["status"]="UNSUPPORTED"
            warnings.append(source+": non-AWS or unidentified provider; no grants inferred")
            continue
        before = masked(before_raw or {}, change.get("before_sensitive"))
        after = masked(after_raw or {}, change.get("after_sensitive"), change.get("after_unknown"))
        before = before if isinstance(before, dict) else {}
        after = after if isinstance(after, dict) else {}
        if change.get("importing") is not None:
            warnings.append(source+": Terraform import may require additional provider-specific reads")
        if mode == "data" and actions in (["delete"],["forget"]):
            entry["status"]="SKIPPED"
            continue
        selected = []
        for action in actions:
            if action == "forget":
                continue
            value = before if action == "delete" else after if after_raw is not None else before
            op = "read" if phase=="plan" or mode=="data" or action=="no-op" else action
            selected.append((op,value))
        if not selected:
            entry["status"]="SKIPPED"
            continue
        for op,value in selected:
            masks=(change.get("before_sensitive"),) if value is before else (change.get("after_sensitive"),change.get("after_unknown"))
            unknown_fields=sorted({k for mask in masks if isinstance(mask,dict) for k,v in mask.items() if re.fullmatch(r"[a-z][a-z0-9_]*",k) and marked(v)})
            tasks.append({"entry":entry,"operation":op,"body":value,"before":before,"unknown_fields":unknown_fields,"all_fields_masked":any(mask is True for mask in masks),"before_masked_fields":sorted(k for k,v in (change.get("before_sensitive") or {}).items() if marked(v)) if isinstance(change.get("before_sensitive"),dict) else [],"all_before_fields_masked":change.get("before_sensitive") is True})
        if phase=="plan" and actions==["update"] and before!=after:
            tasks.append({"entry":entry,"operation":"read","body":before})
    meta={"format_version":version,"terraform_version":terraform_version,
          "complete":doc.get("complete"),"applyable":doc.get("applyable"),
          "change_count":len(entries),"deferred":bool(doc.get("deferred_changes"))}
    return entries,tasks,warnings,meta
