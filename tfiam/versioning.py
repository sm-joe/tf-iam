"""Provider selection and evidence; no inferred proof from version constraints."""
import re
from pathlib import Path
VERSION=re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
AWS="registry.terraform.io/hashicorp/aws"

def selected_version(root, explicit=None):
    if explicit is not None and not VERSION.fullmatch(explicit):
        raise ValueError("--aws-provider-version requires an exact stable MAJOR.MINOR.PATCH version")
    detected=None
    path=Path(root)/".terraform.lock.hcl" if root is not None else None
    status="missing"
    if path is not None and path.is_file():
        try:
            import hcl2
            with path.open(encoding="utf-8-sig") as handle: doc=hcl2.load(handle)
            groups=doc.get("provider",[])
            if isinstance(groups,dict): groups=[groups]
            candidates=[row[AWS]["version"] for row in groups if AWS in row]
            if len(candidates)>1: raise ValueError()
            if candidates:
                detected=candidates[0]
                if not isinstance(detected,str) or not VERSION.fullmatch(detected): raise ValueError()
                status="locked"
            else: status="aws-not-locked"
        except Exception:
            detected=None
            status="invalid-lockfile"
    if explicit and detected and explicit!=detected:
        raise ValueError("Explicit AWS provider version conflicts with Terraform lockfile")
    return {"version":explicit or detected,"lockfile_version":detected,"source":"explicit" if explicit else "lockfile" if detected else "unknown","lockfile_status":status}

def rule_for_version(rule,version):
    if not rule: return None
    selected={k:v for k,v in rule.items() if k!="version_overrides"}
    override=rule.get("version_overrides",{}).get(version)
    if override:
        selected.update(override)
        selected["provider_versions"]=[version] if override.get("validation")=="validated" else []
    return selected

def evidence_status(rule,version):
    if not rule: return "unmapped"
    if not version: return "version-unknown"
    evidence=[e for e in rule.get("evidence",[]) if e["provider_version"]==version]
    if rule["validation"]=="validated" and version in rule["provider_versions"] and any(e["level"]=="lifecycle-verified" for e in evidence):
        return "lifecycle-verified"
    if any(e["level"]=="provider-source-reviewed" for e in evidence):
        return "provider-source-reviewed"
    return "version-unvalidated"
