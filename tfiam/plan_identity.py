"""Resolve Terraform identity references for ECS, ELBv2 and IAM.

Plan configuration references prove the parent relationship. Only known,
non-sensitive parent name/family/path values may become policy identifiers.
Generated AWS IDs remain prospective wildcards where required.
"""
import re

from .plan import AWS, masked
from .plan_network import MODULE, one, split_address


def _config(plan, address):
    parsed = split_address(address)
    if parsed is None:
        return None
    prefix, base, _ = parsed
    module = plan.get("configuration", {}).get("root_module", {})
    for match in MODULE.finditer(prefix):
        module = module.get("module_calls", {}).get(match.group(1), {}).get("module", {})
        if not isinstance(module, dict):
            return None
    return one(module.get("resources", []), base)


def _parent(plan, current, field, kind, select):
    config = _config(plan, current)
    expression = (config or {}).get("expressions", {}).get(field, {})
    refs = expression.get("references", []) if isinstance(expression, dict) else []
    if not isinstance(refs, list) or not refs:
        return None
    parsed = split_address(current)
    if parsed is None:
        return None
    prefix = parsed[0]
    targets = set()
    for ref in refs:
        if not isinstance(ref, str):
            return None
        reference = re.sub(r"\.(?:arn|id|name|family)$", "", ref)
        parent = split_address(reference)
        if parent is None or parent[1].split(".", 1)[0] != kind:
            # Terraform may emit both resource and attribute references;
            # arbitrary variables, indices and mixed parents are not proof.
            return None
        targets.add(prefix + reference)
    if len(targets) != 1:
        return None
    target = next(iter(targets))
    rows = [
        row for row in plan.get("resource_changes", [])
        if row.get("address") == target and not row.get("deposed")
        and row.get("provider_name") == AWS and row.get("mode") == "managed"
    ]
    if len(rows) != 1 or select(target) != select(current):
        return None
    change = rows[0].get("change", {})
    if change.get("actions") not in (["create"], ["delete", "create"], ["create", "delete"], ["no-op"], ["update"]):
        return None
    return masked(change.get("after") or {}, change.get("after_sensitive"), change.get("after_unknown"))


def enrich(plan, address, body, task, select):
    """Add direct graph-proven identities; do not overwrite known values."""
    if task.get("operation") not in ("create", "update") or task.get("all_fields_masked"):
        return body
    typ = task["entry"]["type"]
    ctx = select(address)
    if not ctx or not all(ctx):
        return body
    account, region, partition = ctx
    if not re.fullmatch(r"[0-9]{12}", str(account)):
        return body
    result = dict(body)
    unknown = set(task.get("unknown_fields", []))

    def set_if_unknown(field, value):
        if field in unknown and body.get(field) is None and value:
            result[field] = value

    def role(field):
        parent = _parent(plan, address, field, "aws_iam_role", select)
        if not parent:
            return
        name, path = parent.get("name"), parent.get("path", "/")
        if (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9+=,.@_-]+", name)
                and isinstance(path, str) and re.fullmatch(r"/(?:[A-Za-z0-9+=,.@_/-]*/)?", path)):
            set_if_unknown(field, f"arn:{partition}:iam::{account}:role{path}{name}")

    if typ == "aws_ecs_task_definition":
        role("execution_role_arn")
        role("task_role_arn")
    if typ == "aws_ecs_service":
        # Terraform may mark a provider-computed optional iam_role as unknown
        # even when it was not configured. Only a configured expression or
        # a concrete planned value establishes caller-supplied role intent.
        config = _config(plan, address)
        if isinstance(config, dict):
            expressions = config.get("expressions", {})
            if isinstance(expressions, dict):
                result["_tfiam_ecs_role_configured"] = (
                    "iam_role" in expressions or bool(body.get("iam_role"))
                )
        role("iam_role")
        cluster = _parent(plan, address, "cluster", "aws_ecs_cluster", select)
        if cluster:
            name = cluster.get("name")
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]+", name):
                set_if_unknown("cluster", name)
        definition = _parent(plan, address, "task_definition", "aws_ecs_task_definition", select)
        if definition:
            family = definition.get("family")
            if isinstance(family, str) and re.fullmatch(r"[A-Za-z0-9_-]+", family):
                if "task_definition" in unknown and body.get("task_definition") is None:
                    result["_tfiam_task_definition_family"] = family
    if typ == "aws_lb_listener":
        lb = _parent(plan, address, "load_balancer_arn", "aws_lb", select)
        if lb:
            name = lb.get("name")
            lb_type = lb.get("load_balancer_type") or "application"
            kind = {"application": "app", "network": "net", "gateway": "gwy"}.get(lb_type)
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9-]{1,32}", name) and kind:
                # Keep distinct from exact, allocated load_balancer_arn values.
                result["_tfiam_parent_lb_arn"] = (
                    f"arn:{partition}:elasticloadbalancing:{region}:{account}:"
                    f"loadbalancer/{kind}/{name}/*"
                )
    return result
