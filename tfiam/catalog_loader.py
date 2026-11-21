"""Load the packaged, independently authored AWS permissions catalog."""
import json
from importlib.resources import files
from jsonschema import Draft202012Validator

def load_catalog():
    root = files("tfiam").joinpath("catalog")
    schema = json.loads(root.joinpath("schema.json").read_text(encoding="utf-8"))
    catalog = json.loads(root.joinpath("aws.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(catalog)
    for category in ("resources", "data"):
        for name, rule in catalog[category].items():
            if rule["validation"] == "validated" and not rule["provider_versions"]:
                raise ValueError(f"Validated rule {name} must identify tested provider versions")
            if category == "data" and (rule["write"] or rule["delete"] or rule["attributes"]):
                raise ValueError(f"Data rule {name} must be read-only")
    return catalog

CATALOG = load_catalog()

def get_rule(category, resource_type):
    return CATALOG["resources" if category == "resource" else "data"].get(resource_type)

def attribute_values(body, path):
    values = [body]
    for part in path.split("."):
        values = [item[part] for value in values for item in (value if isinstance(value, list) else [value]) if isinstance(item, dict) and part in item]
    return values

def actions_for(rule, phase):
    return sorted(set(rule["read"] + (rule["write"] + rule["delete"] if phase == "apply" else rule["delete"] if phase == "destroy" else [])))
