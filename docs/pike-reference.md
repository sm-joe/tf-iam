# Reference architecture: Pike

Reference: [Pike](https://github.com/JamesWoolfenden/pike), [mapping catalog](https://github.com/JamesWoolfenden/pike/tree/master/src/mapping), Apache-2.0 licensed. Reviewed README and AWS EKS resource/data mappings. No upstream code or permission files copied into this change.

## Design decisions

Keep the Python CLI and explicit source provenance. Pike models lifecycle phases and attribute-specific actions in external files; adopt this architecture independently, with separate resource/data rules, source references, validation status, provider version constraints, action-specific resource scope and conditions. Do not mechanically import broad permissions. Some Pike entries are placeholders; catalog presence is not evidence of tested coverage.

## Delivery order

1. External schema-validated catalog, coverage inventory and version provenance. Preserve existing rules during migration; separate data sources from resources.
2. Saved Terraform plan JSON input, before/after replacement semantics, variable resolution and installed modules. Do not execute init or plan automatically; treat plan files as sensitive.
3. Expand AWS rules against official action references and reproducible lifecycle evidence. Prioritize EKS, VPC, IAM, S3, EC2 and service identities.
4. Action-specific scope, conditional delegation and risk classification; isolate plan, apply and destructive permissions. A non-escalation action is not necessarily safe.
5. Read-only live policy retrieval, scope-aware comparison and policy validation; distinguish missing, excessive and unknown effective access.
6. Optional audit evidence refinement and isolated lifecycle acceptance tests. Never treat absence from logs as proof an action is unnecessary.
7. Standalone Linux packaging and signed releases; controlled deployment only with explicit approval and separate privileged identity.

## First increment

This PR migrates the AWS catalog, narrows supported providers to AWS and adds deduplicated potential delegation and combination findings to scan, generate diagnostics and compare. These are advisory heuristics, not proofs of exploitable access. Plan support and runtime validation remain open. No automatic policy grants or changes to policy rendering.
