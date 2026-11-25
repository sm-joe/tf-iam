#!/usr/bin/env bash
# Opt-in real AWS lifecycle acceptance for a disposable Terraform workspace.
# Uses the active AWS identity. Never attaches or changes IAM policies.
set -euo pipefail
umask 077

usage() {
  echo "Usage: TFIAM_EXPECTED_ACCOUNT=123456789012 TFIAM_AWS_REGION=us-east-1 $0 {create|update|destroy} TERRAFORM_DIRECTORY" >&2
  exit 2
}
[[ $# -eq 2 ]] || usage
phase=$1
target=$(cd "$2" && pwd -P)
case "$phase" in create|update|destroy) ;; *) usage ;; esac
[[ ${TFIAM_EXPECTED_ACCOUNT:-} =~ ^[0-9]{12}$ ]] || {
  echo "ERROR: TFIAM_EXPECTED_ACCOUNT must be a 12-digit account ID" >&2; exit 2;
}
[[ ${TFIAM_AWS_REGION:-} =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || {
  echo "ERROR: TFIAM_AWS_REGION must be a valid AWS region" >&2; exit 2;
}
for command in terraform tfiam aws; do
  command -v "$command" >/dev/null || { echo "ERROR: Missing $command" >&2; exit 2; }
done

actual=$(aws sts get-caller-identity --query Account --output text)
[[ "$actual" == "$TFIAM_EXPECTED_ACCOUNT" ]] || {
  echo "ERROR: AWS credentials identify account $actual, expected $TFIAM_EXPECTED_ACCOUNT" >&2; exit 2;
}
# This is a local evidence workspace. Plans can contain sensitive values.
evidence_dir="$target/.tfiam-acceptance"
mkdir -p "$evidence_dir"
chmod 700 "$evidence_dir"
plan_path="$evidence_dir/$phase.tfplan"
json_path="$evidence_dir/$phase.plan.json"
policy_path="$evidence_dir/$phase.policy.json"

terraform -chdir="$target" init -input=false
if [[ "$phase" == "destroy" ]]; then
  terraform -chdir="$target" plan -destroy -input=false -out="$plan_path"
else
  terraform -chdir="$target" plan -input=false -out="$plan_path"
fi
terraform -chdir="$target" show -json "$plan_path" > "$json_path"

candidate_phase=apply
[[ "$phase" == "destroy" ]] && candidate_phase=destroy
tfiam generate "$target" --plan-json "$json_path" --phase "$candidate_phase" \
  --aws-account "$TFIAM_EXPECTED_ACCOUNT" --aws-region "$TFIAM_AWS_REGION" \
  --output "$policy_path"

# Validation requires access-analyzer:ValidatePolicy; policy generation must
# not be blocked just because that additional permission is absent.
if [[ ${TFIAM_VALIDATE_WITH_AWS:-no} == yes ]]; then
  tfiam validate-policy "$policy_path" --aws-region "$TFIAM_AWS_REGION" --strict
fi

echo "Candidate: $policy_path"
echo "Plan: $plan_path"
echo "Review the generated grants and confirm the active identity has exactly the candidate policies."
if [[ ${TFIAM_ACCEPT_EXECUTE:-NO} != YES ]]; then
  echo "No AWS resource changes executed. Set TFIAM_ACCEPT_EXECUTE=YES to apply the saved $phase plan."
  exit 0
fi

# Terraform apply is deliberately never automatic without the explicit opt-in.
terraform -chdir="$target" apply -input=false "$plan_path"
echo "Live $phase operation completed with active AWS identity in account $actual."
echo "Run all three lifecycle phases and inspect their evidence before release."
