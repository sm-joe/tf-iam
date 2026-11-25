"""Storage IAM regression covering the seven missing resource families."""
import json

from tfiam.catalog_loader import get_rule
from tfiam.candidate_fallback import include_unresolved
from tfiam.scan import scan


ACCOUNT = "638631156706"
REGION = "ap-south-1"


def _config(tmp_path):
    resource = {
        "aws_iam_role": {
            "gateway": {"name": "demo-storage-gateway-role", "path": "/"}},
        "aws_iam_role_policy": {
            "gateway": {"role": "${aws_iam_role.gateway.id}", "name": "inline",
                        "policy": "{}"}},
        "aws_s3_bucket": {
            "storage": {"bucket": "demo-storage-evidence-bucket-12345"}},
        "aws_kms_key": {"storage": {"description": "Storage key"}},
        "aws_kms_alias": {
            "storage": {"name": "alias/storage-demo",
                        "target_key_id": "${aws_kms_key.storage.key_id}"}},
        "aws_efs_file_system": {"storage": {"creation_token": "efs-demo"}},
        "aws_efs_backup_policy": {
            "storage": {"file_system_id": "${aws_efs_file_system.storage.id}",
                        "backup_policy": {"status": "ENABLED"}}},
        "aws_efs_mount_target": {
            "storage": {"file_system_id": "${aws_efs_file_system.storage.id}",
                        "subnet_id": "subnet-12345678"}},
        "aws_fsx_lustre_file_system": {
            "storage": {"storage_capacity": 1200, "subnet_ids": ["subnet-12345678"]}},
        "aws_fsx_data_repository_association": {
            "storage": {"file_system_id": "${aws_fsx_lustre_file_system.storage.id}",
                        "data_repository_path": "s3://demo-storage-evidence-bucket-12345"}},
        "aws_storagegateway_gateway": {
            "storage": {"gateway_name": "storage-demo", "gateway_ip_address": "10.0.0.1"}},
        "aws_storagegateway_nfs_file_share": {
            "storage": {"gateway_arn": "${aws_storagegateway_gateway.storage.arn}",
                        "location_arn": "arn:aws:s3:::demo-storage-evidence-bucket-12345",
                        "role": "arn:aws:iam::638631156706:role/demo-storage-gateway-role"}},
    }
    (tmp_path / "main.tf.json").write_text(json.dumps({"resource": resource}))
    return resource


def test_all_seven_storage_resource_families_are_mapped(tmp_path):
    _config(tmp_path)
    report = scan(tmp_path, account=ACCOUNT, region=REGION)
    missing = [r["address"] for r in report["resources"]
               if r.get("mapping_status") == "UNMAPPED"]
    assert missing == []
    assert report["mapping_coverage"]["mapped_resources"] == 12


def test_kms_and_role_policy_use_bounded_resources_instead_of_global(tmp_path):
    _config(tmp_path)
    report = scan(tmp_path, account=ACCOUNT, region=REGION)
    role_rows = [p for p in report["permissions"]
                 if p["source"] == "aws_iam_role_policy.gateway"]
    assert {"iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy"} <= {
        p["action"] for p in role_rows}
    assert all(p["scope"] ==
               f"arn:aws:iam::{ACCOUNT}:role/demo-storage-gateway-role"
               for p in role_rows)
    kms_rows = [p for p in report["permissions"] if p["action"].startswith("kms:")]
    assert all(p["scope"] != "*" for p in kms_rows
               if p["action"] not in ("kms:CreateKey", "kms:ListAliases"))
    assert any(p["action"] == "kms:CreateAlias" and ":alias/storage-demo" in p["scope"]
               for p in kms_rows)
    assert any(p["action"] == "kms:CreateAlias" and ":key/*" in p["scope"]
               for p in kms_rows)


def test_storage_actions_have_correct_resource_classes(tmp_path):
    _config(tmp_path)
    report = scan(tmp_path, account=ACCOUNT, region=REGION)
    def scopes(source, action):
        return {p["scope"] for p in report["permissions"]
                if p["source"] == source and p["action"] == action}
    assert scopes("aws_efs_file_system.storage", "elasticfilesystem:CreateFileSystem") == {"*"}
    assert scopes("aws_efs_backup_policy.storage", "elasticfilesystem:PutBackupPolicy") == {
        f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:file-system/*"}
    assert scopes("aws_fsx_data_repository_association.storage",
                  "fsx:CreateDataRepositoryAssociation") == {
        f"arn:aws:fsx:{REGION}:{ACCOUNT}:association/*/*",
        f"arn:aws:fsx:{REGION}:{ACCOUNT}:file-system/*"}
    assert scopes("aws_storagegateway_gateway.storage",
                  "storagegateway:ActivateGateway") == {"*"}
    assert scopes("aws_storagegateway_nfs_file_share.storage",
                  "storagegateway:CreateNFSFileShare") == {
        f"arn:aws:storagegateway:{REGION}:{ACCOUNT}:gateway/*"}
    assert scopes("aws_storagegateway_nfs_file_share.storage",
                  "iam:PassRole") == {
        f"arn:aws:iam::{ACCOUNT}:role/demo-storage-gateway-role"}


def test_unknown_bucket_name_cannot_be_inferred_from_account_or_region(tmp_path):
    (tmp_path / "main.tf.json").write_text(json.dumps({
        "resource": {"aws_s3_bucket": {"storage": {"bucket": "${var.bucket_name}"}}}
    }))
    report = scan(tmp_path, account=ACCOUNT, region=REGION)
    assert any(row["source"] == "aws_s3_bucket.storage"
               for row in report["unresolved_permissions"])
    include_unresolved(report)
    assert report["fallback_permissions"]
    # The unresolved bucket name is an input blocker, not proof of a
    # particular S3 bucket ARN.
