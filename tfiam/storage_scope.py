"""EFS, FSx and Storage Gateway resource-specific candidate authorization.

Uses AWS service authorization resource classes, not guessed opaque IDs.
A bounded class wildcard is identified as prospective access; it is not an
assertion that a generated ID can be known before Terraform applies.
"""
import re

TYPES = {
    "aws_efs_file_system", "aws_efs_backup_policy", "aws_efs_mount_target",
    "aws_fsx_lustre_file_system", "aws_fsx_data_repository_association",
    "aws_storagegateway_gateway", "aws_storagegateway_nfs_file_share",
}
_EFS_ID = re.compile(r"fs-[a-f0-9]{8,40}")
_FSX_ID = re.compile(r"fs-[a-f0-9]{8,40}")
_STORAGE_ARN = re.compile(r"arn:aws(?:-us-gov|-cn)?:storagegateway:[a-z0-9-]+:[0-9]{12}:(?:gateway|share)/[A-Za-z0-9-]+")


def scoped(typ, body, actions, account, region, partition, resolve, emit, omit, task=None):
    if not (account and region and partition):
        for action in actions:
            omit(action, "Storage resource account/region context unresolved")
        return

    def val(name):
        return resolve(body.get(name))

    def class_arn(service, kind, identifier=None):
        return f"arn:{partition}:{service}:{region}:{account}:{kind}/{identifier or '*'}"

    if typ.startswith("aws_efs_"):
        filesystem = val("file_system_id") or val("id")
        if filesystem and filesystem.startswith("arn:"):
            known = filesystem
        else:
            known = class_arn("elasticfilesystem", "file-system",
                              filesystem if filesystem and _EFS_ID.fullmatch(filesystem) else None)
        for action in actions:
            if action == "elasticfilesystem:CreateFileSystem":
                emit(action, "*")  # AWS has no resource type for this action.
            elif action in ("elasticfilesystem:DescribeFileSystems",
                            "elasticfilesystem:DescribeMountTargets",
                            "elasticfilesystem:DescribeBackupPolicy",
                            "elasticfilesystem:PutBackupPolicy",
                            "elasticfilesystem:CreateMountTarget",
                            "elasticfilesystem:DeleteMountTarget",
                            "elasticfilesystem:DeleteFileSystem",
                            "elasticfilesystem:UpdateFileSystem",
                            "elasticfilesystem:TagResource",
                            "elasticfilesystem:ListTagsForResource",
                            "elasticfilesystem:DescribeMountTargetSecurityGroups",
                            "elasticfilesystem:ModifyMountTargetSecurityGroups"):
                emit(action, known)
            else:
                omit(action)
        return

    if typ.startswith("aws_fsx_"):
        fsid = val("file_system_id") or val("id")
        fsarn = class_arn("fsx", "file-system",
                          fsid if fsid and _FSX_ID.fullmatch(fsid) else None)
        assoc = val("association_id") or val("id")
        assocarn = class_arn("fsx", "association",
                            (fsid if fsid and _FSX_ID.fullmatch(fsid) else "*")
                            + "/" + (assoc if assoc and re.fullmatch(r"[a-f0-9-]{8,}", assoc) else "*"))
        for action in actions:
            if action in ("fsx:CreateFileSystem", "fsx:DeleteFileSystem",
                          "fsx:UpdateFileSystem", "fsx:DescribeFileSystems"):
                emit(action, fsarn)
            elif action == "fsx:CreateDataRepositoryAssociation":
                # The action has BOTH mandatory association and file-system
                # resource classes in AWS's Service Authorization Reference.
                emit(action, fsarn)
                emit(action, assocarn)
            elif action in ("fsx:DescribeDataRepositoryAssociations",
                            "fsx:UpdateDataRepositoryAssociation",
                            "fsx:DeleteDataRepositoryAssociation"):
                emit(action, assocarn)
            else:
                omit(action)
        return

    if typ == "aws_storagegateway_gateway":
        gateway_arn = val("gateway_arn") or val("arn")
        if not gateway_arn or not _STORAGE_ARN.fullmatch(gateway_arn) or ":gateway/" not in gateway_arn:
            gateway_arn = class_arn("storagegateway", "gateway")
        for action in actions:
            if action == "storagegateway:ActivateGateway":
                emit(action, "*")  # Creates a new resource, no ARN in request.
            elif action in ("storagegateway:DescribeGatewayInformation",
                            "storagegateway:UpdateGatewayInformation",
                            "storagegateway:DeleteGateway"):
                emit(action, gateway_arn)
            else:
                omit(action)
        return

    if typ == "aws_storagegateway_nfs_file_share":
        gateway_arn = val("gateway_arn")
        if not gateway_arn or not _STORAGE_ARN.fullmatch(gateway_arn) or ":gateway/" not in gateway_arn:
            gateway_arn = class_arn("storagegateway", "gateway")
        share_arn = val("fileshare_arn") or val("file_share_arn") or val("arn")
        if not share_arn or not _STORAGE_ARN.fullmatch(share_arn) or ":share/" not in share_arn:
            share_arn = class_arn("storagegateway", "share")
        for action in actions:
            if action == "storagegateway:CreateNFSFileShare":
                emit(action, gateway_arn)
            elif action in ("storagegateway:DescribeNFSFileShares",
                            "storagegateway:UpdateNFSFileShare",
                            "storagegateway:DeleteFileShare"):
                emit(action, share_arn)
            else:
                omit(action)
        role = val("role")
        if "storagegateway:CreateNFSFileShare" in actions:
            if role and re.fullmatch(rf"arn:{partition}:iam::[0-9]{{12}}:role/[^\s*?]+", role):
                emit("iam:PassRole", role, {
                    "StringEquals": {"iam:PassedToService": "storagegateway.amazonaws.com"}
                })
            elif body.get("role") is not None:
                omit("iam:PassRole", "Storage Gateway file share IAM role unresolved")
