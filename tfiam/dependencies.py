"""Configuration-specific dependencies for supported Terraform AWS resources."""
import re

def dependencies(typ,body,actions,account,region,partition,resolve,emit,omit,task=None,phase="apply"):
    op=task.get("operation") if task else None
    if phase!="apply" or op in ("read","no-op","delete"): return
    before=task.get("before",{}) if task else {}
    unknown=set(task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))
    def present(field): return bool(body.get(field)) or field in unknown
    def changed(field): return not task or op!="update" or field in unknown or before.get(field)!=body.get(field)
    def role(field,service):
        value=resolve(body.get(field))
        if value and account and re.fullmatch(rf"arn:{partition}:iam::{account}:role/[^\s*?]+",value):
            emit("iam:PassRole",value,{"StringEquals":{"iam:PassedToService":service}})
        else: omit("iam:PassRole")
    def key(field,actions):
        value=resolve(body.get(field))
        if value and account and region and re.fullmatch(rf"arn:{partition}:kms:{region}:[0-9]{{12}}:key/[A-Za-z0-9-]+",value):
            for action in actions:
                emit(action,value,{"Bool":{"kms:GrantIsForAWSResource":"true"}} if action=="kms:CreateGrant" else None)
        else:
            for action in actions: omit(action)
    if typ=="aws_s3_bucket_replication_configuration":
        if "s3:PutReplicationConfiguration" in actions:
            role("role","s3.amazonaws.com")
    if typ in ("aws_db_instance","aws_rds_cluster","aws_rds_cluster_instance"):
        if any(a in actions for a in ("rds:CreateDBInstance","rds:CreateDBCluster","rds:ModifyDBInstance","rds:ModifyDBCluster","rds:RestoreDBInstanceFromDBSnapshot","rds:RestoreDBClusterFromSnapshot")):
            if present("monitoring_role_arn") and changed("monitoring_role_arn"): role("monitoring_role_arn","monitoring.rds.amazonaws.com")
            if present("kms_key_id") and changed("kms_key_id"): key("kms_key_id",["kms:DescribeKey","kms:CreateGrant"])
            # Documented RDS multi-resource authorization for configured groups.
            for action in actions:
                if action not in ("rds:CreateDBInstance","rds:ModifyDBInstance","rds:CreateDBCluster","rds:ModifyDBCluster","rds:RestoreDBInstanceFromDBSnapshot","rds:RestoreDBClusterFromSnapshot"): continue
                fields=[("db_subnet_group_name","subgrp")]
                if typ=="aws_rds_cluster": fields.append(("db_cluster_parameter_group_name","cluster-pg"))
                else: fields.extend([("parameter_group_name","pg"),("db_parameter_group_name","pg"),("option_group_name","og")])
                for field,kind in fields:
                    if not present(field): continue
                    value=resolve(body.get(field))
                    if account and region and value and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*",value):
                        emit(action,f"arn:{partition}:rds:{region}:{account}:{kind}:{value.lower()}")
                    else: omit(action)
            snapshot=resolve(body.get("snapshot_identifier"))
            if present("snapshot_identifier") and changed("snapshot_identifier"):
                action="rds:RestoreDBClusterFromSnapshot" if typ=="aws_rds_cluster" else "rds:RestoreDBInstanceFromDBSnapshot"
                kind="cluster-snapshot" if typ=="aws_rds_cluster" else "snapshot"
                prefix=f"arn:{partition}:rds:{region}:{account}:{kind}:"
                if account and region and snapshot and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*",snapshot):
                    emit(action,prefix+snapshot.lower())
                elif account and region and snapshot and re.fullmatch(rf"arn:{partition}:rds:{region}:[0-9]{{12}}:{kind}:[A-Za-z0-9-]+",snapshot):
                    emit(action,snapshot)
                else: omit(action)
            # Explicitly block unsupported operations rather than claim a complete policy.
            for field,action in (("replicate_source_db","rds:CreateDBInstanceReadReplica"),("restore_to_point_in_time","rds:RestoreDBInstanceToPointInTime" if typ=="aws_db_instance" else "rds:RestoreDBClusterToPointInTime"),("s3_import","rds:RestoreDBInstanceFromS3" if typ=="aws_db_instance" else "rds:RestoreDBClusterFromS3"),("manage_master_user_password","secretsmanager:CreateSecret")):
                if present(field) and changed(field): omit(action)
    if typ=="aws_ecs_service":
        if any(a in actions for a in ("ecs:CreateService","ecs:UpdateService")):
            if present("iam_role") and changed("iam_role"): role("iam_role","ecs.amazonaws.com")
            if present("volume_configuration") or present("service_connect_configuration") or present("vpc_lattice_configurations"):
                omit("iam:PassRole")
            if "ecs:CreateService" in actions:
                if account:
                    emit("iam:CreateServiceLinkedRole",f"arn:{partition}:iam::{account}:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",{"StringEquals":{"iam:AWSServiceName":"ecs.amazonaws.com"}})
                else: omit("iam:CreateServiceLinkedRole")

def object_dependencies(body,actions,scope,account,region,partition,resolve,emit,omit,task=None):
    op=task.get("operation") if task else None
    before=task.get("before",{}) if task else {}
    unknown=set(task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))
    def present(field): return bool(body.get(field)) or field in unknown
    def changed(field): return not task or op!="update" or field in unknown or before.get(field)!=body.get(field)
    def grant(action):
        if scope!="*": emit(action,scope)
        else: omit(action)
    if op not in ("read","no-op","delete") and "s3:PutObject" in actions:
        if present("acl") and changed("acl"): grant("s3:PutObjectAcl")
        if present("object_lock_legal_hold_status") and changed("object_lock_legal_hold_status"): grant("s3:PutObjectLegalHold")
        if (present("object_lock_mode") or present("object_lock_retain_until_date")) and (changed("object_lock_mode") or changed("object_lock_retain_until_date")): grant("s3:PutObjectRetention")
        if present("kms_key_id"):
            value=resolve(body.get("kms_key_id"))
            if value and region and re.fullmatch(rf"arn:{partition}:kms:{region}:[0-9]{{12}}:key/[A-Za-z0-9-]+",value):
                for a in ("kms:GenerateDataKey","kms:Decrypt"): emit(a,value,{"StringEquals":{"kms:ViaService":f"s3.{region}.amazonaws.com"+(".cn" if partition=="aws-cn" else "")}})
            else:
                omit("kms:GenerateDataKey"); omit("kms:Decrypt")
        elif body.get("server_side_encryption") in ("aws:kms","aws:kms:dsse") or "server_side_encryption" in unknown:
            omit("kms:GenerateDataKey"); omit("kms:Decrypt")
    if "s3:DeleteObject" in actions:
        # Provider deletes all versions, including delete markers, when a version exists.
        if scope!="*":
            bucket,key=scope.split(":::",1)[1].split("/",1)
            emit("s3:ListBucketVersions",f"arn:{partition}:s3:::{bucket}",{"StringEquals":{"s3:prefix":key}})
            grant("s3:DeleteObjectVersion")
            if body.get("force_destroy") is True or "force_destroy" in unknown: grant("s3:BypassGovernanceRetention")
        else:
            omit("s3:ListBucketVersions"); omit("s3:DeleteObjectVersion")
