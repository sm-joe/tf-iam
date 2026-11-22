"""Configuration-specific dependencies for supported Terraform AWS resources."""
import re

# Create-mode selection is based on known planned arguments. Never grant normal
# creation as a substitute for an unresolved restore or replica operation.
RDS_MODES={
    "aws_db_instance":{
        "snapshot_identifier":"rds:RestoreDBInstanceFromDBSnapshot",
        "replicate_source_db":"rds:CreateDBInstanceReadReplica",
        "restore_to_point_in_time":"rds:RestoreDBInstanceToPointInTime",
        "s3_import":"rds:RestoreDBInstanceFromS3",
    },
    "aws_rds_cluster":{
        "snapshot_identifier":"rds:RestoreDBClusterFromSnapshot",
        "restore_to_point_in_time":"rds:RestoreDBClusterToPointInTime",
        "s3_import":"rds:RestoreDBClusterFromS3",
    }
}
RDS_SPECIAL_ACTIONS={a for modes in RDS_MODES.values() for a in modes.values()}
RDS_SUPPORTED_SPECIAL=RDS_SPECIAL_ACTIONS-{"rds:RestoreDBInstanceFromS3","rds:RestoreDBClusterFromS3"}

def rds_create_actions(typ,body,actions,task=None):
    if typ not in RDS_MODES or task and task.get("operation")!="create": return actions,[]
    unknown=set(task.get("unknown_fields",[])) if task else set(body.get("_tfiam_unknown_fields",[]))
    create="rds:CreateDBCluster" if typ=="aws_rds_cluster" else "rds:CreateDBInstance"
    if create not in actions: return actions,[]
    modes=[(field,action) for field,action in RDS_MODES[typ].items() if body.get(field) or field in unknown]
    # Fully masked plan values are not proof of a normal create.
    if task and task.get("all_fields_masked"):
        return [a for a in actions if a!=create],[create]
    if not modes: return actions,[]
    output=[a for a in actions if a!=create]
    if len(modes)!=1 or modes[0][1] not in RDS_SUPPORTED_SPECIAL:
        return output,[action for _,action in modes]
    field,action=modes[0]
    if field in unknown or not body.get(field): return output,[action]
    return sorted(set(output+[action])),[]

def rds_source(value,kind,account,region,partition):
    if not account or not region or not isinstance(value,str): return None
    prefix=f"arn:{partition}:rds:{region}:{account}:{kind}:"
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*",value): return prefix+value.lower()
    if re.fullmatch(re.escape(prefix)+r"[a-z][a-z0-9-]*",value): return value
    return None

def rds_pitr_source(typ,body,account,region,partition,resolve):
    block=body.get("restore_to_point_in_time")
    if isinstance(block,list): block=block[0] if len(block)==1 else None
    if not isinstance(block,dict): return None
    if typ=="aws_rds_cluster":
        field,other,kind="source_cluster_identifier",("source_cluster_resource_id",),"cluster"
    else:
        field,other,kind="source_db_instance_identifier",("source_dbi_resource_id","source_db_instance_automated_backups_arn"),"db"
    if any(block.get(k) for k in other):
        if typ=="aws_db_instance" and not block.get(field) and not block.get("source_dbi_resource_id"):
            value=resolve(block.get("source_db_instance_automated_backups_arn"))
            prefix=f"arn:{partition}:rds:{region}:{account}:auto-backup:"
            if account and region and value and re.fullmatch(re.escape(prefix)+r"[A-Za-z0-9-]+",value): return value
        return None
    return rds_source(resolve(block.get(field)),kind,account,region,partition)

def managed_rds_secret(typ,body,account,region,partition,resolve,emit,omit,unknown):
    if typ not in ("aws_db_instance","aws_rds_cluster") or not account or not region or "manage_master_user_password" in unknown or body.get("manage_master_user_password") is not True:
        for action in ("secretsmanager:CreateSecret","secretsmanager:TagResource","kms:DescribeKey"): omit(action)
        return
    # RDS creates a service-managed physical name that is not known before
    # deployment. The resource-class prefix is explicit, never secret:*.
    kind="cluster" if typ=="aws_rds_cluster" else "db"
    secret=f"arn:{partition}:secretsmanager:{region}:{account}:secret:rds!{kind}-*"
    emit("secretsmanager:CreateSecret",secret)
    emit("secretsmanager:TagResource",secret)
    key=resolve(body.get("master_user_secret_kms_key_id"))
    key_prefix=f"arn:{partition}:kms:{region}:{account}:key/"
    if key and re.fullmatch(re.escape(key_prefix)+r"(?:mrk-[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",key):
        emit("kms:DescribeKey",key)
        for action in ("kms:Decrypt","kms:GenerateDataKey"): emit(action,key)
        emit("kms:CreateGrant",key,{"Bool":{"kms:GrantIsForAWSResource":"true"}})
    elif "master_user_secret_kms_key_id" not in unknown and not body.get("master_user_secret_kms_key_id"):
        # Alias condition restricts DescribeKey to the AWS-managed service key.
        emit("kms:DescribeKey",key_prefix+"*",{"ForAnyValue:StringEquals":{"kms:ResourceAliases":"alias/aws/secretsmanager"}})
    else:
        for action in ("kms:DescribeKey","kms:Decrypt","kms:GenerateDataKey","kms:CreateGrant"): omit(action)


def dependencies(typ,body,actions,account,region,partition,resolve,emit,omit,task=None,phase="apply"):
    op=task.get("operation") if task else None
    # DeleteDBCluster authorizes a named final cluster snapshot separately.
    # See AWS RDS Service Authorization Reference, DeleteDBCluster.
    if typ=="aws_rds_cluster" and "rds:DeleteDBCluster" in actions and op not in ("read","no-op","update","create"):
        unknown=set(task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))
        final=resolve(body.get("final_snapshot_identifier"))
        if body.get("skip_final_snapshot") is not True and (final or "final_snapshot_identifier" in unknown or "skip_final_snapshot" in unknown or body.get("skip_final_snapshot") is False):
            if account and region and final and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*",final) and "skip_final_snapshot" not in unknown:
                emit("rds:DeleteDBCluster",f"arn:{partition}:rds:{region}:{account}:cluster-snapshot:{final.lower()}")
            else: omit("rds:DeleteDBCluster")
    if phase!="apply" or op in ("read","no-op","delete"): return
    before=task.get("before",{}) if task else {}
    unknown=set(task.get("unknown_fields",[]) if task else body.get("_tfiam_unknown_fields",[]))
    def present(field): return bool(body.get(field)) or field in unknown
    def changed(field): return not task or op!="update" or field in unknown or field in task.get("before_masked_fields",[]) or task.get("all_before_fields_masked") or before.get(field)!=body.get(field)
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
        rds_write={"rds:CreateDBInstance","rds:CreateDBCluster","rds:ModifyDBInstance","rds:ModifyDBCluster"} | RDS_SUPPORTED_SPECIAL
        if set(actions)&rds_write:
            if present("monitoring_role_arn") and changed("monitoring_role_arn"): role("monitoring_role_arn","monitoring.rds.amazonaws.com")
            if present("kms_key_id") and changed("kms_key_id"): key("kms_key_id",["kms:DescribeKey","kms:CreateGrant"])
            # Documented RDS multi-resource authorization for configured groups.
            for action in actions:
                if action not in rds_write: continue
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
            if present("snapshot_identifier") and not task or present("snapshot_identifier") and op=="create":
                action="rds:RestoreDBClusterFromSnapshot" if typ=="aws_rds_cluster" else "rds:RestoreDBInstanceFromDBSnapshot"
                kind="cluster-snapshot" if typ=="aws_rds_cluster" else "snapshot"
                prefix=f"arn:{partition}:rds:{region}:{account}:{kind}:"
                if action not in actions: pass
                elif account and region and snapshot and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*",snapshot):
                    emit(action,prefix+snapshot.lower())
                elif account and region and snapshot and re.fullmatch(rf"arn:{partition}:rds:{region}:[0-9]{{12}}:{kind}:[A-Za-z0-9-]+",snapshot):
                    emit(action,snapshot)
                else: omit(action)
            for field,action in (("replicate_source_db","rds:CreateDBInstanceReadReplica"),
                                 ("restore_to_point_in_time","rds:RestoreDBClusterToPointInTime" if typ=="aws_rds_cluster" else "rds:RestoreDBInstanceToPointInTime")):
                if action not in actions: continue
                source=rds_source(resolve(body.get(field)),"db",account,region,partition) if field=="replicate_source_db" else rds_pitr_source(typ,body,account,region,partition,resolve)
                if source and field not in unknown: emit(action,source)
                else: omit(action)
            if typ=="aws_rds_cluster" and present("replication_source_identifier") and changed("replication_source_identifier"):
                # Cross-region/global Aurora replication has separate source
                # and encryption dependencies; do not treat as ordinary create.
                omit("rds:CreateDBCluster")
            if present("s3_import") and changed("s3_import"):
                omit("rds:RestoreDBClusterFromS3" if typ=="aws_rds_cluster" else "rds:RestoreDBInstanceFromS3")
            if present("manage_master_user_password") and (changed("manage_master_user_password") or changed("master_user_secret_kms_key_id")):
                managed_rds_secret(typ,body,account,region,partition,resolve,emit,omit,unknown)
            if task and op=="update" and typ=="aws_db_instance" and changed("replicate_source_db"):
                if "replicate_source_db" in unknown or "replicate_source_db" in task.get("before_masked_fields",[]) or task.get("all_before_fields_masked"):
                    omit("rds:PromoteReadReplica")
                elif before.get("replicate_source_db") and not body.get("replicate_source_db"):
                    target=rds_source(resolve(body.get("identifier")),"db",account,region,partition)
                    if target: emit("rds:PromoteReadReplica",target)
                    else: omit("rds:PromoteReadReplica")
                elif body.get("replicate_source_db"):
                    omit("rds:CreateDBInstanceReadReplica")
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
