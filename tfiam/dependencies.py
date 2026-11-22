"""Configuration-specific dependencies for supported Terraform AWS resources."""
import re

RDS_CREATION={
    "aws_db_instance":("rds:CreateDBInstance",{"snapshot_identifier":"rds:RestoreDBInstanceFromDBSnapshot","replicate_source_db":"rds:CreateDBInstanceReadReplica","restore_to_point_in_time":"rds:RestoreDBInstanceToPointInTime"}),
    "aws_rds_cluster":("rds:CreateDBCluster",{"snapshot_identifier":"rds:RestoreDBClusterFromSnapshot","restore_to_point_in_time":"rds:RestoreDBClusterToPointInTime"}),
}
def rds_creation(typ,body,actions,unknown,omit):
    normal,alternatives=RDS_CREATION[typ]
    if normal not in actions: return actions
    selected=[action for field,action in alternatives.items() if body.get(field)]
    uncertain=[action for field,action in alternatives.items() if unknown(field)]
    if uncertain or len(selected)>1:
        for action in set(selected+uncertain): omit(action)
        return [a for a in actions if a!=normal]
    return sorted(set([a for a in actions if a!=normal]+selected)) if selected else actions

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
        if any(a in actions for a in ("rds:CreateDBInstance","rds:CreateDBCluster","rds:ModifyDBInstance","rds:ModifyDBCluster","rds:RestoreDBInstanceFromDBSnapshot","rds:RestoreDBClusterFromSnapshot","rds:CreateDBInstanceReadReplica","rds:RestoreDBInstanceToPointInTime","rds:RestoreDBClusterToPointInTime")):
            if present("monitoring_role_arn") and changed("monitoring_role_arn"): role("monitoring_role_arn","monitoring.rds.amazonaws.com")
            if present("kms_key_id") and changed("kms_key_id"): key("kms_key_id",["kms:DescribeKey","kms:CreateGrant"])
            # Documented RDS multi-resource authorization for configured groups.
            for action in actions:
                if action not in ("rds:CreateDBInstance","rds:ModifyDBInstance","rds:CreateDBCluster","rds:ModifyDBCluster","rds:RestoreDBInstanceFromDBSnapshot","rds:RestoreDBClusterFromSnapshot","rds:CreateDBInstanceReadReplica","rds:RestoreDBInstanceToPointInTime","rds:RestoreDBClusterToPointInTime"): continue
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
            def source_arn(action,raw,kind):
                value=resolve(raw)
                prefix=f"arn:{partition}:rds:{region}:{account}:{kind}:"
                if account and region and value and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*",value):
                    emit(action,prefix+value.lower())
                elif account and region and value and re.fullmatch(re.escape(prefix)+r"[A-Za-z][A-Za-z0-9-]*",value):
                    emit(action,value)
                else: omit(action)
            if "rds:CreateDBInstanceReadReplica" in actions:
                source_arn("rds:CreateDBInstanceReadReplica",body.get("replicate_source_db"),"db")
            for action,kind,field in (("rds:RestoreDBInstanceToPointInTime","db","source_db_instance_identifier"),("rds:RestoreDBClusterToPointInTime","cluster","source_cluster_identifier")):
                if action not in actions: continue
                block=body.get("restore_to_point_in_time")
                if isinstance(block,list) and len(block)==1: block=block[0]
                if isinstance(block,dict) and block.get(field) and not any(block.get(k) for k in ("source_dbi_resource_id","source_db_instance_automated_backups_arn","source_cluster_resource_id","source_db_cluster_resource_id")):
                    source_arn(action,block[field],kind)
                else: omit(action)
            if typ=="aws_rds_cluster_instance" and any(a in actions for a in ("rds:CreateDBInstance","rds:ModifyDBInstance")):
                for action in ("rds:CreateDBInstance","rds:ModifyDBInstance"):
                    if action in actions: source_arn(action,body.get("cluster_identifier"),"cluster")
            if present("manage_master_user_password") and changed("manage_master_user_password"):
                if body.get("manage_master_user_password") is not True or not account or not region:
                    for action in ("secretsmanager:CreateSecret","secretsmanager:TagResource","kms:DescribeKey"): omit(action)
                else:
                    # AWS controls the random suffix. Restrict to the documented
                    # RDS namespace and caller account/region, not arbitrary secrets.
                    kind="cluster" if typ=="aws_rds_cluster" else "db"
                    target=f"arn:{partition}:secretsmanager:{region}:{account}:secret:rds!{kind}-*"
                    for action in ("secretsmanager:CreateSecret","secretsmanager:TagResource"): emit(action,target)
                    if present("master_user_secret_kms_key_id"):
                        key("master_user_secret_kms_key_id",["kms:DescribeKey","kms:Decrypt","kms:GenerateDataKey","kms:CreateGrant"])
                    else:
                        emit("kms:DescribeKey",f"arn:{partition}:kms:{region}:{account}:key/*",{"ForAnyValue:StringEquals":{"kms:ResourceAliases":"alias/aws/secretsmanager"}})
            if present("rotate_master_user_password") and changed("rotate_master_user_password"):
                secret=body.get("master_user_secret")
                if isinstance(secret,list) and len(secret)==1: secret=secret[0]
                arn=resolve(secret.get("secret_arn")) if isinstance(secret,dict) else None
                if account and region and arn and re.fullmatch(rf"arn:{partition}:secretsmanager:{region}:{account}:secret:rds![A-Za-z0-9!-]+",arn):
                    emit("secretsmanager:RotateSecret",arn)
                else: omit("secretsmanager:RotateSecret")
            # Cross-region replicas, resource-ID restores and S3 imports still
            # require additional authorization evidence, never a global grant.
            if present("s3_import") and changed("s3_import"):
                omit("rds:RestoreDBClusterFromS3" if typ=="aws_rds_cluster" else "rds:RestoreDBInstanceFromS3")
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
