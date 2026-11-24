"""Conservative AWS Glue Data Catalog database and job IAM scopes."""
import re

DB_NAME=re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,254}")
JOB_NAME=re.compile(r"[A-Za-z0-9_+=,.@-]{1,255}")

def scoped(typ,body,actions,account,region,partition,resolve,emit,omit,task=None):
    if not account or not region:
        for action in actions: omit(action)
        return
    base=f"arn:{partition}:glue:{region}:{account}:"
    val=lambda key: resolve(body.get(key))
    name=val("name")
    if typ=="aws_glue_catalog_database":
        catalog=base+"catalog"
        if isinstance(name,str) and DB_NAME.fullmatch(name):
            database=base+"database/"+name
        elif name is None:
            # Unknown Terraform expressions cannot establish one exact name.
            # Scope to the database resource class in this account and region.
            # This is broader than a named database and must be disclosed.
            database=base+"database/*"
        else:
            for action in actions:
                omit(action,"Glue database name violates known IAM ARN naming constraints")
            return
        # Glue Data Catalog resource hierarchy requires the catalog and
        # the named database in the same authorization policy.
        for action in actions:
            if action in ("glue:CreateDatabase","glue:GetDatabase","glue:UpdateDatabase","glue:DeleteDatabase"):
                emit(action,catalog)
                emit(action,database)
            else: omit(action)
        # AWS Glue requires authorization on database descendants for
        # DeleteDatabase, even when the table/UDF names are not declared
        # by Terraform. Confine children to the database prefix.
        if "glue:DeleteDatabase" in actions:
            emit("glue:DeleteDatabase",base+"table/"+database.rsplit("/",1)[1]+"/*")
            emit("glue:DeleteDatabase",base+"userDefinedFunction/"+database.rsplit("/",1)[1]+"/*")
        return
    if typ=="aws_glue_job":
        if not isinstance(name,str) or not JOB_NAME.fullmatch(name):
            for action in actions: omit(action)
            return
        job=base+"job/"+name
        for action in actions:
            if action in ("glue:CreateJob","glue:GetJob","glue:UpdateJob","glue:DeleteJob"):
                emit(action,job)
            else: omit(action)
        # The role bound to the job is a separate required authorization.
        op=task.get("operation") if task else None
        if not task or op in ("create","update"):
            role=val("role_arn") or val("role")
            if isinstance(role,str) and re.fullmatch(rf"arn:{partition}:iam::{account}:role/[^\\s*?]+",role):
                emit("iam:PassRole",role,{"StringEquals":{"iam:PassedToService":"glue.amazonaws.com"}})
            else:
                omit("iam:PassRole")
        return
    raise ValueError("Unsupported Glue resource type")
