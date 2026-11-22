import json
from tfiam.scan import scan
from tfiam.action_scope import network

A="123456789012"
R="us-east-1"
def test_network_dependencies():
    grants=[]; gaps=[]
    network("aws_nat_gateway",{"subnet_id":"subnet-abc","allocation_id":"eipalloc-def","tags":{"Name":"nat"}},["ec2:CreateNatGateway","ec2:CreateTags"],A,R,"aws",lambda x:x if isinstance(x,str) else None,lambda a,s,c=None:grants.append((a,s,c)),gaps.append,{"operation":"create"})
    assert not gaps
    targets={s for a,s,c in grants if a=="ec2:CreateNatGateway"}
    assert targets=={f"arn:aws:ec2:{R}:{A}:subnet/subnet-abc",f"arn:aws:ec2:{R}:{A}:elastic-ip/eipalloc-def",f"arn:aws:ec2:{R}:{A}:natgateway/*"}
    assert any(a=="ec2:CreateTags" and c=={"StringEquals":{"ec2:CreateAction":"CreateNatGateway"}} for a,s,c in grants)

def test_configured_dependencies(tmp_path):
    role=f"arn:aws:iam::{A}:role/runtime"
    key=f"arn:aws:kms:{R}:{A}:key/12345678-1234-1234-1234-123456789012"
    resources={
        "aws_s3_object":{"o":{"bucket":"fixture-bucket","key":"data/file.txt","acl":"private","kms_key_id":key}},
        "aws_s3_bucket_replication_configuration":{"r":{"bucket":"fixture-bucket","role":role}},
        "aws_db_instance":{"d":{"identifier":"fixture","monitoring_role_arn":role,"kms_key_id":key}},
        "aws_ecs_service":{"s":{"name":"worker","cluster":"demo","task_definition":"worker:1"}},
        "aws_eks_addon":{"a":{"cluster_name":"demo","addon_name":"aws-ebs-csi-driver","pod_identity_association":[{"role_arn":role,"service_account":"ebs-csi-controller-sa"}]}},
    }
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":resources}))
    p=scan(tmp_path,account=A,region=R)
    assert not p["unresolved_permissions"],p["unresolved_permissions"]
    def has(action,scope,condition=None):
        return any(x["action"]==action and x["scope"]==scope and (condition is None or x.get("condition")==condition) for x in p["permissions"])
    assert has("s3:PutObjectAcl","arn:aws:s3:::fixture-bucket/data/file.txt")
    assert has("s3:DeleteObjectVersion","arn:aws:s3:::fixture-bucket/data/file.txt")
    assert has("s3:ListBucketVersions","arn:aws:s3:::fixture-bucket",{"StringEquals":{"s3:prefix":"data/file.txt"}})
    assert has("kms:GenerateDataKey",key)
    assert has("iam:PassRole",role,{"StringEquals":{"iam:PassedToService":"s3.amazonaws.com"}})
    assert has("iam:PassRole",role,{"StringEquals":{"iam:PassedToService":"monitoring.rds.amazonaws.com"}})
    assert has("ecs:CreateService",f"arn:aws:ecs:{R}:{A}:service/demo/worker",{"ArnLike":{"ecs:task-definition":f"arn:aws:ecs:{R}:{A}:task-definition/worker:1"}})
    assert has("iam:PassRole",role,{"StringEquals":{"iam:PassedToService":"pods.eks.amazonaws.com"}})

def test_unknown_replication_role_blocks(tmp_path):
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_s3_bucket_replication_configuration":{"r":{"bucket":"fixture-bucket"}}}}))
    p=scan(tmp_path,account=A,region=R)
    assert any(x["action"]=="iam:PassRole" for x in p["unresolved_permissions"])
