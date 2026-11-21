import json
from tfiam.catalog_loader import get_rule, operation_actions
from tfiam.scan import scan
from tfiam.authorization import catalog_actions

def test_ownership_controls_delete_uses_put_permission(tmp_path):
    rule=get_rule("resource","aws_s3_bucket_ownership_controls")
    assert rule["delete"]==["s3:PutBucketOwnershipControls"]
    assert "s3:DeleteBucketOwnershipControls" not in catalog_actions()
    assert "s3:PutBucketOwnershipControls" not in operation_actions(rule,"read")
    (tmp_path/"main.tf.json").write_text(json.dumps({"resource":{"aws_s3_bucket_ownership_controls":{"example":{"bucket":"example-bucket"}}}}))
    report=scan(tmp_path,phase="destroy")
    assert any(p["action"]=="s3:PutBucketOwnershipControls" and p["scope"]=="arn:aws:s3:::example-bucket" for p in report["permissions"])
