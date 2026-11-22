import importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location("accept_mixed",Path(__file__).resolve().parents[1]/"scripts"/"accept-mixed.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
INFO={"account":"123456789012","region":"us-east-1","prefix":"tfiam-live-0123456789abcdef"}

def test_isolated_fixture():
    first=mod.config(INFO,1)
    second=mod.config(INFO,2)
    assert first["provider"]["aws"]["allowed_account_ids"]==[INFO["account"]]
    assert first["resource"]["aws_instance"]["app"]["associate_public_ip_address"] is False
    assert first["resource"]["aws_instance"]["app"]["metadata_options"]["http_tokens"]=="required"
    assert first["resource"]["aws_subnet"]["private"]["map_public_ip_on_launch"] is False
    assert first["resource"]["aws_s3_bucket"]["storage"]["tags"]["Revision"]=="1"
    assert second["resource"]["aws_s3_bucket"]["storage"]["tags"]["Revision"]=="2"
    assert "aws_internet_gateway" not in first["resource"]

@pytest.mark.parametrize("phase,action",[("create","create"),("update","update"),("destroy","delete")])
def test_expected_operations(phase,action):
    rows=[]
    for typ,items in mod.config(INFO,1)["resource"].items():
        for name,body in items.items():
            for i in range(body.get("count",1)):
                addr=typ+"."+name+("["+str(i)+"]" if "count" in body else "")
                rows.append({"address":addr,"mode":"managed","provider_name":"registry.terraform.io/hashicorp/random" if typ=="random_id" else mod.AWS,"change":{"actions":[action]}})
    plan={"resource_changes":rows}
    assert len(mod.operations(plan,phase,INFO))==len(rows)
    rows[0]["change"]["actions"]=["create","delete"]
    with pytest.raises(ValueError): mod.operations(plan,phase,INFO)
    rows[0]["change"]["actions"]=[action]
    rows.pop()
    with pytest.raises(ValueError): mod.operations(plan,phase,INFO)
