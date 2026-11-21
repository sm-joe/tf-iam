from tfiam.risk import assess

def row(action, provider="aws"):
    return {"provider":provider,"action":action,"source":"fixture","scope":"example"}

def test_delegation_combination():
    findings = assess([row("iam:PassRole"), row("ec2:RunInstances"), row("iam:PassRole")])
    assert len(findings) == 2
    assert any(f["kind"] == "combination" for f in findings)
    assert all(f["sources"] == ["fixture"] for f in findings)

def test_read_only():
    assert assess([row("iam:GetRole")]) == []

def test_azure_case_insensitive():
    assert assess([row("microsoft.authorization/roleassignments/write", "azure")])

def test_no_cross_provider_combination():
    assert not any(f["kind"] == "combination" for f in assess([row("iam:PassRole"), row("ec2:RunInstances", "gcp")]))
