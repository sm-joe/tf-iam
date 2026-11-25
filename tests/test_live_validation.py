"""No AWS credentials or outbound network required for these SDK-injection tests."""
from tfiam import live_validation


def policy(resource):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:DescribeVpcs"], "Resource": resource}
    ]}


def test_unresolved_template_never_calls_aws(monkeypatch):
    def no_client(*args, **kwargs):
        raise AssertionError("No AWS API allowed for unresolved templates")
    monkeypatch.setattr(live_validation.cloud, "client", no_client)
    result = live_validation.validate(policy("arn:aws:ec2:<AWS_REGION>:<AWS_ACCOUNT_ID>:vpc/<REPLACE_WITH_VPC_ID>"),
                                      simulate=True)
    assert result["status"] == "requires-replacement"
    assert result["aws_called"] is False
    assert result["placeholder_count"] == 1


def test_uses_boto3_chain_for_analyzer_and_iam(monkeypatch):
    calls = []
    class Analyzer:
        pass
    class Iam:
        def simulate_custom_policy(self, **kwargs):
            calls.append(kwargs)
            return {"EvaluationResults": [{"EvalDecision": "allowed"}]}
    analyzer, iam = Analyzer(), Iam()
    def fake_client(service, profile, region):
        assert profile == "developer"
        assert region == "us-east-1"
        return {"accessanalyzer": analyzer, "iam": iam}[service]
    def fake_validation(client, doc):
        assert client is analyzer
        return {"status": "no-findings", "counts": {}, "findings": []}
    monkeypatch.setattr(live_validation.cloud, "client", fake_client)
    monkeypatch.setattr(live_validation.cloud, "validate_policy", fake_validation)
    result = live_validation.validate(policy("*"), profile="developer", region="us-east-1", simulate=True)
    assert result["status"] == "validated"
    assert result["simulation"]["status"] == "passed"
    assert len(calls) == 1
    assert calls[0]["ActionNames"] == ["ec2:DescribeVpcs"]


def test_condition_context_not_silently_assumed(monkeypatch):
    doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "iam:PassRole",
         "Resource": "arn:aws:iam::123456789012:role/worker",
         "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}}
    ]}
    monkeypatch.setattr(live_validation.cloud, "client", lambda *args, **kwargs: object())
    monkeypatch.setattr(live_validation.cloud, "validate_policy",
                        lambda client, doc: {"status": "no-findings", "findings": []})
    result = live_validation.validate(doc, simulate=True)
    assert result["status"] == "review"
    assert result["simulation"]["results"][0]["decision"] == "not-evaluated"


def test_simulation_limit_has_no_iam_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(live_validation.cloud, "client",
                        lambda service, profile, region: calls.append(service) or object())
    monkeypatch.setattr(live_validation.cloud, "validate_policy",
                        lambda client, doc: {"status": "no-findings", "findings": []})
    doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:DescribeVpcs", "ec2:DescribeSubnets"], "Resource": "*"}
    ]}
    result = live_validation.validate(doc, simulate=True, max_tests=1)
    assert result["simulation"]["status"] == "not-run"
    assert calls == ["accessanalyzer"]
