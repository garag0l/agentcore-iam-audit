import json
from pathlib import Path
from urllib.parse import quote

import boto3
import pytest
from botocore.stub import Stubber

from agentcore_iam_audit.checks import audit
from agentcore_iam_audit.cli import main
from agentcore_iam_audit.iam import from_file, load_gaad
from agentcore_iam_audit.live import inventory
from agentcore_iam_audit.policy import action_matches, evaluate, resource_matches

F = Path(__file__).parent / "fixtures"
OLD = "AmazonBedrockAgentCoreSDKRuntime-us-east-1-0a1b2c3d4e"
NEW = "AmazonBedrockAgentCoreSDKRuntime-us-east-1-9f8e7d6c5b"


def ids(findings):
    return {(f.id, f.principal) for f in findings}


# ---------------------------------------------------------------- account fixture (real toolkit + AWS managed policies)


def test_account_findings_exact():
    got = ids(audit(from_file(F / "account_gaad.json")))
    expected = {
        # pre-2025-12-09 starter-toolkit role: every Unit 42 "God Mode" path
        *{(i, f"role/{OLD}") for i in ("ACIA-001", "ACIA-002", "ACIA-003", "ACIA-004", "ACIA-005", "ACIA-020")},
        # current toolkit role: scoped, except the shared identity secrets
        ("ACIA-005", f"role/{NEW}"),
        ("ACIA-020", f"role/{NEW}"),
        # agent role with AdministratorAccess: reaches everything
        *{(i, "role/MyBedrockAgentCoreDeployRole") for i in ("ACIA-001", "ACIA-002", "ACIA-003", "ACIA-004", "ACIA-005")},
        # least-privilege role whose trust policy lacks SourceAccount/SourceArn
        ("ACIA-021", "role/support-agent-prod"),
        # AWS managed BedrockAgentCoreFullAccess: PassRole to *BedrockAgentCore* roles -> run code as them
        ("ACIA-010", "user/dev-alice"),
        ("ACIA-011", "user/analyst-bob"),
        ("ACIA-011", "user/ops-carol"),  # can't pass a role to AgentCore (lambda only), but can invoke existing interpreters
    }
    assert got == expected, (got - expected, expected - got)


def test_clean_principals_have_no_findings():
    names = {p for _, p in ids(audit(from_file(F / "account_gaad.json")))}
    for clean in ("role/billing-agent-prod", "role/prod-admin", "user/ci-deployer", "user/readonly-dan"):
        assert clean not in names


def test_escalation_to_admin_is_high_and_names_role():
    f = next(f for f in audit(from_file(F / "account_gaad.json")) if f.id == "ACIA-010")
    assert f.severity == "high"
    assert "MyBedrockAgentCoreDeployRole" in f.detail
    assert "prod-admin" not in f.detail  # name lacks BedrockAgentCore -> not passable under the managed policy


# ---------------------------------------------------------------- policy evaluator


def test_wildcards():
    assert action_matches("bedrock-agentcore:Get*", "bedrock-agentcore:GetMemory")
    assert action_matches("BEDROCK-AGENTCORE:getmemory", "bedrock-agentcore:GetMemory")
    assert resource_matches("arn:aws:bedrock-agentcore:*:*:memory/*", "arn:aws:bedrock-agentcore:us-east-1:1:memory/x")
    assert not resource_matches(
        "arn:aws:bedrock-agentcore:*:*:memory/agent_mem-*", "arn:aws:bedrock-agentcore:us-east-1:1:memory/other"
    )
    assert resource_matches("arn:aws:iam::*:role/*BedrockAgentCore*", "arn:aws:iam::1:role/MyBedrockAgentCoreDeployRole")


def test_not_action_and_explicit_deny():
    st = [("p", {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})]
    assert evaluate(st, "bedrock-agentcore:GetMemory", "arn:x").allowed
    assert not evaluate(st, "iam:PassRole", "arn:x").allowed
    st.append(("d", {"Effect": "Deny", "Action": "bedrock-agentcore:*", "Resource": "*"}))
    assert not evaluate(st, "bedrock-agentcore:GetMemory", "arn:x").allowed


def test_conditional_deny_does_not_block_and_conditions_are_flagged():
    st = [
        (
            "a",
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            },
        ),
        (
            "d",
            {
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            },
        ),
    ]
    g = evaluate(st, "s3:GetObject", "arn:x")
    assert g.allowed and g.conditional


def test_passed_to_service():
    st = [
        (
            "p",
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "bedrock-agentcore.amazonaws.com"}},
            },
        )
    ]
    assert evaluate(st, "iam:PassRole", "arn:r", passed_to_service="bedrock-agentcore.amazonaws.com") == evaluate(
        st, "iam:PassRole", "arn:r", passed_to_service="bedrock-agentcore.amazonaws.com"
    )
    g = evaluate(st, "iam:PassRole", "arn:r", passed_to_service="bedrock-agentcore.amazonaws.com")
    assert g.allowed and not g.conditional
    assert not evaluate(st, "iam:PassRole", "arn:r", passed_to_service="lambda.amazonaws.com").allowed


def test_url_encoded_and_string_documents():
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"}]}
    trust = {
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ]
    }
    principals = load_gaad(
        {
            "RoleDetailList": [
                {
                    "RoleName": "r",
                    "Arn": "arn:aws:iam::1:role/r",
                    "AssumeRolePolicyDocument": quote(json.dumps(trust)),
                    "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": json.dumps(doc)}],
                    "AttachedManagedPolicies": [],
                }
            ]
        }
    )
    assert {f.id for f in audit(principals)} >= {"ACIA-001", "ACIA-002", "ACIA-003", "ACIA-021"}


def test_region_specific_policy_still_detected():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:InvokeAgentRuntime",
                "Resource": "arn:aws:bedrock-agentcore:eu-central-1:1:runtime/*",
            }
        ]
    }
    trust = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": "1"}},
            }
        ]
    }
    p = load_gaad(
        {
            "RoleDetailList": [
                {
                    "RoleName": "r",
                    "Arn": "arn:aws:iam::1:role/r",
                    "AssumeRolePolicyDocument": trust,
                    "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc}],
                    "AttachedManagedPolicies": [],
                }
            ]
        }
    )
    assert {f.id for f in audit(p)} == {"ACIA-002"}


def test_group_policies_apply_to_users():
    full = json.loads((F / "aws_managed_BedrockAgentCoreFullAccess.json").read_text())["PolicyVersion"]["Document"]
    data = json.loads((F / "account_gaad.json").read_text())
    data["GroupDetailList"] = [
        {
            "GroupName": "agent-devs",
            "GroupPolicyList": [{"PolicyName": "full", "PolicyDocument": full}],
            "AttachedManagedPolicies": [],
        }
    ]
    data["UserDetailList"].append(
        {
            "UserName": "dev-erin",
            "Arn": "arn:aws:iam::111122223333:user/dev-erin",
            "GroupList": ["agent-devs"],
            "UserPolicyList": [],
            "AttachedManagedPolicies": [],
        }
    )
    assert ("ACIA-010", "user/dev-erin") in ids(audit(load_gaad(data)))


# ---------------------------------------------------------------- live inventory (botocore Stubber validates real API shapes)


def test_live_inventory_with_stubbed_api():
    session = boto3.session.Session(aws_access_key_id="x", aws_secret_access_key="y", region_name="us-east-1")
    client = session.client("bedrock-agentcore-control")
    st = Stubber(client)
    now = "2026-11-01T00:00:00Z"
    st.add_response(
        "list_code_interpreters",
        {
            "codeInterpreterSummaries": [
                {
                    "codeInterpreterId": "ci-1",
                    "codeInterpreterArn": "arn:aws:bedrock-agentcore:us-east-1:1:code-interpreter/ci-1",
                    "name": "data_ci",
                    "status": "READY",
                    "createdAt": now,
                    "lastUpdatedAt": now,
                }
            ]
        },
        {"type": "CUSTOM"},
    )
    st.add_response(
        "get_code_interpreter",
        {
            "codeInterpreterId": "ci-1",
            "codeInterpreterArn": "arn:aws:bedrock-agentcore:us-east-1:1:code-interpreter/ci-1",
            "name": "data_ci",
            "executionRoleArn": "arn:aws:iam::1:role/ci-role",
            "networkConfiguration": {"networkMode": "PUBLIC"},
            "status": "READY",
            "createdAt": now,
            "lastUpdatedAt": now,
        },
        {"codeInterpreterId": "ci-1"},
    )
    st.add_response(
        "list_agent_runtimes",
        {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/support-abc",
                    "agentRuntimeId": "support-abc",
                    "agentRuntimeVersion": "1",
                    "agentRuntimeName": "support",
                    "description": "support agent",
                    "lastUpdatedAt": now,
                    "status": "READY",
                }
            ]
        },
        {},
    )
    st.add_response(
        "get_agent_runtime",
        {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/support-abc",
            "agentRuntimeName": "support",
            "agentRuntimeId": "support-abc",
            "agentRuntimeVersion": "1",
            "createdAt": now,
            "lastUpdatedAt": now,
            "roleArn": "arn:aws:iam::1:role/support-agent-prod",
            "networkConfiguration": {"networkMode": "VPC"},
            "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 900, "maxLifetime": 28800},
            "status": "READY",
        },
        {"agentRuntimeId": "support-abc"},
    )
    st.add_response("list_browsers", {"browserSummaries": []}, {"type": "CUSTOM"})
    st.activate()

    class S:
        def client(self, name, region_name=None):
            return client

    items, findings = inventory(S(), "us-east-1")
    st.assert_no_pending_responses()
    assert [(i["type"], i["network"]) for i in items] == [("code-interpreter", "PUBLIC"), ("runtime", "VPC")]
    assert [(f.id, f.principal) for f in findings] == [("ACIA-030", "code-interpreter/data_ci")]


# ---------------------------------------------------------------- cli


def test_cli_policy_mode_old_vs_current(capsys):
    old = main(
        ["--policy", str(F / "toolkit_policy_2025_12_03.json"), "--trust", str(F / "toolkit_trust_policy.json"), "--no-color"]
    )
    out_old = capsys.readouterr().out
    new = main(
        ["--policy", str(F / "toolkit_policy_current.json"), "--trust", str(F / "toolkit_trust_policy.json"), "--no-color"]
    )
    out_new = capsys.readouterr().out
    assert old == 1 and "ACIA-001" in out_old and "ACIA-003" in out_old
    assert new == 0 and "ACIA-001" not in out_new and "ACIA-005" in out_new


def test_cli_json_and_fail_on(capsys):
    assert main(["--gaad", str(F / "account_gaad.json"), "-f", "json", "--fail-on", "none"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["principals"] == 11
    assert main(["--gaad", str(F / "account_gaad.json"), "-f", "json"]) == 1
    capsys.readouterr()


def test_cli_requires_source():
    with pytest.raises(SystemExit):
        main([])
