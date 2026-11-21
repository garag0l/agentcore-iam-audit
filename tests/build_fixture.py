"""Build tests/fixtures/account_gaad.json: a realistic `get-account-authorization-details` export.

Real policy documents: AgentCore starter-toolkit execution role (pre-2025-12-09 and current), its trust
policy, and AWS managed BedrockAgentCoreFullAccess (v21). Everything else is a deliberate edge case.
"""

import json
from pathlib import Path

F = Path(__file__).parent / "fixtures"
ACCT = "111122223333"


def load(name):
    return json.loads((F / name).read_text())


FULL = load("aws_managed_BedrockAgentCoreFullAccess.json")["PolicyVersion"]["Document"]
OLD, NEW, TRUST = load("toolkit_policy_2025_12_03.json"), load("toolkit_policy_current.json"), load("toolkit_trust_policy.json")
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
TRUST_NO_COND = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}
TRUST_EC2 = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}
SCOPED = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock-agentcore:GetMemory", "bedrock-agentcore:CreateEvent", "bedrock-agentcore:ListEvents"],
            "Resource": f"arn:aws:bedrock-agentcore:us-west-2:{ACCT}:memory/support_mem-*",
        },
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:InvokeCodeInterpreter",
            "Resource": "arn:aws:bedrock-agentcore:us-west-2:aws:code-interpreter/aws.codeinterpreter.v1",
        },
        {
            "Effect": "Allow",
            "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
            "Resource": f"arn:aws:ecr:us-west-2:{ACCT}:repository/support-agent",
        },
        {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
    ],
}
DENY_OTHERS = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"},
        {
            "Effect": "Deny",
            "Action": "bedrock-agentcore:*",
            "NotResource": [
                f"arn:aws:bedrock-agentcore:us-east-1:{ACCT}:memory/billing_mem-*",
                f"arn:aws:bedrock-agentcore:us-east-1:{ACCT}:runtime/billing-*",
            ],
        },
    ],
}
BOUNDARY_READONLY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["bedrock-agentcore:Get*", "bedrock-agentcore:List*"], "Resource": "*"}],
}


def managed(arn, name, doc):
    return {"PolicyName": name, "Arn": arn, "PolicyVersionList": [{"Document": doc, "IsDefaultVersion": True, "VersionId": "v1"}]}


def role(name, trust, inline=None, attached=(), boundary=None):
    r = {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCT}:role/{name}",
        "AssumeRolePolicyDocument": trust,
        "RolePolicyList": [{"PolicyName": f"{name}-inline", "PolicyDocument": inline}] if inline else [],
        "AttachedManagedPolicies": [{"PolicyArn": a} for a in attached],
    }
    if boundary:
        r["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary, "PermissionsBoundaryType": "Policy"}
    return r


def user(name, inline=None, attached=(), groups=(), boundary=None):
    u = {
        "UserName": name,
        "Arn": f"arn:aws:iam::{ACCT}:user/{name}",
        "GroupList": list(groups),
        "UserPolicyList": [{"PolicyName": f"{name}-inline", "PolicyDocument": inline}] if inline else [],
        "AttachedManagedPolicies": [{"PolicyArn": a} for a in attached],
    }
    if boundary:
        u["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary, "PermissionsBoundaryType": "Policy"}
    return u


FULL_ARN = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
BOUND_ARN = f"arn:aws:iam::{ACCT}:policy/agentcore-readonly-boundary"
CODE_ALL = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "bedrock-agentcore:InvokeCodeInterpreter", "Resource": "*"}],
}
CI_DEPLOY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock-agentcore:CreateCodeInterpreter", "bedrock-agentcore:InvokeCodeInterpreter"],
            "Resource": "*",
        },
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCT}:role/MyBedrockAgentCoreDeployRole"},
    ],
}
PASS_TO_LAMBDA_ONLY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock-agentcore:CreateCodeInterpreter", "bedrock-agentcore:InvokeCodeInterpreter"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
        },
    ],
}

gaad = {
    "Policies": [
        managed(FULL_ARN, "BedrockAgentCoreFullAccess", FULL),
        managed(ADMIN_ARN, "AdministratorAccess", ADMIN),
        managed(BOUND_ARN, "agentcore-readonly-boundary", BOUNDARY_READONLY),
    ],
    "RoleDetailList": [
        role("AmazonBedrockAgentCoreSDKRuntime-us-east-1-0a1b2c3d4e", TRUST, OLD),
        role("AmazonBedrockAgentCoreSDKRuntime-us-east-1-9f8e7d6c5b", TRUST, NEW),
        role("support-agent-prod", TRUST_NO_COND, SCOPED),
        role("billing-agent-prod", TRUST, DENY_OTHERS),
        role("MyBedrockAgentCoreDeployRole", TRUST, attached=[ADMIN_ARN]),
        role("prod-admin", TRUST_EC2, attached=[ADMIN_ARN]),
    ],
    "UserDetailList": [
        user("dev-alice", attached=[FULL_ARN]),
        user("analyst-bob", inline=CODE_ALL),
        user("ci-deployer", inline=CI_DEPLOY, boundary=BOUND_ARN),
        user("ops-carol", inline=PASS_TO_LAMBDA_ONLY),
        user("readonly-dan", inline=BOUNDARY_READONLY),
    ],
    "GroupDetailList": [],
}
(F / "account_gaad.json").write_text(json.dumps(gaad, indent=2) + "\n", encoding="utf-8")
print("wrote", F / "account_gaad.json")
