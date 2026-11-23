"""Checks. Each asks a concrete question with a probe ARN for a resource the principal does NOT own,
e.g. "can this agent's role read some *other* agent's memory?"."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .iam import AGENTCORE_SERVICE, Principal
from .policy import Grant, as_list, evaluate

PROBE = "zz-acia-probe-other-agent"
DEFAULT_ROLE_RX = re.compile(r"^(AmazonBedrockAgentCoreSDKRuntime|AmazonBedrockAgentCoreSDKCodeBuild|AgentCoreEvalsSDK)-")
SEV = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    id: str
    severity: str
    principal: str
    title: str
    detail: str
    conditional: bool = False
    refs: list[str] = field(default_factory=list)


def regions(p: Principal) -> list[str]:
    found = {"us-east-1"}
    for _, st in p.statements:
        for r in as_list(st.get("Resource")) + as_list(st.get("NotResource")):
            parts = str(r).split(":")
            if len(parts) > 3 and parts[2] in ("bedrock-agentcore", "ecr", "secretsmanager") and parts[3] not in ("", "*"):
                found.add(parts[3])
    return sorted(found)


def can(p: Principal, action: str, arn_tpl: str, **kw) -> Grant:
    """Allowed in any relevant region, after the permissions boundary (if any)."""
    best = Grant(False)
    for region in regions(p):
        arn = arn_tpl.format(part=p.partition, region=region, account=p.account, probe=PROBE)
        g = evaluate(p.statements, action, arn, **kw)
        if g.allowed and p.boundary is not None:
            b = evaluate(p.boundary, action, arn, **kw)
            g = Grant(b.allowed, g.conditional or b.conditional, g.source) if b.allowed else Grant(False)
        if g.allowed and (not best.allowed or (best.conditional and not g.conditional)):
            best = g
    return best


MEMORY = "arn:{part}:bedrock-agentcore:{region}:{account}:memory/{probe}"
RUNTIME = "arn:{part}:bedrock-agentcore:{region}:{account}:runtime/{probe}"
CODE_INTERPRETER = "arn:{part}:bedrock-agentcore:{region}:{account}:code-interpreter/{probe}"
ECR_REPO = "arn:{part}:ecr:{region}:{account}:repository/{probe}"
ID_SECRET = "arn:{part}:secretsmanager:{region}:{account}:secret:bedrock-agentcore-identity!default/oauth2/{probe}"
ID_APIKEY = "arn:{part}:secretsmanager:{region}:{account}:secret:bedrock-agentcore-identity!default/apikey/{probe}"
IAM_ROLE = "arn:{part}:iam::{account}:role/{probe}"
WORKLOAD_ID = "arn:{part}:bedrock-agentcore:{region}:{account}:workload-identity-directory/default/workload-identity/{probe}"
WORKLOAD_TOKEN = [
    "bedrock-agentcore:GetWorkloadAccessToken",
    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
]
RESOURCE_CRED = ["bedrock-agentcore:GetResourceOauth2Token", "bedrock-agentcore:GetResourceApiKey"]

MEMORY_READ = [
    "bedrock-agentcore:GetMemory",
    "bedrock-agentcore:RetrieveMemoryRecords",
    "bedrock-agentcore:ListEvents",
    "bedrock-agentcore:GetEvent",
    "bedrock-agentcore:ListMemoryRecords",
    "bedrock-agentcore:GetMemoryRecord",
]
MEMORY_WRITE = [
    "bedrock-agentcore:CreateEvent",
    "bedrock-agentcore:BatchCreateMemoryRecords",
    "bedrock-agentcore:BatchUpdateMemoryRecords",
    "bedrock-agentcore:DeleteMemoryRecord",
]
U42 = "https://unit42.paloaltonetworks.com/exploit-of-aws-agentcore-iam-god-mode/"
SONRAI = "https://sonraisecurity.com/blog/aws-agentcore-privilege-escalation-bedrock-scp-fix/"
SONRAI_EXFIL = "https://sonraisecurity.com/blog/sandboxed-to-compromised-new-research-exposes-credential-exfiltration-paths-in-aws-code-interpreters/"
ZENITY = "https://labs.zenity.io/post/agentcorruption-how-a-single-prompt-collapsed-the-entire-cloud-security-model"
AWS_DEFAULT_ROLES = "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html"


def _any(p: Principal, actions: list[str], tpl: str) -> tuple[list[str], bool]:
    hits, cond = [], False
    for a in actions:
        g = can(p, a, tpl)
        if g.allowed:
            hits.append(a.split(":")[1])
            cond = cond or g.conditional
    return hits, cond


def admin_like(p: Principal) -> bool:
    return (
        any(can(p, a, "arn:{part}:iam::{account}:role/{probe}").allowed for a in ("iam:PutRolePolicy", "iam:AttachRolePolicy"))
        or can(p, "iam:CreateAccessKey", "arn:{part}:iam::{account}:user/{probe}").allowed
    )


def check_agent_role(p: Principal) -> list[Finding]:
    """Execution roles (trusted by bedrock-agentcore.amazonaws.com): cross-agent reach."""
    out: list[Finding] = []
    name = f"role/{p.name}"
    read, c1 = _any(p, MEMORY_READ, MEMORY)
    write, c2 = _any(p, MEMORY_WRITE, MEMORY)
    if read or write:
        out.append(
            Finding(
                "ACIA-001",
                "high",
                name,
                "Agent role can reach other agents' memory",
                f"read: {', '.join(read) or '-'}; write/poison: {', '.join(write) or '-'} on memory not owned by this agent "
                "(memory/* or *). Scope Resource to this agent's memory ARN.",
                c1 or c2,
                [U42],
            )
        )
    g = can(p, "bedrock-agentcore:InvokeAgentRuntime", RUNTIME)
    if g.allowed:
        out.append(
            Finding(
                "ACIA-002",
                "high",
                name,
                "Agent role can invoke other agents",
                "InvokeAgentRuntime on runtimes not owned by this agent (runtime/* or *). A compromised agent can "
                "drive every other agent in the account.",
                g.conditional,
                [U42],
            )
        )
    hits, c = _any(
        p, ["bedrock-agentcore:InvokeCodeInterpreter", "bedrock-agentcore:StartCodeInterpreterSession"], CODE_INTERPRETER
    )
    if hits:
        out.append(
            Finding(
                "ACIA-003",
                "high",
                name,
                "Agent role can use other code interpreters in the account",
                f"{', '.join(hits)} on account code interpreters (code-interpreter/* or *). Code runs with each "
                "interpreter's execution role, not this agent's. Scope to aws.codeinterpreter.v1 or this agent's own.",
                c,
                [U42, SONRAI],
            )
        )
    pull, c = _any(p, ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], ECR_REPO)
    if pull and can(p, "ecr:GetAuthorizationToken", "*").allowed:
        out.append(
            Finding(
                "ACIA-004",
                "medium",
                name,
                "Agent role can pull other agents' container images",
                "ECR pull on repositories not owned by this agent (repository/* or *). Images can contain memory "
                "IDs, endpoints and config used to target other agents.",
                c,
                [U42],
            )
        )
    s1, s2 = can(p, "secretsmanager:GetSecretValue", ID_SECRET), can(p, "secretsmanager:GetSecretValue", ID_APIKEY)
    if s1.allowed or s2.allowed:
        out.append(
            Finding(
                "ACIA-005",
                "medium",
                name,
                "Agent role can read every AgentCore Identity credential secret",
                "secretsmanager:GetSecretValue on bedrock-agentcore-identity!default/oauth2/* or /apikey/*: the "
                "OAuth client secrets and API keys of all credential providers in the account's default token "
                "vault, not just the ones this agent uses (unless a resource policy on each secret denies it, which IAM data alone cannot show).",
                all(g.conditional for g in (s1, s2) if g.allowed),
            )
        )
    mint, c1 = _any(p, WORKLOAD_TOKEN, WORKLOAD_ID)
    fetch, c2 = _any(p, RESOURCE_CRED, WORKLOAD_ID)
    if mint and fetch:
        out.append(
            Finding(
                "ACIA-006",
                "high",
                name,
                "Agent role can act as other agents' workload identities and fetch their tool credentials",
                f"{', '.join(mint)} and {', '.join(fetch)} on workload identities not owned by this agent "
                "(workload-identity/* or *). A compromised agent can mint a workload access token for another "
                "agent and pull that agent's OAuth tokens or API keys from the token vault. Scope both to this "
                "agent's own workload-identity ARN.",
                c1 or c2,
                [ZENITY, AWS_DEFAULT_ROLES],
            )
        )
    if DEFAULT_ROLE_RX.match(p.name):
        out.append(
            Finding(
                "ACIA-020",
                "low",
                name,
                "AgentCore starter-toolkit default role",
                "Auto-created by the starter toolkit. AWS: these default roles are for development and testing "
                "and should never be used in production. Replace with a least-privilege role per agent.",
                refs=[AWS_DEFAULT_ROLES, U42],
            )
        )
    conds = [
        st.get("Condition") or {}
        for st in as_list((p.trust or {}).get("Statement"))
        if AGENTCORE_SERVICE
        in as_list((st.get("Principal") or {}).get("Service") if isinstance(st.get("Principal"), dict) else [])
    ]
    keys = {k.lower() for c in conds for kv in c.values() for k in kv}
    if conds and not ({"aws:sourceaccount", "aws:sourcearn"} & keys):
        out.append(
            Finding(
                "ACIA-021",
                "medium",
                name,
                "Trust policy lacks confused-deputy protection",
                "bedrock-agentcore.amazonaws.com can assume this role with no aws:SourceAccount / aws:SourceArn "
                "condition, so AgentCore resources in other accounts could be configured to use it.",
                refs=["https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"],
            )
        )
    return out


def check_privesc(p: Principal, agent_roles: list[Principal]) -> list[Finding]:
    """Any principal: create a code interpreter with a powerful AgentCore role, then run code as it."""
    out: list[Finding] = []
    name = f"{p.kind}/{p.name}"
    if admin_like(p):
        return out  # already admin-equivalent: nothing to escalate to
    create = can(p, "bedrock-agentcore:CreateCodeInterpreter", CODE_INTERPRETER)
    invoke = can(p, "bedrock-agentcore:InvokeCodeInterpreter", CODE_INTERPRETER)
    if invoke.allowed and not p.trusts_service():
        out.append(
            Finding(
                "ACIA-011",
                "medium",
                name,
                "Can run code in any custom code interpreter",
                "InvokeCodeInterpreter on account code interpreters: code runs with each interpreter's execution "
                "role, and CloudTrail attributes the role's API calls to the interpreter rather than this "
                "principal.",
                invoke.conditional,
                [SONRAI],
            )
        )
    if not (create.allowed and invoke.allowed):
        return out
    passable = []
    for r in agent_roles:
        if r.arn == p.arn:
            continue
        g = evaluate(p.statements, "iam:PassRole", r.arn, passed_to_service=AGENTCORE_SERVICE)
        if g.allowed and p.boundary is not None:
            g = evaluate(p.boundary, "iam:PassRole", r.arn, passed_to_service=AGENTCORE_SERVICE)
        if g.allowed:
            passable.append((r, g.conditional))
    if not passable:
        return out
    strong = [r.name for r, _ in passable if admin_like(r)]
    names = ", ".join(sorted(r.name for r, _ in passable)[:8]) + (" ..." if len(passable) > 8 else "")
    out = [f for f in out if f.id != "ACIA-011"]  # superseded by the escalation finding
    out.append(
        Finding(
            "ACIA-010",
            "high" if strong else "medium",
            name,
            "Privilege escalation via code interpreter (PassRole + Create/InvokeCodeInterpreter)",
            f"Can create a code interpreter with an AgentCore role it can pass and run code as that role: {names}."
            + (f" Admin-equivalent: {', '.join(strong)}." if strong else ""),
            create.conditional or invoke.conditional or all(c for _, c in passable),
            [SONRAI],
        )
    )
    return out


def audit(principals: list[Principal]) -> list[Finding]:
    agent_roles = [p for p in principals if p.kind == "role" and p.trusts_service()]
    findings: list[Finding] = []
    for r in agent_roles:
        findings += check_agent_role(r)
    for p in principals:
        findings += check_privesc(p, agent_roles)
    findings.sort(key=lambda f: (-SEV[f.severity], f.id, f.principal))
    return findings
