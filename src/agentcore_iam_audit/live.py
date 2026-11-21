"""Optional live inventory of AgentCore resources (needs boto3 and read-only credentials)."""

from __future__ import annotations

from .checks import Finding


def _paginate(call, key, **kw):
    token = None
    while True:
        resp = call(**kw, **({"nextToken": token} if token else {}))
        yield from resp.get(key, [])
        token = resp.get("nextToken")
        if not token:
            return


def inventory(session, region: str) -> tuple[list[dict], list[Finding]]:
    c = session.client("bedrock-agentcore-control", region_name=region)
    items, findings = [], []
    for s in _paginate(c.list_code_interpreters, "codeInterpreterSummaries", type="CUSTOM"):
        d = c.get_code_interpreter(codeInterpreterId=s["codeInterpreterId"])
        mode = (d.get("networkConfiguration") or {}).get("networkMode")
        role = d.get("executionRoleArn")
        items.append(
            {"type": "code-interpreter", "name": d.get("name"), "arn": d.get("codeInterpreterArn"), "role": role, "network": mode}
        )
        if role and mode == "PUBLIC":
            findings.append(
                Finding(
                    "ACIA-030",
                    "medium",
                    f"code-interpreter/{d.get('name')}",
                    "Custom code interpreter with an execution role and PUBLIC network",
                    f"Code running in it gets {role.split('/')[-1]} credentials and can send them anywhere. Use SANDBOX or VPC "
                    "mode, or drop the role.",
                    refs=[
                        "https://sonraisecurity.com/blog/sandboxed-to-compromised-new-research-exposes-credential-exfiltration-paths-in-aws-code-interpreters/"
                    ],
                )
            )
    for s in _paginate(c.list_agent_runtimes, "agentRuntimes"):
        d = c.get_agent_runtime(agentRuntimeId=s["agentRuntimeId"])
        items.append(
            {
                "type": "runtime",
                "name": d.get("agentRuntimeName"),
                "arn": d.get("agentRuntimeArn"),
                "role": d.get("roleArn"),
                "network": (d.get("networkConfiguration") or {}).get("networkMode"),
            }
        )
    for s in _paginate(c.list_browsers, "browserSummaries", type="CUSTOM"):
        d = c.get_browser(browserId=s["browserId"])
        items.append(
            {
                "type": "browser",
                "name": d.get("name"),
                "arn": d.get("browserArn"),
                "role": d.get("executionRoleArn"),
                "network": (d.get("networkConfiguration") or {}).get("networkMode"),
            }
        )
    return items, findings
