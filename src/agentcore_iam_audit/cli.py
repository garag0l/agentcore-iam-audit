"""agentcore-iam-audit command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .checks import SEV, audit
from .iam import from_file, from_live, load_gaad


def _single_policy(policy: str, trust: str | None, name: str, account: str) -> list:
    doc = json.loads(Path(policy).read_text(encoding="utf-8-sig"))
    trust_doc = (
        json.loads(Path(trust).read_text(encoding="utf-8-sig"))
        if trust
        else {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                }
            ]
        }
    )
    return load_gaad(
        {
            "RoleDetailList": [
                {
                    "RoleName": name,
                    "Arn": f"arn:aws:iam::{account}:role/{name}",
                    "AssumeRolePolicyDocument": trust_doc,
                    "RolePolicyList": [{"PolicyName": Path(policy).name, "PolicyDocument": doc}],
                    "AttachedManagedPolicies": [],
                }
            ]
        }
    )


def render(findings, inventory, color: bool) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    col = {"high": "31", "medium": "33", "low": "36", "info": "2"}
    lines = [c("1", f"agentcore-iam-audit {__version__}"), ""]
    if inventory:
        lines.append(c("1", "AgentCore resources"))
        for i in inventory:
            lines.append(
                f"  {i['type']:<17} {i['name']:<30} role={str(i.get('role') or '-').split('/')[-1]}  network={i.get('network') or '-'}"
            )
        lines.append("")
    for f in findings:
        tag = c(col[f.severity], f"[{f.severity.upper()}]")
        lines.append(f"{tag} {f.id} {c('1', f.principal)}  {f.title}" + (c("2", "  (conditional)") if f.conditional else ""))
        lines.append(f"       {f.detail}")
        for r in f.refs:
            lines.append(c("2", f"       ref: {r}"))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV}
    lines += ["", c("1", f"{len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, {counts['low']} low")]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agentcore-iam-audit",
        description="Find Amazon Bedrock AgentCore IAM paths: agents reaching other agents' memory, runtimes, code "
        "interpreters, images and secrets, and privilege escalation through code interpreters.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--gaad", metavar="FILE", help="output of `aws iam get-account-authorization-details` (offline)")
    src.add_argument("--live", action="store_true", help="read IAM + AgentCore inventory with your AWS credentials (read-only)")
    src.add_argument("--policy", metavar="FILE", help="check one execution-role policy document before deploying it")
    p.add_argument("--trust", metavar="FILE", help="with --policy: the role's trust policy")
    p.add_argument("--role-name", default="candidate-agent-role", help="with --policy: role name to report")
    p.add_argument("--account", default="111122223333", help="with --policy: account id the role lives in")
    p.add_argument("--profile", help="with --live: AWS profile")
    p.add_argument("--region", action="append", help="with --live: AgentCore region(s) to inventory (default: session region)")
    p.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "none"], default="high")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)

    inventory, extra = [], []
    if a.gaad:
        principals = from_file(a.gaad)
    elif a.policy:
        principals = _single_policy(a.policy, a.trust, a.role_name, a.account)
    else:
        try:
            import boto3
        except ImportError:
            print("live mode needs boto3: pip install 'agentcore-iam-audit[live]'", file=sys.stderr)
            return 2
        from .live import inventory as live_inventory

        session = boto3.session.Session(profile_name=a.profile)
        principals = from_live(session)
        for region in a.region or [session.region_name or "us-east-1"]:
            items, f = live_inventory(session, region)
            inventory += items
            extra += f

    findings = audit(principals) + extra
    findings.sort(key=lambda f: (-SEV[f.severity], f.id, f.principal))
    if a.format == "json":
        print(
            json.dumps(
                {
                    "version": __version__,
                    "principals": len(principals),
                    "inventory": inventory,
                    "findings": [asdict(f) for f in findings],
                },
                indent=2,
            )
        )
    else:
        color = not a.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(render(findings, inventory, color))
    threshold = {"none": 99, **SEV}[a.fail_on]
    return 1 if any(SEV[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
