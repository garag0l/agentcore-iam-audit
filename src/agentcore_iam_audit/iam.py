"""Load IAM state from `aws iam get-account-authorization-details` (file or live) into principals."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from .policy import as_list

AGENTCORE_SERVICE = "bedrock-agentcore.amazonaws.com"


def _doc(d):
    """Policy documents arrive as dicts (boto3), JSON strings, or URL-encoded JSON (some CLI paths)."""
    if isinstance(d, dict):
        return d
    if isinstance(d, str):
        s = d if d.lstrip().startswith("{") else unquote(d)
        return json.loads(s)
    return {"Statement": []}


def _statements(name: str, doc) -> list[tuple[str, dict]]:
    return [(name, st) for st in as_list(_doc(doc).get("Statement"))]


@dataclass
class Principal:
    kind: str  # role | user
    name: str
    arn: str
    statements: list[tuple[str, dict]] = field(default_factory=list)
    boundary: list[tuple[str, dict]] | None = None
    trust: dict | None = None  # roles only

    @property
    def account(self) -> str:
        parts = self.arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    @property
    def partition(self) -> str:
        parts = self.arn.split(":")
        return parts[1] if len(parts) > 1 else "aws"

    def trusts_service(self, service: str = AGENTCORE_SERVICE) -> bool:
        for st in as_list((self.trust or {}).get("Statement")):
            if st.get("Effect") != "Allow":
                continue
            svc = as_list((st.get("Principal") or {}).get("Service")) if isinstance(st.get("Principal"), dict) else []
            if service in svc:
                return True
        return False


def load_gaad(data: dict) -> list[Principal]:
    managed: dict[str, dict] = {}
    for p in data.get("Policies", []):
        default = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
        if default:
            managed[p["Arn"]] = {"name": p.get("PolicyName", p["Arn"]), "doc": default.get("Document")}

    def attached(lst) -> list[tuple[str, dict]]:
        out = []
        for a in lst or []:
            m = managed.get(a.get("PolicyArn"))
            if m:
                out += _statements(m["name"], m["doc"])
        return out

    groups = {}
    for g in data.get("GroupDetailList", []):
        st = attached(g.get("AttachedManagedPolicies"))
        for ip in g.get("GroupPolicyList", []):
            st += _statements(f"{g['GroupName']}/{ip['PolicyName']}", ip.get("PolicyDocument"))
        groups[g["GroupName"]] = st

    def boundary(entity) -> list[tuple[str, dict]] | None:
        pb = entity.get("PermissionsBoundary")
        if not pb:
            return None
        m = managed.get(pb.get("PermissionsBoundaryArn"))
        return _statements(f"boundary:{m['name']}", m["doc"]) if m else None

    out: list[Principal] = []
    for r in data.get("RoleDetailList", []):
        st = attached(r.get("AttachedManagedPolicies"))
        for ip in r.get("RolePolicyList", []):
            st += _statements(ip["PolicyName"], ip.get("PolicyDocument"))
        out.append(Principal("role", r["RoleName"], r["Arn"], st, boundary(r), _doc(r.get("AssumeRolePolicyDocument") or {})))
    for u in data.get("UserDetailList", []):
        st = attached(u.get("AttachedManagedPolicies"))
        for ip in u.get("UserPolicyList", []):
            st += _statements(ip["PolicyName"], ip.get("PolicyDocument"))
        for g in u.get("GroupList", []):
            st += groups.get(g, [])
        out.append(Principal("user", u["UserName"], u["Arn"], st, boundary(u)))
    return out


def from_file(path: str | Path) -> list[Principal]:
    return load_gaad(json.loads(Path(path).read_text(encoding="utf-8-sig")))


def from_live(session) -> list[Principal]:
    iam = session.client("iam")
    merged: dict[str, list] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        for k in merged:
            merged[k] += page.get(k, [])
    return load_gaad(merged)
