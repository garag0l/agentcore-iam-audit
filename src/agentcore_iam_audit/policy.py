"""Minimal IAM policy evaluator: does a set of statements allow an action on a specific resource ARN?

Covers what this audit needs: Allow/Deny, Action/NotAction, Resource/NotResource, wildcards (* and ?),
permission boundaries (by the caller), and visibility into Conditions (reported, not evaluated, except
`iam:PassedToService`, which is evaluated for iam:PassRole). SCPs and resource policies are out of scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache


def as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


@lru_cache(maxsize=4096)
def _rx(pattern: str, case_insensitive: bool) -> re.Pattern:
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(f"^{body}$", (re.I if case_insensitive else 0) | re.S)


def action_matches(pattern: str, action: str) -> bool:
    return bool(_rx(pattern, True).match(action))


def resource_matches(pattern: str, arn: str) -> bool:
    return bool(_rx(pattern, False).match(arn))


@dataclass(frozen=True)
class Grant:
    allowed: bool
    conditional: bool = False  # an allowing statement carried a Condition we did not evaluate
    source: str = ""  # policy name that granted it


def _matches(stmt: dict, action: str, arn: str) -> bool:
    if "NotAction" in stmt:
        if any(action_matches(p, action) for p in as_list(stmt["NotAction"])):
            return False
    elif not any(action_matches(p, action) for p in as_list(stmt.get("Action"))):
        return False
    if "NotResource" in stmt:
        return not any(resource_matches(p, arn) for p in as_list(stmt["NotResource"]))
    return any(resource_matches(p, arn) for p in as_list(stmt.get("Resource")))


def _passed_to_service_ok(stmt: dict, service: str | None) -> bool:
    """Evaluate iam:PassedToService conditions for PassRole. Unknown conditions are treated as satisfiable."""
    if not service:
        return True
    for op, kv in (stmt.get("Condition") or {}).items():
        for key, vals in (kv or {}).items():
            if key.lower() != "iam:passedtoservice":
                continue
            vals = [str(v) for v in as_list(vals)]
            op_l = op.lower()
            if op_l.startswith("stringequals") and service not in vals:
                return False
            if op_l.startswith("stringlike") and not any(action_matches(v, service) for v in vals):
                return False
            if op_l.startswith("stringnotequals") and service in vals:
                return False
    return True


def evaluate(statements: list[tuple[str, dict]], action: str, arn: str, *, passed_to_service: str | None = None) -> Grant:
    """statements: (policy_name, statement) pairs from all identity policies of a principal."""
    allow: Grant | None = None
    for name, st in statements:
        if not _matches(st, action, arn):
            continue
        if st.get("Effect") == "Deny":
            if not st.get("Condition"):
                return Grant(False, source=name)
            continue  # conditional deny: can't prove it applies; keep evaluating
        if st.get("Effect") == "Allow" and _passed_to_service_ok(st, passed_to_service):
            cond = bool(st.get("Condition")) and not (
                passed_to_service and set(k.lower() for kv in st["Condition"].values() for k in kv) == {"iam:passedtoservice"}
            )
            if allow is None or (allow.conditional and not cond):
                allow = Grant(True, conditional=cond, source=name)
    return allow or Grant(False)
