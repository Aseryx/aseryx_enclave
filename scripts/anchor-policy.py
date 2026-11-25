#!/usr/bin/env python3
"""Anchors every regular-expression environment rule of a generated CCE policy.

usage: anchor-policy.py IN.rego OUT.rego

The policy engine allows an environment variable when any rule matches its NAME=VALUE text, and a regular-expression rule
is a search, not a full match: HOSTNAME=.+ allows ENCLAVE_API_URL=https://evil.example/?HOSTNAME=1. confcom adds such
rules to every container (the platform's own variables) and writes ours (the memory setting) the same way. This script
rewrites each one as ^(?:...)$, an inline flag first (see policy_patterns.py): the group makes the anchors cover every
alternative of a pattern with a top-level alternation, and the rewrite only narrows what the policy allows, so a variable
is allowed only when its whole text is the rule. The deployed policy is the text of OUT.rego, and its SHA-256 is the
workload identity.
"""
import json
import sys

from policy_patterns import anchored

PREFIX = "containers := "


def main(source: str, destination: str) -> int:
    lines = open(source).read().split("\n")
    index = [i for i, line in enumerate(lines) if line.startswith(PREFIX)]
    if len(index) != 1:
        raise SystemExit("the policy must have exactly one containers line")
    containers = json.loads(lines[index[0]][len(PREFIX):])
    changed = 0
    for container in containers:
        for rule in container["env_rules"]:
            if rule["strategy"] == "re2":
                new = anchored(rule["pattern"])
                changed += new != rule["pattern"]
                rule["pattern"] = new
    lines[index[0]] = PREFIX + json.dumps(containers, separators=(",", ":"), ensure_ascii=False)
    open(destination, "w").write("\n".join(lines))
    print(f"anchored {changed} regular-expression environment rules")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
