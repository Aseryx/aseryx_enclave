#!/usr/bin/env python3
"""Checks a generated CCE policy against the release template and the engine pin.

usage: check-policy.py POLICY.rego TEMPLATE.json ENGINE.sha256

The workload container must be locked down (no exec, no stdio) and every ENCLAVE_* environment rule must be an exact
string equal to the template's value. ENCLAVE_MEMORY_GB is the one exception: its rule may be any pattern, because the
workload refuses to start unless the container's cgroup shows 85% of the size it claims. Besides that, the only regular
expressions allowed are the platform's own fixed rules, which confcom adds to every container. The engine pin in the
environment must be the hash of the engine module in the image.
"""
import json
import re
import sys

WORKLOAD = "enclave-workload"
EXCEPTION = "ENCLAVE_MEMORY_GB"
PLATFORM_RE2 = {
    "(?i)(FABRIC)_.+=.+",
    "HOSTNAME=.+",
    "T(E)?MP=.+",
    "FabricPackageFileName=.+",
    "HostedServiceName=.+",
    "IDENTITY_API_VERSION=.+",
    "IDENTITY_HEADER=.+",
    "IDENTITY_SERVER_THUMBPRINT=.+",
    "azurecontainerinstance_restarted_by=.+",
}


def containers(rego: str) -> list:
    for line in rego.splitlines():
        if line.startswith("containers := "):
            return json.loads(line[len("containers := "):])
    raise SystemExit("the policy has no containers line")


def main(policy_path: str, template_path: str, engine_path: str) -> int:
    problems = []
    workload = next((c for c in containers(open(policy_path).read()) if c["name"] == WORKLOAD), None)
    if workload is None:
        raise SystemExit(f"the policy has no container named {WORKLOAD}")
    template = json.load(open(template_path))
    declared = next(
        c["properties"]["environmentVariables"]
        for c in template["resources"][0]["properties"]["containers"]
        if c["name"] == WORKLOAD
    )
    expected = {e["name"]: e["value"] for e in declared}

    if workload["exec_processes"]:
        problems.append("the workload allows exec")
    if workload["allow_stdio_access"]:
        problems.append("the workload allows stdio")

    rules = workload["env_rules"]
    for rule in rules:
        name = rule["pattern"].split("=", 1)[0]
        if rule["strategy"] == "re2":
            if rule["pattern"] not in PLATFORM_RE2 and name != EXCEPTION:
                problems.append(f"a regular expression rule that is not the platform's: {rule['pattern']}")
        elif rule["strategy"] == "string":
            if name.startswith("ENCLAVE_") and name not in expected:
                problems.append(f"an ENCLAVE_ rule the template does not declare: {name}")
        else:
            problems.append(f"an environment rule with strategy {rule['strategy']}")
    for name, value in expected.items():
        mine = [r for r in rules if r["pattern"].split("=", 1)[0].startswith(name) or r["pattern"].startswith(name)]
        exact = [r for r in rules if r["strategy"] == "string" and r["pattern"] == f"{name}={value}"]
        if name == EXCEPTION:
            if not mine:
                problems.append(f"no rule for {name}")
            continue
        if len(exact) != 1:
            problems.append(f"{name} is not pinned to exactly the template's value")
        if len([r for r in rules if r["pattern"].split("=", 1)[0] == name]) != 1:
            problems.append(f"{name} has more than one rule")

    pin = open(engine_path).read().split()[0]
    if expected.get("ENCLAVE_ENGINE_SHA256") != "0x" + pin:
        problems.append("ENCLAVE_ENGINE_SHA256 is not the hash of the engine module in the image")
    if not re.fullmatch(r"0x[0-9a-f]{64}", expected.get("ENCLAVE_ENGINE_SHA256", "")):
        problems.append("ENCLAVE_ENGINE_SHA256 is not 0x and 64 lower-case hex digits")

    for problem in problems:
        print("policy problem:", problem)
    if not problems:
        print("policy ok:", ", ".join(sorted(expected)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
