#!/usr/bin/env python3
"""Checks a generated CCE policy against the release template and the engine pin.

usage: check-policy.py POLICY.rego TEMPLATE.json ENGINE.sha256
       check-policy.py --self-test

The policy engine allows an environment variable when any rule of its container matches the text NAME=VALUE, and a
regular-expression rule is a search, not a full match. So this checker does not read the rules, it asks the question the
engine asks: for the texts a deployer could try, is the text allowed? It fails unless

- every regular-expression environment rule of every container is anchored at both ends (anchor-policy.py does that);
- each ENCLAVE_* variable of the template is allowed with exactly its value and with nothing else: not another value, not
  its value followed by text that would satisfy another rule (the platform's, or the memory rule's);
- ENCLAVE_MEMORY_GB is allowed with the whole numbers 1 to 32 and no other text, and no other variable is allowed by its
  rule (X=ENCLAVE_MEMORY_GB=4, ENCLAVE_API_URL=<value>?ENCLAVE_MEMORY_GB=4, LD_PRELOAD=/a:ENCLAVE_MEMORY_GB=4);
- the workload allows no exec and no stdio, and the engine pin in its environment is the hash of the engine library.
"""
import json
import re
import sys

from policy_patterns import anchored, is_anchored

WORKLOAD = "enclave-workload"
MEMORY = "ENCLAVE_MEMORY_GB"
MEMORY_PATTERN = "^(?:ENCLAVE_MEMORY_GB=([1-9]|[12][0-9]|3[0-2]))$"
# The environment variables the platform sets, as confcom writes them: the text each rule is built from
PLATFORM_VARIABLES = [
    "HOSTNAME", "TMP", "TEMP", "FABRIC_X", "FabricPackageFileName", "HostedServiceName", "IDENTITY_API_VERSION",
    "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT", "azurecontainerinstance_restarted_by",
]
# What a deployer could append to a value to satisfy a rule that is not the variable's own
SUFFIXES = [f"?{name}=1" for name in PLATFORM_VARIABLES] + [f"?{MEMORY}=4", f":{MEMORY}=4", f"\n{MEMORY}=4"]


def containers(rego: str) -> list:
    for line in rego.splitlines():
        if line.startswith("containers := "):
            return json.loads(line[len("containers := "):])
    raise SystemExit("the policy has no containers line")


def matches(rule: dict, text: str) -> bool:
    """One environment rule against one text, as the engine does it: exact for a string, a search for a pattern, with
    RE2's meaning of . (not a newline) and $ (the end of the text)."""
    if rule["strategy"] == "string":
        return rule["pattern"] == text
    pattern, flags = rule["pattern"], 0
    if pattern.startswith("^(?i)"):
        pattern, flags = "^" + pattern[len("^(?i)"):], flags | re.IGNORECASE
    if pattern.endswith("$"):
        pattern = pattern[:-1] + r"\Z"
    return re.search(pattern, text, flags) is not None


def allowed(rules: list, text: str) -> bool:
    return any(matches(rule, text) for rule in rules)


def check_rules(rules: list, expected: dict) -> list:
    """The problems an environment rule list has, given the template's ENCLAVE_* variables."""
    problems = []
    for rule in rules:
        if rule["strategy"] not in ("string", "re2"):
            problems.append(f"an environment rule with strategy {rule['strategy']}")
        if rule["strategy"] == "re2" and not is_anchored(rule["pattern"]):
            problems.append(f"a regular expression rule that is not wrapped and anchored as ^(?:...)$: {rule['pattern']}")
    for name, value in expected.items():
        if name == MEMORY:
            continue
        if not allowed(rules, f"{name}={value}"):
            problems.append(f"{name} is not allowed with the template's value")
        for text in [f"{name}=evil", f"{name}=", f"X{name}={value}"] + [f"{name}={value}{s}" for s in SUFFIXES]:
            if allowed(rules, text):
                problems.append(f"{name} is allowed with another text: {text!r}")
    for number in range(1, 33):
        if not allowed(rules, f"{MEMORY}={number}"):
            problems.append(f"{MEMORY}={number} is not allowed")
    attacks = ["0", "33", "45", "4x", "04", "100", "", " 4", "4 ", "4\n", "-1", "1,2"]
    for text in [f"{MEMORY}={v}" for v in attacks] + [
        f"X={MEMORY}=4",
        f"LD_PRELOAD=/a:{MEMORY}=4",
        f"{MEMORY}=4\nLD_PRELOAD=/a",
    ] + [f"{name}={value}?{MEMORY}=4" for name, value in expected.items() if name != MEMORY]:
        if allowed(rules, text):
            problems.append(f"an environment text that is allowed and must not be: {text!r}")
    for name in PLATFORM_VARIABLES:
        for text in [f"LD_PRELOAD=/a:{name}=1", f"ENCLAVE_NEW=1?{name}=1"]:
            if allowed(rules, text):
                problems.append(f"an environment text that is allowed and must not be: {text!r}")
    return problems


def self_test() -> int:
    platform = [
        {"pattern": "HOSTNAME=.+", "strategy": "re2"},
        {"pattern": "T(E)?MP=.+", "strategy": "re2"},
        {"pattern": "(?i)(FABRIC)_.+=.+", "strategy": "re2"},
        {"pattern": "FabricPackageFileName=.+", "strategy": "re2"},
        {"pattern": "HostedServiceName=.+", "strategy": "re2"},
        {"pattern": "IDENTITY_API_VERSION=.+", "strategy": "re2"},
        {"pattern": "IDENTITY_HEADER=.+", "strategy": "re2"},
        {"pattern": "IDENTITY_SERVER_THUMBPRINT=.+", "strategy": "re2"},
        {"pattern": "azurecontainerinstance_restarted_by=.+", "strategy": "re2"},
    ]
    exact = [{"pattern": "ENCLAVE_API_URL=https://a.example/f", "strategy": "string"}]
    memory = [{"pattern": "ENCLAVE_MEMORY_GB=([1-9]|[12][0-9]|3[0-2])", "strategy": "re2"}]
    expected = {"ENCLAVE_API_URL": "https://a.example/f", MEMORY: "4"}

    def anchor(rules):
        return [{**r, "pattern": anchored(r["pattern"])} if r["strategy"] == "re2" else r for r in rules]

    failures = []
    unanchored = check_rules(platform + exact + memory, expected)
    if not any("not wrapped" in p for p in unanchored) or not any("allowed with another text" in p for p in unanchored):
        failures.append("the checker does not see the hole in unanchored rules")
    good = check_rules(anchor(platform + memory) + exact, expected)
    if good:
        failures.append(f"the checker refuses anchored rules: {good[:3]}")
    legit = ["HOSTNAME=abc", "TMP=/tmp", "TEMP=/tmp", "FABRIC_NODE=1", "fabric_node=1", "Fabric_Node=a=b", "IDENTITY_HEADER=x"]
    wrong = [t for t in legit if not allowed(anchor(platform), t)]
    if wrong:
        failures.append(f"anchored platform rules refuse legitimate values: {wrong}")
    print("policy checker self-test:", "ok" if not failures else failures)
    return 1 if failures else 0


def main(policy_path: str, template_path: str, engine_path: str) -> int:
    problems = []
    all_containers = containers(open(policy_path).read())
    workload = next((c for c in all_containers if c["name"] == WORKLOAD), None)
    if workload is None:
        raise SystemExit(f"the policy has no container named {WORKLOAD}")
    template = json.load(open(template_path))
    declared = next(
        c["properties"]["environmentVariables"]
        for c in template["resources"][0]["properties"]["containers"]
        if c["name"] == WORKLOAD
    )
    expected = {e["name"]: e["value"] for e in declared}

    for container in all_containers:
        for rule in container["env_rules"]:
            if rule["strategy"] == "re2" and not is_anchored(rule["pattern"]):
                problems.append(f"{container['name']}: a regular expression rule that is not wrapped and anchored: {rule['pattern']}")
    if workload["exec_processes"]:
        problems.append("the workload allows exec")
    if workload["allow_stdio_access"]:
        problems.append("the workload allows stdio")
    problems += check_rules(workload["env_rules"], expected)
    if not any(r["pattern"] == MEMORY_PATTERN and r["strategy"] == "re2" for r in workload["env_rules"]):
        problems.append(f"the memory rule is not exactly {MEMORY_PATTERN}")
    if [n for n in expected if n.startswith("ENCLAVE_")] != [n for n in expected]:
        problems.append("the template has an environment variable that is not ENCLAVE_*")

    pin = open(engine_path).read().split()[0]
    if expected.get("ENCLAVE_ENGINE_SHA256") != "0x" + pin:
        problems.append("ENCLAVE_ENGINE_SHA256 is not the hash of the engine library in the image")
    if not re.fullmatch(r"0x[0-9a-f]{64}", expected.get("ENCLAVE_ENGINE_SHA256", "")):
        problems.append("ENCLAVE_ENGINE_SHA256 is not 0x and 64 lower-case hex digits")

    for problem in dict.fromkeys(problems):
        print("policy problem:", problem)
    if not problems:
        print("policy ok:", ", ".join(sorted(expected)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main(*sys.argv[1:4]))
