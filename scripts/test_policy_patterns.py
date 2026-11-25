"""Tests of the policy anchoring: python3 -m unittest discover -s scripts -p 'test_*.py'"""
import importlib.util
import os
import unittest

from policy_patterns import anchored, group_end, is_anchored

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("check_policy", os.path.join(HERE, "check-policy.py"))
check_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_policy)


def allowed(patterns, text):
    return check_policy.allowed([{"pattern": p, "strategy": "re2"} for p in patterns], text)


class Anchoring(unittest.TestCase):
    def test_a_plain_pattern_is_wrapped(self):
        self.assertEqual(anchored("HOSTNAME=.+"), "^(?:HOSTNAME=.+)$")

    def test_an_inline_flag_goes_first(self):
        self.assertEqual(anchored("(?i)(FABRIC)_.+=.+"), "^(?i)(?:(FABRIC)_.+=.+)$")

    def test_an_anchored_pattern_is_left_as_it_is(self):
        for pattern in ["^(?:A=.+)$", "^(?i)(?:A=.+)$", "^(?:(a)|(b))$"]:
            self.assertEqual(anchored(pattern), pattern)
            self.assertEqual(anchored(anchored(pattern)), pattern)

    def test_anchors_on_the_outside_are_wrapped_not_trusted(self):
        self.assertEqual(anchored("^A=.+$"), "^(?:^A=.+$)$")
        self.assertTrue(is_anchored(anchored("^A=.+$")))

    def test_a_top_level_alternation_is_wrapped_whole(self):
        self.assertEqual(anchored("A=.+|B=.+"), "^(?:A=.+|B=.+)$")
        self.assertEqual(anchored("^A=.+|B=.+$"), "^(?:^A=.+|B=.+$)$")

    def test_an_alternation_inside_a_group_stays_inside(self):
        self.assertEqual(anchored("A=(1|2)"), "^(?:A=(1|2))$")

    def test_escaped_parentheses_and_classes_do_not_confuse_the_group_end(self):
        for body in [r"A=\)", r"A=[)]", r"A=[^)]+", r"A=[]()]", r"A=\\", r"A=(?:x\))"]:
            wrapped = f"^(?:{body})$"
            self.assertTrue(is_anchored(wrapped), body)
            self.assertEqual(anchored(body), wrapped)

    def test_a_pattern_that_only_looks_anchored_is_not(self):
        for pattern in [
            "A=.+", "^A=.+$", "^A=.+|B=.+$", "^(?:A=.+)|(?:B=.+)$", "(?:A=.+)$", "^(?:A=.+)",
            "^(?:A=.+))$", "^(?:A=(.+)$", "(?i)^(?:A=.+)$", "",
        ]:
            self.assertFalse(is_anchored(pattern), pattern)

    def test_group_end_finds_the_matching_parenthesis(self):
        self.assertEqual(group_end("(a(b)c)d", 0), 6)
        self.assertEqual(group_end("(a", 0), -1)
        self.assertEqual(group_end(r"(a\)b)", 0), 5)


class Injection(unittest.TestCase):
    ATTACKS = ["ENCLAVE_API_URL=https://evil/?B=1", "ENCLAVE_API_URL=https://evil/?A=1", "X=A=1", "A=1\nX=1", "LD_PRELOAD=/a:B=2"]

    def test_the_old_outside_anchoring_left_a_top_level_alternation_open(self):
        old = "^A=.+|B=.+$"
        self.assertTrue(allowed([old], "ENCLAVE_API_URL=https://evil/?B=1"))

    def test_wrapping_closes_every_alternative(self):
        pattern = anchored("A=.+|B=.+")
        for text in self.ATTACKS:
            self.assertFalse(allowed([pattern], text), text)
        for text in ["A=1", "B=2", "A=x y"]:
            self.assertTrue(allowed([pattern], text), text)

    def test_a_flagged_pattern_matches_in_either_case_and_only_whole(self):
        pattern = anchored("(?i)(FABRIC)_.+=.+")
        for text in ["FABRIC_NODE=1", "fabric_node=1", "Fabric_Node=a=b"]:
            self.assertTrue(allowed([pattern], text), text)
        for text in ["ENCLAVE_API_URL=https://e/?FABRIC_X=1", "XFABRIC_X=1"]:
            self.assertFalse(allowed([pattern], text), text)

    def test_the_memory_rule_takes_1_to_32_only(self):
        rule = [check_policy.MEMORY_PATTERN]
        for n in range(1, 33):
            self.assertTrue(allowed(rule, f"ENCLAVE_MEMORY_GB={n}"), n)
        for text in ["ENCLAVE_MEMORY_GB=0", "ENCLAVE_MEMORY_GB=33", "ENCLAVE_MEMORY_GB=45", "ENCLAVE_MEMORY_GB=04",
                     "X=ENCLAVE_MEMORY_GB=4", "ENCLAVE_API_URL=https://e/?ENCLAVE_MEMORY_GB=4",
                     "LD_PRELOAD=/a:ENCLAVE_MEMORY_GB=4", "ENCLAVE_MEMORY_GB=4\nLD_PRELOAD=/a"]:
            self.assertFalse(allowed(rule, text), text)


if __name__ == "__main__":
    unittest.main()
