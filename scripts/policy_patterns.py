"""Anchoring regular-expression environment rules of a CCE policy.

The policy engine allows an environment variable when any rule matches its NAME=VALUE text, and a regular-expression rule
is a search, not a full match. A rule is only as tight as its anchors, and anchors written around the outside of the text
anchor only the first and last alternative of a top-level alternation ("A=.+|B=.+" as "^A=.+|B=.+$" still matches B=.+
anywhere), so a rule is anchored by wrapping it: ^(?:pattern)$, with an inline flag first: ^(?i)(?:pattern)$.
"""

FLAG = "(?i)"


def split_flags(pattern: str) -> tuple[str, str]:
    """The inline flag a pattern starts with, and the rest."""
    return (FLAG, pattern[len(FLAG):]) if pattern.startswith(FLAG) else ("", pattern)


def group_end(text: str, start: int) -> int:
    """The index of the parenthesis that closes the group opened at text[start], or -1. Escaped characters and the inside
    of a character class are skipped."""
    depth, i, in_class = 0, start, False
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if text[i + 1:i + 2] == "^":
                i += 1
            if text[i + 1:i + 2] == "]":
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def is_anchored(pattern: str) -> bool:
    """True for ^(?:...)$, an inline flag allowed after the ^, where the group is the whole pattern between the anchors."""
    if not (pattern.startswith("^") and pattern.endswith(")$")):
        return False
    flags, rest = split_flags(pattern[1:])
    return rest.startswith("(?:") and group_end(rest, 0) == len(rest) - 2


def anchored(pattern: str) -> str:
    """The pattern wrapped as ^(?:pattern)$ with an inline flag first. An anchored pattern is returned as it is."""
    if is_anchored(pattern):
        return pattern
    flags, body = split_flags(pattern)
    return f"^{flags}(?:{body})$"
