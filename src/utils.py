"""just some smaall helpers
rc, everyone can use, don't duplicate logic.
"""


def normalize_domain(raw: str) -> str:
    """Lowercase, strip trailing dot + whitespace.
    TODO: implement (1-liner). Ex: 'A.Bad.COM.' -> 'a.bad.com'
    """
    # TODO: return raw.strip().lower().rstrip(".")
    raise NotImplementedError


def is_subdomain(candidate: str, parent: str) -> bool:
    """True if candidate == parent or ends with '.'+parent.
    Ex: is_subdomain('a.bad.com','bad.com') -> True
    TODO: implement, used by Justin's blocklist checker.
    """
    raise NotImplementedError


def split_labels(domain: str) -> list[str]:
    """Split 'a.b.com' -> ['a','b','com']. Used by entropy/typo checkers."""
    # TODO: return normalize_domain(domain).split(".")
    raise NotImplementedError
