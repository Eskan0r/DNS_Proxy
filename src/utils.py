"""Shared helpers for DNS names."""


def normalize_domain(raw: str) -> str:
    """Lowercase and remove surrounding whitespace and trailing dots."""
    return raw.strip().lower().rstrip(".")


def is_subdomain(candidate: str, parent: str) -> bool:
    """Match exact names and child labels, without matching partial labels."""
    candidate, parent = normalize_domain(candidate), normalize_domain(parent)
    return bool(candidate and parent) and (
        candidate == parent or candidate.endswith("." + parent)
    )


def split_labels(domain: str) -> list[str]:
    """Return normalized labels; the DNS root has no labels."""
    name = normalize_domain(domain)
    return name.split(".") if name else []
