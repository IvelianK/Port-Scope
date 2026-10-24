"""PortScope: see what your machine and your router expose, and how to close it."""

__version__ = "2.0.2"


def clean(value: str | None, limit: int = 200) -> str:
    """Untrusted text (router replies, process names) -> printable, bounded.
    Drops C0/C1 controls, so no terminal escape sequences reach --cli output."""
    if not value:
        return ""
    return "".join(ch for ch in value if ch.isprintable()).strip()[:limit]
