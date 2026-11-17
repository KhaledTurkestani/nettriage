"""Settings read from the environment and from a ``.env`` file in the working folder."""

from __future__ import annotations

import os
from pathlib import Path

_TRUE = ("1", "true", "yes", "on")


def load_dotenv(path: Path = Path(".env")) -> None:
    """Read KEY=VALUE lines from a .env file, without overriding variables that are already set."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#") and value.strip():
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def api_key_configured() -> bool:
    """Whether a Claude API credential is available. Says nothing about the credential itself."""
    load_dotenv()
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def read_only() -> bool:
    """A read-only server shows stored captures and investigations and accepts nothing new.

    Set NETTRIAGE_READ_ONLY=1 wherever strangers can reach the page: an upload is untrusted
    input, and every investigation is billed to the server's API key.
    """
    return os.environ.get("NETTRIAGE_READ_ONLY", "").strip().lower() in _TRUE


def max_upload_bytes() -> int:
    try:
        megabytes = float(os.environ.get("NETTRIAGE_MAX_UPLOAD_MB", "200"))
    except ValueError:
        megabytes = 200.0
    return int(max(1.0, megabytes) * 1024 * 1024)


def allowed_hosts() -> list[str]:
    """Host names the server answers to. Anything else is refused, which stops DNS-rebinding pages."""
    extra = [h.strip() for h in os.environ.get("NETTRIAGE_ALLOWED_HOSTS", "").split(",") if h.strip()]
    return ["localhost", "127.0.0.1", "testserver", *extra]
