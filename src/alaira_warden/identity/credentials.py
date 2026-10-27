"""Opaque API credentials. The plaintext exists only in the issuance return value."""

import hashlib
import hmac
import re
import secrets

from alaira_warden.identity.errors import AuthenticationRequired, IdentityConfigurationError

TOKEN_PREFIX = "wdn_"
_TOKEN_RE = re.compile(r"^wdn_[A-Za-z0-9_-]{43}$")
_MIN_PEPPER_BYTES = 16


def generate_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def is_well_formed(token: str) -> bool:
    return bool(_TOKEN_RE.fullmatch(token))


def require_pepper(pepper: bytes) -> bytes:
    if not isinstance(pepper, bytes) or len(pepper) < _MIN_PEPPER_BYTES:
        raise IdentityConfigurationError("Credential pepper is not configured.")
    return pepper


def credential_digest(token: str, pepper: bytes) -> str:
    """HMAC-SHA256 hex digest. Equal length inputs use compare_digest at lookup."""
    require_pepper(pepper)
    if not is_well_formed(token):
        raise AuthenticationRequired("Authentication required.")
    return hmac.new(pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()


def digests_match(stored: str, computed: str) -> bool:
    try:
        return hmac.compare_digest(stored, computed)
    except Exception:
        return False
