"""Identity failures. Messages are fixed and safe to return to clients."""


class IdentityError(Exception):
    """Base error. Callers must treat every subclass as not authorized."""


class AuthenticationRequired(IdentityError):
    """No usable credential was presented."""


class PermissionDenied(IdentityError):
    """The authenticated principal may not perform the operation."""


class IdentityUnavailable(IdentityError):
    """The identity store failed. This is not an allow."""


class IdentityStoreError(IdentityUnavailable):
    """Persistence failed. Callers must not convert this into access."""


class IdentityConfigurationError(IdentityError):
    """Authentication is misconfigured and must fail closed."""


class ProvisioningClosed(IdentityError):
    """Initial administrator provisioning is no longer available."""


class IdentityConflict(IdentityError):
    """The write duplicates an existing identity record."""


class IdentityRejected(IdentityError):
    """The submitted identity fields were rejected."""


class IdentityReferenceError(IdentityError):
    """The subject or application referenced by the write does not exist."""
