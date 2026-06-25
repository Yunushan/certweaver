class CertWeaverError(Exception):
    """Base error for user-facing CertWeaver failures."""


class ConfigurationError(CertWeaverError):
    """Raised when a deployment configuration is invalid."""
