"""Exit codes and error types for Package Autopsy."""

from __future__ import annotations

from typing import Any

EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_USAGE = 2
EXIT_INVALID = 3
EXIT_INTEGRITY = 4
EXIT_POLICY = 5
EXIT_UNSUPPORTED = 6
EXIT_RESOURCE = 7
EXIT_PARTIAL = 8
EXIT_INCOMPLETE = 9


class PackageAutopsyError(Exception):
    """Base error that maps to a process exit code."""

    exit_code = EXIT_GENERAL
    kind = "error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.kind, "message": self.message}


class UsageError(PackageAutopsyError):
    exit_code = EXIT_USAGE
    kind = "usage"


class UsageExit(SystemExit):
    """Raised instead of ``sys.exit`` from argparse."""


class InvalidDistributionError(PackageAutopsyError):
    exit_code = EXIT_INVALID
    kind = "invalid_distribution"


class IntegrityError(PackageAutopsyError):
    exit_code = EXIT_INTEGRITY
    kind = "integrity"


class PolicyError(PackageAutopsyError):
    exit_code = EXIT_POLICY
    kind = "policy"


class UnsupportedError(PackageAutopsyError):
    exit_code = EXIT_UNSUPPORTED
    kind = "unsupported"


class ResourceLimitError(PackageAutopsyError):
    exit_code = EXIT_RESOURCE
    kind = "resource"


class IncompleteError(PackageAutopsyError):
    exit_code = EXIT_INCOMPLETE
    kind = "incomplete"
