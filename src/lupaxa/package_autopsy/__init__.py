"""lupaxa.package_autopsy — inspect Python wheels and source distributions.

The product is the ``package-autopsy`` console script. ``lupaxa`` is a
namespace package — there is no ``lupaxa/__init__.py``.
"""

from __future__ import annotations

from .version import __version__, get_version

__all__ = [
    "__version__",
    "get_version",
]
