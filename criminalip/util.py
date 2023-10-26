"""util functions for criminalip.io"""
from .constants import URL_BASE


def _convert_bool(val: bool) -> str:
    """Converts bool value to string.

    Args:
        val: The value to convert.

    Returns:
        String representation of the passed value.
    """
    return str(val).lower()


def _build_full_url(path: str) -> str:
    """Builds furl URL.

    Args:
        path: Path to add to url base.

    Returns:
        Full URL to query.
    """
    return URL_BASE + path


class CriminalIPException(Exception):
    """Exception generated for errors in CriminalIP API."""


class CriminalIPServerException(CriminalIPException):
    """Exception generated for server issues."""


class CriminalIPAPIException(CriminalIPException):
    """Exception generated for API issues"""
