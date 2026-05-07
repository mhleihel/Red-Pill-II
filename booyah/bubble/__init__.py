"""Bubble Analysis — Red-Pill semantic XSS analysis engine."""
from importlib.metadata import version, PackageNotFoundError
try:
    __version__ = version("booyah")
except PackageNotFoundError:
    __version__ = "0.0.0"
