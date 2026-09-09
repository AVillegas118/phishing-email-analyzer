"""Herramientas para analizar señales sencillas en correos .eml."""

from .analyzer import analyze_bytes, analyze_file
from .models import AnalysisReport, EmailMetadata, Finding

__all__ = [
    "AnalysisReport",
    "EmailMetadata",
    "Finding",
    "analyze_bytes",
    "analyze_file",
]

__version__ = "0.1.0"

