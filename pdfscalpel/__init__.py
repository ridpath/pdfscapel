"""
PDFScalpel - Forensic-grade PDF analysis and CTF toolkit
"""

__version__ = "0.1.0"
__author__ = "PDFScalpel Contributors"

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import (
    PDFScalpelError,
    PDFOpenError,
    PDFEncryptedError,
    PDFCorruptedError,
    PDFNotFoundError,
    DependencyMissingError,
)

__all__ = [
    "PDFDocument",
    "PDFScalpelError",
    "PDFOpenError",
    "PDFEncryptedError",
    "PDFCorruptedError",
    "PDFNotFoundError",
    "DependencyMissingError",
]
