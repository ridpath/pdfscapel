"""External tool integrations for PDFAutopsy"""

from pdfscalpel.integrations.ghostscript import GhostscriptIntegration
from pdfscalpel.integrations.qpdf import QPDFIntegration
from pdfscalpel.integrations.john import JohnIntegration
from pdfscalpel.integrations.hashcat import HashcatIntegration
from pdfscalpel.integrations.tesseract import TesseractIntegration

__all__ = [
    'GhostscriptIntegration',
    'QPDFIntegration',
    'JohnIntegration',
    'HashcatIntegration',
    'TesseractIntegration',
]
