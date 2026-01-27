"""PDF redaction operations"""

from pathlib import Path
from typing import List, Optional, Tuple, Pattern, Dict
import re

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import (
    PDFScalpelError,
    DependencyMissingError,
)
from pdfscalpel.core.logging import get_logger

logger = get_logger()


REDACTION_PATTERNS = {
    'ssn': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
    'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'date_iso': r'\b\d{4}-\d{2}-\d{2}\b',
    'date_us': r'\b\d{1,2}/\d{1,2}/\d{2,4}\b',
}


class RedactionRegion:
    """Represents a rectangular region to redact"""
    
    def __init__(
        self,
        page: int,
        x0: float,
        y0: float,
        x1: float,
        y1: float,
    ):
        self.page = page
        self.x0 = x0
        self.y0 = y0
        self.x1 = x1
        self.y1 = y1
    
    def __repr__(self):
        return f"RedactionRegion(page={self.page}, x0={self.x0}, y0={self.y0}, x1={self.x1}, y1={self.y1})"


def redact_text_pattern(
    input_path: Path,
    output_path: Path,
    pattern: str,
    replacement: str = "[REDACTED]",
    pattern_name: Optional[str] = None,
) -> Tuple[Path, int]:
    """
    Redact text matching a regex pattern
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        pattern: Regex pattern or predefined pattern name (ssn, phone, email, etc.)
        replacement: Replacement text
        pattern_name: Name of pattern for logging
    
    Returns:
        Tuple of (output_path, redaction_count)
    
    Raises:
        PDFScalpelError: If redaction fails
    
    Warning:
        This performs basic text stream replacement and may not work on all PDFs.
        For production redaction, use Adobe Acrobat or similar professional tools.
        This does NOT redact text in images or scanned content.
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    if pattern in REDACTION_PATTERNS:
        pattern_name = pattern_name or pattern
        pattern = REDACTION_PATTERNS[pattern]
    
    logger.info(f"Redacting text matching pattern: {pattern_name or pattern}")
    logger.warning("Basic text redaction - not secure for images or advanced PDFs")
    
    try:
        redaction_count = 0
        pattern_compiled = re.compile(pattern.encode())
        replacement_bytes = replacement.encode()
        
        with pikepdf.Pdf.open(input_path) as pdf:
            for page_num, page in enumerate(pdf.pages):
                if '/Contents' not in page:
                    continue
                
                try:
                    content = page.Contents.read_bytes()
                    
                    matches = list(pattern_compiled.finditer(content))
                    if matches:
                        for match in matches:
                            redaction_count += 1
                        
                        content = pattern_compiled.sub(replacement_bytes, content)
                        page.Contents = pdf.make_stream(content)
                        
                        logger.debug(f"Page {page_num + 1}: {len(matches)} redactions")
                
                except Exception as e:
                    logger.warning(f"Could not process page {page_num + 1}: {e}")
            
            pdf.save(output_path)
        
        logger.info(f"Redacted {redaction_count} occurrences, saved to {output_path}")
        return output_path, redaction_count
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to redact text: {e}") from e


def redact_regions(
    input_path: Path,
    output_path: Path,
    regions: List[RedactionRegion],
    redaction_color: Tuple[float, float, float] = (0, 0, 0),
) -> Path:
    """
    Redact specific rectangular regions by drawing black boxes
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        regions: List of RedactionRegion objects
        redaction_color: RGB color tuple (0-1 range)
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If redaction fails
    
    Warning:
        This adds black boxes over content but does not remove underlying text.
        For secure redaction, use professional tools.
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Redacting {len(regions)} regions from {input_path}")
    logger.warning("Region redaction adds overlay - does not remove underlying data")
    
    try:
        with pikepdf.Pdf.open(input_path) as pdf:
            for region in regions:
                if region.page < 0 or region.page >= len(pdf.pages):
                    logger.warning(f"Invalid page {region.page}, skipping region")
                    continue
                
                page = pdf.pages[region.page]
                
                r, g, b = redaction_color
                redaction_stream = f"""
                q
                {r} {g} {b} rg
                {region.x0} {region.y0} {region.x1 - region.x0} {region.y1 - region.y0} re
                f
                Q
                """.strip()
                
                if '/Contents' in page:
                    existing_content = page.Contents.read_bytes()
                    new_content = existing_content + b'\n' + redaction_stream.encode()
                    page.Contents = pdf.make_stream(new_content)
                else:
                    page.Contents = pdf.make_stream(redaction_stream.encode())
            
            pdf.save(output_path)
        
        logger.info(f"Successfully redacted {len(regions)} regions to {output_path}")
        return output_path
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to redact regions: {e}") from e


def find_text_locations(
    input_path: Path,
    pattern: str,
) -> List[Dict]:
    """
    Find locations of text matching a pattern
    
    Args:
        input_path: Input PDF path
        pattern: Regex pattern or predefined pattern name
    
    Returns:
        List of dictionaries with page, text, and bounding box information
    
    Raises:
        DependencyMissingError: If pdfplumber is not installed
    """
    if pdfplumber is None:
        raise DependencyMissingError(
            dependency="pdfplumber",
            install_hint="Install with: pip install pdfplumber"
        )
    
    if pattern in REDACTION_PATTERNS:
        pattern = REDACTION_PATTERNS[pattern]
    
    pattern_compiled = re.compile(pattern)
    
    logger.info(f"Finding text locations for pattern: {pattern}")
    
    locations = []
    
    with pdfplumber.open(input_path) as pdf:
        for page_num, page in enumerate(pdf.pages):
            text = page.extract_text()
            if not text:
                continue
            
            for match in pattern_compiled.finditer(text):
                matched_text = match.group(0)
                
                words = page.search(matched_text)
                if words:
                    for word_match in words:
                        locations.append({
                            'page': page_num,
                            'text': matched_text,
                            'x0': word_match['x0'],
                            'y0': word_match['top'],
                            'x1': word_match['x1'],
                            'y1': word_match['bottom'],
                        })
    
    logger.info(f"Found {len(locations)} text locations")
    return locations


def redact_pattern_regions(
    input_path: Path,
    output_path: Path,
    pattern: str,
    padding: float = 2.0,
) -> Tuple[Path, int]:
    """
    Find and redact all occurrences of a pattern by covering them
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        pattern: Regex pattern or predefined pattern name
        padding: Padding around text in points
    
    Returns:
        Tuple of (output_path, redaction_count)
    
    Raises:
        PDFScalpelError: If redaction fails
    """
    logger.info(f"Redacting pattern regions: {pattern}")
    
    try:
        locations = find_text_locations(input_path, pattern)
        
        if not locations:
            logger.warning("No matches found for pattern")
            with pikepdf.Pdf.open(input_path) as pdf:
                pdf.save(output_path)
            return output_path, 0
        
        regions = [
            RedactionRegion(
                page=loc['page'],
                x0=loc['x0'] - padding,
                y0=loc['y0'] - padding,
                x1=loc['x1'] + padding,
                y1=loc['y1'] + padding,
            )
            for loc in locations
        ]
        
        redact_regions(input_path, output_path, regions)
        
        return output_path, len(regions)
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to redact pattern regions: {e}") from e


def list_redaction_patterns() -> Dict[str, str]:
    """Get list of predefined redaction patterns"""
    return REDACTION_PATTERNS.copy()
