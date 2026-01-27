"""PDF bookmark operations"""

from pathlib import Path
from typing import List, Optional, Dict, Any
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


DEFAULT_HEADING_PATTERNS = [
    r'^#+\s+(.+)$',
    r'^([A-Z][A-Z\s]{3,})$',
    r'^\d+\.\s+([A-Z].+)$',
    r'^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4})$',
]


class Bookmark:
    """Represents a PDF bookmark"""
    
    def __init__(self, title: str, page: int, level: int = 0):
        self.title = title
        self.page = page
        self.level = level
    
    def __repr__(self):
        return f"Bookmark(title='{self.title}', page={self.page}, level={self.level})"


def extract_headings_font_based(
    pdf_path: Path,
    patterns: Optional[List[str]] = None,
    min_font_size: float = 12.0,
    min_length: int = 3,
    max_length: int = 60,
) -> List[Dict[str, Any]]:
    """
    Extract headings from PDF using font analysis
    
    Args:
        pdf_path: Path to PDF
        patterns: Regex patterns to match headings
        min_font_size: Minimum font size for headings
        min_length: Minimum heading text length
        max_length: Maximum heading text length
    
    Returns:
        List of heading dictionaries with 'page', 'text', 'font_size', 'is_bold'
    
    Raises:
        DependencyMissingError: If pdfplumber is not installed
    """
    if pdfplumber is None:
        raise DependencyMissingError(
            dependency="pdfplumber",
            install_hint="Install with: pip install pdfplumber"
        )
    
    if patterns is None:
        patterns = DEFAULT_HEADING_PATTERNS
    
    logger.info(f"Extracting headings from {pdf_path} using font analysis")
    
    headings = []
    
    with pdfplumber.open(pdf_path) as pdf:
        for page_num, page in enumerate(pdf.pages):
            words = page.extract_words(keep_blank_chars=True)
            if not words:
                continue
            
            lines = {}
            for word in words:
                y = word['bottom']
                if y not in lines:
                    lines[y] = []
                lines[y].append(word)
            
            sorted_lines = sorted(lines.items(), key=lambda x: -x[0])
            
            for y, line_words in sorted_lines:
                line_text = ' '.join(w['text'] for w in line_words).strip()
                if not line_text or len(line_text) < min_length or len(line_text) > max_length:
                    continue
                
                is_heading_by_pattern = False
                for pattern in patterns:
                    if re.match(pattern, line_text):
                        is_heading_by_pattern = True
                        break
                
                fonts = set(w.get('fontname', '') for w in line_words)
                sizes = [w.get('size', 0) for w in line_words]
                avg_size = sum(sizes) / len(sizes) if sizes else 0
                is_bold = any('bold' in f.lower() for f in fonts)
                
                if is_heading_by_pattern or is_bold or avg_size >= min_font_size:
                    headings.append({
                        'page': page_num,
                        'text': line_text,
                        'font_size': avg_size,
                        'is_bold': is_bold,
                    })
    
    logger.info(f"Found {len(headings)} potential headings")
    return headings


def extract_headings_pattern_based(
    pdf_path: Path,
    patterns: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Extract headings from PDF using pattern matching only
    
    Args:
        pdf_path: Path to PDF
        patterns: Regex patterns to match headings
    
    Returns:
        List of heading dictionaries with 'page' and 'text'
    
    Raises:
        DependencyMissingError: If pdfplumber is not installed
    """
    if pdfplumber is None:
        raise DependencyMissingError(
            dependency="pdfplumber",
            install_hint="Install with: pip install pdfplumber"
        )
    
    if patterns is None:
        patterns = DEFAULT_HEADING_PATTERNS
    
    logger.info(f"Extracting headings from {pdf_path} using pattern matching")
    
    headings = []
    
    with pdfplumber.open(pdf_path) as pdf:
        for page_num, page in enumerate(pdf.pages):
            text = page.extract_text()
            if not text:
                continue
            
            for line in text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                for pattern in patterns:
                    match = re.match(pattern, line)
                    if match:
                        heading_text = match.group(1) if match.groups() else line
                        headings.append({
                            'page': page_num,
                            'text': heading_text,
                        })
                        break
    
    logger.info(f"Found {len(headings)} headings by pattern")
    return headings


def add_bookmarks(
    input_path: Path,
    output_path: Path,
    bookmarks: Optional[List[Bookmark]] = None,
    auto_detect: bool = False,
    patterns: Optional[List[str]] = None,
    use_font_analysis: bool = True,
) -> Path:
    """
    Add bookmarks to a PDF
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        bookmarks: List of Bookmark objects (manual mode)
        auto_detect: Auto-detect headings from document
        patterns: Regex patterns for auto-detection
        use_font_analysis: Use font-based detection (more accurate)
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If operation fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Adding bookmarks to {input_path}")
    
    try:
        if auto_detect:
            if use_font_analysis:
                headings = extract_headings_font_based(input_path, patterns)
            else:
                headings = extract_headings_pattern_based(input_path, patterns)
            
            if not headings:
                logger.warning("No headings found, creating page-based bookmarks")
                with pikepdf.Pdf.open(input_path) as pdf:
                    total_pages = len(pdf.pages)
                    headings = [
                        {'page': i, 'text': f'Page {i+1}'}
                        for i in range(0, total_pages, 10)
                    ]
            
            bookmarks = [
                Bookmark(title=h['text'], page=h['page'])
                for h in headings
            ]
        
        if not bookmarks:
            raise PDFScalpelError("No bookmarks provided and auto-detect disabled")
        
        with pikepdf.Pdf.open(input_path) as pdf:
            with pdf.open_outline() as outline:
                for bookmark in bookmarks:
                    outline.root.append(
                        pikepdf.OutlineItem(
                            bookmark.title,
                            destination=bookmark.page
                        )
                    )
            
            pdf.save(output_path)
        
        logger.info(f"Successfully added {len(bookmarks)} bookmarks to {output_path}")
        return output_path
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to add bookmarks: {e}") from e


def add_bookmarks_manual(
    input_path: Path,
    output_path: Path,
    bookmark_list: List[Dict[str, Any]],
) -> Path:
    """
    Add bookmarks from a list of dictionaries
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        bookmark_list: List of dicts with 'title', 'page', optional 'level'
    
    Returns:
        Path to output PDF
    """
    bookmarks = [
        Bookmark(
            title=b['title'],
            page=b['page'],
            level=b.get('level', 0)
        )
        for b in bookmark_list
    ]
    
    return add_bookmarks(
        input_path=input_path,
        output_path=output_path,
        bookmarks=bookmarks,
        auto_detect=False,
    )


def remove_bookmarks(
    input_path: Path,
    output_path: Path,
) -> Path:
    """
    Remove all bookmarks from a PDF
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If operation fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Removing bookmarks from {input_path}")
    
    try:
        with pikepdf.Pdf.open(input_path) as pdf:
            if '/Outlines' in pdf.Root:
                del pdf.Root.Outlines
            
            pdf.save(output_path)
        
        logger.info(f"Successfully removed bookmarks from {output_path}")
        return output_path
    
    except Exception as e:
        raise PDFScalpelError(f"Failed to remove bookmarks: {e}") from e


def export_bookmarks(
    input_path: Path,
) -> List[Dict[str, Any]]:
    """
    Export bookmarks from a PDF
    
    Args:
        input_path: Input PDF path
    
    Returns:
        List of bookmark dictionaries
    
    Raises:
        PDFScalpelError: If operation fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Exporting bookmarks from {input_path}")
    
    try:
        bookmarks = []
        
        with pikepdf.Pdf.open(input_path) as pdf:
            if hasattr(pdf, 'open_outline'):
                with pdf.open_outline() as outline:
                    if outline.root:
                        for item in outline.root:
                            bookmarks.append({
                                'title': str(item.title),
                                'page': int(item.destination) if hasattr(item, 'destination') else 0,
                            })
        
        logger.info(f"Exported {len(bookmarks)} bookmarks")
        return bookmarks
    
    except Exception as e:
        raise PDFScalpelError(f"Failed to export bookmarks: {e}") from e
