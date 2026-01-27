"""Text extraction from PDF files"""

from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import DependencyMissingError
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class TextExtractor:
    """Extract text from PDF with layout preservation"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
    
    def extract_all(self, preserve_layout: bool = True) -> str:
        """
        Extract all text from PDF
        
        Args:
            preserve_layout: Preserve layout and spacing
        
        Returns:
            Extracted text as string
        """
        logger.debug(f"Extracting text from {self.pdf_doc.num_pages} pages")
        
        if preserve_layout and pdfplumber is not None:
            return self._extract_with_pdfplumber()
        else:
            return self._extract_with_pikepdf()
    
    def extract_page(self, page_num: int, preserve_layout: bool = True) -> str:
        """
        Extract text from specific page
        
        Args:
            page_num: Page number (0-indexed)
            preserve_layout: Preserve layout and spacing
        
        Returns:
            Extracted text from page
        """
        if page_num < 0 or page_num >= self.pdf_doc.num_pages:
            raise ValueError(f"Invalid page number: {page_num} (PDF has {self.pdf_doc.num_pages} pages)")
        
        if preserve_layout and pdfplumber is not None:
            return self._extract_page_with_pdfplumber(page_num)
        else:
            return self._extract_page_with_pikepdf(page_num)
    
    def extract_with_positions(self, page_num: int) -> List[Dict[str, Any]]:
        """
        Extract text with position information
        
        Args:
            page_num: Page number (0-indexed)
        
        Returns:
            List of text elements with positions
        """
        if pdfplumber is None:
            raise DependencyMissingError(
                dependency="pdfplumber",
                install_hint="Install with: pip install pdfplumber"
            )
        
        if page_num < 0 or page_num >= self.pdf_doc.num_pages:
            raise ValueError(f"Invalid page number: {page_num}")
        
        with pdfplumber.open(self.pdf_doc.path) as pdf:
            page = pdf.pages[page_num]
            chars = page.chars
            
            elements = []
            for char in chars:
                elements.append({
                    'text': char.get('text', ''),
                    'x0': char.get('x0', 0),
                    'y0': char.get('y0', 0),
                    'x1': char.get('x1', 0),
                    'y1': char.get('y1', 0),
                    'width': char.get('width', 0),
                    'height': char.get('height', 0),
                    'fontname': char.get('fontname', ''),
                    'size': char.get('size', 0),
                })
            
            logger.debug(f"Extracted {len(elements)} text elements from page {page_num}")
            return elements
    
    def _extract_with_pdfplumber(self) -> str:
        """Extract text using pdfplumber (better layout preservation)"""
        with pdfplumber.open(self.pdf_doc.path) as pdf:
            text_parts = []
            for i, page in enumerate(pdf.pages):
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(f"--- Page {i + 1} ---\n{page_text}")
            
            return "\n\n".join(text_parts)
    
    def _extract_page_with_pdfplumber(self, page_num: int) -> str:
        """Extract single page text using pdfplumber"""
        with pdfplumber.open(self.pdf_doc.path) as pdf:
            page = pdf.pages[page_num]
            return page.extract_text() or ""
    
    def _extract_with_pikepdf(self) -> str:
        """Extract text using pikepdf (basic extraction)"""
        text_parts = []
        
        for i, page in enumerate(self.pdf_doc.get_pages()):
            page_text = self._extract_page_text_pikepdf(page)
            if page_text:
                text_parts.append(f"--- Page {i + 1} ---\n{page_text}")
        
        return "\n\n".join(text_parts)
    
    def _extract_page_with_pikepdf(self, page_num: int) -> str:
        """Extract single page text using pikepdf"""
        page = self.pdf_doc.get_page(page_num)
        return self._extract_page_text_pikepdf(page)
    
    def _extract_page_text_pikepdf(self, page) -> str:
        """Extract text from a pikepdf page object"""
        try:
            if hasattr(page, 'Contents'):
                contents = page.Contents
                if contents is None:
                    return ""
                
                if isinstance(contents, list):
                    stream_data = b""
                    for content in contents:
                        try:
                            stream_data += bytes(content.read_bytes())
                        except Exception:
                            pass
                else:
                    try:
                        stream_data = bytes(contents.read_bytes())
                    except Exception:
                        return ""
                
                text = self._extract_text_from_stream(stream_data)
                return text
        except Exception as e:
            logger.debug(f"Failed to extract text from page: {e}")
        
        return ""
    
    def _extract_text_from_stream(self, stream_data: bytes) -> str:
        """Extract text operators from content stream"""
        text_parts = []
        
        try:
            content = stream_data.decode('latin-1')
            
            in_text_block = False
            for line in content.split('\n'):
                line = line.strip()
                
                if line == 'BT':
                    in_text_block = True
                elif line == 'ET':
                    in_text_block = False
                elif in_text_block:
                    if line.endswith(' Tj') or line.endswith(' TJ'):
                        text = line.split(' ')[0]
                        if text.startswith('(') and text.endswith(')'):
                            text = text[1:-1]
                            text_parts.append(text)
        except Exception as e:
            logger.debug(f"Failed to parse stream: {e}")
        
        return ' '.join(text_parts)


def extract_text(
    input_pdf: Path,
    output_file: Optional[Path] = None,
    page_num: Optional[int] = None,
    preserve_layout: bool = True,
    password: Optional[str] = None,
) -> str:
    """
    Extract text from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_file: Optional output file path
        page_num: Optional specific page number (0-indexed), None for all pages
        preserve_layout: Preserve layout and spacing
        password: Optional password for encrypted PDFs
    
    Returns:
        Extracted text
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = TextExtractor(pdf_doc)
        
        if page_num is not None:
            text = extractor.extract_page(page_num, preserve_layout=preserve_layout)
        else:
            text = extractor.extract_all(preserve_layout=preserve_layout)
        
        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(text, encoding='utf-8')
            logger.info(f"Text saved to: {output_file}")
        
        return text
