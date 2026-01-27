"""PDF page manipulation operations"""

from pathlib import Path
from typing import List, Optional, Union, Tuple
import re

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import (
    PDFScalpelError,
    DependencyMissingError,
)
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class PageRange:
    """Parse and represent page ranges like '1-5,7,9-12'"""
    
    def __init__(self, range_str: str):
        self.range_str = range_str
        self.pages = self._parse(range_str)
    
    def _parse(self, range_str: str) -> List[int]:
        """Parse page range string into list of 0-indexed page numbers"""
        pages = set()
        
        for part in range_str.split(','):
            part = part.strip()
            if '-' in part:
                start_str, end_str = part.split('-', 1)
                start = int(start_str.strip())
                end = int(end_str.strip())
                pages.update(range(start - 1, end))
            else:
                pages.add(int(part) - 1)
        
        return sorted(pages)
    
    def filter_valid(self, total_pages: int) -> List[int]:
        """Filter out invalid page numbers"""
        return [p for p in self.pages if 0 <= p < total_pages]


def merge_pdfs(
    pdf_paths: List[Path],
    output_path: Path,
    preserve_bookmarks: bool = True,
) -> Path:
    """
    Merge multiple PDFs into one
    
    Args:
        pdf_paths: List of PDF files to merge
        output_path: Output PDF path
        preserve_bookmarks: Keep bookmarks from source PDFs
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If merge fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    if not pdf_paths:
        raise PDFScalpelError("No PDFs provided to merge")
    
    logger.info(f"Merging {len(pdf_paths)} PDFs into {output_path}")
    
    try:
        merged_pdf = pikepdf.Pdf.new()
        total_pages = 0
        
        for pdf_path in pdf_paths:
            logger.debug(f"Adding PDF: {pdf_path}")
            with pikepdf.Pdf.open(pdf_path) as src:
                num_pages = len(src.pages)
                
                if preserve_bookmarks and hasattr(src, 'open_outline'):
                    try:
                        with src.open_outline() as src_outline:
                            if src_outline.root:
                                with merged_pdf.open_outline() as dest_outline:
                                    for item in src_outline.root:
                                        dest_item = pikepdf.OutlineItem(
                                            item.title,
                                            destination=item.destination + total_pages if hasattr(item, 'destination') else total_pages
                                        )
                                        dest_outline.root.append(dest_item)
                    except Exception as e:
                        logger.warning(f"Could not preserve bookmarks from {pdf_path}: {e}")
                
                merged_pdf.pages.extend(src.pages)
                total_pages += num_pages
        
        merged_pdf.save(output_path)
        merged_pdf.close()
        
        logger.info(f"Successfully merged {len(pdf_paths)} PDFs ({total_pages} total pages)")
        return output_path
    
    except Exception as e:
        raise PDFScalpelError(f"Failed to merge PDFs: {e}") from e


def extract_pages(
    input_path: Path,
    output_path: Path,
    page_ranges: Union[str, List[int]],
) -> Path:
    """
    Extract specific pages from a PDF
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        page_ranges: Either "1-5,7,9-12" string or list of 0-indexed page numbers
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If extraction fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Extracting pages from {input_path}")
    
    try:
        with pikepdf.Pdf.open(input_path) as pdf:
            total_pages = len(pdf.pages)
            
            if isinstance(page_ranges, str):
                page_range = PageRange(page_ranges)
                pages_to_extract = page_range.filter_valid(total_pages)
            else:
                pages_to_extract = [p for p in page_ranges if 0 <= p < total_pages]
            
            if not pages_to_extract:
                raise PDFScalpelError("No valid pages to extract")
            
            logger.debug(f"Extracting {len(pages_to_extract)} pages: {pages_to_extract}")
            
            new_pdf = pikepdf.Pdf.new()
            for page_idx in pages_to_extract:
                new_pdf.pages.append(pdf.pages[page_idx])
            
            new_pdf.save(output_path)
            new_pdf.close()
        
        logger.info(f"Successfully extracted {len(pages_to_extract)} pages to {output_path}")
        return output_path
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to extract pages: {e}") from e


def reorder_pages(
    input_path: Path,
    output_path: Path,
    new_order: List[int],
) -> Path:
    """
    Reorder pages in a PDF
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        new_order: List of 0-indexed page numbers in desired order
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If reordering fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Reordering pages in {input_path}")
    
    try:
        with pikepdf.Pdf.open(input_path) as pdf:
            total_pages = len(pdf.pages)
            
            if len(new_order) != total_pages:
                raise PDFScalpelError(
                    f"New order must contain all pages. Expected {total_pages}, got {len(new_order)}"
                )
            
            if set(new_order) != set(range(total_pages)):
                raise PDFScalpelError("New order must contain each page exactly once")
            
            new_pdf = pikepdf.Pdf.new()
            for page_idx in new_order:
                new_pdf.pages.append(pdf.pages[page_idx])
            
            new_pdf.save(output_path)
            new_pdf.close()
        
        logger.info(f"Successfully reordered pages to {output_path}")
        return output_path
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to reorder pages: {e}") from e


def delete_pages(
    input_path: Path,
    output_path: Path,
    pages_to_delete: Union[str, List[int]],
) -> Path:
    """
    Delete specific pages from a PDF
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        pages_to_delete: Either "1-5,7,9-12" string or list of 0-indexed page numbers
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If deletion fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Deleting pages from {input_path}")
    
    try:
        with pikepdf.Pdf.open(input_path) as pdf:
            total_pages = len(pdf.pages)
            
            if isinstance(pages_to_delete, str):
                page_range = PageRange(pages_to_delete)
                delete_set = set(page_range.filter_valid(total_pages))
            else:
                delete_set = set(p for p in pages_to_delete if 0 <= p < total_pages)
            
            if not delete_set:
                raise PDFScalpelError("No valid pages to delete")
            
            if len(delete_set) >= total_pages:
                raise PDFScalpelError("Cannot delete all pages from PDF")
            
            logger.debug(f"Deleting {len(delete_set)} pages")
            
            new_pdf = pikepdf.Pdf.new()
            for idx in range(total_pages):
                if idx not in delete_set:
                    new_pdf.pages.append(pdf.pages[idx])
            
            new_pdf.save(output_path)
            new_pdf.close()
        
        logger.info(f"Successfully deleted {len(delete_set)} pages, saved to {output_path}")
        return output_path
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to delete pages: {e}") from e


def rotate_pages(
    input_path: Path,
    output_path: Path,
    rotation: int,
    page_ranges: Optional[Union[str, List[int]]] = None,
) -> Path:
    """
    Rotate pages in a PDF
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        rotation: Rotation angle (90, 180, 270, or -90, -180, -270)
        page_ranges: Pages to rotate (all if None)
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If rotation fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    if rotation not in [90, 180, 270, -90, -180, -270]:
        raise PDFScalpelError("Rotation must be 90, 180, 270, or negative equivalents")
    
    rotation = rotation % 360
    
    logger.info(f"Rotating pages in {input_path} by {rotation} degrees")
    
    try:
        with pikepdf.Pdf.open(input_path) as pdf:
            total_pages = len(pdf.pages)
            
            if page_ranges is None:
                pages_to_rotate = set(range(total_pages))
            elif isinstance(page_ranges, str):
                page_range = PageRange(page_ranges)
                pages_to_rotate = set(page_range.filter_valid(total_pages))
            else:
                pages_to_rotate = set(p for p in page_ranges if 0 <= p < total_pages)
            
            if not pages_to_rotate:
                raise PDFScalpelError("No valid pages to rotate")
            
            logger.debug(f"Rotating {len(pages_to_rotate)} pages")
            
            for idx in pages_to_rotate:
                page = pdf.pages[idx]
                current_rotation = int(page.get('/Rotate', 0))
                new_rotation = (current_rotation + rotation) % 360
                page.Rotate = new_rotation
            
            pdf.save(output_path)
        
        logger.info(f"Successfully rotated pages, saved to {output_path}")
        return output_path
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to rotate pages: {e}") from e
