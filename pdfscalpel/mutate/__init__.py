"""Mutate module - PDF modification operations"""

from pdfscalpel.mutate.watermark import (
    WatermarkRemover,
    WatermarkAdder,
    RemovalMethod,
    RemovalResult,
)
from pdfscalpel.mutate.encryption import (
    PDFEncryptor,
    PDFDecryptor,
    EncryptionLevel,
    encrypt_pdf,
    decrypt_pdf,
)
from pdfscalpel.mutate.pages import (
    merge_pdfs,
    extract_pages,
    reorder_pages,
    delete_pages,
    rotate_pages,
    PageRange,
)
from pdfscalpel.mutate.bookmarks import (
    add_bookmarks,
    add_bookmarks_manual,
    remove_bookmarks,
    export_bookmarks,
    extract_headings_font_based,
    extract_headings_pattern_based,
    Bookmark,
)
from pdfscalpel.mutate.redaction import (
    redact_text_pattern,
    redact_regions,
    redact_pattern_regions,
    find_text_locations,
    list_redaction_patterns,
    RedactionRegion,
)
from pdfscalpel.mutate.optimize import (
    compress_pdf,
    remove_unused_objects,
    linearize_pdf,
    optimize_pdf,
    OptimizationResult,
)
from pdfscalpel.mutate.ocr import (
    run_ocr,
    check_ocr_dependencies,
    get_available_languages,
    OCRError,
)

__all__ = [
    'WatermarkRemover',
    'WatermarkAdder',
    'RemovalMethod',
    'RemovalResult',
    'PDFEncryptor',
    'PDFDecryptor',
    'EncryptionLevel',
    'encrypt_pdf',
    'decrypt_pdf',
    'merge_pdfs',
    'extract_pages',
    'reorder_pages',
    'delete_pages',
    'rotate_pages',
    'PageRange',
    'add_bookmarks',
    'add_bookmarks_manual',
    'remove_bookmarks',
    'export_bookmarks',
    'extract_headings_font_based',
    'extract_headings_pattern_based',
    'Bookmark',
    'redact_text_pattern',
    'redact_regions',
    'redact_pattern_regions',
    'find_text_locations',
    'list_redaction_patterns',
    'RedactionRegion',
    'compress_pdf',
    'remove_unused_objects',
    'linearize_pdf',
    'optimize_pdf',
    'OptimizationResult',
    'run_ocr',
    'check_ocr_dependencies',
    'get_available_languages',
    'OCRError',
]
