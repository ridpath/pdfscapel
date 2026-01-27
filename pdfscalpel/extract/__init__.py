"""PDF extraction modules"""

from pdfscalpel.extract.text import extract_text, TextExtractor
from pdfscalpel.extract.images import extract_images, ImageExtractor
from pdfscalpel.extract.objects import (
    list_objects,
    dump_object,
    dump_objects_by_type,
    ObjectExtractor,
)
from pdfscalpel.extract.streams import extract_streams, StreamExtractor
from pdfscalpel.extract.javascript import extract_javascript, JavaScriptExtractor
from pdfscalpel.extract.attachments import extract_attachments, AttachmentExtractor
from pdfscalpel.extract.hidden import extract_hidden_data, HiddenDataExtractor
from pdfscalpel.extract.forms import extract_forms, FormsExtractor
from pdfscalpel.extract.revisions import extract_revisions, RevisionExtractor, RevisionInfo
from pdfscalpel.extract.web import (
    WebExtractionConfig,
    WebPageExtractor,
    parse_page_range,
    build_url,
)

__all__ = [
    'extract_text',
    'TextExtractor',
    'extract_images',
    'ImageExtractor',
    'list_objects',
    'dump_object',
    'dump_objects_by_type',
    'ObjectExtractor',
    'extract_streams',
    'StreamExtractor',
    'extract_javascript',
    'JavaScriptExtractor',
    'extract_attachments',
    'AttachmentExtractor',
    'extract_hidden_data',
    'HiddenDataExtractor',
    'extract_forms',
    'FormsExtractor',
    'extract_revisions',
    'RevisionExtractor',
    'RevisionInfo',
    'WebExtractionConfig',
    'WebPageExtractor',
    'parse_page_range',
    'build_url',
]
