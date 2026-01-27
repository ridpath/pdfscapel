"""Comprehensive flag detection across all PDF layers"""

from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import re
import base64
import binascii
import hashlib

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import PDFScalpelError
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.constants import CTF_FLAG_PATTERNS

from pdfscalpel.extract.text import TextExtractor
from pdfscalpel.extract.javascript import JavaScriptExtractor
from pdfscalpel.extract.streams import StreamExtractor
from pdfscalpel.extract.hidden import HiddenDataExtractor
from pdfscalpel.extract.forms import FormsExtractor
from pdfscalpel.extract.revisions import RevisionExtractor
from pdfscalpel.analyze.metadata import PDFMetadataAnalyzer

logger = get_logger()


class FlagLocation(Enum):
    """Where a flag was found in the PDF"""
    VISIBLE_TEXT = "visible_text"
    METADATA_INFO = "metadata_info"
    METADATA_XMP = "metadata_xmp"
    JAVASCRIPT = "javascript"
    OBJECT_STREAM = "object_stream"
    COMPRESSED_STREAM = "compressed_stream"
    REVISION = "revision"
    COMMENT = "comment"
    ANNOTATION = "annotation"
    FORM_FIELD = "form_field"
    INVISIBLE_TEXT = "invisible_text"
    WHITESPACE = "whitespace"
    ZERO_WIDTH_CHARS = "zero_width_chars"
    ATTACHMENT = "attachment"
    BOOKMARK = "bookmark"
    RAW_OBJECT = "raw_object"


class FlagEncoding(Enum):
    """How a flag is encoded"""
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    HEX = "hex"
    ROT13 = "rot13"
    URL_ENCODED = "url_encoded"
    REVERSED = "reversed"
    UNICODE_ESCAPE = "unicode_escape"
    GZIP = "gzip"
    ZLIB = "zlib"
    MIXED = "mixed"


@dataclass
class FlagCandidate:
    """A potential flag found in the PDF"""
    value: str
    location: FlagLocation
    encoding: FlagEncoding
    confidence: float
    page_number: Optional[int] = None
    object_id: Optional[int] = None
    context: str = ""
    pattern_matched: str = ""
    decoding_chain: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'value': self.value,
            'location': self.location.value,
            'encoding': self.encoding.value,
            'confidence': self.confidence,
            'page_number': self.page_number,
            'object_id': self.object_id,
            'context': self.context,
            'pattern_matched': self.pattern_matched,
            'decoding_chain': self.decoding_chain,
        }


class FlagHunter:
    """Hunt for flags across all PDF layers"""
    
    HASH_PATTERNS = {
        'md5': (r'\b[a-f0-9]{32}\b', 32),
        'sha1': (r'\b[a-f0-9]{40}\b', 40),
        'sha256': (r'\b[a-f0-9]{64}\b', 64),
        'sha512': (r'\b[a-f0-9]{128}\b', 128),
    }
    
    def __init__(
        self,
        pdf_doc: PDFDocument,
        custom_patterns: Optional[List[str]] = None,
        builtin_patterns: Optional[List[str]] = None
    ):
        """
        Initialize flag hunter
        
        Args:
            pdf_doc: PDF document to search
            custom_patterns: Custom regex patterns to search for
            builtin_patterns: Built-in pattern types (ctf, md5, sha1, sha256, sha512)
        """
        self.pdf_doc = pdf_doc
        self.candidates: List[FlagCandidate] = []
        self.seen_values: Set[str] = set()
        
        self.patterns: List[tuple] = []
        
        if builtin_patterns:
            self._add_builtin_patterns(builtin_patterns)
        else:
            for pattern in CTF_FLAG_PATTERNS:
                self.patterns.append((pattern, 'ctf'))
        
        if custom_patterns:
            for pattern in custom_patterns:
                self.patterns.append((pattern, 'custom'))
        
        logger.debug(f"Initialized FlagHunter with {len(self.patterns)} pattern(s)")
    
    def _add_builtin_patterns(self, pattern_types: List[str]):
        """Add built-in patterns based on requested types"""
        for ptype in pattern_types:
            ptype = ptype.lower()
            
            if ptype == 'ctf':
                for pattern in CTF_FLAG_PATTERNS:
                    self.patterns.append((pattern, 'ctf'))
            
            elif ptype in self.HASH_PATTERNS:
                pattern, length = self.HASH_PATTERNS[ptype]
                self.patterns.append((pattern, ptype))
            
            elif ptype == 'all':
                for pattern in CTF_FLAG_PATTERNS:
                    self.patterns.append((pattern, 'ctf'))
                for hash_type, (pattern, _) in self.HASH_PATTERNS.items():
                    self.patterns.append((pattern, hash_type))
    
    def hunt(self) -> List[FlagCandidate]:
        """
        Hunt for flags across all PDF layers
        
        Returns:
            List of flag candidates sorted by confidence
        """
        logger.info(f"Starting comprehensive flag hunt in {self.pdf_doc.path}")
        
        self.candidates = []
        self.seen_values = set()
        
        self._scan_visible_text()
        self._scan_metadata()
        self._scan_javascript()
        self._scan_streams()
        self._scan_revisions()
        self._scan_comments()
        self._scan_annotations()
        self._scan_forms()
        self._scan_hidden_data()
        self._scan_attachments()
        self._scan_bookmarks()
        self._scan_raw_objects()
        
        self._prioritize_candidates()
        
        logger.info(f"Found {len(self.candidates)} flag candidate(s)")
        return self.candidates
    
    def _scan_visible_text(self):
        """Scan visible text on all pages"""
        logger.debug("Scanning visible text")
        
        try:
            extractor = TextExtractor(self.pdf_doc)
            
            for page_num in range(self.pdf_doc.num_pages):
                try:
                    text = extractor.extract_page(page_num)
                    self._search_in_text(
                        text,
                        FlagLocation.VISIBLE_TEXT,
                        page_number=page_num
                    )
                except Exception as e:
                    logger.debug(f"Error extracting text from page {page_num}: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to scan visible text: {e}")
    
    def _scan_metadata(self):
        """Scan Info dictionary and XMP metadata"""
        logger.debug("Scanning metadata")
        
        try:
            analyzer = PDFMetadataAnalyzer(self.pdf_doc)
            metadata = analyzer.analyze()
            
            info_dict = metadata.get('info_dict', {})
            for key, value in info_dict.items():
                text = f"{key}: {value}"
                self._search_in_text(
                    text,
                    FlagLocation.METADATA_INFO,
                    context=f"Info dict key: {key}"
                )
            
            xmp_metadata = metadata.get('xmp_metadata', {})
            for key, value in xmp_metadata.items():
                text = f"{key}: {value}"
                self._search_in_text(
                    text,
                    FlagLocation.METADATA_XMP,
                    context=f"XMP key: {key}"
                )
            
            hidden_fields = metadata.get('hidden_fields', [])
            for field in hidden_fields:
                key = field.get('key', '')
                value = field.get('value', '')
                text = f"{key}: {value}"
                self._search_in_text(
                    text,
                    FlagLocation.METADATA_INFO,
                    context=f"Hidden metadata: {key}"
                )
        
        except Exception as e:
            logger.warning(f"Failed to scan metadata: {e}")
    
    def _scan_javascript(self):
        """Scan JavaScript code"""
        logger.debug("Scanning JavaScript")
        
        try:
            extractor = JavaScriptExtractor(self.pdf_doc)
            scripts = extractor.extract_all(deobfuscate=True)
            
            for script in scripts:
                code = script.get('code', '')
                deobfuscated = script.get('deobfuscated', '')
                location = script.get('location', 'unknown')
                
                self._search_in_text(
                    code,
                    FlagLocation.JAVASCRIPT,
                    context=f"JavaScript ({location})"
                )
                
                if deobfuscated and deobfuscated != code:
                    self._search_in_text(
                        deobfuscated,
                        FlagLocation.JAVASCRIPT,
                        context=f"Deobfuscated JavaScript ({location})"
                    )
        
        except Exception as e:
            logger.warning(f"Failed to scan JavaScript: {e}")
    
    def _scan_streams(self):
        """Scan object streams and compressed streams"""
        logger.debug("Scanning streams")
        
        try:
            for obj in self.pdf_doc.pdf.objects:
                try:
                    obj_id = obj.objgen[0]
                    
                    if hasattr(obj, 'read_bytes'):
                        try:
                            stream_data = bytes(obj.read_bytes())
                            
                            text = stream_data.decode('utf-8', errors='ignore')
                            
                            is_compressed = '/Filter' in obj if hasattr(obj, '__contains__') else False
                            location = FlagLocation.COMPRESSED_STREAM if is_compressed else FlagLocation.OBJECT_STREAM
                            
                            self._search_in_text(
                                text,
                                location,
                                object_id=obj_id,
                                context=f"Object {obj_id} stream"
                            )
                            
                            self._search_in_binary(
                                stream_data,
                                location,
                                object_id=obj_id,
                                context=f"Object {obj_id} stream (binary)"
                            )
                        
                        except Exception as e:
                            logger.debug(f"Could not read stream from object {obj_id}: {e}")
                
                except Exception as e:
                    logger.debug(f"Error processing object: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to scan streams: {e}")
    
    def _scan_revisions(self):
        """Scan previous revisions"""
        logger.debug("Scanning revisions")
        
        try:
            extractor = RevisionExtractor(self.pdf_doc)
            revisions = extractor.extract_all_revisions()
            
            for revision in revisions:
                rev_num = revision.revision_number
                
                metadata_changes = revision.metadata_changes
                for key, (old_val, new_val) in metadata_changes.items():
                    text = f"{key}: {old_val} -> {new_val}"
                    self._search_in_text(
                        text,
                        FlagLocation.REVISION,
                        context=f"Revision {rev_num} metadata change"
                    )
                
                for activity in revision.suspicious_activities:
                    self._search_in_text(
                        activity,
                        FlagLocation.REVISION,
                        context=f"Revision {rev_num} suspicious activity"
                    )
        
        except Exception as e:
            logger.warning(f"Failed to scan revisions: {e}")
    
    def _scan_comments(self):
        """Scan PDF comments"""
        logger.debug("Scanning comments")
        
        try:
            with open(self.pdf_doc.path, 'rb') as f:
                data = f.read()
            
            text = data.decode('latin-1', errors='ignore')
            
            comment_pattern = r'%[^\r\n]+'
            for match in re.finditer(comment_pattern, text):
                comment = match.group(0)
                
                if not comment.startswith('%PDF') and not comment.startswith('%%EOF'):
                    self._search_in_text(
                        comment,
                        FlagLocation.COMMENT,
                        context="PDF comment"
                    )
        
        except Exception as e:
            logger.warning(f"Failed to scan comments: {e}")
    
    def _scan_annotations(self):
        """Scan annotations"""
        logger.debug("Scanning annotations")
        
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Annots' not in page:
                    continue
                
                annots = page['/Annots']
                if not annots:
                    continue
                
                for annot in annots:
                    try:
                        annot_obj = annot if isinstance(annot, pikepdf.Dictionary) else self.pdf_doc.pdf.get_object(annot)
                        
                        if '/Contents' in annot_obj:
                            contents = str(annot_obj['/Contents'])
                            self._search_in_text(
                                contents,
                                FlagLocation.ANNOTATION,
                                page_number=page_num,
                                context=f"Annotation on page {page_num}"
                            )
                        
                        if '/Subj' in annot_obj:
                            subject = str(annot_obj['/Subj'])
                            self._search_in_text(
                                subject,
                                FlagLocation.ANNOTATION,
                                page_number=page_num,
                                context=f"Annotation subject on page {page_num}"
                            )
                    
                    except Exception as e:
                        logger.debug(f"Error processing annotation: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to scan annotations: {e}")
    
    def _scan_forms(self):
        """Scan form fields"""
        logger.debug("Scanning forms")
        
        try:
            extractor = FormsExtractor(self.pdf_doc)
            forms_data = extractor.extract_all()
            
            for field in forms_data.get('acroform_fields', []):
                field_name = field.get('field_name', '')
                field_value = field.get('field_value', '')
                field_type = field.get('field_type', '')
                
                text = f"{field_name}: {field_value}"
                self._search_in_text(
                    text,
                    FlagLocation.FORM_FIELD,
                    context=f"Form field ({field_type}): {field_name}"
                )
            
            xfa_data = forms_data.get('xfa_data', {})
            if xfa_data and 'raw_xml' in xfa_data:
                self._search_in_text(
                    xfa_data['raw_xml'],
                    FlagLocation.FORM_FIELD,
                    context="XFA form data"
                )
        
        except Exception as e:
            logger.warning(f"Failed to scan forms: {e}")
    
    def _scan_hidden_data(self):
        """Scan hidden data"""
        logger.debug("Scanning hidden data")
        
        try:
            extractor = HiddenDataExtractor(self.pdf_doc)
            findings = extractor.extract_all()
            
            for finding in findings:
                data = finding.get('data', '')
                finding_type = finding.get('type', '')
                page = finding.get('page')
                
                location = FlagLocation.INVISIBLE_TEXT
                if 'whitespace' in finding_type:
                    location = FlagLocation.WHITESPACE
                elif 'zero_width' in finding_type:
                    location = FlagLocation.ZERO_WIDTH_CHARS
                
                self._search_in_text(
                    data,
                    location,
                    page_number=page,
                    context=f"Hidden data ({finding_type})"
                )
        
        except Exception as e:
            logger.warning(f"Failed to scan hidden data: {e}")
    
    def _scan_attachments(self):
        """Scan embedded files/attachments"""
        logger.debug("Scanning attachments")
        
        try:
            if '/Names' not in self.pdf_doc.pdf.Root:
                return
            
            names = self.pdf_doc.pdf.Root['/Names']
            if '/EmbeddedFiles' not in names:
                return
            
            embedded_files = names['/EmbeddedFiles']
            if '/Names' not in embedded_files:
                return
            
            names_array = embedded_files['/Names']
            
            for i in range(0, len(names_array), 2):
                try:
                    filename = str(names_array[i])
                    filespec = names_array[i + 1]
                    
                    self._search_in_text(
                        filename,
                        FlagLocation.ATTACHMENT,
                        context=f"Attachment filename: {filename}"
                    )
                    
                    if '/EF' in filespec and '/F' in filespec['/EF']:
                        stream = filespec['/EF']['/F']
                        data = bytes(stream.read_bytes())
                        
                        text = data.decode('utf-8', errors='ignore')
                        self._search_in_text(
                            text,
                            FlagLocation.ATTACHMENT,
                            context=f"Attachment content: {filename}"
                        )
                
                except Exception as e:
                    logger.debug(f"Error processing attachment: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to scan attachments: {e}")
    
    def _scan_bookmarks(self):
        """Scan bookmarks/outline"""
        logger.debug("Scanning bookmarks")
        
        try:
            if '/Outlines' not in self.pdf_doc.pdf.Root:
                return
            
            outlines = self.pdf_doc.pdf.Root['/Outlines']
            self._scan_outline_item(outlines)
        
        except Exception as e:
            logger.warning(f"Failed to scan bookmarks: {e}")
    
    def _scan_outline_item(self, item):
        """Recursively scan outline items"""
        try:
            if '/Title' in item:
                title = str(item['/Title'])
                self._search_in_text(
                    title,
                    FlagLocation.BOOKMARK,
                    context="Bookmark title"
                )
            
            if '/First' in item:
                self._scan_outline_item(item['/First'])
            
            if '/Next' in item:
                self._scan_outline_item(item['/Next'])
        
        except Exception as e:
            logger.debug(f"Error scanning outline item: {e}")
    
    def _scan_raw_objects(self):
        """Scan raw object content as last resort"""
        logger.debug("Scanning raw objects")
        
        try:
            for obj in self.pdf_doc.pdf.objects:
                try:
                    obj_id = obj.objgen[0]
                    obj_str = str(obj)
                    
                    self._search_in_text(
                        obj_str,
                        FlagLocation.RAW_OBJECT,
                        object_id=obj_id,
                        context=f"Raw object {obj_id}"
                    )
                
                except Exception as e:
                    logger.debug(f"Error processing raw object: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to scan raw objects: {e}")
    
    def _search_in_text(
        self,
        text: str,
        location: FlagLocation,
        page_number: Optional[int] = None,
        object_id: Optional[int] = None,
        context: str = ""
    ):
        """Search for patterns in text"""
        if not text:
            return
        
        for pattern, pattern_type in self.patterns:
            try:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    value = match.group(0)
                    
                    if value in self.seen_values:
                        continue
                    
                    self.seen_values.add(value)
                    
                    candidate = FlagCandidate(
                        value=value,
                        location=location,
                        encoding=FlagEncoding.PLAINTEXT,
                        confidence=0.0,
                        page_number=page_number,
                        object_id=object_id,
                        context=context or self._extract_context(text, match.start(), match.end()),
                        pattern_matched=pattern_type,
                    )
                    
                    candidate.confidence = self._calculate_confidence(candidate)
                    self.candidates.append(candidate)
            
            except Exception as e:
                logger.debug(f"Error searching pattern '{pattern}': {e}")
        
        self._search_encoded_flags(text, location, page_number, object_id, context)
    
    def _search_in_binary(
        self,
        data: bytes,
        location: FlagLocation,
        object_id: Optional[int] = None,
        context: str = ""
    ):
        """Search for patterns in binary data (check for encoded content)"""
        try:
            for pattern, pattern_type in self.patterns:
                matches = re.finditer(pattern.encode('latin-1'), data, re.IGNORECASE)
                for match in matches:
                    value = match.group(0).decode('latin-1', errors='ignore')
                    
                    if value in self.seen_values:
                        continue
                    
                    self.seen_values.add(value)
                    
                    candidate = FlagCandidate(
                        value=value,
                        location=location,
                        encoding=FlagEncoding.PLAINTEXT,
                        confidence=0.0,
                        object_id=object_id,
                        context=context,
                        pattern_matched=pattern_type,
                    )
                    
                    candidate.confidence = self._calculate_confidence(candidate)
                    self.candidates.append(candidate)
        
        except Exception as e:
            logger.debug(f"Error searching binary data: {e}")
    
    def _search_encoded_flags(
        self,
        text: str,
        location: FlagLocation,
        page_number: Optional[int] = None,
        object_id: Optional[int] = None,
        context: str = ""
    ):
        """Search for encoded flags (base64, hex, ROT13, etc.)"""
        
        self._search_base64_encoded(text, location, page_number, object_id, context)
        self._search_hex_encoded(text, location, page_number, object_id, context)
        self._search_rot13_encoded(text, location, page_number, object_id, context)
        self._search_reversed(text, location, page_number, object_id, context)
    
    def _search_base64_encoded(
        self,
        text: str,
        location: FlagLocation,
        page_number: Optional[int] = None,
        object_id: Optional[int] = None,
        context: str = ""
    ):
        """Search for base64-encoded flags"""
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        
        for match in re.finditer(base64_pattern, text):
            encoded_value = match.group(0)
            
            try:
                decoded = base64.b64decode(encoded_value).decode('utf-8', errors='ignore')
                
                for pattern, pattern_type in self.patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        flag_match = re.search(pattern, decoded, re.IGNORECASE)
                        value = flag_match.group(0)
                        
                        if value in self.seen_values:
                            continue
                        
                        self.seen_values.add(value)
                        
                        candidate = FlagCandidate(
                            value=value,
                            location=location,
                            encoding=FlagEncoding.BASE64,
                            confidence=0.0,
                            page_number=page_number,
                            object_id=object_id,
                            context=f"{context} (base64 encoded: {encoded_value[:50]}...)",
                            pattern_matched=pattern_type,
                            decoding_chain=['base64'],
                        )
                        
                        candidate.confidence = self._calculate_confidence(candidate)
                        self.candidates.append(candidate)
            
            except Exception:
                pass
    
    def _search_hex_encoded(
        self,
        text: str,
        location: FlagLocation,
        page_number: Optional[int] = None,
        object_id: Optional[int] = None,
        context: str = ""
    ):
        """Search for hex-encoded flags"""
        hex_pattern = r'(?:0x)?[0-9a-fA-F]{40,}'
        
        for match in re.finditer(hex_pattern, text):
            encoded_value = match.group(0).replace('0x', '')
            
            if len(encoded_value) % 2 != 0:
                continue
            
            try:
                decoded = bytes.fromhex(encoded_value).decode('utf-8', errors='ignore')
                
                for pattern, pattern_type in self.patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        flag_match = re.search(pattern, decoded, re.IGNORECASE)
                        value = flag_match.group(0)
                        
                        if value in self.seen_values:
                            continue
                        
                        self.seen_values.add(value)
                        
                        candidate = FlagCandidate(
                            value=value,
                            location=location,
                            encoding=FlagEncoding.HEX,
                            confidence=0.0,
                            page_number=page_number,
                            object_id=object_id,
                            context=f"{context} (hex encoded: {encoded_value[:50]}...)",
                            pattern_matched=pattern_type,
                            decoding_chain=['hex'],
                        )
                        
                        candidate.confidence = self._calculate_confidence(candidate)
                        self.candidates.append(candidate)
            
            except Exception:
                pass
    
    def _search_rot13_encoded(
        self,
        text: str,
        location: FlagLocation,
        page_number: Optional[int] = None,
        object_id: Optional[int] = None,
        context: str = ""
    ):
        """Search for ROT13-encoded flags"""
        try:
            import codecs
            decoded = codecs.decode(text, 'rot_13')
            
            for pattern, pattern_type in self.patterns:
                for match in re.finditer(pattern, decoded, re.IGNORECASE):
                    value = match.group(0)
                    
                    if value in self.seen_values:
                        continue
                    
                    self.seen_values.add(value)
                    
                    candidate = FlagCandidate(
                        value=value,
                        location=location,
                        encoding=FlagEncoding.ROT13,
                        confidence=0.0,
                        page_number=page_number,
                        object_id=object_id,
                        context=f"{context} (ROT13 encoded)",
                        pattern_matched=pattern_type,
                        decoding_chain=['rot13'],
                    )
                    
                    candidate.confidence = self._calculate_confidence(candidate)
                    self.candidates.append(candidate)
        
        except Exception as e:
            logger.debug(f"Error decoding ROT13: {e}")
    
    def _search_reversed(
        self,
        text: str,
        location: FlagLocation,
        page_number: Optional[int] = None,
        object_id: Optional[int] = None,
        context: str = ""
    ):
        """Search for reversed flags"""
        reversed_text = text[::-1]
        
        for pattern, pattern_type in self.patterns:
            for match in re.finditer(pattern, reversed_text, re.IGNORECASE):
                value = match.group(0)
                
                if value in self.seen_values:
                    continue
                
                self.seen_values.add(value)
                
                candidate = FlagCandidate(
                    value=value,
                    location=location,
                    encoding=FlagEncoding.REVERSED,
                    confidence=0.0,
                    page_number=page_number,
                    object_id=object_id,
                    context=f"{context} (reversed)",
                    pattern_matched=pattern_type,
                    decoding_chain=['reversed'],
                )
                
                candidate.confidence = self._calculate_confidence(candidate)
                self.candidates.append(candidate)
    
    def _extract_context(self, text: str, start: int, end: int, window: int = 50) -> str:
        """Extract context around a match"""
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        
        context = text[context_start:context_end]
        
        context = context.replace('\n', ' ').replace('\r', ' ')
        context = ' '.join(context.split())
        
        if len(context) > 150:
            context = context[:150] + "..."
        
        return context
    
    def _calculate_confidence(self, candidate: FlagCandidate) -> float:
        """
        Calculate confidence score for a flag candidate
        
        Higher confidence for:
        - CTF flag formats (CTF{...}, FLAG{...})
        - Plaintext encoding
        - Found in metadata/JavaScript (common CTF locations)
        - Reasonable length
        - Contains readable characters
        """
        confidence = 0.5
        
        if candidate.pattern_matched == 'ctf':
            if re.match(r'^(CTF|FLAG|flag)\{[^}]+\}$', candidate.value, re.IGNORECASE):
                confidence += 0.3
            else:
                confidence += 0.1
        
        elif candidate.pattern_matched in ['md5', 'sha1', 'sha256', 'sha512']:
            confidence += 0.15
        
        if candidate.encoding == FlagEncoding.PLAINTEXT:
            confidence += 0.1
        else:
            confidence += 0.05
        
        high_value_locations = [
            FlagLocation.METADATA_INFO,
            FlagLocation.METADATA_XMP,
            FlagLocation.JAVASCRIPT,
            FlagLocation.INVISIBLE_TEXT,
            FlagLocation.FORM_FIELD,
        ]
        
        if candidate.location in high_value_locations:
            confidence += 0.15
        
        low_value_locations = [
            FlagLocation.RAW_OBJECT,
            FlagLocation.OBJECT_STREAM,
        ]
        
        if candidate.location in low_value_locations:
            confidence -= 0.1
        
        length = len(candidate.value)
        if 20 <= length <= 100:
            confidence += 0.05
        elif length > 100:
            confidence -= 0.05
        
        printable_ratio = sum(c.isprintable() for c in candidate.value) / len(candidate.value)
        if printable_ratio > 0.95:
            confidence += 0.05
        
        return min(1.0, max(0.0, confidence))
    
    def _prioritize_candidates(self):
        """Sort candidates by confidence (highest first)"""
        self.candidates.sort(key=lambda c: c.confidence, reverse=True)
    
    def export_report(self, output_path: Path):
        """Export flag hunting report"""
        output_path = Path(output_path)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("PDFAutopsy Flag Hunt Report\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"PDF: {self.pdf_doc.path}\n")
            f.write(f"Total candidates: {len(self.candidates)}\n\n")
            
            if not self.candidates:
                f.write("No flag candidates found.\n")
                return
            
            high_confidence = [c for c in self.candidates if c.confidence >= 0.7]
            medium_confidence = [c for c in self.candidates if 0.4 <= c.confidence < 0.7]
            low_confidence = [c for c in self.candidates if c.confidence < 0.4]
            
            if high_confidence:
                f.write(f"\nHIGH CONFIDENCE ({len(high_confidence)})\n")
                f.write("-" * 80 + "\n")
                for candidate in high_confidence:
                    self._write_candidate(f, candidate)
            
            if medium_confidence:
                f.write(f"\nMEDIUM CONFIDENCE ({len(medium_confidence)})\n")
                f.write("-" * 80 + "\n")
                for candidate in medium_confidence:
                    self._write_candidate(f, candidate)
            
            if low_confidence:
                f.write(f"\nLOW CONFIDENCE ({len(low_confidence)})\n")
                f.write("-" * 80 + "\n")
                for candidate in low_confidence:
                    self._write_candidate(f, candidate)
        
        logger.info(f"Report exported to {output_path}")
    
    def _write_candidate(self, f, candidate: FlagCandidate):
        """Write a candidate to report file"""
        f.write(f"\nValue: {candidate.value}\n")
        f.write(f"Confidence: {candidate.confidence:.2f}\n")
        f.write(f"Location: {candidate.location.value}\n")
        f.write(f"Encoding: {candidate.encoding.value}\n")
        f.write(f"Pattern: {candidate.pattern_matched}\n")
        
        if candidate.page_number is not None:
            f.write(f"Page: {candidate.page_number}\n")
        
        if candidate.object_id is not None:
            f.write(f"Object ID: {candidate.object_id}\n")
        
        if candidate.decoding_chain:
            f.write(f"Decoding chain: {' -> '.join(candidate.decoding_chain)}\n")
        
        if candidate.context:
            f.write(f"Context: {candidate.context}\n")
        
        f.write("\n")
