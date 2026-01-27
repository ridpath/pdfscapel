"""
Comprehensive PDF steganography detection and solving

Implements 20+ steganography techniques beyond simple LSB for CTF and forensics.
Based on research from advanced_stego_research.md.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import math
import base64
import binascii
import struct
import io

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

try:
    import numpy as np
    from PIL import Image
    HAS_IMAGE_LIBS = True
except ImportError:
    HAS_IMAGE_LIBS = False

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError

logger = get_logger()


class StegoTechnique(Enum):
    """Steganography technique types"""
    STREAM_OPERATOR = "stream_operator_manipulation"
    OBJECT_ORDERING = "object_id_ordering"
    WHITESPACE_UNICODE = "whitespace_unicode"
    ZERO_WIDTH_CHARS = "zero_width_characters"
    XREF_MANIPULATION = "xref_table_manipulation"
    INCREMENTAL_UPDATE = "incremental_update_embedding"
    DATA_AFTER_EOF = "data_after_eof"
    TRAILER_CUSTOM = "trailer_dictionary_custom"
    COMMENT_ENCODING = "comment_field_encoding"
    FREE_OBJECTS = "unused_object_slots"
    LINEARIZATION_HINT = "linearization_hint_table"
    HOMOGLYPH_SUBST = "homoglyph_substitution"
    FONT_ENCODING = "custom_font_encoding"
    TOUNICODE_CMAP = "tounicode_cmap_manipulation"
    FONT_SUBSET = "font_subset_manipulation"
    GLYPH_POSITIONING = "glyph_positioning"
    CHARACTER_SPACING = "character_spacing_manipulation"
    FLATEDECODE_PRED = "flatedecode_prediction"
    ASCII_ENCODING = "ascii85_asciihex_artifacts"
    LZW_TABLE = "lzw_compression_table"
    RUNLENGTH = "runlength_encode_manipulation"
    CCITTFAX = "ccittfax_manipulation"
    JBIG2 = "jbig2_steganography"
    DCT_ADVANCED = "dct_jpeg_advanced"
    IMAGE_LSB = "image_lsb_steganography"
    DISTRIBUTED = "distributed_across_pages"
    TRANSPARENCY = "transparency_opacity_manipulation"
    COLORSPACE = "colorspace_manipulation"
    PAGE_ROTATION = "page_rotation_covert"
    CONTENT_OBFUSCATION = "content_stream_obfuscation"
    METADATA_CUSTOM = "metadata_custom_fields"


class DetectionDifficulty(Enum):
    """Detection difficulty levels"""
    LOW = "low"
    MEDIUM = "medium"
    MEDIUM_HIGH = "medium_high"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class StegoFinding:
    """Steganography detection finding"""
    technique: StegoTechnique
    confidence: float
    location: str
    data: Optional[Any] = None
    extracted_data: Optional[bytes] = None
    difficulty: DetectionDifficulty = DetectionDifficulty.MEDIUM
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'technique': self.technique.value,
            'confidence': self.confidence,
            'location': self.location,
            'has_extracted_data': self.extracted_data is not None,
            'extracted_size': len(self.extracted_data) if self.extracted_data else 0,
            'difficulty': self.difficulty.value,
            'details': self.details,
        }


class StegoSolver:
    """Comprehensive steganography detection and extraction"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.findings: List[StegoFinding] = []
        
    def detect_all(self) -> List[StegoFinding]:
        """
        Detect all steganography techniques
        
        Returns:
            List of steganography findings
        """
        logger.info(f"Running comprehensive steganography detection on {self.pdf_doc.path}")
        
        self.findings = []
        
        self._detect_stream_operator_manipulation()
        self._detect_object_ordering()
        self._detect_whitespace_unicode()
        self._detect_zero_width_characters()
        self._detect_xref_manipulation()
        self._detect_incremental_updates()
        self._detect_data_after_eof()
        self._detect_trailer_custom_fields()
        self._detect_comment_encoding()
        self._detect_free_objects()
        self._detect_linearization_hints()
        self._detect_homoglyph_substitution()
        self._detect_font_manipulation()
        self._detect_glyph_positioning()
        self._detect_character_spacing()
        self._detect_compression_manipulation()
        self._detect_image_lsb()
        self._detect_transparency_manipulation()
        self._detect_colorspace_manipulation()
        self._detect_page_rotation_covert()
        self._detect_metadata_custom()
        
        logger.info(f"Detected {len(self.findings)} steganography findings")
        return self.findings
    
    def extract_all(self, output_dir: Optional[Path] = None) -> Path:
        """
        Extract all detected hidden data
        
        Args:
            output_dir: Output directory for extracted data
            
        Returns:
            Path to output directory
        """
        if output_dir is None:
            output_dir = self.pdf_doc.path.parent / f"{self.pdf_doc.path.stem}_stego_extracted"
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Extracting {len(self.findings)} steganography findings to {output_dir}")
        
        for i, finding in enumerate(self.findings):
            if finding.extracted_data:
                filename = output_dir / f"finding_{i:03d}_{finding.technique.name}.bin"
                with open(filename, 'wb') as f:
                    f.write(finding.extracted_data)
                logger.debug(f"Extracted {len(finding.extracted_data)} bytes to {filename}")
        
        summary_file = output_dir / "summary.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Steganography Detection Summary\n")
            f.write(f"PDF: {self.pdf_doc.path}\n")
            f.write(f"Total Findings: {len(self.findings)}\n\n")
            
            for i, finding in enumerate(self.findings):
                f.write(f"Finding #{i+1}\n")
                f.write(f"  Technique: {finding.technique.value}\n")
                f.write(f"  Confidence: {finding.confidence:.0%}\n")
                f.write(f"  Location: {finding.location}\n")
                f.write(f"  Difficulty: {finding.difficulty.value}\n")
                if finding.extracted_data:
                    f.write(f"  Extracted Size: {len(finding.extracted_data)} bytes\n")
                f.write(f"  Details: {finding.details}\n\n")
        
        logger.info(f"Summary saved to {summary_file}")
        return output_dir
    
    def _detect_stream_operator_manipulation(self):
        """Detect steganography in PDF stream operators (Tm, Td, Tc, Tw, Tz)"""
        logger.debug("Detecting stream operator manipulation")
        
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Contents' not in page:
                    continue
                
                stream_data = self._get_page_content_stream(page)
                if not stream_data:
                    continue
                
                content_str = stream_data.decode('latin-1', errors='replace')
                
                suspicious_operands = self._find_suspicious_float_operands(content_str)
                
                if suspicious_operands:
                    confidence = min(0.95, len(suspicious_operands) / 100.0 + 0.5)
                    
                    self.findings.append(StegoFinding(
                        technique=StegoTechnique.STREAM_OPERATOR,
                        confidence=confidence,
                        location=f"Page {page_num} content stream",
                        difficulty=DetectionDifficulty.MEDIUM,
                        details={
                            'suspicious_operands': len(suspicious_operands),
                            'examples': suspicious_operands[:5],
                        }
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to detect stream operator manipulation: {e}")
    
    def _find_suspicious_float_operands(self, content: str) -> List[Tuple[str, float]]:
        """Find floating-point operands with unusual precision"""
        suspicious = []
        
        operators = ['Tm', 'Td', 'TD', 'Tc', 'Tw', 'Tz', 'cm']
        
        for operator in operators:
            pattern = r'([\d.]+)\s+' + operator
            matches = re.findall(pattern, content)
            
            for match in matches:
                try:
                    value = float(match)
                    decimal_places = len(match.split('.')[-1]) if '.' in match else 0
                    
                    if decimal_places > 4:
                        suspicious.append((operator, value))
                
                except ValueError:
                    pass
        
        return suspicious
    
    def _detect_object_ordering(self):
        """Detect object ID ordering covert channel"""
        logger.debug("Detecting object ID ordering patterns")
        
        try:
            objects = list(self.pdf_doc.get_objects())
            if len(objects) < 10:
                return
            
            obj_ids = [obj_id[0] for obj_id in objects[:100]]
            
            entropy = self._calculate_sequence_entropy(obj_ids)
            
            sorted_ids = sorted(obj_ids)
            inversions = sum(1 for i in range(len(obj_ids)-1) if obj_ids[i] > obj_ids[i+1])
            
            if entropy > 0.8 and inversions > len(obj_ids) * 0.2:
                confidence = min(0.85, entropy * 0.7 + (inversions / len(obj_ids)) * 0.3)
                
                self.findings.append(StegoFinding(
                    technique=StegoTechnique.OBJECT_ORDERING,
                    confidence=confidence,
                    location="PDF object tree",
                    difficulty=DetectionDifficulty.HIGH,
                    details={
                        'total_objects': len(obj_ids),
                        'entropy': entropy,
                        'inversions': inversions,
                    }
                ))
        
        except Exception as e:
            logger.debug(f"Failed to detect object ordering: {e}")
    
    def _detect_whitespace_unicode(self):
        """Detect Unicode whitespace steganography"""
        logger.debug("Detecting whitespace Unicode steganography")
        
        if pdfplumber is None:
            return
        
        try:
            with pdfplumber.open(self.pdf_doc.path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    text = page.extract_text()
                    if not text:
                        continue
                    
                    whitespace_chars = self._find_unusual_whitespace(text)
                    
                    if whitespace_chars:
                        extracted = self._decode_whitespace_steganography(whitespace_chars)
                        
                        confidence = min(0.9, len(whitespace_chars) / 100.0 + 0.6)
                        
                        self.findings.append(StegoFinding(
                            technique=StegoTechnique.WHITESPACE_UNICODE,
                            confidence=confidence,
                            location=f"Page {page_num} text content",
                            extracted_data=extracted,
                            difficulty=DetectionDifficulty.MEDIUM,
                            details={
                                'whitespace_count': len(whitespace_chars),
                                'patterns': self._analyze_whitespace_patterns(whitespace_chars),
                            }
                        ))
        
        except Exception as e:
            logger.debug(f"Failed to detect whitespace Unicode: {e}")
    
    def _find_unusual_whitespace(self, text: str) -> List[Tuple[int, str, str]]:
        """Find unusual Unicode whitespace characters"""
        unusual_whitespace = {
            '\u200B': 'ZERO_WIDTH_SPACE',
            '\u200C': 'ZERO_WIDTH_NON_JOINER',
            '\u200D': 'ZERO_WIDTH_JOINER',
            '\uFEFF': 'ZERO_WIDTH_NO_BREAK_SPACE',
            '\u2800': 'BRAILLE_PATTERN_BLANK',
            '\u180E': 'MONGOLIAN_VOWEL_SEPARATOR',
            '\u2060': 'WORD_JOINER',
        }
        
        findings = []
        for i, char in enumerate(text):
            if char in unusual_whitespace:
                findings.append((i, char, unusual_whitespace[char]))
        
        return findings
    
    def _decode_whitespace_steganography(self, whitespace_chars: List[Tuple[int, str, str]]) -> bytes:
        """Decode binary data from whitespace patterns"""
        binary_map = {
            '\u200B': '0',
            '\u200C': '1',
            '\u200D': '00',
            '\uFEFF': '11',
        }
        
        binary_str = ''
        for _, char, _ in whitespace_chars:
            binary_str += binary_map.get(char, '0')
        
        if len(binary_str) < 8:
            return b''
        
        padding = (8 - len(binary_str) % 8) % 8
        binary_str += '0' * padding
        
        try:
            data = bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))
            return data
        except Exception:
            return b''
    
    def _analyze_whitespace_patterns(self, whitespace_chars: List[Tuple[int, str, str]]) -> Dict[str, int]:
        """Analyze patterns in whitespace characters"""
        patterns = {}
        for _, _, name in whitespace_chars:
            patterns[name] = patterns.get(name, 0) + 1
        return patterns
    
    def _detect_zero_width_characters(self):
        """Detect zero-width character steganography"""
        logger.debug("Detecting zero-width characters")
        
        if pdfplumber is None:
            return
        
        try:
            with pdfplumber.open(self.pdf_doc.path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    text = page.extract_text()
                    if not text:
                        continue
                    
                    zero_width_chars = [c for c in text if ord(c) in [0x200B, 0x200C, 0x200D, 0xFEFF]]
                    
                    if len(zero_width_chars) > 3:
                        binary_data = self._extract_zero_width_binary(zero_width_chars)
                        
                        confidence = min(0.95, len(zero_width_chars) / 50.0 + 0.7)
                        
                        self.findings.append(StegoFinding(
                            technique=StegoTechnique.ZERO_WIDTH_CHARS,
                            confidence=confidence,
                            location=f"Page {page_num}",
                            extracted_data=binary_data,
                            difficulty=DetectionDifficulty.MEDIUM,
                            details={'char_count': len(zero_width_chars)}
                        ))
        
        except Exception as e:
            logger.debug(f"Failed to detect zero-width characters: {e}")
    
    def _extract_zero_width_binary(self, chars: List[str]) -> bytes:
        """Extract binary data from zero-width characters"""
        mapping = {'\u200B': '0', '\u200C': '1'}
        binary = ''.join(mapping.get(c, '0') for c in chars)
        
        if len(binary) < 8:
            return b''
        
        padding = (8 - len(binary) % 8) % 8
        binary += '0' * padding
        
        try:
            return bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
        except Exception:
            return b''
    
    def _detect_xref_manipulation(self):
        """Detect cross-reference table manipulation"""
        logger.debug("Detecting xref table manipulation")
        
        try:
            pdf = self.pdf_doc.pdf
            
            if '/XRef' in pdf.trailer or hasattr(pdf, 'xref_table'):
                free_entries = 0
                unusual_gen_nums = 0
                
                for obj_id in self.pdf_doc.get_objects():
                    try:
                        obj = pdf.get_object(obj_id)
                        if obj is None:
                            free_entries += 1
                        
                        if obj_id[1] > 5:
                            unusual_gen_nums += 1
                    except Exception:
                        pass
                
                if free_entries > 5 or unusual_gen_nums > 2:
                    confidence = min(0.7, (free_entries / 10.0) + (unusual_gen_nums / 5.0))
                    
                    self.findings.append(StegoFinding(
                        technique=StegoTechnique.XREF_MANIPULATION,
                        confidence=confidence,
                        location="Cross-reference table",
                        difficulty=DetectionDifficulty.MEDIUM_HIGH,
                        details={
                            'free_entries': free_entries,
                            'unusual_gen_numbers': unusual_gen_nums,
                        }
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to detect xref manipulation: {e}")
    
    def _detect_incremental_updates(self):
        """Detect incremental update embedding"""
        logger.debug("Detecting incremental update steganography")
        
        try:
            with open(self.pdf_doc.path, 'rb') as f:
                content = f.read()
            
            eof_markers = content.count(b'%%EOF')
            
            if eof_markers > 1:
                startxref_count = content.count(b'startxref')
                
                confidence = min(0.85, (eof_markers - 1) / 5.0 + 0.5)
                
                self.findings.append(StegoFinding(
                    technique=StegoTechnique.INCREMENTAL_UPDATE,
                    confidence=confidence,
                    location="Incremental updates",
                    difficulty=DetectionDifficulty.MEDIUM,
                    details={
                        'eof_markers': eof_markers,
                        'update_count': eof_markers - 1,
                        'startxref_count': startxref_count,
                    }
                ))
        
        except Exception as e:
            logger.debug(f"Failed to detect incremental updates: {e}")
    
    def _detect_data_after_eof(self):
        """Detect data appended after %%EOF marker"""
        logger.debug("Detecting data after EOF")
        
        try:
            with open(self.pdf_doc.path, 'rb') as f:
                content = f.read()
            
            last_eof = content.rfind(b'%%EOF')
            
            if last_eof != -1 and last_eof < len(content) - 10:
                trailing_data = content[last_eof + 5:].strip()
                
                if len(trailing_data) > 10:
                    confidence = min(0.99, len(trailing_data) / 1000.0 + 0.8)
                    
                    self.findings.append(StegoFinding(
                        technique=StegoTechnique.DATA_AFTER_EOF,
                        confidence=confidence,
                        location="After %%EOF marker",
                        extracted_data=trailing_data,
                        difficulty=DetectionDifficulty.LOW,
                        details={'size': len(trailing_data)}
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to detect data after EOF: {e}")
    
    def _detect_trailer_custom_fields(self):
        """Detect custom fields in trailer dictionary"""
        logger.debug("Detecting trailer custom fields")
        
        try:
            pdf = self.pdf_doc.pdf
            trailer = pdf.trailer
            
            standard_keys = {'/Size', '/Root', '/Encrypt', '/Info', '/ID', '/Prev', '/XRefStm'}
            
            custom_keys = []
            for key in trailer.keys():
                if str(key) not in standard_keys:
                    custom_keys.append(str(key))
            
            if custom_keys:
                extracted_data = {}
                for key in custom_keys:
                    try:
                        value = trailer[key]
                        extracted_data[key] = str(value)
                    except Exception:
                        pass
                
                confidence = min(0.9, len(custom_keys) / 5.0 + 0.6)
                
                data_str = '\n'.join(f"{k}: {v}" for k, v in extracted_data.items())
                
                self.findings.append(StegoFinding(
                    technique=StegoTechnique.TRAILER_CUSTOM,
                    confidence=confidence,
                    location="Trailer dictionary",
                    extracted_data=data_str.encode('utf-8'),
                    difficulty=DetectionDifficulty.LOW,
                    details={'custom_keys': custom_keys}
                ))
        
        except Exception as e:
            logger.debug(f"Failed to detect trailer custom fields: {e}")
    
    def _detect_comment_encoding(self):
        """Detect data encoded in PDF comments"""
        logger.debug("Detecting comment encoding")
        
        try:
            with open(self.pdf_doc.path, 'rb') as f:
                content = f.read()
            
            lines = content.split(b'\n')
            comment_lines = [line for line in lines if line.strip().startswith(b'%') and not line.strip().startswith(b'%%')]
            
            if len(comment_lines) > 10:
                combined_comments = b' '.join(comment_lines)
                
                decoded_attempts = self._try_decode_comments(combined_comments)
                
                if decoded_attempts:
                    confidence = 0.85
                    
                    self.findings.append(StegoFinding(
                        technique=StegoTechnique.COMMENT_ENCODING,
                        confidence=confidence,
                        location="PDF comments",
                        extracted_data=combined_comments,
                        difficulty=DetectionDifficulty.LOW,
                        details={
                            'comment_count': len(comment_lines),
                            'decoded_attempts': decoded_attempts,
                        }
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to detect comment encoding: {e}")
    
    def _try_decode_comments(self, comment_data: bytes) -> List[str]:
        """Try to decode comment data using various methods"""
        decoded = []
        
        comment_text = comment_data.decode('latin-1', errors='ignore')
        
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', comment_text):
            decoded.append('base64')
        
        if re.search(r'[0-9a-fA-F]{32,}', comment_text):
            decoded.append('hex')
        
        return decoded
    
    def _detect_free_objects(self):
        """Detect unused object slots with embedded data"""
        logger.debug("Detecting free object exploitation")
        
        try:
            pdf = self.pdf_doc.pdf
            free_count = 0
            
            for obj_id in self.pdf_doc.get_objects():
                try:
                    obj = pdf.get_object(obj_id)
                    if obj is None:
                        free_count += 1
                except Exception:
                    free_count += 1
            
            if free_count > 3:
                confidence = min(0.65, free_count / 10.0 + 0.4)
                
                self.findings.append(StegoFinding(
                    technique=StegoTechnique.FREE_OBJECTS,
                    confidence=confidence,
                    location="Free object entries",
                    difficulty=DetectionDifficulty.MEDIUM_HIGH,
                    details={'free_object_count': free_count}
                ))
        
        except Exception as e:
            logger.debug(f"Failed to detect free objects: {e}")
    
    def _detect_linearization_hints(self):
        """Detect linearization hint table manipulation"""
        logger.debug("Detecting linearization hint manipulation")
        
        try:
            pdf = self.pdf_doc.pdf
            
            if '/Linearized' in pdf.trailer or (pdf.Root and '/Linearized' in pdf.Root):
                confidence = 0.6
                
                self.findings.append(StegoFinding(
                    technique=StegoTechnique.LINEARIZATION_HINT,
                    confidence=confidence,
                    location="Linearization dictionary",
                    difficulty=DetectionDifficulty.HIGH,
                    details={'note': 'Linearized PDF detected - hint table may contain steganography'}
                ))
        
        except Exception as e:
            logger.debug(f"Failed to detect linearization hints: {e}")
    
    def _detect_homoglyph_substitution(self):
        """Detect homoglyph substitution (Unicode lookalikes)"""
        logger.debug("Detecting homoglyph substitution")
        
        if pdfplumber is None:
            return
        
        try:
            with pdfplumber.open(self.pdf_doc.path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    text = page.extract_text()
                    if not text:
                        continue
                    
                    homoglyphs = self._find_homoglyphs(text)
                    
                    if homoglyphs:
                        confidence = min(0.8, len(homoglyphs) / 20.0 + 0.5)
                        
                        self.findings.append(StegoFinding(
                            technique=StegoTechnique.HOMOGLYPH_SUBST,
                            confidence=confidence,
                            location=f"Page {page_num}",
                            difficulty=DetectionDifficulty.MEDIUM,
                            details={'homoglyph_count': len(homoglyphs)}
                        ))
        
        except Exception as e:
            logger.debug(f"Failed to detect homoglyphs: {e}")
    
    def _find_homoglyphs(self, text: str) -> List[Tuple[int, str, str]]:
        """Find homoglyph characters (lookalikes)"""
        homoglyph_pairs = [
            ('A', '\u0410'),  # Latin A vs Cyrillic A
            ('O', '\u041E'),  # Latin O vs Cyrillic O
            ('e', '\u0435'),  # Latin e vs Cyrillic e
            ('o', '\u03BF'),  # Latin o vs Greek omicron
        ]
        
        findings = []
        for i, char in enumerate(text):
            for latin, lookalike in homoglyph_pairs:
                if char == lookalike:
                    findings.append((i, char, f"Lookalike for '{latin}'"))
        
        return findings
    
    def _detect_font_manipulation(self):
        """Detect font encoding and ToUnicode CMap manipulation"""
        logger.debug("Detecting font manipulation")
        
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Resources' not in page or '/Font' not in page['/Resources']:
                    continue
                
                fonts = page['/Resources']['/Font']
                
                for font_name, font_obj in fonts.items():
                    if '/ToUnicode' in font_obj:
                        confidence = 0.65
                        
                        self.findings.append(StegoFinding(
                            technique=StegoTechnique.TOUNICODE_CMAP,
                            confidence=confidence,
                            location=f"Page {page_num}, Font {font_name}",
                            difficulty=DetectionDifficulty.MEDIUM,
                            details={'font': str(font_name)}
                        ))
        
        except Exception as e:
            logger.debug(f"Failed to detect font manipulation: {e}")
    
    def _detect_glyph_positioning(self):
        """Detect glyph positioning covert channel"""
        logger.debug("Detecting glyph positioning manipulation")
        
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Contents' not in page:
                    continue
                
                stream_data = self._get_page_content_stream(page)
                if not stream_data:
                    continue
                
                content_str = stream_data.decode('latin-1', errors='replace')
                
                tm_operators = re.findall(r'([\d.]+)\s+([\d.]+)\s+Tm', content_str)
                
                if len(tm_operators) > 20:
                    precision_counts = {}
                    for x, y in tm_operators:
                        x_precision = len(x.split('.')[-1]) if '.' in x else 0
                        y_precision = len(y.split('.')[-1]) if '.' in y else 0
                        max_precision = max(x_precision, y_precision)
                        precision_counts[max_precision] = precision_counts.get(max_precision, 0) + 1
                    
                    high_precision = sum(count for precision, count in precision_counts.items() if precision > 3)
                    
                    if high_precision > len(tm_operators) * 0.3:
                        confidence = min(0.75, high_precision / len(tm_operators))
                        
                        self.findings.append(StegoFinding(
                            technique=StegoTechnique.GLYPH_POSITIONING,
                            confidence=confidence,
                            location=f"Page {page_num}",
                            difficulty=DetectionDifficulty.MEDIUM_HIGH,
                            details={
                                'total_positions': len(tm_operators),
                                'high_precision_count': high_precision,
                            }
                        ))
        
        except Exception as e:
            logger.debug(f"Failed to detect glyph positioning: {e}")
    
    def _detect_character_spacing(self):
        """Detect character spacing manipulation (Tc, Tw)"""
        logger.debug("Detecting character spacing manipulation")
        
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Contents' not in page:
                    continue
                
                stream_data = self._get_page_content_stream(page)
                if not stream_data:
                    continue
                
                content_str = stream_data.decode('latin-1', errors='replace')
                
                tc_values = re.findall(r'([\d.]+)\s+Tc', content_str)
                tw_values = re.findall(r'([\d.]+)\s+Tw', content_str)
                
                total_spacing = len(tc_values) + len(tw_values)
                
                if total_spacing > 10:
                    high_precision = sum(1 for v in tc_values + tw_values if '.' in v and len(v.split('.')[-1]) > 3)
                    
                    if high_precision > total_spacing * 0.2:
                        confidence = min(0.7, high_precision / total_spacing + 0.4)
                        
                        self.findings.append(StegoFinding(
                            technique=StegoTechnique.CHARACTER_SPACING,
                            confidence=confidence,
                            location=f"Page {page_num}",
                            difficulty=DetectionDifficulty.MEDIUM,
                            details={
                                'tc_count': len(tc_values),
                                'tw_count': len(tw_values),
                                'high_precision': high_precision,
                            }
                        ))
        
        except Exception as e:
            logger.debug(f"Failed to detect character spacing: {e}")
    
    def _detect_compression_manipulation(self):
        """Detect FlateDecode, LZW, and other compression manipulation"""
        logger.debug("Detecting compression manipulation")
        
        try:
            for obj_id in self.pdf_doc.get_objects():
                try:
                    obj = self.pdf_doc.pdf.get_object(obj_id)
                    
                    if hasattr(obj, 'get') and '/Filter' in obj:
                        filter_type = str(obj['/Filter'])
                        
                        if 'FlateDecode' in filter_type and '/DecodeParms' in obj:
                            confidence = 0.6
                            
                            self.findings.append(StegoFinding(
                                technique=StegoTechnique.FLATEDECODE_PRED,
                                confidence=confidence,
                                location=f"Object {obj_id}",
                                difficulty=DetectionDifficulty.MEDIUM_HIGH,
                                details={'filter': filter_type}
                            ))
                        
                        elif 'LZWDecode' in filter_type:
                            confidence = 0.65
                            
                            self.findings.append(StegoFinding(
                                technique=StegoTechnique.LZW_TABLE,
                                confidence=confidence,
                                location=f"Object {obj_id}",
                                difficulty=DetectionDifficulty.HIGH,
                                details={'filter': filter_type}
                            ))
                        
                        elif 'ASCII85Decode' in filter_type or 'ASCIIHexDecode' in filter_type:
                            confidence = 0.5
                            
                            self.findings.append(StegoFinding(
                                technique=StegoTechnique.ASCII_ENCODING,
                                confidence=confidence,
                                location=f"Object {obj_id}",
                                difficulty=DetectionDifficulty.MEDIUM,
                                details={'filter': filter_type}
                            ))
                
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"Failed to detect compression manipulation: {e}")
    
    def _detect_image_lsb(self):
        """Detect LSB steganography in embedded images"""
        logger.debug("Detecting image LSB steganography")
        
        if not HAS_IMAGE_LIBS:
            logger.debug("Image libraries not available, skipping LSB detection")
            return
        
        try:
            for obj_id in self.pdf_doc.get_objects():
                try:
                    obj = self.pdf_doc.pdf.get_object(obj_id)
                    
                    if hasattr(obj, 'get') and obj.get('/Subtype') == '/Image':
                        if hasattr(obj, 'read_bytes'):
                            image_data = obj.read_bytes()
                            
                            lsb_entropy = self._calculate_lsb_entropy(image_data)
                            
                            if lsb_entropy > 0.8:
                                confidence = min(0.9, lsb_entropy)
                                
                                self.findings.append(StegoFinding(
                                    technique=StegoTechnique.IMAGE_LSB,
                                    confidence=confidence,
                                    location=f"Image object {obj_id}",
                                    difficulty=DetectionDifficulty.MEDIUM,
                                    details={'lsb_entropy': lsb_entropy}
                                ))
                
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"Failed to detect image LSB: {e}")
    
    def _calculate_lsb_entropy(self, data: bytes) -> float:
        """Calculate entropy of LSB in data"""
        if len(data) < 100:
            return 0.0
        
        lsb_bits = [byte & 1 for byte in data[:1000]]
        
        ones = sum(lsb_bits)
        zeros = len(lsb_bits) - ones
        
        if zeros == 0 or ones == 0:
            return 0.0
        
        p_zero = zeros / len(lsb_bits)
        p_one = ones / len(lsb_bits)
        
        entropy = -(p_zero * math.log2(p_zero) + p_one * math.log2(p_one))
        
        return entropy
    
    def _detect_transparency_manipulation(self):
        """Detect transparency/opacity manipulation"""
        logger.debug("Detecting transparency manipulation")
        
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Contents' not in page:
                    continue
                
                stream_data = self._get_page_content_stream(page)
                if not stream_data:
                    continue
                
                content_str = stream_data.decode('latin-1', errors='replace')
                
                ca_values = re.findall(r'([\d.]+)\s+ca', content_str)
                CA_values = re.findall(r'([\d.]+)\s+CA', content_str)
                
                total_alpha = len(ca_values) + len(CA_values)
                
                if total_alpha > 5:
                    high_precision = sum(1 for v in ca_values + CA_values if '.' in v and len(v.split('.')[-1]) > 2)
                    
                    if high_precision > total_alpha * 0.3:
                        confidence = min(0.75, high_precision / total_alpha + 0.4)
                        
                        self.findings.append(StegoFinding(
                            technique=StegoTechnique.TRANSPARENCY,
                            confidence=confidence,
                            location=f"Page {page_num}",
                            difficulty=DetectionDifficulty.MEDIUM_HIGH,
                            details={
                                'alpha_count': total_alpha,
                                'high_precision': high_precision,
                            }
                        ))
        
        except Exception as e:
            logger.debug(f"Failed to detect transparency manipulation: {e}")
    
    def _detect_colorspace_manipulation(self):
        """Detect color space manipulation"""
        logger.debug("Detecting colorspace manipulation")
        
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Resources' not in page or '/ColorSpace' not in page['/Resources']:
                    continue
                
                colorspaces = page['/Resources']['/ColorSpace']
                
                custom_colorspaces = []
                for cs_name, cs_obj in colorspaces.items():
                    cs_type = str(cs_obj) if not isinstance(cs_obj, list) else str(cs_obj[0])
                    if 'ICCBased' in cs_type or 'CalRGB' in cs_type or 'Lab' in cs_type:
                        custom_colorspaces.append(cs_name)
                
                if custom_colorspaces:
                    confidence = 0.65
                    
                    self.findings.append(StegoFinding(
                        technique=StegoTechnique.COLORSPACE,
                        confidence=confidence,
                        location=f"Page {page_num}",
                        difficulty=DetectionDifficulty.HIGH,
                        details={'custom_colorspaces': [str(cs) for cs in custom_colorspaces]}
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to detect colorspace manipulation: {e}")
    
    def _detect_page_rotation_covert(self):
        """Detect page rotation as covert channel"""
        logger.debug("Detecting page rotation covert channel")
        
        try:
            rotations = []
            for page in self.pdf_doc.get_pages():
                rotation = page.get('/Rotate', 0)
                rotations.append(int(rotation))
            
            if len(rotations) > 5:
                non_zero = sum(1 for r in rotations if r != 0)
                unique_rotations = len(set(rotations))
                
                if non_zero > 2 and unique_rotations > 1:
                    confidence = min(0.7, non_zero / len(rotations) + 0.3)
                    
                    self.findings.append(StegoFinding(
                        technique=StegoTechnique.PAGE_ROTATION,
                        confidence=confidence,
                        location="Page rotations",
                        difficulty=DetectionDifficulty.MEDIUM,
                        details={
                            'total_pages': len(rotations),
                            'rotated_pages': non_zero,
                            'rotation_pattern': rotations,
                        }
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to detect page rotation: {e}")
    
    def _detect_metadata_custom(self):
        """Detect custom metadata fields"""
        logger.debug("Detecting custom metadata")
        
        try:
            pdf = self.pdf_doc.pdf
            
            if pdf.docinfo:
                standard_keys = {
                    '/Title', '/Author', '/Subject', '/Keywords', '/Creator', '/Producer',
                    '/CreationDate', '/ModDate', '/Trapped'
                }
                
                custom_keys = []
                extracted_data = {}
                
                for key, value in pdf.docinfo.items():
                    if str(key) not in standard_keys:
                        custom_keys.append(str(key))
                        extracted_data[str(key)] = str(value)
                
                if custom_keys:
                    confidence = min(0.8, len(custom_keys) / 3.0 + 0.5)
                    
                    data_str = '\n'.join(f"{k}: {v}" for k, v in extracted_data.items())
                    
                    self.findings.append(StegoFinding(
                        technique=StegoTechnique.METADATA_CUSTOM,
                        confidence=confidence,
                        location="Document Info dictionary",
                        extracted_data=data_str.encode('utf-8'),
                        difficulty=DetectionDifficulty.LOW,
                        details={'custom_keys': custom_keys}
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to detect custom metadata: {e}")
    
    def _get_page_content_stream(self, page) -> Optional[bytes]:
        """Get decompressed content stream from page"""
        if '/Contents' not in page:
            return None
        
        contents = page['/Contents']
        stream_data = b''
        
        if isinstance(contents, list):
            for content in contents:
                try:
                    stream_data += bytes(content.read_bytes())
                except Exception:
                    pass
        else:
            try:
                stream_data = bytes(contents.read_bytes())
            except Exception:
                return None
        
        return stream_data
    
    def _calculate_sequence_entropy(self, sequence: List[int]) -> float:
        """Calculate Shannon entropy of a sequence"""
        if not sequence:
            return 0.0
        
        from collections import Counter
        counts = Counter(sequence)
        total = len(sequence)
        
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1.0
        
        return entropy / max_entropy if max_entropy > 0 else 0.0


def solve_steganography(
    pdf_path: Path,
    output_dir: Optional[Path] = None,
    techniques: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Detect and solve steganography in PDF
    
    Args:
        pdf_path: Path to PDF file
        output_dir: Output directory for extracted data
        techniques: Specific techniques to check (None = all)
        
    Returns:
        Dictionary with detection results
    """
    logger.info(f"Solving steganography in {pdf_path}")
    
    pdf_doc = PDFDocument.open(Path(pdf_path))
    solver = StegoSolver(pdf_doc)
    
    findings = solver.detect_all()
    
    if findings:
        extract_dir = solver.extract_all(output_dir)
        
        logger.info(f"Extracted {len(findings)} findings to {extract_dir}")
    
    return {
        'total_findings': len(findings),
        'findings': [f.to_dict() for f in findings],
        'techniques_detected': list(set(f.technique.value for f in findings)),
        'high_confidence_findings': [
            f.to_dict() for f in findings if f.confidence >= 0.8
        ],
        'extracted_data_available': any(f.extracted_data for f in findings),
    }
