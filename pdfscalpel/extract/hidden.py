"""Hidden data extraction from PDF files"""

from pathlib import Path
from typing import Optional, List, Dict, Any
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
from pdfscalpel.core.logging import get_logger

logger = get_logger()


ZERO_WIDTH_CHARS = {
    '\u200B': 'ZERO WIDTH SPACE',
    '\u200C': 'ZERO WIDTH NON-JOINER',
    '\u200D': 'ZERO WIDTH JOINER',
    '\uFEFF': 'ZERO WIDTH NO-BREAK SPACE',
    '\u180E': 'MONGOLIAN VOWEL SEPARATOR',
    '\u2060': 'WORD JOINER',
    '\u2062': 'INVISIBLE TIMES',
    '\u2063': 'INVISIBLE SEPARATOR',
    '\u2064': 'INVISIBLE PLUS',
}


class HiddenDataExtractor:
    """Extract hidden data from PDF"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.findings: List[Dict[str, Any]] = []
    
    def extract_all(self) -> List[Dict[str, Any]]:
        """
        Extract all types of hidden data from PDF
        
        Returns:
            List of hidden data findings
        """
        logger.debug(f"Searching for hidden data in {self.pdf_doc.path}")
        
        self.findings = []
        
        self._find_invisible_text_layers()
        self._find_zero_width_characters()
        self._find_white_on_white_text()
        self._find_whitespace_encoding()
        self._find_tiny_text()
        self._find_text_behind_images()
        
        logger.info(f"Found {len(self.findings)} hidden data occurrences")
        return self.findings
    
    def _find_invisible_text_layers(self):
        """Find text with rendering mode 3 (invisible)"""
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Contents' not in page:
                    continue
                
                contents = page['/Contents']
                if isinstance(contents, list):
                    stream_data = b''
                    for content in contents:
                        try:
                            stream_data += bytes(content.read_bytes())
                        except Exception:
                            pass
                else:
                    try:
                        stream_data = bytes(contents.read_bytes())
                    except Exception:
                        continue
                
                content_str = stream_data.decode('latin-1', errors='replace')
                
                invisible_texts = self._extract_invisible_text(content_str)
                
                for text in invisible_texts:
                    self.findings.append({
                        'type': 'invisible_text_layer',
                        'page': page_num,
                        'data': text,
                        'method': 'Text rendering mode 3 (invisible)',
                        'location': f'Page {page_num} content stream',
                    })
        
        except Exception as e:
            logger.debug(f"Failed to find invisible text layers: {e}")
    
    def _extract_invisible_text(self, content: str) -> List[str]:
        """Extract text between Tr 3 (invisible mode) operators"""
        texts = []
        
        lines = content.split('\n')
        invisible_mode = False
        current_text = []
        
        for line in lines:
            line = line.strip()
            
            if re.match(r'^3\s+Tr', line):
                invisible_mode = True
            elif re.match(r'^\d+\s+Tr', line):
                if invisible_mode and current_text:
                    texts.append(' '.join(current_text))
                    current_text = []
                invisible_mode = False
            
            if invisible_mode:
                tj_match = re.search(r'\(([^)]+)\)\s*Tj', line)
                if tj_match:
                    current_text.append(tj_match.group(1))
                
                tj_array_match = re.search(r'\[(.*?)\]\s*TJ', line)
                if tj_array_match:
                    array_content = tj_array_match.group(1)
                    strings = re.findall(r'\(([^)]+)\)', array_content)
                    current_text.extend(strings)
        
        if invisible_mode and current_text:
            texts.append(' '.join(current_text))
        
        return texts
    
    def _find_zero_width_characters(self):
        """Find zero-width Unicode characters"""
        if pdfplumber is None:
            logger.debug("pdfplumber not available, skipping zero-width character detection")
            return
        
        try:
            with pdfplumber.open(self.pdf_doc.path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    text = page.extract_text()
                    if not text:
                        continue
                    
                    for char, name in ZERO_WIDTH_CHARS.items():
                        if char in text:
                            count = text.count(char)
                            
                            encoded = self._encode_zero_width_binary(text)
                            
                            self.findings.append({
                                'type': 'zero_width_characters',
                                'page': page_num,
                                'character': name,
                                'unicode': f'U+{ord(char):04X}',
                                'count': count,
                                'data': encoded if encoded else text.replace(char, f'[{name}]'),
                                'method': f'Zero-width character: {name}',
                                'location': f'Page {page_num}',
                            })
        
        except Exception as e:
            logger.debug(f"Failed to find zero-width characters: {e}")
    
    def _encode_zero_width_binary(self, text: str) -> Optional[str]:
        """Attempt to decode zero-width character binary encoding"""
        try:
            zero_width_present = any(char in text for char in ZERO_WIDTH_CHARS)
            if not zero_width_present:
                return None
            
            binary = ''
            for char in text:
                if char == '\u200B':
                    binary += '0'
                elif char == '\u200C':
                    binary += '1'
            
            if len(binary) >= 8 and len(binary) % 8 == 0:
                decoded = ''
                for i in range(0, len(binary), 8):
                    byte = binary[i:i+8]
                    try:
                        decoded += chr(int(byte, 2))
                    except ValueError:
                        return None
                
                if decoded.isprintable() or any(c in decoded for c in '\r\n\t'):
                    return f"Decoded binary: {decoded}"
            
            return None
        
        except Exception:
            return None
    
    def _find_white_on_white_text(self):
        """Find white text on white background"""
        if pdfplumber is None:
            logger.debug("pdfplumber not available, skipping white-on-white detection")
            return
        
        try:
            with pdfplumber.open(self.pdf_doc.path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    chars = page.chars
                    
                    white_chars = []
                    for char in chars:
                        stroking = char.get('stroking_color')
                        non_stroking = char.get('non_stroking_color')
                        
                        is_white = False
                        if isinstance(stroking, (list, tuple)):
                            if all(c >= 0.9 for c in stroking):
                                is_white = True
                        if isinstance(non_stroking, (list, tuple)):
                            if all(c >= 0.9 for c in non_stroking):
                                is_white = True
                        
                        if is_white:
                            white_chars.append(char.get('text', ''))
                    
                    if white_chars:
                        white_text = ''.join(white_chars)
                        self.findings.append({
                            'type': 'white_on_white_text',
                            'page': page_num,
                            'data': white_text,
                            'method': 'White text (color >= 0.9)',
                            'location': f'Page {page_num}',
                            'char_count': len(white_chars),
                        })
        
        except Exception as e:
            logger.debug(f"Failed to find white-on-white text: {e}")
    
    def _find_whitespace_encoding(self):
        """Find data encoded in whitespace patterns"""
        if pdfplumber is None:
            logger.debug("pdfplumber not available, skipping whitespace encoding detection")
            return
        
        try:
            with pdfplumber.open(self.pdf_doc.path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    text = page.extract_text()
                    if not text:
                        continue
                    
                    lines = text.split('\n')
                    for line_num, line in enumerate(lines):
                        trailing_spaces = len(line) - len(line.rstrip(' \t'))
                        
                        if trailing_spaces > 5:
                            whitespace = line[len(line.rstrip(' \t')):]
                            
                            binary = whitespace.replace(' ', '0').replace('\t', '1')
                            
                            if len(binary) >= 8 and len(binary) % 8 == 0:
                                decoded = self._decode_binary_whitespace(binary)
                                if decoded:
                                    self.findings.append({
                                        'type': 'whitespace_encoding',
                                        'page': page_num,
                                        'line': line_num,
                                        'data': decoded,
                                        'method': 'Trailing whitespace (space=0, tab=1)',
                                        'location': f'Page {page_num}, line {line_num}',
                                        'raw_binary': binary,
                                    })
        
        except Exception as e:
            logger.debug(f"Failed to find whitespace encoding: {e}")
    
    def _decode_binary_whitespace(self, binary: str) -> Optional[str]:
        """Decode binary string from whitespace"""
        try:
            decoded = ''
            for i in range(0, len(binary), 8):
                byte = binary[i:i+8]
                char_code = int(byte, 2)
                if 32 <= char_code <= 126 or char_code in [9, 10, 13]:
                    decoded += chr(char_code)
                else:
                    return None
            
            return decoded if decoded else None
        
        except Exception:
            return None
    
    def _find_tiny_text(self):
        """Find extremely small text (potential hidden data)"""
        if pdfplumber is None:
            logger.debug("pdfplumber not available, skipping tiny text detection")
            return
        
        try:
            with pdfplumber.open(self.pdf_doc.path) as pdf:
                for page_num, page in enumerate(pdf.pages):
                    chars = page.chars
                    
                    tiny_chars = []
                    for char in chars:
                        size = char.get('size', 12)
                        if size < 1:
                            tiny_chars.append(char.get('text', ''))
                    
                    if tiny_chars:
                        tiny_text = ''.join(tiny_chars)
                        self.findings.append({
                            'type': 'tiny_text',
                            'page': page_num,
                            'data': tiny_text,
                            'method': 'Text with size < 1pt',
                            'location': f'Page {page_num}',
                            'char_count': len(tiny_chars),
                        })
        
        except Exception as e:
            logger.debug(f"Failed to find tiny text: {e}")
    
    def _find_text_behind_images(self):
        """Find text hidden behind images (layer order)"""
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Contents' not in page:
                    continue
                
                contents = page['/Contents']
                if isinstance(contents, list):
                    stream_data = b''
                    for content in contents:
                        try:
                            stream_data += bytes(content.read_bytes())
                        except Exception:
                            pass
                else:
                    try:
                        stream_data = bytes(contents.read_bytes())
                    except Exception:
                        continue
                
                content_str = stream_data.decode('latin-1', errors='replace')
                
                hidden_behind = self._extract_text_before_images(content_str)
                
                if hidden_behind:
                    self.findings.append({
                        'type': 'text_behind_images',
                        'page': page_num,
                        'data': ' '.join(hidden_behind),
                        'method': 'Text drawn before image objects',
                        'location': f'Page {page_num} content stream',
                        'text_count': len(hidden_behind),
                    })
        
        except Exception as e:
            logger.debug(f"Failed to find text behind images: {e}")
    
    def _extract_text_before_images(self, content: str) -> List[str]:
        """Extract text that appears before image operations"""
        texts = []
        current_texts = []
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            tj_match = re.search(r'\(([^)]+)\)\s*Tj', line)
            if tj_match:
                current_texts.append(tj_match.group(1))
            
            tj_array_match = re.search(r'\[(.*?)\]\s*TJ', line)
            if tj_array_match:
                array_content = tj_array_match.group(1)
                strings = re.findall(r'\(([^)]+)\)', array_content)
                current_texts.extend(strings)
            
            if re.search(r'\bDo\b', line) and current_texts:
                texts.extend(current_texts)
                current_texts = []
        
        return texts


def extract_hidden_data(
    input_pdf: Path,
    output_file: Optional[Path] = None,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Extract hidden data from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_file: Optional output file for findings report
        password: Optional password for encrypted PDFs
    
    Returns:
        List of hidden data findings
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = HiddenDataExtractor(pdf_doc)
        findings = extractor.extract_all()
        
        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            content = "HIDDEN DATA EXTRACTION REPORT\n"
            content += "=" * 80 + "\n"
            content += f"File: {input_pdf}\n"
            content += f"Total findings: {len(findings)}\n\n"
            
            by_type = {}
            for finding in findings:
                by_type.setdefault(finding['type'], []).append(finding)
            
            for type_name, type_findings in by_type.items():
                content += f"\n{type_name.upper().replace('_', ' ')} ({len(type_findings)} occurrences)\n"
                content += "-" * 80 + "\n"
                
                for i, finding in enumerate(type_findings, 1):
                    content += f"\n#{i} - {finding['location']}\n"
                    content += f"Method: {finding['method']}\n"
                    content += f"Data: {finding['data'][:200]}"
                    if len(str(finding['data'])) > 200:
                        content += "...(truncated)"
                    content += "\n"
            
            output_file.write_text(content, encoding='utf-8')
            logger.info(f"Hidden data report saved to: {output_file}")
        
        return findings
