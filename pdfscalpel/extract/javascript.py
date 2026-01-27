"""JavaScript extraction and deobfuscation from PDF files"""

from pathlib import Path
from typing import Optional, List, Dict, Any
import re
import base64
import codecs

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class JavaScriptExtractor:
    """Extract and analyze JavaScript from PDF"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.scripts: List[Dict[str, Any]] = []
    
    def extract_all(self, deobfuscate: bool = True) -> List[Dict[str, Any]]:
        """
        Extract all JavaScript from PDF
        
        Args:
            deobfuscate: Attempt to deobfuscate extracted JavaScript
        
        Returns:
            List of dictionaries containing JavaScript code and metadata
        """
        logger.debug(f"Extracting JavaScript from {self.pdf_doc.path}")
        
        self.scripts = []
        
        self._extract_from_names_tree()
        self._extract_from_open_action()
        self._extract_from_additional_actions()
        self._extract_from_annotations()
        self._extract_from_form_fields()
        
        if deobfuscate:
            for script in self.scripts:
                if script['code']:
                    script['deobfuscated'] = self._deobfuscate_javascript(script['code'])
                    script['obfuscation_detected'] = script['code'] != script['deobfuscated']
        
        logger.info(f"Extracted {len(self.scripts)} JavaScript blocks")
        return self.scripts
    
    def _extract_from_names_tree(self):
        """Extract JavaScript from document-level Names tree"""
        try:
            root = self.pdf_doc.root
            if '/Names' not in root:
                return
            
            names = root['/Names']
            if '/JavaScript' not in names:
                return
            
            js_names = names['/JavaScript']
            if '/Names' in js_names:
                names_array = js_names['/Names']
                
                for i in range(0, len(names_array), 2):
                    try:
                        name = str(names_array[i])
                        js_dict = names_array[i + 1]
                        
                        if '/JS' in js_dict:
                            code = self._extract_js_code(js_dict['/JS'])
                            if code:
                                self.scripts.append({
                                    'source': 'Names tree',
                                    'name': name,
                                    'code': code,
                                    'location': f'/Names/JavaScript/{name}',
                                    'deobfuscated': None,
                                    'obfuscation_detected': False,
                                })
                    except Exception as e:
                        logger.debug(f"Failed to extract JavaScript from Names tree entry: {e}")
        
        except Exception as e:
            logger.debug(f"Failed to extract JavaScript from Names tree: {e}")
    
    def _extract_from_open_action(self):
        """Extract JavaScript from OpenAction"""
        try:
            root = self.pdf_doc.root
            if '/OpenAction' not in root:
                return
            
            action = root['/OpenAction']
            self._extract_from_action(action, 'OpenAction', '/OpenAction')
        
        except Exception as e:
            logger.debug(f"Failed to extract JavaScript from OpenAction: {e}")
    
    def _extract_from_additional_actions(self):
        """Extract JavaScript from AA (Additional Actions)"""
        try:
            root = self.pdf_doc.root
            if '/AA' not in root:
                return
            
            aa_dict = root['/AA']
            
            trigger_types = ['/WC', '/WS', '/DS', '/WP', '/DP']
            for trigger in trigger_types:
                if trigger in aa_dict:
                    self._extract_from_action(aa_dict[trigger], f'AA {trigger}', f'/AA{trigger}')
        
        except Exception as e:
            logger.debug(f"Failed to extract JavaScript from AA: {e}")
    
    def _extract_from_annotations(self):
        """Extract JavaScript from page annotations"""
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Annots' not in page:
                    continue
                
                annots = page['/Annots']
                for i, annot in enumerate(annots):
                    try:
                        if '/A' in annot:
                            self._extract_from_action(
                                annot['/A'],
                                f'Annotation (page {page_num}, annot {i})',
                                f'/Page[{page_num}]/Annots[{i}]/A'
                            )
                        
                        if '/AA' in annot:
                            aa_dict = annot['/AA']
                            for trigger in aa_dict.keys():
                                self._extract_from_action(
                                    aa_dict[trigger],
                                    f'Annotation AA {trigger} (page {page_num})',
                                    f'/Page[{page_num}]/Annots[{i}]/AA{trigger}'
                                )
                    except Exception as e:
                        logger.debug(f"Failed to extract JavaScript from annotation: {e}")
        
        except Exception as e:
            logger.debug(f"Failed to extract JavaScript from annotations: {e}")
    
    def _extract_from_form_fields(self):
        """Extract JavaScript from form field actions"""
        try:
            root = self.pdf_doc.root
            if '/AcroForm' not in root:
                return
            
            acroform = root['/AcroForm']
            if '/Fields' not in acroform:
                return
            
            fields = acroform['/Fields']
            self._extract_from_field_list(fields, [])
        
        except Exception as e:
            logger.debug(f"Failed to extract JavaScript from form fields: {e}")
    
    def _extract_from_field_list(self, fields, path: List[str]):
        """Recursively extract JavaScript from form fields"""
        for i, field in enumerate(fields):
            try:
                field_path = path + [str(i)]
                field_name = field.get('/T', 'unnamed')
                
                if '/AA' in field:
                    aa_dict = field['/AA']
                    for trigger in aa_dict.keys():
                        self._extract_from_action(
                            aa_dict[trigger],
                            f'Form field {field_name} AA {trigger}',
                            f'/AcroForm/Fields[{"/".join(field_path)}]/AA{trigger}'
                        )
                
                if '/A' in field:
                    self._extract_from_action(
                        field['/A'],
                        f'Form field {field_name} action',
                        f'/AcroForm/Fields[{"/".join(field_path)}]/A'
                    )
                
                if '/Kids' in field:
                    self._extract_from_field_list(field['/Kids'], field_path)
            
            except Exception as e:
                logger.debug(f"Failed to extract JavaScript from form field: {e}")
    
    def _extract_from_action(self, action, source: str, location: str):
        """Extract JavaScript from an action dictionary"""
        try:
            if not action:
                return
            
            if '/S' in action and action['/S'] == '/JavaScript':
                if '/JS' in action:
                    code = self._extract_js_code(action['/JS'])
                    if code:
                        self.scripts.append({
                            'source': source,
                            'name': None,
                            'code': code,
                            'location': location,
                            'deobfuscated': None,
                            'obfuscation_detected': False,
                        })
            
            if '/Next' in action:
                next_action = action['/Next']
                if isinstance(next_action, list):
                    for i, na in enumerate(next_action):
                        self._extract_from_action(na, f'{source} (Next {i})', f'{location}/Next[{i}]')
                else:
                    self._extract_from_action(next_action, f'{source} (Next)', f'{location}/Next')
        
        except Exception as e:
            logger.debug(f"Failed to extract JavaScript from action: {e}")
    
    def _extract_js_code(self, js_obj) -> Optional[str]:
        """Extract JavaScript code from a JS object (string or stream)"""
        try:
            if isinstance(js_obj, str):
                return js_obj
            
            if hasattr(js_obj, 'read_bytes'):
                code = bytes(js_obj.read_bytes()).decode('utf-8', errors='replace')
                return code
            
            return str(js_obj)
        
        except Exception as e:
            logger.debug(f"Failed to extract JavaScript code: {e}")
            return None
    
    def _deobfuscate_javascript(self, code: str) -> str:
        """
        Attempt to deobfuscate common JavaScript obfuscation patterns
        
        Common patterns:
        - eval(unescape(...))
        - String.fromCharCode(...)
        - Hex/Unicode escapes
        - Base64 encoding
        """
        original = code
        
        code = self._deobfuscate_unescape(code)
        code = self._deobfuscate_fromcharcode(code)
        code = self._deobfuscate_hex_escapes(code)
        code = self._deobfuscate_base64(code)
        code = self._beautify_javascript(code)
        
        return code
    
    def _deobfuscate_unescape(self, code: str) -> str:
        """Deobfuscate unescape() patterns"""
        pattern = r'unescape\(["\']([^"\']+)["\']\)'
        
        def replace_unescape(match):
            try:
                escaped = match.group(1)
                return codecs.decode(escaped, 'unicode_escape')
            except Exception:
                return match.group(0)
        
        return re.sub(pattern, replace_unescape, code)
    
    def _deobfuscate_fromcharcode(self, code: str) -> str:
        """Deobfuscate String.fromCharCode() patterns"""
        pattern = r'String\.fromCharCode\(([0-9,\s]+)\)'
        
        def replace_fromcharcode(match):
            try:
                char_codes = [int(x.strip()) for x in match.group(1).split(',')]
                return '"' + ''.join(chr(c) for c in char_codes) + '"'
            except Exception:
                return match.group(0)
        
        return re.sub(pattern, replace_fromcharcode, code)
    
    def _deobfuscate_hex_escapes(self, code: str) -> str:
        """Deobfuscate hex escape sequences"""
        try:
            return codecs.decode(code, 'unicode_escape')
        except Exception:
            return code
    
    def _deobfuscate_base64(self, code: str) -> str:
        """Detect and decode base64 strings"""
        pattern = r'atob\(["\']([A-Za-z0-9+/=]+)["\']\)'
        
        def replace_base64(match):
            try:
                b64_str = match.group(1)
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='replace')
                return f'"{decoded}"'
            except Exception:
                return match.group(0)
        
        return re.sub(pattern, replace_base64, code)
    
    def _beautify_javascript(self, code: str) -> str:
        """Basic JavaScript beautification"""
        code = code.replace(';', ';\n')
        code = code.replace('{', '{\n')
        code = code.replace('}', '\n}\n')
        
        lines = []
        indent = 0
        for line in code.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('}'):
                indent = max(0, indent - 1)
            
            lines.append('  ' * indent + line)
            
            if line.endswith('{'):
                indent += 1
            elif line.endswith('}'):
                pass
        
        return '\n'.join(lines)


def extract_javascript(
    input_pdf: Path,
    output_dir: Optional[Path] = None,
    deobfuscate: bool = True,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Extract JavaScript from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_dir: Optional output directory for individual JS files
        deobfuscate: Attempt to deobfuscate JavaScript
        password: Optional password for encrypted PDFs
    
    Returns:
        List of JavaScript blocks with metadata
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = JavaScriptExtractor(pdf_doc)
        scripts = extractor.extract_all(deobfuscate=deobfuscate)
        
        if output_dir and scripts:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            for i, script in enumerate(scripts):
                filename = f"script_{i:03d}"
                if script['name']:
                    safe_name = re.sub(r'[^\w\-]', '_', script['name'])
                    filename = f"{i:03d}_{safe_name}"
                
                js_file = output_dir / f"{filename}.js"
                js_file.write_text(script['code'], encoding='utf-8')
                
                if script.get('deobfuscated'):
                    deob_file = output_dir / f"{filename}_deobfuscated.js"
                    deob_file.write_text(script['deobfuscated'], encoding='utf-8')
                
                meta_file = output_dir / f"{filename}_meta.txt"
                meta_content = f"Source: {script['source']}\n"
                meta_content += f"Location: {script['location']}\n"
                if script['name']:
                    meta_content += f"Name: {script['name']}\n"
                meta_content += f"Obfuscation detected: {script.get('obfuscation_detected', False)}\n"
                meta_file.write_text(meta_content, encoding='utf-8')
                
                logger.debug(f"Saved JavaScript to: {js_file}")
        
        return scripts
