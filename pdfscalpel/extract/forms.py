"""Form extraction from PDF files (AcroForm and XFA)"""

from pathlib import Path
from typing import Optional, List, Dict, Any
import xml.etree.ElementTree as ET
import re

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class FormsExtractor:
    """Extract and analyze PDF forms (AcroForm and XFA)"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.acroform_fields: List[Dict[str, Any]] = []
        self.xfa_data: Optional[Dict[str, Any]] = None
        self.javascript_from_forms: List[Dict[str, Any]] = []
    
    def extract_all(self) -> Dict[str, Any]:
        """
        Extract all form data from PDF
        
        Returns:
            Dictionary containing AcroForm fields, XFA data, and JavaScript
        """
        logger.debug(f"Extracting forms from {self.pdf_doc.path}")
        
        has_forms = self._check_for_forms()
        
        if has_forms:
            self._extract_acroform_fields()
            self._extract_xfa_data()
            self._extract_form_javascript()
        
        result = {
            'has_forms': has_forms,
            'acroform_fields': self.acroform_fields,
            'xfa_data': self.xfa_data,
            'javascript': self.javascript_from_forms,
            'total_fields': len(self.acroform_fields),
            'total_scripts': len(self.javascript_from_forms),
        }
        
        logger.info(f"Extracted {len(self.acroform_fields)} form fields, "
                   f"{len(self.javascript_from_forms)} JavaScript blocks")
        
        return result
    
    def _check_for_forms(self) -> bool:
        """Check if PDF contains forms"""
        try:
            root = self.pdf_doc.root
            return '/AcroForm' in root
        except Exception:
            return False
    
    def _extract_acroform_fields(self):
        """Extract AcroForm fields"""
        try:
            root = self.pdf_doc.root
            if '/AcroForm' not in root:
                return
            
            acroform = root['/AcroForm']
            
            if '/Fields' not in acroform:
                return
            
            fields = acroform['/Fields']
            self._process_field_array(fields, parent_path=[])
        
        except Exception as e:
            logger.debug(f"Failed to extract AcroForm fields: {e}")
    
    def _process_field_array(self, fields, parent_path: List[str]):
        """Recursively process form field array"""
        for i, field in enumerate(fields):
            try:
                self._process_field(field, parent_path, i)
            except Exception as e:
                logger.debug(f"Failed to process field: {e}")
    
    def _process_field(self, field, parent_path: List[str], index: int):
        """Process a single form field"""
        field_info = {
            'index': index,
            'path': parent_path + [str(index)],
        }
        
        if '/T' in field:
            field_info['name'] = str(field['/T'])
        else:
            field_info['name'] = f'field_{index}'
        
        if '/FT' in field:
            field_type = str(field['/FT'])
            field_info['type'] = {
                '/Tx': 'text',
                '/Btn': 'button',
                '/Ch': 'choice',
                '/Sig': 'signature',
            }.get(field_type, field_type)
        else:
            field_info['type'] = 'unknown'
        
        if '/V' in field:
            try:
                field_info['value'] = str(field['/V'])
            except Exception:
                field_info['value'] = repr(field['/V'])
        else:
            field_info['value'] = None
        
        if '/DV' in field:
            try:
                field_info['default_value'] = str(field['/DV'])
            except Exception:
                field_info['default_value'] = repr(field['/DV'])
        else:
            field_info['default_value'] = None
        
        if '/TU' in field:
            field_info['tooltip'] = str(field['/TU'])
        
        if '/TM' in field:
            field_info['mapping_name'] = str(field['/TM'])
        
        field_info['flags'] = self._parse_field_flags(field)
        
        field_info['actions'] = self._extract_field_actions(field)
        
        if field_info['type'] == 'choice':
            field_info['options'] = self._extract_choice_options(field)
        
        field_info['calculations'] = self._extract_field_calculations(field)
        
        field_info['validation'] = self._extract_field_validation(field)
        
        field_info['format'] = self._extract_field_format(field)
        
        field_info['hidden'] = field_info['flags'].get('hidden', False)
        
        if '/Kids' in field:
            kids = field['/Kids']
            field_info['has_children'] = True
            self._process_field_array(kids, parent_path + [field_info['name']])
        else:
            field_info['has_children'] = False
            self.acroform_fields.append(field_info)
    
    def _parse_field_flags(self, field) -> Dict[str, bool]:
        """Parse field flags"""
        flags = {}
        
        if '/Ff' in field:
            ff = int(field['/Ff'])
            
            flags['readonly'] = bool(ff & 1)
            flags['required'] = bool(ff & 2)
            flags['no_export'] = bool(ff & 4)
            flags['multiline'] = bool(ff & (1 << 12))
            flags['password'] = bool(ff & (1 << 13))
            flags['file_select'] = bool(ff & (1 << 20))
            flags['do_not_spell_check'] = bool(ff & (1 << 22))
            flags['do_not_scroll'] = bool(ff & (1 << 23))
            flags['comb'] = bool(ff & (1 << 24))
            flags['rich_text'] = bool(ff & (1 << 25))
            flags['hidden'] = bool(ff & (1 << 1))
        
        return flags
    
    def _extract_field_actions(self, field) -> Dict[str, Any]:
        """Extract field actions"""
        actions = {}
        
        if '/AA' in field:
            aa = field['/AA']
            
            action_types = {
                '/K': 'keystroke',
                '/F': 'format',
                '/V': 'validate',
                '/C': 'calculate',
            }
            
            for key, name in action_types.items():
                if key in aa:
                    action = aa[key]
                    actions[name] = self._parse_action(action)
        
        if '/A' in field:
            actions['default'] = self._parse_action(field['/A'])
        
        return actions
    
    def _parse_action(self, action) -> Dict[str, Any]:
        """Parse action dictionary"""
        action_info = {}
        
        if '/S' in action:
            action_type = str(action['/S'])
            action_info['type'] = action_type
            
            if action_type == '/JavaScript':
                if '/JS' in action:
                    js_code = self._extract_js_from_action(action['/JS'])
                    action_info['javascript'] = js_code
            elif action_type == '/SubmitForm':
                if '/F' in action:
                    action_info['url'] = str(action['/F'])
                if '/Fields' in action:
                    action_info['fields'] = [str(f) for f in action['/Fields']]
            elif action_type == '/ResetForm':
                if '/Fields' in action:
                    action_info['fields'] = [str(f) for f in action['/Fields']]
            elif action_type == '/ImportData':
                if '/F' in action:
                    action_info['file'] = str(action['/F'])
        
        return action_info
    
    def _extract_js_from_action(self, js_obj) -> Optional[str]:
        """Extract JavaScript code from action"""
        try:
            if isinstance(js_obj, str):
                return js_obj
            
            if hasattr(js_obj, 'read_bytes'):
                return bytes(js_obj.read_bytes()).decode('utf-8', errors='replace')
            
            return str(js_obj)
        except Exception:
            return None
    
    def _extract_choice_options(self, field) -> List[Any]:
        """Extract options from choice field"""
        options = []
        
        try:
            if '/Opt' in field:
                opt = field['/Opt']
                for item in opt:
                    if isinstance(item, (list, tuple)):
                        options.append({
                            'export_value': str(item[0]),
                            'display_value': str(item[1]) if len(item) > 1 else str(item[0]),
                        })
                    else:
                        options.append({
                            'export_value': str(item),
                            'display_value': str(item),
                        })
        except Exception as e:
            logger.debug(f"Failed to extract choice options: {e}")
        
        return options
    
    def _extract_field_calculations(self, field) -> Optional[str]:
        """Extract calculation script from field"""
        try:
            if '/AA' in field and '/C' in field['/AA']:
                calc_action = field['/AA']['/C']
                if '/S' in calc_action and calc_action['/S'] == '/JavaScript':
                    if '/JS' in calc_action:
                        return self._extract_js_from_action(calc_action['/JS'])
        except Exception:
            pass
        return None
    
    def _extract_field_validation(self, field) -> Optional[str]:
        """Extract validation script from field"""
        try:
            if '/AA' in field and '/V' in field['/AA']:
                val_action = field['/AA']['/V']
                if '/S' in val_action and val_action['/S'] == '/JavaScript':
                    if '/JS' in val_action:
                        return self._extract_js_from_action(val_action['/JS'])
        except Exception:
            pass
        return None
    
    def _extract_field_format(self, field) -> Optional[str]:
        """Extract format script from field"""
        try:
            if '/AA' in field and '/F' in field['/AA']:
                fmt_action = field['/AA']['/F']
                if '/S' in fmt_action and fmt_action['/S'] == '/JavaScript':
                    if '/JS' in fmt_action:
                        return self._extract_js_from_action(fmt_action['/JS'])
        except Exception:
            pass
        return None
    
    def _extract_xfa_data(self):
        """Extract XFA (XML Forms Architecture) data"""
        try:
            root = self.pdf_doc.root
            if '/AcroForm' not in root:
                return
            
            acroform = root['/AcroForm']
            if '/XFA' not in acroform:
                return
            
            xfa = acroform['/XFA']
            
            xfa_xml = self._extract_xfa_xml(xfa)
            
            if xfa_xml:
                self.xfa_data = {
                    'has_xfa': True,
                    'xml_raw': xfa_xml,
                    'parsed': self._parse_xfa_xml(xfa_xml),
                }
        
        except Exception as e:
            logger.debug(f"Failed to extract XFA data: {e}")
    
    def _extract_xfa_xml(self, xfa) -> Optional[str]:
        """Extract XFA XML content"""
        try:
            if isinstance(xfa, list):
                xml_parts = []
                for i in range(0, len(xfa), 2):
                    if i + 1 < len(xfa):
                        stream_obj = xfa[i + 1]
                        if hasattr(stream_obj, 'read_bytes'):
                            xml_data = bytes(stream_obj.read_bytes()).decode('utf-8', errors='replace')
                            xml_parts.append(xml_data)
                
                return ''.join(xml_parts)
            
            elif hasattr(xfa, 'read_bytes'):
                return bytes(xfa.read_bytes()).decode('utf-8', errors='replace')
        
        except Exception as e:
            logger.debug(f"Failed to extract XFA XML: {e}")
        
        return None
    
    def _parse_xfa_xml(self, xml_content: str) -> Dict[str, Any]:
        """Parse XFA XML structure"""
        try:
            root = ET.fromstring(xml_content)
            
            return {
                'root_tag': root.tag,
                'namespaces': dict(root.attrib),
                'structure': self._xml_to_dict(root),
            }
        
        except Exception as e:
            logger.debug(f"Failed to parse XFA XML: {e}")
            return {'error': str(e)}
    
    def _xml_to_dict(self, element, max_depth: int = 5, current_depth: int = 0) -> Dict[str, Any]:
        """Convert XML element to dictionary"""
        if current_depth > max_depth:
            return {'_truncated': True}
        
        result = {
            'tag': element.tag.split('}')[-1] if '}' in element.tag else element.tag,
            'attributes': dict(element.attrib),
        }
        
        if element.text and element.text.strip():
            result['text'] = element.text.strip()
        
        children = list(element)
        if children:
            result['children'] = [
                self._xml_to_dict(child, max_depth, current_depth + 1)
                for child in children
            ]
        
        return result
    
    def _extract_form_javascript(self):
        """Collect all JavaScript from form fields"""
        for field in self.acroform_fields:
            for action_type, action_info in field.get('actions', {}).items():
                if 'javascript' in action_info:
                    self.javascript_from_forms.append({
                        'source': f"Form field '{field['name']}' {action_type} action",
                        'field_name': field['name'],
                        'action_type': action_type,
                        'code': action_info['javascript'],
                    })
            
            if field.get('calculations'):
                self.javascript_from_forms.append({
                    'source': f"Form field '{field['name']}' calculation",
                    'field_name': field['name'],
                    'action_type': 'calculate',
                    'code': field['calculations'],
                })
            
            if field.get('validation'):
                self.javascript_from_forms.append({
                    'source': f"Form field '{field['name']}' validation",
                    'field_name': field['name'],
                    'action_type': 'validate',
                    'code': field['validation'],
                })
            
            if field.get('format'):
                self.javascript_from_forms.append({
                    'source': f"Form field '{field['name']}' format",
                    'field_name': field['name'],
                    'action_type': 'format',
                    'code': field['format'],
                })


def extract_forms(
    input_pdf: Path,
    output_dir: Optional[Path] = None,
    export_fdf: bool = False,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract form data from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_dir: Optional output directory for form data files
        export_fdf: Export form data in FDF format
        password: Optional password for encrypted PDFs
    
    Returns:
        Dictionary containing all form data
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = FormsExtractor(pdf_doc)
        result = extractor.extract_all()
        
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            if result['acroform_fields']:
                fields_file = output_dir / 'acroform_fields.txt'
                content = _format_acroform_fields(result['acroform_fields'])
                fields_file.write_text(content, encoding='utf-8')
                logger.info(f"AcroForm fields saved to: {fields_file}")
            
            if result['xfa_data'] and result['xfa_data']['has_xfa']:
                xfa_file = output_dir / 'xfa_data.xml'
                xfa_file.write_text(result['xfa_data']['xml_raw'], encoding='utf-8')
                logger.info(f"XFA XML saved to: {xfa_file}")
            
            if result['javascript']:
                for i, js_block in enumerate(result['javascript']):
                    js_file = output_dir / f'form_script_{i:03d}.js'
                    js_file.write_text(js_block['code'], encoding='utf-8')
                    
                    meta_file = output_dir / f'form_script_{i:03d}_meta.txt'
                    meta_content = f"Source: {js_block['source']}\n"
                    meta_content += f"Field: {js_block['field_name']}\n"
                    meta_content += f"Action: {js_block['action_type']}\n"
                    meta_file.write_text(meta_content, encoding='utf-8')
                
                logger.info(f"Form JavaScript saved to: {output_dir}")
            
            if export_fdf and result['acroform_fields']:
                fdf_file = output_dir / 'form_data.fdf'
                fdf_content = _generate_fdf(input_pdf, result['acroform_fields'])
                fdf_file.write_text(fdf_content, encoding='utf-8')
                logger.info(f"FDF data saved to: {fdf_file}")
        
        return result


def _format_acroform_fields(fields: List[Dict[str, Any]]) -> str:
    """Format AcroForm fields for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("ACROFORM FIELDS")
    lines.append("=" * 80)
    lines.append(f"Total fields: {len(fields)}\n")
    
    for i, field in enumerate(fields, 1):
        lines.append(f"\nField #{i}: {field['name']}")
        lines.append(f"  Type: {field['type']}")
        lines.append(f"  Value: {field.get('value', '(none)')}")
        if field.get('default_value'):
            lines.append(f"  Default: {field['default_value']}")
        if field.get('tooltip'):
            lines.append(f"  Tooltip: {field['tooltip']}")
        
        if field['flags']:
            flag_list = [k for k, v in field['flags'].items() if v]
            if flag_list:
                lines.append(f"  Flags: {', '.join(flag_list)}")
        
        if field.get('hidden'):
            lines.append("  ** HIDDEN FIELD **")
        
        if field.get('options'):
            lines.append(f"  Options ({len(field['options'])}):")
            for opt in field['options'][:5]:
                lines.append(f"    - {opt['display_value']}")
            if len(field['options']) > 5:
                lines.append(f"    ... and {len(field['options']) - 5} more")
        
        if field.get('actions'):
            lines.append(f"  Actions: {', '.join(field['actions'].keys())}")
    
    return '\n'.join(lines)


def _generate_fdf(pdf_path: Path, fields: List[Dict[str, Any]]) -> str:
    """Generate FDF (Forms Data Format) file"""
    fdf_lines = []
    fdf_lines.append('%FDF-1.2')
    fdf_lines.append('1 0 obj')
    fdf_lines.append('<<')
    fdf_lines.append('/FDF << /Fields [')
    
    for field in fields:
        if field.get('value'):
            fdf_lines.append('<<')
            fdf_lines.append(f'/T ({field["name"]})')
            fdf_lines.append(f'/V ({field["value"]})')
            fdf_lines.append('>>')
    
    fdf_lines.append(']')
    fdf_lines.append(f'/F ({pdf_path.name})')
    fdf_lines.append('>>')
    fdf_lines.append('>>')
    fdf_lines.append('endobj')
    fdf_lines.append('trailer')
    fdf_lines.append('<<')
    fdf_lines.append('/Root 1 0 R')
    fdf_lines.append('>>')
    fdf_lines.append('%%EOF')
    
    return '\n'.join(fdf_lines)
