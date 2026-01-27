"""PDF metadata extraction and analysis"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import re
import xml.etree.ElementTree as ET

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class PDFMetadataAnalyzer:
    """Extract and analyze PDF metadata"""
    
    KNOWN_PRODUCERS = {
        "Adobe": [
            r"Adobe (Acrobat|PDF Library|PDFMaker|Distiller|InDesign|Illustrator|Photoshop)",
            r"Acrobat",
        ],
        "Microsoft": [
            r"Microsoft.*Word",
            r"Microsoft.*Excel",
            r"Microsoft.*PowerPoint",
            r"Microsoft.*Print To PDF",
        ],
        "LibreOffice": [
            r"LibreOffice",
            r"OpenOffice",
        ],
        "LaTeX": [
            r"pdfTeX",
            r"XeTeX",
            r"LuaTeX",
            r"LaTeX",
        ],
        "Google": [
            r"Chrome PDF",
            r"Chromium PDF",
        ],
        "Apple": [
            r"macOS",
            r"Mac OS X.*Quartz",
        ],
        "Foxit": [
            r"Foxit",
        ],
        "iText": [
            r"iText",
        ],
        "PDFtk": [
            r"pdftk",
        ],
        "QPDF": [
            r"qpdf",
        ],
        "Ghostscript": [
            r"GPL Ghostscript",
        ],
        "WeasyPrint": [
            r"WeasyPrint",
        ],
        "wkhtmltopdf": [
            r"wkhtmltopdf",
        ],
        "Reportlab": [
            r"ReportLab",
        ],
    }
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive metadata analysis
        
        Returns:
            Dictionary containing metadata analysis results
        """
        logger.info(f"Analyzing PDF metadata: {self.pdf_doc.path}")
        
        result = {
            "file_path": str(self.pdf_doc.path),
            "info_dict": self._extract_info_dict(),
            "xmp_metadata": self._extract_xmp_metadata(),
            "hidden_fields": self._find_hidden_metadata(),
            "tool_fingerprint": self._identify_creation_tool(),
            "timestamps": self._extract_timestamps(),
        }
        
        return result
    
    def _extract_info_dict(self) -> Dict[str, str]:
        """Extract standard Info dictionary metadata"""
        info = {}
        
        try:
            if hasattr(self.pdf, 'docinfo'):
                for key, value in self.pdf.docinfo.items():
                    key_str = str(key).replace('/', '')
                    try:
                        value_str = str(value)
                        if hasattr(value, 'decode'):
                            try:
                                value_str = value.decode('utf-8')
                            except:
                                value_str = value.decode('latin-1', errors='ignore')
                        info[key_str] = value_str
                    except Exception as e:
                        logger.debug(f"Failed to decode metadata value for {key_str}: {e}")
                        info[key_str] = repr(value)
        except Exception as e:
            logger.warning(f"Failed to extract Info dict: {e}")
        
        return info
    
    def _extract_xmp_metadata(self) -> Dict[str, Any]:
        """Extract XMP metadata"""
        xmp_data = {
            "present": False,
            "raw": None,
            "parsed": {}
        }
        
        try:
            root = self.pdf.Root
            if '/Metadata' in root:
                xmp_data["present"] = True
                metadata_obj = root['/Metadata']
                
                try:
                    xmp_bytes = metadata_obj.read_bytes()
                    xmp_data["raw"] = xmp_bytes.decode('utf-8', errors='ignore')
                    
                    xmp_data["parsed"] = self._parse_xmp(xmp_bytes)
                except Exception as e:
                    logger.debug(f"Failed to read XMP metadata: {e}")
                    xmp_data["error"] = str(e)
        except Exception as e:
            logger.warning(f"Failed to extract XMP: {e}")
        
        return xmp_data
    
    def _parse_xmp(self, xmp_bytes: bytes) -> Dict[str, Any]:
        """Parse XMP XML metadata"""
        parsed = {}
        
        try:
            xmp_str = xmp_bytes.decode('utf-8', errors='ignore')
            
            root = ET.fromstring(xmp_str)
            
            namespaces = {
                'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
                'dc': 'http://purl.org/dc/elements/1.1/',
                'xmp': 'http://ns.adobe.com/xap/1.0/',
                'pdf': 'http://ns.adobe.com/pdf/1.3/',
                'pdfaid': 'http://www.aiim.org/pdfa/ns/id/',
                'xmpMM': 'http://ns.adobe.com/xap/1.0/mm/',
            }
            
            for prefix, uri in namespaces.items():
                elements = root.findall(f'.//{{{uri}}}*')
                if elements:
                    parsed[prefix] = {}
                    for elem in elements:
                        tag = elem.tag.replace(f'{{{uri}}}', '')
                        if elem.text:
                            parsed[prefix][tag] = elem.text.strip()
        
        except ET.ParseError as e:
            logger.debug(f"Failed to parse XMP XML: {e}")
            
            simple_patterns = {
                'creator': r'<dc:creator[^>]*>(.*?)</dc:creator>',
                'title': r'<dc:title[^>]*>(.*?)</dc:title>',
                'subject': r'<dc:subject[^>]*>(.*?)</dc:subject>',
                'producer': r'<pdf:Producer[^>]*>(.*?)</pdf:Producer>',
                'create_date': r'<xmp:CreateDate[^>]*>(.*?)</xmp:CreateDate>',
                'modify_date': r'<xmp:ModifyDate[^>]*>(.*?)</xmp:ModifyDate>',
            }
            
            for key, pattern in simple_patterns.items():
                match = re.search(pattern, xmp_str, re.DOTALL | re.IGNORECASE)
                if match:
                    parsed[key] = match.group(1).strip()
        
        except Exception as e:
            logger.debug(f"XMP parsing error: {e}")
        
        return parsed
    
    def _find_hidden_metadata(self) -> List[Dict[str, str]]:
        """Find hidden or non-standard metadata fields"""
        hidden = []
        
        standard_fields = {
            'Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer',
            'CreationDate', 'ModDate', 'Trapped'
        }
        
        try:
            if hasattr(self.pdf, 'docinfo'):
                for key in self.pdf.docinfo.keys():
                    key_str = str(key).replace('/', '')
                    if key_str not in standard_fields:
                        hidden.append({
                            "field": key_str,
                            "value": str(self.pdf.docinfo[key]),
                            "type": "non_standard_info_field"
                        })
        except Exception as e:
            logger.debug(f"Failed to check for hidden fields: {e}")
        
        try:
            root = self.pdf.Root
            
            suspicious_keys = ['/JavaScript', '/JS', '/OpenAction', '/AA', '/Names']
            for key in suspicious_keys:
                if key in root:
                    hidden.append({
                        "field": key,
                        "value": "present",
                        "type": "potentially_suspicious"
                    })
        except Exception as e:
            logger.debug(f"Failed to check Root for suspicious fields: {e}")
        
        return hidden
    
    def _identify_creation_tool(self) -> Dict[str, Any]:
        """Identify the tool that created/modified the PDF"""
        fingerprint = {
            "creator": None,
            "producer": None,
            "identified_tool": None,
            "confidence": 0.0,
            "indicators": []
        }
        
        info_dict = self._extract_info_dict()
        
        fingerprint["creator"] = info_dict.get("Creator", "unknown")
        fingerprint["producer"] = info_dict.get("Producer", "unknown")
        
        creator_str = f"{fingerprint['creator']} {fingerprint['producer']}".lower()
        
        matched_tool = None
        max_confidence = 0.0
        
        for tool, patterns in self.KNOWN_PRODUCERS.items():
            for pattern in patterns:
                if re.search(pattern, creator_str, re.IGNORECASE):
                    confidence = 0.9
                    if matched_tool is None or confidence > max_confidence:
                        matched_tool = tool
                        max_confidence = confidence
                        fingerprint["indicators"].append(f"Matched pattern: {pattern}")
        
        if matched_tool:
            fingerprint["identified_tool"] = matched_tool
            fingerprint["confidence"] = max_confidence
        else:
            fingerprint["identified_tool"] = "unknown"
            fingerprint["confidence"] = 0.0
        
        if "pdftk" in creator_str or "qpdf" in creator_str:
            fingerprint["indicators"].append("Document may have been modified/processed after creation")
        
        if fingerprint["creator"] == fingerprint["producer"]:
            fingerprint["indicators"].append("Creator and Producer are identical")
        
        return fingerprint
    
    def _extract_timestamps(self) -> Dict[str, Any]:
        """Extract and analyze timestamps"""
        timestamps = {
            "creation_date": None,
            "modification_date": None,
            "file_system": {},
            "inconsistencies": []
        }
        
        info_dict = self._extract_info_dict()
        
        creation_raw = info_dict.get("CreationDate")
        if creation_raw:
            timestamps["creation_date"] = self._parse_pdf_date(creation_raw)
        
        mod_raw = info_dict.get("ModDate")
        if mod_raw:
            timestamps["modification_date"] = self._parse_pdf_date(mod_raw)
        
        try:
            stat = self.pdf_doc.path.stat()
            timestamps["file_system"] = {
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat() if hasattr(stat, 'st_ctime') else None,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat() if hasattr(stat, 'st_atime') else None,
            }
        except Exception as e:
            logger.debug(f"Failed to get filesystem timestamps: {e}")
        
        if timestamps["creation_date"] and timestamps["modification_date"]:
            try:
                creation_dt = datetime.fromisoformat(timestamps["creation_date"].replace('Z', '+00:00'))
                mod_dt = datetime.fromisoformat(timestamps["modification_date"].replace('Z', '+00:00'))
                
                if mod_dt < creation_dt:
                    timestamps["inconsistencies"].append(
                        "Modification date is earlier than creation date"
                    )
            except Exception:
                pass
        
        return timestamps
    
    def _parse_pdf_date(self, date_str: str) -> Optional[str]:
        """Parse PDF date format (D:YYYYMMDDHHmmSSOHH'mm')"""
        try:
            date_str = str(date_str).strip()
            
            if date_str.startswith('D:'):
                date_str = date_str[2:]
            
            year = date_str[0:4]
            month = date_str[4:6] if len(date_str) >= 6 else '01'
            day = date_str[6:8] if len(date_str) >= 8 else '01'
            hour = date_str[8:10] if len(date_str) >= 10 else '00'
            minute = date_str[10:12] if len(date_str) >= 12 else '00'
            second = date_str[12:14] if len(date_str) >= 14 else '00'
            
            iso_date = f"{year}-{month}-{day}T{hour}:{minute}:{second}"
            
            datetime.fromisoformat(iso_date)
            
            return iso_date + "Z"
        
        except Exception as e:
            logger.debug(f"Failed to parse PDF date '{date_str}': {e}")
            return None


def analyze_metadata(pdf_path: Path) -> Dict[str, Any]:
    """
    Convenience function to analyze PDF metadata
    
    Args:
        pdf_path: Path to PDF file
    
    Returns:
        Metadata analysis results dictionary
    """
    with PDFDocument.open(pdf_path) as pdf_doc:
        analyzer = PDFMetadataAnalyzer(pdf_doc)
        return analyzer.analyze()
