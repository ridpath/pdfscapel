"""PDF structure analysis and compliance checking"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import re

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError

logger = get_logger()


class PDFStructureAnalyzer:
    """Analyzes PDF structure and detects anomalies"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
        
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive structure analysis
        
        Returns:
            Dictionary containing structure analysis results
        """
        logger.info(f"Analyzing PDF structure: {self.pdf_doc.path}")
        
        result = {
            "file_path": str(self.pdf_doc.path),
            "file_size": self.pdf_doc.path.stat().st_size if self.pdf_doc.path.exists() else 0,
            "pdf_version": self._get_pdf_version(),
            "pages": self.pdf_doc.num_pages,
            "object_statistics": self._analyze_objects(),
            "structure_info": self._analyze_structure(),
            "anomalies": self._detect_anomalies(),
            "incremental_updates": self._detect_incremental_updates(),
            "linearized": self._is_linearized(),
        }
        
        return result
    
    def _get_pdf_version(self) -> str:
        """Get PDF version"""
        try:
            if hasattr(self.pdf, 'pdf_version'):
                return str(self.pdf.pdf_version)
            
            with open(self.pdf_doc.path, 'rb') as f:
                header = f.read(20).decode('latin-1', errors='ignore')
                match = re.search(r'%PDF-(\d+\.\d+)', header)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.debug(f"Failed to extract PDF version: {e}")
        
        return "unknown"
    
    def _analyze_objects(self) -> Dict[str, Any]:
        """Analyze PDF objects and count by type"""
        stats = {
            "total_objects": 0,
            "by_type": defaultdict(int),
            "streams": 0,
            "compressed_objects": 0,
            "indirect_objects": 0,
        }
        
        try:
            for obj_id in self.pdf.objects:
                stats["total_objects"] += 1
                
                try:
                    obj = self.pdf.get_object(obj_id)
                    
                    if isinstance(obj, pikepdf.Dictionary):
                        obj_type = obj.get('/Type')
                        if obj_type:
                            type_name = str(obj_type).replace('/', '')
                            stats["by_type"][type_name] += 1
                        else:
                            stats["by_type"]["Dictionary"] += 1
                        
                        if obj.get('/Length') is not None or hasattr(obj, 'read_bytes'):
                            stats["streams"] += 1
                    
                    elif isinstance(obj, pikepdf.Array):
                        stats["by_type"]["Array"] += 1
                    
                    elif isinstance(obj, pikepdf.Stream):
                        stats["streams"] += 1
                        obj_type = obj.get('/Type')
                        if obj_type:
                            type_name = str(obj_type).replace('/', '')
                            stats["by_type"][type_name] += 1
                    
                    else:
                        stats["by_type"]["Other"] += 1
                    
                except Exception as e:
                    logger.debug(f"Failed to analyze object {obj_id}: {e}")
                    stats["by_type"]["Error"] += 1
        
        except Exception as e:
            logger.warning(f"Failed to enumerate objects: {e}")
        
        stats["by_type"] = dict(stats["by_type"])
        
        return stats
    
    def _analyze_structure(self) -> Dict[str, Any]:
        """Analyze PDF internal structure"""
        info = {
            "has_root": False,
            "has_info": False,
            "has_pages": False,
            "encryption": None,
            "trailer_keys": [],
        }
        
        try:
            trailer = self.pdf.trailer
            if trailer:
                info["trailer_keys"] = [str(k) for k in trailer.keys()]
                info["has_root"] = '/Root' in trailer
                info["has_info"] = '/Info' in trailer
                
                if '/Encrypt' in trailer:
                    info["encryption"] = "present"
                else:
                    info["encryption"] = "none"
            
            if hasattr(self.pdf, 'Root'):
                root = self.pdf.Root
                if root and '/Pages' in root:
                    info["has_pages"] = True
        
        except Exception as e:
            logger.warning(f"Failed to analyze structure: {e}")
        
        return info
    
    def _detect_anomalies(self) -> List[Dict[str, str]]:
        """Detect structural anomalies"""
        anomalies = []
        
        try:
            trailer = self.pdf.trailer
            
            if not trailer:
                anomalies.append({
                    "type": "missing_trailer",
                    "severity": "critical",
                    "description": "PDF trailer is missing or corrupted"
                })
            else:
                if '/Root' not in trailer:
                    anomalies.append({
                        "type": "missing_root",
                        "severity": "critical",
                        "description": "PDF Root object missing from trailer"
                    })
                
                if '/Size' not in trailer:
                    anomalies.append({
                        "type": "missing_size",
                        "severity": "high",
                        "description": "Trailer missing /Size entry"
                    })
            
            if self.pdf_doc.num_pages == 0:
                anomalies.append({
                    "type": "no_pages",
                    "severity": "high",
                    "description": "PDF contains no pages"
                })
            
            stats = self._analyze_objects()
            if stats["total_objects"] == 0:
                anomalies.append({
                    "type": "no_objects",
                    "severity": "critical",
                    "description": "No PDF objects found"
                })
        
        except Exception as e:
            logger.debug(f"Error detecting anomalies: {e}")
            anomalies.append({
                "type": "analysis_error",
                "severity": "medium",
                "description": f"Failed to complete anomaly detection: {e}"
            })
        
        return anomalies
    
    def _detect_incremental_updates(self) -> Dict[str, Any]:
        """Detect incremental updates (revisions)"""
        updates_info = {
            "detected": False,
            "count": 0,
            "indicators": []
        }
        
        try:
            with open(self.pdf_doc.path, 'rb') as f:
                content = f.read()
                
                eof_count = content.count(b'%%EOF')
                if eof_count > 1:
                    updates_info["detected"] = True
                    updates_info["count"] = eof_count - 1
                    updates_info["indicators"].append(f"Multiple %%EOF markers ({eof_count})")
                
                xref_count = content.count(b'xref')
                if xref_count > 1:
                    if not updates_info["detected"]:
                        updates_info["detected"] = True
                    updates_info["indicators"].append(f"Multiple xref tables ({xref_count})")
                
                startxref_count = content.count(b'startxref')
                if startxref_count > 1:
                    if not updates_info["detected"]:
                        updates_info["detected"] = True
                    updates_info["indicators"].append(f"Multiple startxref entries ({startxref_count})")
        
        except Exception as e:
            logger.debug(f"Failed to detect incremental updates: {e}")
            updates_info["indicators"].append(f"Detection error: {e}")
        
        return updates_info
    
    def _is_linearized(self) -> bool:
        """Check if PDF is linearized (optimized for web)"""
        try:
            if hasattr(self.pdf, 'is_linearized'):
                return self.pdf.is_linearized
            
            with open(self.pdf_doc.path, 'rb') as f:
                first_kb = f.read(1024)
                return b'/Linearized' in first_kb
        
        except Exception:
            return False


class PDFComplianceChecker:
    """Check PDF compliance with various standards"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
    
    def check_compliance(self, standard: str = "all") -> Dict[str, Any]:
        """
        Check compliance with PDF standards
        
        Args:
            standard: Standard to check (pdfa, pdfx, pdfe, pdfua, all)
        
        Returns:
            Dictionary with compliance results
        """
        logger.info(f"Checking {standard} compliance for: {self.pdf_doc.path}")
        
        results = {
            "file_path": str(self.pdf_doc.path),
            "pdf_version": PDFStructureAnalyzer(self.pdf_doc)._get_pdf_version(),
        }
        
        if standard == "all" or standard == "pdfa":
            results["pdf_a"] = self._check_pdfa_compliance()
        
        if standard == "all" or standard == "pdfx":
            results["pdf_x"] = self._check_pdfx_compliance()
        
        if standard == "all" or standard == "pdfe":
            results["pdf_e"] = self._check_pdfe_compliance()
        
        if standard == "all" or standard == "pdfua":
            results["pdf_ua"] = self._check_pdfua_compliance()
        
        if standard == "all":
            results["version_compliance"] = self._check_version_features()
        
        return results
    
    def _check_pdfa_compliance(self) -> Dict[str, Any]:
        """Check PDF/A (archival) compliance"""
        result = {
            "compliant": None,
            "level": None,
            "violations": []
        }
        
        try:
            root = self.pdf.Root
            
            if '/Metadata' in root:
                metadata = root['/Metadata']
                try:
                    metadata_bytes = metadata.read_bytes()
                    if b'pdfaid:part' in metadata_bytes:
                        match = re.search(rb'pdfaid:part>(\d+)', metadata_bytes)
                        if match:
                            result["level"] = f"PDF/A-{match.group(1).decode()}"
                        result["compliant"] = True
                    else:
                        result["compliant"] = False
                        result["violations"].append("No PDF/A identification in XMP metadata")
                except Exception as e:
                    logger.debug(f"Failed to read metadata: {e}")
                    result["violations"].append("Unable to read XMP metadata")
            else:
                result["compliant"] = False
                result["violations"].append("Missing XMP metadata (required for PDF/A)")
            
            if self.pdf_doc.is_encrypted:
                result["compliant"] = False
                result["violations"].append("Encryption not allowed in PDF/A")
            
            if '/JavaScript' in root or '/JS' in root:
                result["compliant"] = False
                result["violations"].append("JavaScript not allowed in PDF/A")
        
        except Exception as e:
            logger.debug(f"Error checking PDF/A compliance: {e}")
            result["violations"].append(f"Analysis error: {e}")
        
        if result["compliant"] is None:
            result["compliant"] = False
        
        return result
    
    def _check_pdfx_compliance(self) -> Dict[str, Any]:
        """Check PDF/X (printing/prepress) compliance"""
        result = {
            "compliant": None,
            "version": None,
            "violations": []
        }
        
        try:
            root = self.pdf.Root
            
            if '/OutputIntents' in root:
                output_intents = root['/OutputIntents']
                if output_intents:
                    result["compliant"] = True
                    for intent in output_intents:
                        if '/GTS_PDFX' in str(intent.get('/S', '')):
                            result["version"] = "PDF/X detected"
                            break
                else:
                    result["violations"].append("OutputIntents array is empty")
            else:
                result["compliant"] = False
                result["violations"].append("Missing OutputIntents (required for PDF/X)")
            
            if '/Metadata' not in root:
                result["violations"].append("Missing XMP metadata (recommended for PDF/X)")
            
            if self.pdf_doc.is_encrypted:
                result["compliant"] = False
                result["violations"].append("Encryption not allowed in PDF/X")
        
        except Exception as e:
            logger.debug(f"Error checking PDF/X compliance: {e}")
            result["violations"].append(f"Analysis error: {e}")
        
        if result["compliant"] is None:
            result["compliant"] = False
        
        return result
    
    def _check_pdfe_compliance(self) -> Dict[str, Any]:
        """Check PDF/E (engineering) compliance"""
        result = {
            "compliant": None,
            "violations": []
        }
        
        try:
            root = self.pdf.Root
            
            if '/Metadata' in root:
                result["compliant"] = True
            else:
                result["violations"].append("Missing XMP metadata (recommended for PDF/E)")
            
            if '/JavaScript' in root or '/JS' in root:
                result["violations"].append("JavaScript usage (review for PDF/E compliance)")
        
        except Exception as e:
            logger.debug(f"Error checking PDF/E compliance: {e}")
            result["violations"].append(f"Analysis error: {e}")
        
        if result["compliant"] is None:
            result["compliant"] = None
        
        return result
    
    def _check_pdfua_compliance(self) -> Dict[str, Any]:
        """Check PDF/UA (accessibility) compliance"""
        result = {
            "compliant": None,
            "violations": []
        }
        
        try:
            root = self.pdf.Root
            
            if '/MarkInfo' in root:
                mark_info = root['/MarkInfo']
                if mark_info.get('/Marked') == True:
                    result["compliant"] = True
                else:
                    result["violations"].append("Document not marked as tagged")
            else:
                result["compliant"] = False
                result["violations"].append("Missing MarkInfo dictionary (required for PDF/UA)")
            
            if '/StructTreeRoot' not in root:
                result["compliant"] = False
                result["violations"].append("Missing structure tree (required for PDF/UA)")
            
            if '/Metadata' not in root:
                result["violations"].append("Missing XMP metadata (required for PDF/UA)")
            
            if '/Lang' not in root:
                result["violations"].append("Missing document language (required for PDF/UA)")
        
        except Exception as e:
            logger.debug(f"Error checking PDF/UA compliance: {e}")
            result["violations"].append(f"Analysis error: {e}")
        
        if result["compliant"] is None:
            result["compliant"] = False
        
        return result
    
    def _check_version_features(self) -> Dict[str, Any]:
        """Check version-specific feature usage"""
        result = {
            "version": PDFStructureAnalyzer(self.pdf_doc)._get_pdf_version(),
            "features": [],
            "warnings": []
        }
        
        try:
            root = self.pdf.Root
            
            if '/AcroForm' in root:
                result["features"].append("AcroForm (PDF 1.2+)")
            
            if '/Metadata' in root:
                result["features"].append("XMP Metadata (PDF 1.4+)")
            
            if self.pdf_doc.is_encrypted:
                enc_info = self.pdf_doc.check_encryption()
                if enc_info and enc_info.get('version') == 5:
                    result["features"].append("AES-256 Encryption (PDF 1.7 Extension Level 3)")
                elif enc_info and enc_info.get('version') == 4:
                    result["features"].append("AES-128 Encryption (PDF 1.6+)")
            
            if '/OCProperties' in root:
                result["features"].append("Optional Content Groups (PDF 1.5+)")
            
            if '/Collection' in root:
                result["features"].append("PDF Package/Portfolio (PDF 1.7+)")
        
        except Exception as e:
            logger.debug(f"Error checking version features: {e}")
            result["warnings"].append(f"Feature detection incomplete: {e}")
        
        return result


def analyze_structure(pdf_path: Path) -> Dict[str, Any]:
    """
    Convenience function to analyze PDF structure
    
    Args:
        pdf_path: Path to PDF file
    
    Returns:
        Analysis results dictionary
    """
    with PDFDocument.open(pdf_path) as pdf_doc:
        analyzer = PDFStructureAnalyzer(pdf_doc)
        return analyzer.analyze()


def check_compliance(pdf_path: Path, standard: str = "all") -> Dict[str, Any]:
    """
    Convenience function to check PDF compliance
    
    Args:
        pdf_path: Path to PDF file
        standard: Standard to check (pdfa, pdfx, pdfe, pdfua, all)
    
    Returns:
        Compliance results dictionary
    """
    with PDFDocument.open(pdf_path) as pdf_doc:
        checker = PDFComplianceChecker(pdf_doc)
        return checker.check_compliance(standard)
