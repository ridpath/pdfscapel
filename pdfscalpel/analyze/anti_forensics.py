"""
PDF Anti-Forensics Detection Module

Detect PDF sanitization and anti-forensic manipulation including:
- Sanitization tool fingerprinting (ExifTool, MAT2, pdf-redact-tools, QPDF)
- Metadata removal detection
- Incremental update history analysis
- Object manipulation detection
- Producer/creator string analysis
- Timestamp anomaly detection

Based on extensive research from anti_forensics_research.md (50KB, 1484 lines)
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import re

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class AntiForensicsSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SanitizationTool(Enum):
    EXIFTOOL = "exiftool"
    MAT2 = "mat2"
    PDF_REDACT_TOOLS = "pdf_redact_tools"
    QPDF = "qpdf"
    GHOSTSCRIPT = "ghostscript"
    UNKNOWN = "unknown"


@dataclass
class AntiForensicsFinding:
    """A single anti-forensics detection finding"""
    type: str
    severity: AntiForensicsSeverity
    description: str
    evidence: List[str] = field(default_factory=list)
    tool_signature: Optional[SanitizationTool] = None
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['severity'] = self.severity.value
        if self.tool_signature:
            result['tool_signature'] = self.tool_signature.value
        return result


@dataclass
class ToolFingerprint:
    """Sanitization tool fingerprint"""
    tool: SanitizationTool
    confidence: float
    indicators: Dict[str, bool]
    evidence: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['tool'] = self.tool.value
        return result


@dataclass
class AntiForensicsResult:
    """Complete anti-forensics analysis result"""
    file_path: str
    is_sanitized: bool
    sanitization_confidence: float
    detected_tools: List[ToolFingerprint]
    findings: List[AntiForensicsFinding]
    metadata_removed: bool
    incremental_updates_removed: bool
    javascript_removed: bool
    embedded_files_removed: bool
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['detected_tools'] = [t.to_dict() for t in self.detected_tools]
        result['findings'] = [f.to_dict() for f in self.findings]
        return result


class PDFAntiForensicsDetector:
    """
    PDF Anti-Forensics Detector - Identify sanitization and manipulation
    
    Detects:
    - ExifTool metadata removal patterns
    - MAT2 re-rendering signatures
    - pdf-redact-tools flattening
    - QPDF linearization/normalization
    - Ghostscript re-rendering
    - Metadata stripping
    - Incremental update removal
    """
    
    SANITIZATION_PRODUCERS = {
        "cairo": SanitizationTool.MAT2,
        "poppler": SanitizationTool.MAT2,
        "mat2": SanitizationTool.MAT2,
        "qpdf": SanitizationTool.QPDF,
        "ghostscript": SanitizationTool.GHOSTSCRIPT,
        "gs": SanitizationTool.GHOSTSCRIPT,
    }
    
    EPOCH_TIMESTAMP = datetime(1970, 1, 1)
    
    def __init__(self):
        if not pikepdf:
            logger.warning("pikepdf not installed. Limited anti-forensics detection.")
    
    def analyze(self, pdf_path: Path) -> AntiForensicsResult:
        """
        Perform comprehensive anti-forensics analysis
        
        Args:
            pdf_path: Path to PDF file
        
        Returns:
            AntiForensicsResult with all findings
        """
        findings = []
        detected_tools = []
        
        try:
            with PDFDocument(pdf_path) as doc:
                metadata_removed = self._check_metadata_removal(doc)
                
                incremental_updates_removed = self._check_incremental_updates_removed(doc)
                
                javascript_removed = self._check_javascript_removal(doc)
                
                embedded_files_removed = self._check_embedded_files_removal(doc)
                
                exiftool_fp = self._detect_exiftool(doc)
                if exiftool_fp.confidence >= 0.5:
                    detected_tools.append(exiftool_fp)
                    
                    findings.append(AntiForensicsFinding(
                        type="sanitization_tool_detected",
                        severity=AntiForensicsSeverity.MEDIUM,
                        description="ExifTool metadata removal detected",
                        evidence=exiftool_fp.evidence,
                        tool_signature=SanitizationTool.EXIFTOOL,
                        confidence=exiftool_fp.confidence
                    ))
                
                mat2_fp = self._detect_mat2(doc)
                if mat2_fp.confidence >= 0.6:
                    detected_tools.append(mat2_fp)
                    
                    findings.append(AntiForensicsFinding(
                        type="sanitization_tool_detected",
                        severity=AntiForensicsSeverity.HIGH,
                        description="MAT2 re-rendering detected",
                        evidence=mat2_fp.evidence,
                        tool_signature=SanitizationTool.MAT2,
                        confidence=mat2_fp.confidence
                    ))
                
                pdf_redact_fp = self._detect_pdf_redact_tools(doc)
                if pdf_redact_fp.confidence >= 0.5:
                    detected_tools.append(pdf_redact_fp)
                    
                    findings.append(AntiForensicsFinding(
                        type="sanitization_tool_detected",
                        severity=AntiForensicsSeverity.MEDIUM,
                        description="pdf-redact-tools processing detected",
                        evidence=pdf_redact_fp.evidence,
                        tool_signature=SanitizationTool.PDF_REDACT_TOOLS,
                        confidence=pdf_redact_fp.confidence
                    ))
                
                qpdf_fp = self._detect_qpdf(doc)
                if qpdf_fp.confidence >= 0.5:
                    detected_tools.append(qpdf_fp)
                    
                    findings.append(AntiForensicsFinding(
                        type="sanitization_tool_detected",
                        severity=AntiForensicsSeverity.LOW,
                        description="QPDF processing detected (optimization)",
                        evidence=qpdf_fp.evidence,
                        tool_signature=SanitizationTool.QPDF,
                        confidence=qpdf_fp.confidence
                    ))
                
                timestamp_findings = self._detect_timestamp_anomalies(doc)
                findings.extend(timestamp_findings)
                
                object_findings = self._detect_object_manipulation(doc)
                findings.extend(object_findings)
                
                is_sanitized = len(detected_tools) > 0 or metadata_removed
                
                sanitization_confidence = 0.0
                if detected_tools:
                    sanitization_confidence = max(t.confidence for t in detected_tools)
                elif metadata_removed:
                    sanitization_confidence = 0.7
                
                recommendations = self._generate_recommendations(
                    detected_tools, findings, metadata_removed
                )
                
                return AntiForensicsResult(
                    file_path=str(pdf_path),
                    is_sanitized=is_sanitized,
                    sanitization_confidence=sanitization_confidence,
                    detected_tools=detected_tools,
                    findings=findings,
                    metadata_removed=metadata_removed,
                    incremental_updates_removed=incremental_updates_removed,
                    javascript_removed=javascript_removed,
                    embedded_files_removed=embedded_files_removed,
                    recommendations=recommendations
                )
        
        except Exception as e:
            logger.error(f"Error analyzing anti-forensics: {e}")
            
            return AntiForensicsResult(
                file_path=str(pdf_path),
                is_sanitized=False,
                sanitization_confidence=0.0,
                detected_tools=[],
                findings=[],
                metadata_removed=False,
                incremental_updates_removed=False,
                javascript_removed=False,
                embedded_files_removed=False,
                recommendations=[f"Analysis error: {str(e)}"]
            )
    
    def _check_metadata_removal(self, doc: PDFDocument) -> bool:
        """Check if metadata has been removed"""
        try:
            info_dict = doc.pdf.docinfo if hasattr(doc.pdf, 'docinfo') else {}
            
            if not info_dict or len(info_dict) <= 1:
                return True
            
            has_xmp = False
            for page in doc.pdf.pages:
                if '/Metadata' in page:
                    has_xmp = True
                    break
            
            if not has_xmp and not info_dict:
                return True
        
        except:
            pass
        
        return False
    
    def _check_incremental_updates_removed(self, doc: PDFDocument) -> bool:
        """Check if incremental updates have been removed"""
        try:
            pdf_data = doc.pdf_path.read_bytes()
            
            xref_count = len(re.findall(rb'xref\s', pdf_data))
            
            return xref_count <= 1
        
        except:
            pass
        
        return False
    
    def _check_javascript_removal(self, doc: PDFDocument) -> bool:
        """Check if JavaScript has been removed"""
        try:
            pdf_data = doc.pdf_path.read_bytes()
            pdf_str = pdf_data.decode('latin-1', errors='ignore')
            
            if '/JavaScript' not in pdf_str and '/JS' not in pdf_str:
                return True
        
        except:
            pass
        
        return False
    
    def _check_embedded_files_removal(self, doc: PDFDocument) -> bool:
        """Check if embedded files have been removed"""
        try:
            if '/Names' in doc.pdf.Root:
                names = doc.pdf.Root['/Names']
                if '/EmbeddedFiles' in names:
                    return False
            
            return True
        
        except:
            pass
        
        return False
    
    def _detect_exiftool(self, doc: PDFDocument) -> ToolFingerprint:
        """Detect ExifTool sanitization patterns"""
        indicators = {
            'empty_info_dict': False,
            'missing_xmp': False,
            'embedded_metadata_present': False,
            'suspicious_timestamps': False
        }
        evidence = []
        
        try:
            info_dict = doc.pdf.docinfo if hasattr(doc.pdf, 'docinfo') else {}
            
            if not info_dict or len(info_dict) <= 2:
                indicators['empty_info_dict'] = True
                evidence.append("Info dictionary empty or minimal")
            
            has_xmp = False
            for page in doc.pdf.pages:
                if '/Metadata' in page:
                    has_xmp = True
                    break
            
            if not has_xmp:
                indicators['missing_xmp'] = True
                evidence.append("XMP metadata missing")
            
            if info_dict:
                for key, value in info_dict.items():
                    if isinstance(value, datetime):
                        if value.year == 1970:
                            indicators['suspicious_timestamps'] = True
                            evidence.append(f"Epoch timestamp in {key}")
        
        except Exception as e:
            logger.debug(f"ExifTool detection error: {e}")
        
        confidence = sum(indicators.values()) / len(indicators)
        
        return ToolFingerprint(
            tool=SanitizationTool.EXIFTOOL,
            confidence=confidence,
            indicators=indicators,
            evidence=evidence
        )
    
    def _detect_mat2(self, doc: PDFDocument) -> ToolFingerprint:
        """Detect MAT2 re-rendering patterns"""
        indicators = {
            'cairo_poppler_producer': False,
            'no_metadata_anywhere': False,
            'sequential_objects': False,
            'single_generation': False,
            'rerendering_artifacts': False
        }
        evidence = []
        
        try:
            info_dict = doc.pdf.docinfo if hasattr(doc.pdf, 'docinfo') else {}
            producer = str(info_dict.get('/Producer', '')).lower()
            
            for tool, signature in self.SANITIZATION_PRODUCERS.items():
                if tool in producer:
                    if signature == SanitizationTool.MAT2:
                        indicators['cairo_poppler_producer'] = True
                        evidence.append(f"Producer: {producer}")
            
            if not info_dict or len(info_dict) == 0:
                indicators['no_metadata_anywhere'] = True
                evidence.append("Complete metadata absence")
            
            try:
                object_ids = []
                for obj in doc.pdf.objects:
                    if hasattr(obj, 'objgen'):
                        object_ids.append(obj.objgen[0])
                
                if object_ids and object_ids == list(range(1, len(object_ids) + 1)):
                    indicators['sequential_objects'] = True
                    evidence.append("Sequential object numbering (1, 2, 3, ...)")
            except:
                pass
            
            pdf_data = doc.pdf_path.read_bytes()
            xref_count = len(re.findall(rb'xref\s', pdf_data))
            
            if xref_count == 1:
                indicators['single_generation'] = True
                evidence.append("Single generation (no incremental updates)")
        
        except Exception as e:
            logger.debug(f"MAT2 detection error: {e}")
        
        confidence = sum(indicators.values()) / len(indicators)
        
        return ToolFingerprint(
            tool=SanitizationTool.MAT2,
            confidence=confidence,
            indicators=indicators,
            evidence=evidence
        )
    
    def _detect_pdf_redact_tools(self, doc: PDFDocument) -> ToolFingerprint:
        """Detect pdf-redact-tools sanitization patterns"""
        indicators = {
            'no_javascript': False,
            'no_embedded_files': False,
            'flattened_forms': False,
            'no_actions': False,
            'metadata_removed': False
        }
        evidence = []
        
        try:
            pdf_data = doc.pdf_path.read_bytes()
            pdf_str = pdf_data.decode('latin-1', errors='ignore')
            
            if '/JavaScript' not in pdf_str and '/JS' not in pdf_str:
                indicators['no_javascript'] = True
                evidence.append("JavaScript removed")
            
            if '/EmbeddedFiles' not in pdf_str:
                indicators['no_embedded_files'] = True
                evidence.append("Embedded files removed")
            
            if '/AcroForm' in doc.pdf.Root:
                acroform = doc.pdf.Root['/AcroForm']
                if '/Fields' not in acroform or len(acroform.get('/Fields', [])) == 0:
                    indicators['flattened_forms'] = True
                    evidence.append("Forms flattened")
            
            if '/OpenAction' not in doc.pdf.Root and '/AA' not in doc.pdf.Root:
                indicators['no_actions'] = True
                evidence.append("Actions removed")
            
            info_dict = doc.pdf.docinfo if hasattr(doc.pdf, 'docinfo') else {}
            if not info_dict or len(info_dict) <= 1:
                indicators['metadata_removed'] = True
                evidence.append("Metadata removed")
        
        except Exception as e:
            logger.debug(f"pdf-redact-tools detection error: {e}")
        
        confidence = sum(indicators.values()) / len(indicators)
        
        return ToolFingerprint(
            tool=SanitizationTool.PDF_REDACT_TOOLS,
            confidence=confidence,
            indicators=indicators,
            evidence=evidence
        )
    
    def _detect_qpdf(self, doc: PDFDocument) -> ToolFingerprint:
        """Detect QPDF processing patterns"""
        indicators = {
            'linearized': False,
            'qpdf_producer': False,
            'normalized_structure': False,
            'rebuilt_xref': False
        }
        evidence = []
        
        try:
            info_dict = doc.pdf.docinfo if hasattr(doc.pdf, 'docinfo') else {}
            producer = str(info_dict.get('/Producer', '')).lower()
            
            if 'qpdf' in producer:
                indicators['qpdf_producer'] = True
                evidence.append(f"Producer: {producer}")
            
            if hasattr(doc.pdf, 'is_linearized') and doc.pdf.is_linearized:
                indicators['linearized'] = True
                evidence.append("PDF is linearized")
            
            pdf_data = doc.pdf_path.read_bytes()
            
            if b'/Linearized' in pdf_data[:5000]:
                indicators['linearized'] = True
                evidence.append("Linearization dictionary present")
        
        except Exception as e:
            logger.debug(f"QPDF detection error: {e}")
        
        confidence = sum(indicators.values()) / len(indicators)
        
        return ToolFingerprint(
            tool=SanitizationTool.QPDF,
            confidence=confidence,
            indicators=indicators,
            evidence=evidence
        )
    
    def _detect_timestamp_anomalies(self, doc: PDFDocument) -> List[AntiForensicsFinding]:
        """Detect timestamp manipulation"""
        findings = []
        
        try:
            info_dict = doc.pdf.docinfo if hasattr(doc.pdf, 'docinfo') else {}
            
            if not info_dict:
                findings.append(AntiForensicsFinding(
                    type="timestamp_removal",
                    severity=AntiForensicsSeverity.MEDIUM,
                    description="All timestamps removed from document",
                    evidence=["Info dictionary missing or empty"],
                    confidence=0.8
                ))
            
            else:
                for key in ['/CreationDate', '/ModDate']:
                    if key in info_dict:
                        value = info_dict[key]
                        
                        if isinstance(value, datetime):
                            if value.year == 1970:
                                findings.append(AntiForensicsFinding(
                                    type="timestamp_anomaly",
                                    severity=AntiForensicsSeverity.MEDIUM,
                                    description=f"Epoch timestamp detected in {key}",
                                    evidence=[f"{key}: {value}"],
                                    confidence=0.9
                                ))
        
        except Exception as e:
            logger.debug(f"Timestamp detection error: {e}")
        
        return findings
    
    def _detect_object_manipulation(self, doc: PDFDocument) -> List[AntiForensicsFinding]:
        """Detect object manipulation patterns"""
        findings = []
        
        try:
            pdf_data = doc.pdf_path.read_bytes()
            
            objects = re.findall(rb'(\d+)\s+(\d+)\s+obj', pdf_data)
            object_ids = [int(obj[0]) for obj in objects]
            
            if object_ids:
                max_id = max(object_ids)
                expected_count = max_id
                actual_count = len(set(object_ids))
                
                gap_ratio = (expected_count - actual_count) / expected_count if expected_count > 0 else 0
                
                if gap_ratio > 0.2:
                    findings.append(AntiForensicsFinding(
                        type="object_gaps",
                        severity=AntiForensicsSeverity.MEDIUM,
                        description=f"Significant object ID gaps detected ({gap_ratio:.1%})",
                        evidence=[f"Expected {expected_count} objects, found {actual_count}"],
                        confidence=0.7
                    ))
                
                if object_ids == list(range(1, len(object_ids) + 1)):
                    findings.append(AntiForensicsFinding(
                        type="sequential_renumbering",
                        severity=AntiForensicsSeverity.LOW,
                        description="Perfect sequential object numbering (possible re-rendering)",
                        evidence=["Objects numbered 1, 2, 3, ... with no gaps"],
                        confidence=0.6
                    ))
        
        except Exception as e:
            logger.debug(f"Object manipulation detection error: {e}")
        
        return findings
    
    def _generate_recommendations(
        self,
        detected_tools: List[ToolFingerprint],
        findings: List[AntiForensicsFinding],
        metadata_removed: bool
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if detected_tools:
            tools_str = ", ".join([t.tool.value for t in detected_tools])
            recommendations.append(f"Document processed by: {tools_str}")
            
            if any(t.tool == SanitizationTool.MAT2 for t in detected_tools):
                recommendations.append("MAT2 re-rendering detected - original metadata irrecoverable")
            
            if any(t.tool == SanitizationTool.EXIFTOOL for t in detected_tools):
                recommendations.append("ExifTool sanitization - check embedded objects for residual metadata")
        
        if metadata_removed:
            recommendations.append("Metadata removed - forensic value reduced")
        
        if any(f.type == "timestamp_anomaly" for f in findings):
            recommendations.append("Timestamp manipulation detected - document timeline unreliable")
        
        if not recommendations:
            recommendations.append("No obvious sanitization detected")
        
        return recommendations


def analyze_anti_forensics(pdf_path: Path) -> Dict[str, Any]:
    """
    Convenience function for anti-forensics analysis
    
    Args:
        pdf_path: Path to PDF file
    
    Returns:
        Dictionary with analysis results
    """
    detector = PDFAntiForensicsDetector()
    result = detector.analyze(pdf_path)
    return result.to_dict()
