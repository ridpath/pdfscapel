"""
PDF Advanced Steganography Detection Module

Detect advanced steganography techniques beyond simple LSB including:
- Stream operator manipulation (floating-point embedding)
- Object ID ordering covert channels
- Whitespace encoding (zero-width Unicode characters)
- Cross-reference table manipulation
- Incremental update embedding
- Trailer dictionary custom fields
- Comment field encoding
- Free object slots utilization

Based on extensive research from advanced_stego_research.md (43KB, 1324 lines)
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import re
import math

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class StegoSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class StegoTechnique(Enum):
    STREAM_OPERATOR = "stream_operator"
    OBJECT_ORDERING = "object_ordering"
    WHITESPACE_ENCODING = "whitespace_encoding"
    XREF_MANIPULATION = "xref_manipulation"
    INCREMENTAL_UPDATE = "incremental_update"
    TRAILING_DATA = "trailing_data"
    TRAILER_CUSTOM_FIELDS = "trailer_custom_fields"
    COMMENT_ENCODING = "comment_encoding"
    FREE_OBJECTS = "free_objects"


@dataclass
class StegoFinding:
    """A single steganography detection finding"""
    technique: StegoTechnique
    severity: StegoSeverity
    description: str
    location: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    estimated_capacity: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['technique'] = self.technique.value
        result['severity'] = self.severity.value
        return result


@dataclass
class StegoAnalysisResult:
    """Complete steganography analysis result"""
    file_path: str
    stego_detected: bool
    overall_confidence: float
    findings: List[StegoFinding]
    entropy_anomalies: List[Dict[str, Any]]
    trailing_data_size: int
    incremental_updates_count: int
    suspicious_objects_count: int
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['findings'] = [f.to_dict() for f in self.findings]
        return result


class PDFAdvancedStegoDetector:
    """
    PDF Advanced Steganography Detector - Detect covert data hiding
    
    Detects:
    - Stream operator manipulation (high capacity)
    - Object ID ordering covert channels
    - Zero-width Unicode character encoding
    - Cross-reference table manipulation
    - Incremental update embedding
    - Trailing data after %%EOF
    - Custom trailer fields
    - Comment field encoding
    """
    
    ZERO_WIDTH_CHARS = [
        '\u200B',
        '\u200C',
        '\u200D',
        '\uFEFF',
        '\u2800',
    ]
    
    PDF_OPERATORS_WITH_REALS = [
        'Tm', 'Td', 'TD', 'Tc', 'Tw', 'Tz', 'TL',
        'cm', 'l', 'm', 're', 'c', 'v', 'y',
        'w', 'd', 'M', 'J', 'j',
        'SC', 'SCN', 'sc', 'scn', 'G', 'g', 'RG', 'rg', 'K', 'k'
    ]
    
    STANDARD_TRAILER_KEYS = [
        '/Size', '/Root', '/Info', '/ID', '/Encrypt', '/Prev'
    ]
    
    def __init__(self):
        if not pikepdf:
            logger.warning("pikepdf not installed. Limited stego detection.")
    
    def analyze(self, pdf_path: Path, deep_analysis: bool = True) -> StegoAnalysisResult:
        """
        Perform comprehensive steganography analysis
        
        Args:
            pdf_path: Path to PDF file
            deep_analysis: Perform deep content stream analysis
        
        Returns:
            StegoAnalysisResult with all findings
        """
        findings = []
        entropy_anomalies = []
        
        try:
            pdf_data = pdf_path.read_bytes()
            
            trailing_size = self._detect_trailing_data(pdf_data)
            if trailing_size > 0:
                findings.append(StegoFinding(
                    technique=StegoTechnique.TRAILING_DATA,
                    severity=StegoSeverity.HIGH,
                    description=f"Trailing data after %%EOF ({trailing_size} bytes)",
                    location="After EOF marker",
                    evidence=[f"{trailing_size} bytes appended"],
                    confidence=0.95,
                    estimated_capacity=f"{trailing_size} bytes"
                ))
            
            incremental_updates = self._count_incremental_updates(pdf_data)
            
            if incremental_updates > 3:
                findings.append(StegoFinding(
                    technique=StegoTechnique.INCREMENTAL_UPDATE,
                    severity=StegoSeverity.MEDIUM,
                    description=f"Multiple incremental updates ({incremental_updates} found)",
                    location="PDF structure",
                    evidence=[f"{incremental_updates} xref tables"],
                    confidence=0.6,
                    estimated_capacity="HIGH (varies)"
                ))
            
            comment_data = self._analyze_comments(pdf_data)
            if comment_data['suspicious']:
                findings.append(StegoFinding(
                    technique=StegoTechnique.COMMENT_ENCODING,
                    severity=StegoSeverity.MEDIUM,
                    description=f"Suspicious comments detected ({comment_data['count']} comments)",
                    location="Various locations",
                    evidence=comment_data['evidence'],
                    confidence=comment_data['confidence'],
                    estimated_capacity="MEDIUM (~1-5 KB)"
                ))
            
            with PDFDocument(pdf_path) as doc:
                trailer_findings = self._analyze_trailer(doc)
                findings.extend(trailer_findings)
                
                xref_findings = self._analyze_xref_manipulation(doc)
                findings.extend(xref_findings)
                
                if deep_analysis:
                    stream_findings = self._analyze_stream_operators(doc)
                    findings.extend(stream_findings)
                    
                    whitespace_findings = self._analyze_whitespace_encoding(doc)
                    findings.extend(whitespace_findings)
                    
                    object_order_findings = self._analyze_object_ordering(doc)
                    findings.extend(object_order_findings)
                
                entropy_anomalies = self._analyze_entropy(doc)
            
            suspicious_objects_count = sum(
                1 for f in findings
                if f.technique in [StegoTechnique.XREF_MANIPULATION, StegoTechnique.FREE_OBJECTS]
            )
            
            stego_detected = len(findings) > 0
            
            overall_confidence = 0.0
            if findings:
                overall_confidence = max(f.confidence for f in findings)
            
            recommendations = self._generate_recommendations(findings)
            
            return StegoAnalysisResult(
                file_path=str(pdf_path),
                stego_detected=stego_detected,
                overall_confidence=overall_confidence,
                findings=findings,
                entropy_anomalies=entropy_anomalies,
                trailing_data_size=trailing_size,
                incremental_updates_count=incremental_updates,
                suspicious_objects_count=suspicious_objects_count,
                recommendations=recommendations
            )
        
        except Exception as e:
            logger.error(f"Error analyzing steganography: {e}")
            
            return StegoAnalysisResult(
                file_path=str(pdf_path),
                stego_detected=False,
                overall_confidence=0.0,
                findings=[],
                entropy_anomalies=[],
                trailing_data_size=0,
                incremental_updates_count=0,
                suspicious_objects_count=0,
                recommendations=[f"Analysis error: {str(e)}"]
            )
    
    def _detect_trailing_data(self, pdf_data: bytes) -> int:
        """Detect data after %%EOF marker"""
        try:
            eof_positions = [m.start() for m in re.finditer(rb'%%EOF', pdf_data)]
            
            if eof_positions:
                last_eof = eof_positions[-1]
                file_size = len(pdf_data)
                trailing_size = file_size - last_eof - 5
                
                if trailing_size > 10:
                    return trailing_size
        
        except:
            pass
        
        return 0
    
    def _count_incremental_updates(self, pdf_data: bytes) -> int:
        """Count number of incremental updates (xref tables)"""
        try:
            xref_matches = re.findall(rb'xref\s', pdf_data)
            return len(xref_matches)
        except:
            return 0
    
    def _analyze_comments(self, pdf_data: bytes) -> Dict[str, Any]:
        """Analyze PDF comments for suspicious patterns"""
        result = {
            'suspicious': False,
            'count': 0,
            'confidence': 0.0,
            'evidence': []
        }
        
        try:
            pdf_str = pdf_data.decode('latin-1', errors='ignore')
            
            comment_lines = re.findall(r'^%[^%\r\n].*$', pdf_str, re.MULTILINE)
            
            result['count'] = len(comment_lines)
            
            if len(comment_lines) > 50:
                result['suspicious'] = True
                result['confidence'] = 0.7
                result['evidence'].append(f"{len(comment_lines)} comment lines (unusually high)")
            
            suspicious_patterns = [
                r'[A-Za-z0-9+/]{50,}=*',
                r'[0-9a-fA-F]{100,}',
                r'flag\{.*\}',
            ]
            
            for line in comment_lines:
                for pattern in suspicious_patterns:
                    if re.search(pattern, line):
                        result['suspicious'] = True
                        result['confidence'] = max(result['confidence'], 0.8)
                        result['evidence'].append(f"Encoded data pattern in comment")
                        break
        
        except Exception as e:
            logger.debug(f"Comment analysis error: {e}")
        
        return result
    
    def _analyze_trailer(self, doc: PDFDocument) -> List[StegoFinding]:
        """Analyze trailer dictionary for custom fields"""
        findings = []
        
        try:
            trailer = doc.pdf.trailer
            
            custom_keys = []
            for key in trailer.keys():
                key_str = str(key)
                if key_str not in self.STANDARD_TRAILER_KEYS:
                    custom_keys.append(key_str)
            
            if custom_keys:
                findings.append(StegoFinding(
                    technique=StegoTechnique.TRAILER_CUSTOM_FIELDS,
                    severity=StegoSeverity.MEDIUM,
                    description=f"Custom trailer fields detected ({len(custom_keys)} keys)",
                    location="Trailer dictionary",
                    evidence=custom_keys,
                    confidence=0.7,
                    estimated_capacity="MEDIUM (~1-10 KB)"
                ))
        
        except Exception as e:
            logger.debug(f"Trailer analysis error: {e}")
        
        return findings
    
    def _analyze_xref_manipulation(self, doc: PDFDocument) -> List[StegoFinding]:
        """Analyze cross-reference table for manipulation"""
        findings = []
        
        try:
            pdf_data = doc.pdf_path.read_bytes()
            
            free_entries = re.findall(rb'(\d{10})\s+(\d{5})\s+f', pdf_data)
            
            if len(free_entries) > 10:
                findings.append(StegoFinding(
                    technique=StegoTechnique.FREE_OBJECTS,
                    severity=StegoSeverity.MEDIUM,
                    description=f"Multiple free object entries ({len(free_entries)} found)",
                    location="Xref table",
                    evidence=[f"{len(free_entries)} free entries"],
                    confidence=0.6,
                    estimated_capacity="LOW (~10-100 bytes)"
                ))
        
        except Exception as e:
            logger.debug(f"Xref analysis error: {e}")
        
        return findings
    
    def _analyze_stream_operators(self, doc: PDFDocument) -> List[StegoFinding]:
        """Analyze content streams for operator manipulation"""
        findings = []
        
        try:
            total_high_precision = 0
            total_operators = 0
            
            for page in doc.pdf.pages:
                if '/Contents' in page:
                    contents = page['/Contents']
                    
                    if hasattr(contents, 'read_bytes'):
                        try:
                            stream_data = contents.read_bytes().decode('latin-1', errors='ignore')
                            
                            float_pattern = r'(\d+\.\d{5,})\s+([a-zA-Z]{1,3})'
                            matches = re.findall(float_pattern, stream_data)
                            
                            total_operators += len(re.findall(r'\s+[a-zA-Z]{1,3}\s', stream_data))
                            total_high_precision += len(matches)
                        except:
                            pass
            
            if total_operators > 0:
                precision_ratio = total_high_precision / total_operators
                
                if precision_ratio > 0.1:
                    findings.append(StegoFinding(
                        technique=StegoTechnique.STREAM_OPERATOR,
                        severity=StegoSeverity.HIGH,
                        description=f"High-precision floating-point operators detected ({precision_ratio:.1%})",
                        location="Content streams",
                        evidence=[f"{total_high_precision} high-precision values in {total_operators} operators"],
                        confidence=0.8,
                        estimated_capacity="HIGH (~0.5-2 KB per page)"
                    ))
        
        except Exception as e:
            logger.debug(f"Stream operator analysis error: {e}")
        
        return findings
    
    def _analyze_whitespace_encoding(self, doc: PDFDocument) -> List[StegoFinding]:
        """Analyze for zero-width Unicode character encoding"""
        findings = []
        
        try:
            zero_width_count = 0
            
            for page in doc.pdf.pages:
                if '/Contents' in page:
                    contents = page['/Contents']
                    
                    if hasattr(contents, 'read_bytes'):
                        try:
                            stream_data = contents.read_bytes().decode('utf-8', errors='ignore')
                            
                            for char in self.ZERO_WIDTH_CHARS:
                                zero_width_count += stream_data.count(char)
                        except:
                            pass
            
            if zero_width_count > 10:
                findings.append(StegoFinding(
                    technique=StegoTechnique.WHITESPACE_ENCODING,
                    severity=StegoSeverity.HIGH,
                    description=f"Zero-width Unicode characters detected ({zero_width_count} found)",
                    location="Text content",
                    evidence=[f"{zero_width_count} invisible characters"],
                    confidence=0.85,
                    estimated_capacity="MEDIUM (~1 bit per character)"
                ))
        
        except Exception as e:
            logger.debug(f"Whitespace analysis error: {e}")
        
        return findings
    
    def _analyze_object_ordering(self, doc: PDFDocument) -> List[StegoFinding]:
        """Analyze object ID ordering for covert channels"""
        findings = []
        
        try:
            object_ids = []
            for obj in doc.pdf.objects:
                if hasattr(obj, 'objgen'):
                    object_ids.append(obj.objgen[0])
            
            if len(object_ids) > 10:
                expected_sequence = list(range(1, len(object_ids) + 1))
                
                if object_ids != expected_sequence:
                    inversions = 0
                    for i in range(len(object_ids) - 1):
                        for j in range(i + 1, len(object_ids)):
                            if object_ids[i] > object_ids[j]:
                                inversions += 1
                    
                    if inversions > len(object_ids) * 0.2:
                        findings.append(StegoFinding(
                            technique=StegoTechnique.OBJECT_ORDERING,
                            severity=StegoSeverity.MEDIUM,
                            description=f"Non-sequential object ordering detected ({inversions} inversions)",
                            location="Object structure",
                            evidence=[f"{inversions} ordering inversions"],
                            confidence=0.6,
                            estimated_capacity="LOW (~log2(n!) bits)"
                        ))
        
        except Exception as e:
            logger.debug(f"Object ordering analysis error: {e}")
        
        return findings
    
    def _analyze_entropy(self, doc: PDFDocument) -> List[Dict[str, Any]]:
        """Analyze entropy of PDF streams for anomalies"""
        anomalies = []
        
        try:
            for obj_id, obj in enumerate(doc.pdf.objects):
                if hasattr(obj, 'read_bytes'):
                    try:
                        data = obj.read_bytes()
                        entropy = self._calculate_entropy(data)
                        
                        if entropy > 7.9 and len(data) > 100:
                            anomalies.append({
                                'object_id': obj_id,
                                'entropy': round(entropy, 3),
                                'size': len(data),
                                'assessment': 'high_entropy_stego_candidate'
                            })
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"Entropy analysis error: {e}")
        
        return anomalies
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0.0
        
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _generate_recommendations(self, findings: List[StegoFinding]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        techniques = {f.technique for f in findings}
        
        if StegoTechnique.TRAILING_DATA in techniques:
            recommendations.append("Extract data after %%EOF marker for analysis")
        
        if StegoTechnique.STREAM_OPERATOR in techniques:
            recommendations.append("Extract and analyze floating-point precision in content streams")
        
        if StegoTechnique.WHITESPACE_ENCODING in techniques:
            recommendations.append("Extract text and filter zero-width Unicode characters")
        
        if StegoTechnique.INCREMENTAL_UPDATE in techniques:
            recommendations.append("Use pdfresurrect to extract all PDF versions/updates")
        
        if StegoTechnique.TRAILER_CUSTOM_FIELDS in techniques:
            recommendations.append("Inspect custom trailer fields for encoded data")
        
        if StegoTechnique.COMMENT_ENCODING in techniques:
            recommendations.append("Extract all comment lines and check for Base64/hex encoding")
        
        if not recommendations:
            if findings:
                recommendations.append("Perform deep forensic analysis - subtle stego detected")
            else:
                recommendations.append("No obvious steganography detected")
        
        return recommendations


def analyze_stego(pdf_path: Path, deep_analysis: bool = True) -> Dict[str, Any]:
    """
    Convenience function for steganography analysis
    
    Args:
        pdf_path: Path to PDF file
        deep_analysis: Perform deep content analysis
    
    Returns:
        Dictionary with analysis results
    """
    detector = PDFAdvancedStegoDetector()
    result = detector.analyze(pdf_path, deep_analysis)
    return result.to_dict()
