"""
PDF Form Security Analysis Module

Comprehensive form vulnerability detection including:
- AcroForm field analysis (JavaScript, hidden fields, submit URLs)
- XFA (XML Forms Architecture) exploitation detection
- XXE (XML External Entity) vulnerability detection
- Form-based attacks (data exfiltration, injection)
- Hybrid AcroForm/XFA analysis

Based on extensive research from form_exploitation_research.md (46KB, 1415 lines)
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import re
import xml.etree.ElementTree as ET

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class FormSecuritySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    XXE = "xxe"
    XML_INJECTION = "xml_injection"
    JAVASCRIPT_INJECTION = "javascript_injection"
    SSRF = "ssrf"
    DATA_EXFILTRATION = "data_exfiltration"
    HIDDEN_FIELD = "hidden_field"
    MALICIOUS_URL = "malicious_url"
    XFA_EXPLOITATION = "xfa_exploitation"
    HYBRID_FORM_RISK = "hybrid_form_risk"


@dataclass
class FormVulnerability:
    """A single form security vulnerability"""
    type: VulnerabilityType
    severity: FormSecuritySeverity
    description: str
    location: str
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    cve_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['type'] = self.type.value
        result['severity'] = self.severity.value
        return result


@dataclass
class FormField:
    """AcroForm field information"""
    name: str
    field_type: str
    value: Any
    default_value: Any
    is_hidden: bool
    has_javascript: bool
    javascript_actions: List[str] = field(default_factory=list)
    submit_url: Optional[str] = None
    flags: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class XFAInfo:
    """XFA form information"""
    has_xfa: bool
    xfa_size: int
    has_xxe_indicators: bool
    has_external_entities: bool
    has_javascript: bool
    has_connection_sets: bool
    dataset_fields: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormSecurityResult:
    """Complete form security analysis result"""
    file_path: str
    has_acroform: bool
    has_xfa: bool
    is_hybrid: bool
    total_fields: int
    hidden_fields: int
    javascript_fields: int
    submit_urls: List[str]
    vulnerabilities: List[FormVulnerability]
    acroform_fields: List[FormField]
    xfa_info: Optional[XFAInfo]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        result['acroform_fields'] = [f.to_dict() for f in self.acroform_fields]
        if self.xfa_info:
            result['xfa_info'] = self.xfa_info.to_dict()
        return result


class PDFFormSecurityAnalyzer:
    """
    PDF Form Security Analyzer - Comprehensive form vulnerability detection
    
    Detects:
    - XXE vulnerabilities in XFA (CVE-2025-54988)
    - JavaScript injection in AcroForm fields
    - SSRF via SubmitForm actions
    - Hidden fields and data leakage
    - Malicious submit URLs
    - Hybrid AcroForm/XFA inconsistencies
    """
    
    XXE_PATTERNS = [
        r'<!ENTITY\s+\w+\s+SYSTEM',
        r'<!ENTITY\s+\w+\s+PUBLIC',
        r'<!DOCTYPE[^>]*\[',
        r'file:///',
        r'&\w+;',
    ]
    
    MALICIOUS_URL_SCHEMES = [
        "javascript:",
        "file:",
        "data:",
        "vbscript:",
        "\\\\",
        "smb://",
        "ftp://",
    ]
    
    DANGEROUS_JS_ACTIONS = [
        "app.launchURL",
        "submitForm",
        "importDataObject",
        "exportDataObject",
        "Collab.collectEmailInfo",
        "util.printf",
    ]
    
    SSRF_INDICATORS = [
        "localhost",
        "127.0.0.1",
        "192.168.",
        "10.",
        "172.16.",
        "169.254.",
        "internal",
        "intranet",
    ]
    
    def __init__(self):
        if not pikepdf:
            logger.warning("pikepdf not installed. Limited form analysis available.")
    
    def analyze(
        self,
        pdf_path: Path,
        check_xxe: bool = True,
        check_javascript: bool = True,
        check_hidden_fields: bool = True
    ) -> FormSecurityResult:
        """
        Perform comprehensive form security analysis
        
        Args:
            pdf_path: Path to PDF file
            check_xxe: Check for XXE vulnerabilities in XFA
            check_javascript: Analyze JavaScript in form fields
            check_hidden_fields: Detect hidden form fields
        
        Returns:
            FormSecurityResult with all findings
        """
        vulnerabilities = []
        acroform_fields = []
        submit_urls = []
        
        try:
            with PDFDocument(pdf_path) as doc:
                has_acroform = '/AcroForm' in doc.pdf.Root
                has_xfa = self._has_xfa(doc)
                is_hybrid = has_acroform and has_xfa
                
                if has_acroform:
                    fields, field_vulns = self._analyze_acroform(
                        doc, check_javascript, check_hidden_fields
                    )
                    acroform_fields = fields
                    vulnerabilities.extend(field_vulns)
                    
                    submit_urls = self._extract_submit_urls(doc)
                    
                    for url in submit_urls:
                        url_vulns = self._analyze_submit_url(url)
                        vulnerabilities.extend(url_vulns)
                
                xfa_info = None
                if has_xfa:
                    xfa_info, xfa_vulns = self._analyze_xfa(doc, check_xxe)
                    vulnerabilities.extend(xfa_vulns)
                
                if is_hybrid:
                    hybrid_vulns = self._analyze_hybrid_risks(doc)
                    vulnerabilities.extend(hybrid_vulns)
                
                total_fields = len(acroform_fields)
                hidden_fields = sum(1 for f in acroform_fields if f.is_hidden)
                javascript_fields = sum(1 for f in acroform_fields if f.has_javascript)
                
                recommendations = self._generate_recommendations(
                    vulnerabilities, has_xfa, is_hybrid
                )
                
                return FormSecurityResult(
                    file_path=str(pdf_path),
                    has_acroform=has_acroform,
                    has_xfa=has_xfa,
                    is_hybrid=is_hybrid,
                    total_fields=total_fields,
                    hidden_fields=hidden_fields,
                    javascript_fields=javascript_fields,
                    submit_urls=submit_urls,
                    vulnerabilities=vulnerabilities,
                    acroform_fields=acroform_fields,
                    xfa_info=xfa_info,
                    recommendations=recommendations
                )
        
        except Exception as e:
            logger.error(f"Error analyzing PDF forms: {e}")
            
            return FormSecurityResult(
                file_path=str(pdf_path),
                has_acroform=False,
                has_xfa=False,
                is_hybrid=False,
                total_fields=0,
                hidden_fields=0,
                javascript_fields=0,
                submit_urls=[],
                vulnerabilities=[],
                acroform_fields=[],
                xfa_info=None,
                recommendations=[f"Analysis error: {str(e)}"]
            )
    
    def _has_xfa(self, doc: PDFDocument) -> bool:
        """Check if PDF contains XFA forms"""
        try:
            if '/AcroForm' in doc.pdf.Root:
                acroform = doc.pdf.Root['/AcroForm']
                return '/XFA' in acroform
        except:
            pass
        return False
    
    def _analyze_acroform(
        self,
        doc: PDFDocument,
        check_javascript: bool,
        check_hidden_fields: bool
    ) -> Tuple[List[FormField], List[FormVulnerability]]:
        """Analyze AcroForm fields for vulnerabilities"""
        fields = []
        vulnerabilities = []
        
        try:
            if '/AcroForm' not in doc.pdf.Root:
                return fields, vulnerabilities
            
            acroform = doc.pdf.Root['/AcroForm']
            
            if '/Fields' not in acroform:
                return fields, vulnerabilities
            
            field_array = acroform['/Fields']
            
            for field_obj in field_array:
                field_dict = field_obj.as_dict() if hasattr(field_obj, 'as_dict') else field_obj
                
                if not isinstance(field_dict, dict):
                    continue
                
                field_name = str(field_dict.get('/T', 'Unknown'))
                field_type = str(field_dict.get('/FT', 'Unknown'))
                field_value = field_dict.get('/V', None)
                default_value = field_dict.get('/DV', None)
                flags = int(field_dict.get('/F', 0))
                
                is_hidden = self._is_field_hidden(field_dict, flags)
                
                javascript_actions = []
                has_javascript = False
                
                if check_javascript:
                    javascript_actions = self._extract_field_javascript(field_dict)
                    has_javascript = len(javascript_actions) > 0
                    
                    if has_javascript:
                        js_vulns = self._analyze_field_javascript(
                            field_name, javascript_actions
                        )
                        vulnerabilities.extend(js_vulns)
                
                if check_hidden_fields and is_hidden:
                    vulnerabilities.append(FormVulnerability(
                        type=VulnerabilityType.HIDDEN_FIELD,
                        severity=FormSecuritySeverity.MEDIUM,
                        description=f"Hidden form field detected: {field_name}",
                        location=f"Field: {field_name}",
                        evidence=[f"Flags: {flags}", f"Type: {field_type}"],
                        recommendation="Review hidden field for sensitive data or malicious content"
                    ))
                
                submit_url = self._extract_field_submit_url(field_dict)
                
                field = FormField(
                    name=field_name,
                    field_type=field_type,
                    value=field_value,
                    default_value=default_value,
                    is_hidden=is_hidden,
                    has_javascript=has_javascript,
                    javascript_actions=javascript_actions,
                    submit_url=submit_url,
                    flags=flags
                )
                
                fields.append(field)
        
        except Exception as e:
            logger.debug(f"AcroForm analysis error: {e}")
        
        return fields, vulnerabilities
    
    def _is_field_hidden(self, field_dict: Dict[str, Any], flags: int) -> bool:
        """Check if field is hidden"""
        hidden_flag = flags & 2
        noview_flag = flags & 32
        
        if hidden_flag or noview_flag:
            return True
        
        if '/Rect' in field_dict:
            rect = field_dict['/Rect']
            try:
                if isinstance(rect, list) and len(rect) == 4:
                    x1, y1, x2, y2 = [float(x) for x in rect]
                    width = abs(x2 - x1)
                    height = abs(y2 - y1)
                    
                    if width == 0 or height == 0:
                        return True
                    
                    if x1 < 0 or y1 < 0:
                        return True
            except:
                pass
        
        return False
    
    def _extract_field_javascript(self, field_dict: Dict[str, Any]) -> List[str]:
        """Extract JavaScript from field actions"""
        javascript = []
        
        try:
            if '/AA' in field_dict:
                aa = field_dict['/AA']
                
                if isinstance(aa, dict):
                    for event in ['/K', '/F', '/V', '/C', '/O']:
                        if event in aa:
                            action = aa[event]
                            if isinstance(action, dict) and '/JS' in action:
                                js_code = str(action['/JS'])
                                javascript.append(f"{event}: {js_code}")
        except:
            pass
        
        return javascript
    
    def _analyze_field_javascript(
        self, field_name: str, javascript_actions: List[str]
    ) -> List[FormVulnerability]:
        """Analyze JavaScript in form fields for threats"""
        vulnerabilities = []
        
        for action in javascript_actions:
            for dangerous_func in self.DANGEROUS_JS_ACTIONS:
                if dangerous_func in action:
                    severity = FormSecuritySeverity.HIGH
                    if dangerous_func in ["app.launchURL", "submitForm"]:
                        severity = FormSecuritySeverity.CRITICAL
                    
                    vulnerabilities.append(FormVulnerability(
                        type=VulnerabilityType.JAVASCRIPT_INJECTION,
                        severity=severity,
                        description=f"Dangerous JavaScript function in field: {dangerous_func}",
                        location=f"Field: {field_name}",
                        evidence=[action],
                        recommendation=f"Review JavaScript action for malicious behavior",
                        cve_id="CVE-2024-4367" if "launchURL" in dangerous_func else None
                    ))
        
        return vulnerabilities
    
    def _extract_field_submit_url(self, field_dict: Dict[str, Any]) -> Optional[str]:
        """Extract submit URL from field"""
        try:
            if '/AA' in field_dict:
                aa = field_dict['/AA']
                if isinstance(aa, dict):
                    for event in aa.values():
                        if isinstance(event, dict):
                            if '/S' in event and event['/S'] == '/SubmitForm':
                                if '/F' in event:
                                    return str(event['/F'])
        except:
            pass
        
        return None
    
    def _extract_submit_urls(self, doc: PDFDocument) -> List[str]:
        """Extract all form submission URLs"""
        urls = []
        
        try:
            pdf_bytes = doc.pdf_path.read_bytes()
            pdf_str = pdf_bytes.decode('latin-1', errors='ignore')
            
            submit_pattern = r'/SubmitForm.*?/F\s*\((.*?)\)'
            matches = re.findall(submit_pattern, pdf_str, re.DOTALL)
            
            for match in matches:
                url = match.strip()
                if url and url not in urls:
                    urls.append(url)
        
        except Exception as e:
            logger.debug(f"Submit URL extraction error: {e}")
        
        return urls
    
    def _analyze_submit_url(self, url: str) -> List[FormVulnerability]:
        """Analyze submit URL for security risks"""
        vulnerabilities = []
        
        url_lower = url.lower()
        
        for scheme in self.MALICIOUS_URL_SCHEMES:
            if url_lower.startswith(scheme):
                vulnerabilities.append(FormVulnerability(
                    type=VulnerabilityType.MALICIOUS_URL,
                    severity=FormSecuritySeverity.CRITICAL,
                    description=f"Dangerous URL scheme detected: {scheme}",
                    location="SubmitForm action",
                    evidence=[url],
                    recommendation="CRITICAL: Malicious URL scheme - reject document",
                    cve_id="CVE-2013-5325" if scheme == "javascript:" else None
                ))
        
        for indicator in self.SSRF_INDICATORS:
            if indicator in url_lower:
                vulnerabilities.append(FormVulnerability(
                    type=VulnerabilityType.SSRF,
                    severity=FormSecuritySeverity.HIGH,
                    description="Potential SSRF - internal network URL",
                    location="SubmitForm action",
                    evidence=[url],
                    recommendation="URL points to internal network - possible SSRF attack",
                    cve_id="CVE-2024-55082"
                ))
        
        if not url.startswith("https://"):
            vulnerabilities.append(FormVulnerability(
                type=VulnerabilityType.DATA_EXFILTRATION,
                severity=FormSecuritySeverity.MEDIUM,
                description="Insecure form submission (non-HTTPS)",
                location="SubmitForm action",
                evidence=[url],
                recommendation="Form data transmitted over unencrypted connection"
            ))
        
        return vulnerabilities
    
    def _analyze_xfa(
        self, doc: PDFDocument, check_xxe: bool
    ) -> Tuple[Optional[XFAInfo], List[FormVulnerability]]:
        """Analyze XFA forms for vulnerabilities"""
        vulnerabilities = []
        
        try:
            if '/AcroForm' not in doc.pdf.Root:
                return None, vulnerabilities
            
            acroform = doc.pdf.Root['/AcroForm']
            
            if '/XFA' not in acroform:
                return None, vulnerabilities
            
            xfa_data = acroform['/XFA']
            
            xfa_bytes = b''
            
            if isinstance(xfa_data, list):
                for item in xfa_data:
                    if hasattr(item, 'read_bytes'):
                        xfa_bytes += item.read_bytes()
            elif hasattr(xfa_data, 'read_bytes'):
                xfa_bytes = xfa_data.read_bytes()
            
            xfa_str = xfa_bytes.decode('utf-8', errors='ignore')
            
            has_xxe_indicators = False
            has_external_entities = False
            has_javascript = False
            has_connection_sets = False
            dataset_fields = []
            
            if check_xxe:
                for pattern in self.XXE_PATTERNS:
                    if re.search(pattern, xfa_str, re.IGNORECASE):
                        has_xxe_indicators = True
                        
                        if 'SYSTEM' in pattern or 'file:///' in pattern:
                            has_external_entities = True
                            
                            vulnerabilities.append(FormVulnerability(
                                type=VulnerabilityType.XXE,
                                severity=FormSecuritySeverity.CRITICAL,
                                description="XXE (XML External Entity) vulnerability detected in XFA",
                                location="XFA template",
                                evidence=[f"Pattern: {pattern}"],
                                recommendation="CRITICAL: XXE vulnerability - can lead to file disclosure, SSRF",
                                cve_id="CVE-2025-54988"
                            ))
            
            if '<script' in xfa_str.lower():
                has_javascript = True
                
                vulnerabilities.append(FormVulnerability(
                    type=VulnerabilityType.XFA_EXPLOITATION,
                    severity=FormSecuritySeverity.HIGH,
                    description="JavaScript detected in XFA template",
                    location="XFA template",
                    evidence=["<script> elements found"],
                    recommendation="Review XFA JavaScript for malicious behavior"
                ))
            
            if '<connectionSet' in xfa_str:
                has_connection_sets = True
                
                vulnerabilities.append(FormVulnerability(
                    type=VulnerabilityType.XFA_EXPLOITATION,
                    severity=FormSecuritySeverity.MEDIUM,
                    description="XFA connection sets detected (may contain credentials)",
                    location="XFA template",
                    evidence=["<connectionSet> elements found"],
                    recommendation="Review connection strings for sensitive information"
                ))
            
            try:
                root = ET.fromstring(xfa_bytes)
                for elem in root.iter():
                    if 'field' in elem.tag.lower():
                        name = elem.get('name', elem.tag)
                        dataset_fields.append(name)
            except:
                pass
            
            xfa_info = XFAInfo(
                has_xfa=True,
                xfa_size=len(xfa_bytes),
                has_xxe_indicators=has_xxe_indicators,
                has_external_entities=has_external_entities,
                has_javascript=has_javascript,
                has_connection_sets=has_connection_sets,
                dataset_fields=dataset_fields
            )
            
            return xfa_info, vulnerabilities
        
        except Exception as e:
            logger.debug(f"XFA analysis error: {e}")
            return None, vulnerabilities
    
    def _analyze_hybrid_risks(self, doc: PDFDocument) -> List[FormVulnerability]:
        """Analyze security risks in hybrid AcroForm/XFA PDFs"""
        vulnerabilities = []
        
        vulnerabilities.append(FormVulnerability(
            type=VulnerabilityType.HYBRID_FORM_RISK,
            severity=FormSecuritySeverity.MEDIUM,
            description="Hybrid AcroForm/XFA detected - reader-specific behavior",
            location="PDF structure",
            evidence=["Both AcroForm and XFA present"],
            recommendation="Different PDF readers may display different content - verify in multiple readers"
        ))
        
        return vulnerabilities
    
    def _generate_recommendations(
        self,
        vulnerabilities: List[FormVulnerability],
        has_xfa: bool,
        is_hybrid: bool
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if any(v.type == VulnerabilityType.XXE for v in vulnerabilities):
            recommendations.append("CRITICAL: XXE vulnerability detected - do not process with vulnerable parsers")
        
        if any(v.type == VulnerabilityType.JAVASCRIPT_INJECTION for v in vulnerabilities):
            recommendations.append("Disable JavaScript in PDF reader when viewing this document")
        
        if any(v.type == VulnerabilityType.SSRF for v in vulnerabilities):
            recommendations.append("Block form submission to prevent SSRF attacks")
        
        if any(v.type == VulnerabilityType.MALICIOUS_URL for v in vulnerabilities):
            recommendations.append("Malicious URLs detected - reject document")
        
        if has_xfa:
            recommendations.append("XFA forms have larger attack surface - consider converting to static PDF")
        
        if is_hybrid:
            recommendations.append("Verify document in multiple readers (Adobe, Firefox, Chrome) for consistency")
        
        if not recommendations:
            if not vulnerabilities:
                recommendations.append("No critical form security issues detected")
            else:
                recommendations.append("Review all findings and apply appropriate mitigations")
        
        return recommendations


def analyze_form_security(
    pdf_path: Path,
    check_xxe: bool = True,
    check_javascript: bool = True,
    check_hidden_fields: bool = True
) -> Dict[str, Any]:
    """
    Convenience function for form security analysis
    
    Args:
        pdf_path: Path to PDF file
        check_xxe: Check for XXE vulnerabilities
        check_javascript: Analyze JavaScript in fields
        check_hidden_fields: Detect hidden fields
    
    Returns:
        Dictionary with analysis results
    """
    analyzer = PDFFormSecurityAnalyzer()
    result = analyzer.analyze(pdf_path, check_xxe, check_javascript, check_hidden_fields)
    return result.to_dict()
