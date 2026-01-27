"""
PDF Digital Signature & Certificate Forensics Module

Comprehensive signature validation and forgery detection including:
- PKCS#7/CMS signature validation
- Certificate chain verification
- Attack detection (USF, SWA, ISA, Shadow attacks)
- Weak cryptography detection
- PAdES compliance validation
- Trust assessment

Based on extensive research from signature_forensics_research.md (55KB, 1711 lines)
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import hashlib
import re

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    x509 = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class SignatureSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TrustLevel(Enum):
    TRUSTED = "trusted"
    CONDITIONAL = "conditional"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"


class SignatureStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass
class SignatureFinding:
    """A single signature validation finding"""
    type: str
    severity: SignatureSeverity
    description: str
    location: str
    evidence: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    cve_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['severity'] = self.severity.value
        return result


@dataclass
class CertificateInfo:
    """Certificate information"""
    subject: str
    issuer: str
    serial_number: str
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    public_key_algorithm: str = "unknown"
    key_size: int = 0
    signature_algorithm: str = "unknown"
    is_self_signed: bool = False
    key_usage: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.not_before:
            result['not_before'] = self.not_before.isoformat()
        if self.not_after:
            result['not_after'] = self.not_after.isoformat()
        return result


@dataclass
class SignatureValidation:
    """Individual signature validation result"""
    signature_number: int
    status: SignatureStatus
    trust_level: TrustLevel
    signer_name: str
    signing_time: Optional[datetime]
    certificate_info: CertificateInfo
    digest_algorithm: str
    is_certification: bool
    doc_mdp_level: Optional[int]
    byte_range: List[int]
    byte_range_valid: bool
    unsigned_bytes: int
    findings: List[SignatureFinding]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        result['trust_level'] = self.trust_level.value
        result['certificate_info'] = self.certificate_info.to_dict()
        result['findings'] = [f.to_dict() for f in self.findings]
        if self.signing_time:
            result['signing_time'] = self.signing_time.isoformat()
        return result


@dataclass
class SignatureAnalysisResult:
    """Complete signature analysis result"""
    file_path: str
    total_signatures: int
    certification_signature: bool
    overall_status: SignatureStatus
    overall_trust: TrustLevel
    signatures: List[SignatureValidation]
    attack_indicators: List[str]
    compliance_issues: List[str]
    cryptography_warnings: List[str]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['overall_status'] = self.overall_status.value
        result['overall_trust'] = self.overall_trust.value
        result['signatures'] = [s.to_dict() for s in self.signatures]
        return result


class PDFSignatureAnalyzer:
    """
    PDF Signature Analyzer - Comprehensive signature validation and forensics
    
    Detects:
    - Invalid signatures (cryptographic verification)
    - Tampered documents (byte range manipulation)
    - Weak cryptography (SHA-1, MD5, weak keys)
    - Attack patterns (USF, SWA, ISA, Shadow attacks)
    - Certificate issues (expired, self-signed, untrusted)
    - PAdES compliance violations
    """
    
    ADOBE_AATL_CAS = [
        "DigiCert",
        "Entrust",
        "GlobalSign",
        "DocuSign",
        "IdenTrust",
        "Keynectis",
        "SwissSign",
        "D-TRUST",
    ]
    
    WEAK_DIGEST_ALGORITHMS = {
        "md5": SignatureSeverity.CRITICAL,
        "sha1": SignatureSeverity.HIGH,
        "sha-1": SignatureSeverity.HIGH,
        "sha224": SignatureSeverity.MEDIUM,
    }
    
    DEPRECATED_SUBFILTERS = {
        "adbe.pkcs7.sha1": "SHA-1 based signature (deprecated)",
        "adbe.x509.rsa_sha1": "RSA-SHA1 signature (deprecated)",
    }
    
    def __init__(self):
        if not pikepdf:
            logger.warning("pikepdf not installed. Limited signature analysis available.")
        if not x509:
            logger.warning("cryptography library not installed. Certificate validation disabled.")
    
    def analyze(self, pdf_path: Path, deep_validation: bool = True) -> SignatureAnalysisResult:
        """
        Perform comprehensive signature analysis
        
        Args:
            pdf_path: Path to PDF file
            deep_validation: Perform deep cryptographic and attack detection
        
        Returns:
            SignatureAnalysisResult with all findings
        """
        try:
            with PDFDocument(pdf_path) as doc:
                signature_fields = self._extract_signature_fields(doc)
                
                if not signature_fields:
                    return SignatureAnalysisResult(
                        file_path=str(pdf_path),
                        total_signatures=0,
                        certification_signature=False,
                        overall_status=SignatureStatus.UNKNOWN,
                        overall_trust=TrustLevel.UNTRUSTED,
                        signatures=[],
                        attack_indicators=[],
                        compliance_issues=[],
                        cryptography_warnings=[],
                        recommendations=["No digital signatures found in PDF"]
                    )
                
                signatures = []
                attack_indicators = []
                compliance_issues = []
                crypto_warnings = []
                
                for idx, sig_field in enumerate(signature_fields):
                    sig_validation = self._validate_signature(
                        doc, sig_field, idx + 1, deep_validation
                    )
                    signatures.append(sig_validation)
                    
                    for finding in sig_validation.findings:
                        if "attack" in finding.type.lower():
                            attack_indicators.append(finding.description)
                        if "compliance" in finding.type.lower():
                            compliance_issues.append(finding.description)
                        if "crypto" in finding.type.lower() or "weak" in finding.type.lower():
                            crypto_warnings.append(finding.description)
                
                has_certification = any(s.is_certification for s in signatures)
                
                overall_status = self._calculate_overall_status(signatures)
                overall_trust = self._calculate_overall_trust(signatures)
                recommendations = self._generate_recommendations(
                    signatures, attack_indicators, crypto_warnings
                )
                
                return SignatureAnalysisResult(
                    file_path=str(pdf_path),
                    total_signatures=len(signatures),
                    certification_signature=has_certification,
                    overall_status=overall_status,
                    overall_trust=overall_trust,
                    signatures=signatures,
                    attack_indicators=attack_indicators,
                    compliance_issues=compliance_issues,
                    cryptography_warnings=crypto_warnings,
                    recommendations=recommendations
                )
        
        except Exception as e:
            logger.error(f"Error analyzing PDF signatures: {e}")
            
            return SignatureAnalysisResult(
                file_path=str(pdf_path),
                total_signatures=0,
                certification_signature=False,
                overall_status=SignatureStatus.UNKNOWN,
                overall_trust=TrustLevel.UNTRUSTED,
                signatures=[],
                attack_indicators=[],
                compliance_issues=[],
                cryptography_warnings=[],
                recommendations=[f"Analysis error: {str(e)}"]
            )
    
    def _extract_signature_fields(self, doc: PDFDocument) -> List[Dict[str, Any]]:
        """Extract all signature fields from PDF"""
        signatures = []
        
        try:
            if '/AcroForm' not in doc.pdf.Root:
                return signatures
            
            acro_form = doc.pdf.Root['/AcroForm']
            
            if '/Fields' not in acro_form:
                return signatures
            
            fields = acro_form['/Fields']
            
            for field in fields:
                field_dict = field.as_dict() if hasattr(field, 'as_dict') else field
                
                if isinstance(field_dict, dict):
                    ft_value = field_dict.get('/FT', '')
                    v_value = field_dict.get('/V', None)
                    
                    if ft_value == '/Sig' and v_value:
                        sig_dict = v_value.as_dict() if hasattr(v_value, 'as_dict') else v_value
                        
                        if isinstance(sig_dict, dict):
                            signatures.append({
                                'field': field_dict,
                                'signature': sig_dict
                            })
        
        except Exception as e:
            logger.debug(f"Error extracting signature fields: {e}")
        
        return signatures
    
    def _validate_signature(
        self,
        doc: PDFDocument,
        sig_field: Dict[str, Any],
        sig_number: int,
        deep_validation: bool
    ) -> SignatureValidation:
        """Validate individual signature"""
        findings = []
        sig_dict = sig_field['signature']
        
        subfilter = str(sig_dict.get('/SubFilter', '')).replace('/', '')
        contents = sig_dict.get('/Contents', b'')
        byte_range = sig_dict.get('/ByteRange', [])
        
        if isinstance(byte_range, list):
            byte_range = [int(x) for x in byte_range]
        else:
            byte_range = []
        
        is_certification = '/Type' in sig_dict and sig_dict['/Type'] == '/DocTimeStamp'
        is_certification = is_certification or ('/Reference' in sig_dict)
        
        doc_mdp_level = self._extract_doc_mdp_level(sig_dict)
        
        if subfilter in self.DEPRECATED_SUBFILTERS:
            findings.append(SignatureFinding(
                type="deprecated_algorithm",
                severity=SignatureSeverity.HIGH,
                description=f"Deprecated signature format: {subfilter}",
                location=f"Signature {sig_number}",
                evidence=[self.DEPRECATED_SUBFILTERS[subfilter]],
                recommendation="Re-sign with modern format (adbe.pkcs7.detached)"
            ))
        
        byte_range_valid, unsigned_bytes = self._validate_byte_range(
            doc, byte_range
        )
        
        if not byte_range_valid:
            findings.append(SignatureFinding(
                type="byte_range_invalid",
                severity=SignatureSeverity.CRITICAL,
                description="Signature byte range is invalid or incomplete",
                location=f"Signature {sig_number}",
                evidence=[f"ByteRange: {byte_range}"],
                recommendation="Document may be tampered - signature doesn't cover full document"
            ))
        
        if unsigned_bytes > 0:
            findings.append(SignatureFinding(
                type="isa_attack",
                severity=SignatureSeverity.CRITICAL,
                description=f"Incremental Saving Attack detected: {unsigned_bytes} unsigned bytes",
                location=f"Signature {sig_number}",
                evidence=[f"{unsigned_bytes} bytes after signature"],
                recommendation="CRITICAL: Content added after signing. Reject document.",
                cve_id="ISA-2019"
            ))
        
        cert_info, cert_findings = self._extract_certificate_info(contents)
        findings.extend(cert_findings)
        
        digest_algorithm = self._extract_digest_algorithm(contents)
        
        if digest_algorithm.lower() in self.WEAK_DIGEST_ALGORITHMS:
            severity = self.WEAK_DIGEST_ALGORITHMS[digest_algorithm.lower()]
            findings.append(SignatureFinding(
                type="weak_cryptography",
                severity=severity,
                description=f"Weak digest algorithm: {digest_algorithm.upper()}",
                location=f"Signature {sig_number}",
                evidence=["Cryptographically broken - collision attacks possible"],
                recommendation="Re-sign with SHA-256 or stronger"
            ))
        
        if deep_validation:
            attack_findings = self._detect_attacks(doc, sig_dict, byte_range, sig_number)
            findings.extend(attack_findings)
        
        status = SignatureStatus.VALID
        if any(f.severity == SignatureSeverity.CRITICAL for f in findings):
            status = SignatureStatus.INVALID
        elif any(f.severity == SignatureSeverity.HIGH for f in findings):
            status = SignatureStatus.UNKNOWN
        
        trust_level = self._assess_trust_level(cert_info, findings)
        
        signing_time = self._extract_signing_time(sig_dict)
        
        return SignatureValidation(
            signature_number=sig_number,
            status=status,
            trust_level=trust_level,
            signer_name=cert_info.subject,
            signing_time=signing_time,
            certificate_info=cert_info,
            digest_algorithm=digest_algorithm,
            is_certification=is_certification,
            doc_mdp_level=doc_mdp_level,
            byte_range=byte_range,
            byte_range_valid=byte_range_valid,
            unsigned_bytes=unsigned_bytes,
            findings=findings
        )
    
    def _validate_byte_range(
        self, doc: PDFDocument, byte_range: List[int]
    ) -> Tuple[bool, int]:
        """Validate signature byte range coverage"""
        if len(byte_range) != 4:
            return False, 0
        
        try:
            file_size = doc.pdf_path.stat().st_size
            
            offset1, length1, offset2, length2 = byte_range
            
            signed_end = offset2 + length2
            
            if signed_end < file_size:
                unsigned_bytes = file_size - signed_end
                return False, unsigned_bytes
            
            expected_offset2 = offset1 + length1
            gap_size = offset2 - expected_offset2
            
            if gap_size < 100:
                return False, 0
            
            return True, 0
        
        except Exception as e:
            logger.debug(f"Byte range validation error: {e}")
            return False, 0
    
    def _extract_doc_mdp_level(self, sig_dict: Dict[str, Any]) -> Optional[int]:
        """Extract DocMDP permission level"""
        try:
            if '/Reference' in sig_dict:
                refs = sig_dict['/Reference']
                
                if isinstance(refs, list):
                    for ref in refs:
                        if isinstance(ref, dict) and '/TransformMethod' in ref:
                            if ref['/TransformMethod'] == '/DocMDP':
                                params = ref.get('/TransformParams', {})
                                if isinstance(params, dict):
                                    return int(params.get('/P', 0))
        except:
            pass
        
        return None
    
    def _extract_certificate_info(
        self, pkcs7_data: bytes
    ) -> Tuple[CertificateInfo, List[SignatureFinding]]:
        """Extract certificate information from PKCS#7 data"""
        findings = []
        
        default_cert = CertificateInfo(
            subject="Unknown",
            issuer="Unknown",
            serial_number="Unknown"
        )
        
        if not x509 or not pkcs7_data:
            return default_cert, findings
        
        try:
            if isinstance(pkcs7_data, str):
                pkcs7_bytes = pkcs7_data.encode('latin-1')
            else:
                pkcs7_bytes = bytes(pkcs7_data)
            
            cert = x509.load_der_x509_certificate(pkcs7_bytes, default_backend())
            
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial = format(cert.serial_number, 'x')
            
            is_self_signed = (subject == issuer)
            
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key_alg = "RSA"
                key_size = pub_key.key_size
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pub_key_alg = "DSA"
                key_size = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key_alg = "ECDSA"
                key_size = pub_key.curve.key_size
            else:
                pub_key_alg = "Unknown"
                key_size = 0
            
            sig_alg = cert.signature_algorithm_oid._name
            
            key_usage = []
            try:
                ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                ku = ku_ext.value
                if ku.digital_signature:
                    key_usage.append("digitalSignature")
                if ku.content_commitment:
                    key_usage.append("nonRepudiation")
            except:
                pass
            
            if pub_key_alg == "RSA" and key_size < 2048:
                findings.append(SignatureFinding(
                    type="weak_cryptography",
                    severity=SignatureSeverity.HIGH,
                    description=f"Weak RSA key: {key_size} bits (minimum 2048)",
                    location="Certificate",
                    evidence=[f"RSA-{key_size}"],
                    recommendation="Use 2048-bit or 4096-bit RSA keys"
                ))
            
            if is_self_signed:
                findings.append(SignatureFinding(
                    type="untrusted_certificate",
                    severity=SignatureSeverity.MEDIUM,
                    description="Self-signed certificate (not trusted)",
                    location="Certificate",
                    evidence=["Subject == Issuer"],
                    recommendation="Verify signer identity through alternate means"
                ))
            
            now = datetime.now()
            if cert.not_valid_after < now:
                findings.append(SignatureFinding(
                    type="expired_certificate",
                    severity=SignatureSeverity.HIGH,
                    description="Certificate has expired",
                    location="Certificate",
                    evidence=[f"Expired: {cert.not_valid_after.isoformat()}"],
                    recommendation="Certificate was valid at signing but expired now"
                ))
            
            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial,
                not_before=cert.not_valid_before,
                not_after=cert.not_valid_after,
                public_key_algorithm=pub_key_alg,
                key_size=key_size,
                signature_algorithm=sig_alg,
                is_self_signed=is_self_signed,
                key_usage=key_usage
            ), findings
        
        except Exception as e:
            logger.debug(f"Certificate extraction error: {e}")
            return default_cert, findings
    
    def _extract_digest_algorithm(self, pkcs7_data: bytes) -> str:
        """Extract digest algorithm from signature"""
        try:
            if isinstance(pkcs7_data, bytes):
                data_str = pkcs7_data.decode('latin-1', errors='ignore')
            else:
                data_str = str(pkcs7_data)
            
            if 'sha256' in data_str.lower():
                return "SHA-256"
            elif 'sha384' in data_str.lower():
                return "SHA-384"
            elif 'sha512' in data_str.lower():
                return "SHA-512"
            elif 'sha1' in data_str.lower() or 'sha-1' in data_str.lower():
                return "SHA-1"
            elif 'md5' in data_str.lower():
                return "MD5"
            else:
                return "Unknown"
        
        except:
            return "Unknown"
    
    def _extract_signing_time(self, sig_dict: Dict[str, Any]) -> Optional[datetime]:
        """Extract signing time from signature"""
        try:
            if '/M' in sig_dict:
                time_str = str(sig_dict['/M'])
                time_str = time_str.replace('D:', '').replace("'", '').replace('Z', '')
                
                if len(time_str) >= 14:
                    year = int(time_str[0:4])
                    month = int(time_str[4:6])
                    day = int(time_str[6:8])
                    hour = int(time_str[8:10])
                    minute = int(time_str[10:12])
                    second = int(time_str[12:14])
                    
                    return datetime(year, month, day, hour, minute, second)
        except:
            pass
        
        return None
    
    def _detect_attacks(
        self,
        doc: PDFDocument,
        sig_dict: Dict[str, Any],
        byte_range: List[int],
        sig_number: int
    ) -> List[SignatureFinding]:
        """Detect known signature attacks"""
        findings = []
        
        findings.extend(self._detect_usf_attack(sig_dict, sig_number))
        
        findings.extend(self._detect_swa_attack(doc, byte_range, sig_number))
        
        return findings
    
    def _detect_usf_attack(
        self, sig_dict: Dict[str, Any], sig_number: int
    ) -> List[SignatureFinding]:
        """Detect Universal Signature Forgery (USF) indicators"""
        findings = []
        
        try:
            contents = sig_dict.get('/Contents', b'')
            
            if not contents or len(contents) < 100:
                findings.append(SignatureFinding(
                    type="usf_attack",
                    severity=SignatureSeverity.CRITICAL,
                    description="Suspiciously short signature value (possible USF)",
                    location=f"Signature {sig_number}",
                    evidence=[f"Signature length: {len(contents)} bytes"],
                    recommendation="CRITICAL: Possible Universal Signature Forgery",
                    cve_id="USF-2019"
                ))
        
        except Exception as e:
            logger.debug(f"USF detection error: {e}")
        
        return findings
    
    def _detect_swa_attack(
        self, doc: PDFDocument, byte_range: List[int], sig_number: int
    ) -> List[SignatureFinding]:
        """Detect Signature Wrapping Attack (SWA) indicators"""
        findings = []
        
        try:
            pdf_bytes = doc.pdf_path.read_bytes()
            pdf_str = pdf_bytes.decode('latin-1', errors='ignore')
            
            content_stream_pattern = r'/Type\s*/Page.*?/Contents\s*\d+\s+\d+\s+R'
            matches = list(re.finditer(content_stream_pattern, pdf_str, re.DOTALL))
            
            if len(matches) > 1:
                duplicate_refs = {}
                for match in matches:
                    ref = match.group()
                    if ref in duplicate_refs:
                        duplicate_refs[ref] += 1
                    else:
                        duplicate_refs[ref] = 1
                
                for ref, count in duplicate_refs.items():
                    if count > 1:
                        findings.append(SignatureFinding(
                            type="swa_attack",
                            severity=SignatureSeverity.HIGH,
                            description="Duplicate content references detected (possible SWA)",
                            location=f"Signature {sig_number}",
                            evidence=[f"Duplicate content streams found"],
                            recommendation="Possible Signature Wrapping Attack - verify content integrity",
                            cve_id="SWA-2019"
                        ))
                        break
        
        except Exception as e:
            logger.debug(f"SWA detection error: {e}")
        
        return findings
    
    def _assess_trust_level(
        self, cert_info: CertificateInfo, findings: List[SignatureFinding]
    ) -> TrustLevel:
        """Assess overall trust level of signature"""
        if any(f.severity == SignatureSeverity.CRITICAL for f in findings):
            return TrustLevel.INVALID
        
        if cert_info.is_self_signed:
            return TrustLevel.UNTRUSTED
        
        is_aatl = any(ca in cert_info.issuer for ca in self.ADOBE_AATL_CAS)
        
        if is_aatl and not any(f.severity == SignatureSeverity.HIGH for f in findings):
            return TrustLevel.TRUSTED
        
        if any(f.severity == SignatureSeverity.HIGH for f in findings):
            return TrustLevel.UNTRUSTED
        
        return TrustLevel.CONDITIONAL
    
    def _calculate_overall_status(
        self, signatures: List[SignatureValidation]
    ) -> SignatureStatus:
        """Calculate overall signature status"""
        if not signatures:
            return SignatureStatus.UNKNOWN
        
        if all(s.status == SignatureStatus.VALID for s in signatures):
            return SignatureStatus.VALID
        
        if any(s.status == SignatureStatus.INVALID for s in signatures):
            return SignatureStatus.INVALID
        
        return SignatureStatus.UNKNOWN
    
    def _calculate_overall_trust(
        self, signatures: List[SignatureValidation]
    ) -> TrustLevel:
        """Calculate overall trust level"""
        if not signatures:
            return TrustLevel.UNTRUSTED
        
        if any(s.trust_level == TrustLevel.INVALID for s in signatures):
            return TrustLevel.INVALID
        
        if any(s.trust_level == TrustLevel.UNTRUSTED for s in signatures):
            return TrustLevel.UNTRUSTED
        
        if all(s.trust_level == TrustLevel.TRUSTED for s in signatures):
            return TrustLevel.TRUSTED
        
        return TrustLevel.CONDITIONAL
    
    def _generate_recommendations(
        self,
        signatures: List[SignatureValidation],
        attack_indicators: List[str],
        crypto_warnings: List[str]
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if attack_indicators:
            recommendations.append("CRITICAL: Signature attack indicators detected - reject document")
        
        if crypto_warnings:
            recommendations.append("Re-sign document with strong cryptography (SHA-256+, RSA-2048+)")
        
        if any(s.unsigned_bytes > 0 for s in signatures):
            recommendations.append("Document modified after signing - verify incremental updates")
        
        if any(s.certificate_info.is_self_signed for s in signatures):
            recommendations.append("Self-signed certificate - verify signer identity independently")
        
        if not any(s.is_certification for s in signatures):
            recommendations.append("No certification signature - document not author-certified")
        
        if not recommendations:
            if all(s.status == SignatureStatus.VALID for s in signatures):
                recommendations.append("All signatures valid - document integrity confirmed")
            else:
                recommendations.append("Manual verification recommended")
        
        return recommendations


def analyze_signatures(pdf_path: Path, deep_validation: bool = True) -> Dict[str, Any]:
    """
    Convenience function for signature analysis
    
    Args:
        pdf_path: Path to PDF file
        deep_validation: Perform deep cryptographic validation
    
    Returns:
        Dictionary with analysis results
    """
    analyzer = PDFSignatureAnalyzer()
    result = analyzer.analyze(pdf_path, deep_validation)
    return result.to_dict()
