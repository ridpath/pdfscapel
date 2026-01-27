"""PDF encryption analysis and exploitation detection"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import math

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError
from pdfscalpel.core.constants import EncryptionAlgorithm

logger = get_logger()


@dataclass
class CrackabilityAssessment:
    """Assessment of how crackable a PDF's encryption is"""
    dictionary_attack_probability: float
    brute_force_estimate_seconds: Optional[float]
    recommended_approach: str
    weaknesses: List[str]
    exploitable_owner_password: bool
    permission_bypass_possible: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EncryptionInfo:
    """Comprehensive encryption information"""
    is_encrypted: bool
    algorithm: Optional[str]
    key_length: Optional[int]
    revision: Optional[int]
    has_user_password: bool
    has_owner_password: bool
    permissions: Dict[str, bool]
    crackability: Optional[CrackabilityAssessment]
    encryption_handler: Optional[str]
    filter_type: Optional[str]
    owner_password_weakness: Optional[str]
    certificate_based: bool
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.crackability:
            result['crackability'] = self.crackability.to_dict()
        return result


class PDFEncryptionAnalyzer:
    """Analyzes PDF encryption parameters and vulnerabilities"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
        
    def analyze(self, check_exploits: bool = True) -> EncryptionInfo:
        """
        Perform comprehensive encryption analysis
        
        Args:
            check_exploits: Whether to check for exploitation opportunities
            
        Returns:
            EncryptionInfo object with comprehensive encryption details
        """
        logger.info(f"Analyzing PDF encryption: {self.pdf_doc.path}")
        
        if not self.pdf.is_encrypted:
            return EncryptionInfo(
                is_encrypted=False,
                algorithm=None,
                key_length=None,
                revision=None,
                has_user_password=False,
                has_owner_password=False,
                permissions={},
                crackability=None,
                encryption_handler=None,
                filter_type=None,
                owner_password_weakness=None,
                certificate_based=False,
            )
        
        # Extract encryption parameters
        algorithm, key_length = self._detect_algorithm()
        revision = self._get_revision()
        permissions = self._analyze_permissions()
        has_user, has_owner = self._detect_password_types()
        handler, filter_type = self._get_encryption_handler()
        cert_based = self._is_certificate_based()
        
        # Assess crackability
        crackability = None
        owner_weakness = None
        if check_exploits:
            crackability = self._assess_crackability(algorithm, key_length, revision)
            owner_weakness = self._analyze_owner_password_weakness(revision, permissions)
        
        return EncryptionInfo(
            is_encrypted=True,
            algorithm=algorithm,
            key_length=key_length,
            revision=revision,
            has_user_password=has_user,
            has_owner_password=has_owner,
            permissions=permissions,
            crackability=crackability,
            encryption_handler=handler,
            filter_type=filter_type,
            owner_password_weakness=owner_weakness,
            certificate_based=cert_based,
        )
    
    def _detect_algorithm(self) -> tuple[Optional[str], Optional[int]]:
        """Detect encryption algorithm and key length"""
        try:
            encryption = self.pdf.trailer.get('/Encrypt')
            if not encryption:
                return None, None
            
            # Get V (algorithm selector) and Length
            v = int(encryption.get('/V', 0))
            length = int(encryption.get('/Length', 40))
            
            # Determine algorithm based on V value
            if v == 1:
                # RC4, 40-bit
                return "RC4-40", 40
            elif v == 2:
                # RC4, variable length (typically 128-bit)
                return f"RC4-{length}", length
            elif v == 4:
                # Check stream filter
                cf = encryption.get('/CF')
                if cf:
                    # Check for AES
                    for key in cf.keys():
                        filter_dict = cf[key]
                        cfm = str(filter_dict.get('/CFM', ''))
                        if 'AESV2' in cfm:
                            return "AES-128", 128
                        elif 'AESV3' in cfm:
                            return "AES-256", 256
                        elif 'V2' in cfm:
                            return f"RC4-{length}", length
                
                # Default for V4
                return f"RC4-{length}", length
            elif v == 5:
                # AES-256 (PDF 2.0)
                return "AES-256", 256
            else:
                return f"Unknown-V{v}", length
                
        except Exception as e:
            logger.warning(f"Error detecting encryption algorithm: {e}")
            return "Unknown", None
    
    def _get_revision(self) -> Optional[int]:
        """Get encryption revision (R value)"""
        try:
            encryption = self.pdf.trailer.get('/Encrypt')
            if encryption:
                return int(encryption.get('/R', 0))
        except Exception as e:
            logger.warning(f"Error getting encryption revision: {e}")
        return None
    
    def _analyze_permissions(self) -> Dict[str, bool]:
        """Analyze permission flags"""
        permissions = {}
        
        try:
            encryption = self.pdf.trailer.get('/Encrypt')
            if not encryption:
                return permissions
            
            p = int(encryption.get('/P', -1))
            
            # Parse permission bits (PDF Reference 1.7, Table 3.20)
            permissions = {
                'print': bool(p & (1 << 2)),
                'modify': bool(p & (1 << 3)),
                'extract': bool(p & (1 << 4)),
                'annotate': bool(p & (1 << 5)),
                'fill_forms': bool(p & (1 << 8)),
                'extract_accessibility': bool(p & (1 << 9)),
                'assemble': bool(p & (1 << 10)),
                'print_high_quality': bool(p & (1 << 11)),
            }
            
        except Exception as e:
            logger.warning(f"Error analyzing permissions: {e}")
        
        return permissions
    
    def _detect_password_types(self) -> tuple[bool, bool]:
        """Detect if user and owner passwords are set"""
        try:
            encryption = self.pdf.trailer.get('/Encrypt')
            if not encryption:
                return False, False
            
            # Check for U and O entries
            has_u = '/U' in encryption
            has_o = '/O' in encryption
            
            # Both should exist if encrypted
            # Determine if actually password-protected by trying to open
            has_user = has_u
            has_owner = has_o
            
            return has_user, has_owner
            
        except Exception as e:
            logger.warning(f"Error detecting password types: {e}")
            return False, False
    
    def _get_encryption_handler(self) -> tuple[Optional[str], Optional[str]]:
        """Get encryption handler and filter type"""
        try:
            encryption = self.pdf.trailer.get('/Encrypt')
            if not encryption:
                return None, None
            
            handler = str(encryption.get('/Filter', 'Unknown'))
            
            # Get StmF (stream filter)
            stmf = str(encryption.get('/StmF', 'Unknown'))
            
            return handler, stmf
            
        except Exception as e:
            logger.warning(f"Error getting encryption handler: {e}")
            return None, None
    
    def _is_certificate_based(self) -> bool:
        """Check if encryption is certificate-based (public key)"""
        try:
            encryption = self.pdf.trailer.get('/Encrypt')
            if not encryption:
                return False
            
            # Check for SubFilter indicating public key encryption
            subfilter = str(encryption.get('/SubFilter', ''))
            if 'adbe.pkcs7' in subfilter.lower():
                return True
            
            # Check filter type
            filter_type = str(encryption.get('/Filter', ''))
            if 'pubsec' in filter_type.lower():
                return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking certificate-based encryption: {e}")
            return False
    
    def _assess_crackability(
        self, 
        algorithm: Optional[str], 
        key_length: Optional[int],
        revision: Optional[int]
    ) -> CrackabilityAssessment:
        """Assess how crackable the encryption is"""
        
        weaknesses = []
        dictionary_prob = 0.0
        brute_force_time = None
        recommended = "Dictionary attack first, then brute force if necessary"
        exploitable_owner = False
        permission_bypass = False
        
        if not algorithm:
            return CrackabilityAssessment(
                dictionary_attack_probability=0.0,
                brute_force_estimate_seconds=None,
                recommended_approach="Cannot assess - unknown algorithm",
                weaknesses=["Unknown encryption algorithm"],
                exploitable_owner_password=False,
                permission_bypass_possible=False,
            )
        
        # Analyze based on algorithm
        if "RC4-40" in algorithm:
            weaknesses.append("RC4-40 is extremely weak (deprecated)")
            weaknesses.append("40-bit key space is trivially crackable")
            dictionary_prob = 0.9
            brute_force_time = 60.0  # ~1 minute
            recommended = "Brute force attack (very fast for 40-bit)"
        
        elif "RC4-128" in algorithm:
            weaknesses.append("RC4-128 has known cryptographic weaknesses")
            dictionary_prob = 0.6
            brute_force_time = 86400.0 * 30  # ~30 days for simple passwords
            recommended = "Dictionary attack with common passwords"
        
        elif "AES-128" in algorithm:
            dictionary_prob = 0.5
            brute_force_time = 86400.0 * 365  # ~1 year
            recommended = "Dictionary attack with large wordlist"
        
        elif "AES-256" in algorithm:
            dictionary_prob = 0.4
            brute_force_time = None  # Infeasible
            recommended = "Dictionary attack only (brute force infeasible)"
        
        # Check revision-specific weaknesses
        if revision is not None:
            if revision <= 2:
                weaknesses.append(f"Revision {revision} has weak key derivation")
                dictionary_prob = min(1.0, dictionary_prob + 0.2)
                exploitable_owner = True
            
            if revision == 3 or revision == 4:
                weaknesses.append(f"Revision {revision} may have owner password weakness")
                permission_bypass = True
        
        # Adjust estimates based on weaknesses
        if brute_force_time and len(weaknesses) > 2:
            brute_force_time *= 0.5  # Faster due to weaknesses
        
        return CrackabilityAssessment(
            dictionary_attack_probability=dictionary_prob,
            brute_force_estimate_seconds=brute_force_time,
            recommended_approach=recommended,
            weaknesses=weaknesses,
            exploitable_owner_password=exploitable_owner,
            permission_bypass_possible=permission_bypass,
        )
    
    def _analyze_owner_password_weakness(
        self, 
        revision: Optional[int],
        permissions: Dict[str, bool]
    ) -> Optional[str]:
        """Analyze owner password weaknesses and exploitation opportunities"""
        
        if revision is None:
            return None
        
        weaknesses = []
        
        # R2 and R3 have known owner password weaknesses
        if revision == 2:
            weaknesses.append(
                "RC4-40 owner password uses weak 5-byte key - "
                "can be brute forced in seconds"
            )
        
        if revision == 3:
            weaknesses.append(
                "RC4-128 owner password computation allows for padding oracle attacks"
            )
        
        if revision <= 4:
            # Check if only permissions are restricted (no user password)
            all_restricted = not any(permissions.values())
            if all_restricted:
                weaknesses.append(
                    "All permissions denied - likely permission-only password. "
                    "Owner password may be bypassable using qpdf or pikepdf"
                )
        
        # Check for permission manipulation vulnerabilities
        if revision == 4:
            weaknesses.append(
                "R4 encryption may be vulnerable to permission flag manipulation"
            )
        
        if weaknesses:
            return "; ".join(weaknesses)
        
        return None


def analyze_encryption(
    input_pdf: Path, 
    check_exploits: bool = True
) -> Dict[str, Any]:
    """
    Analyze PDF encryption (convenience function)
    
    Args:
        input_pdf: Path to PDF file
        check_exploits: Whether to check for exploitation opportunities
        
    Returns:
        Dictionary with encryption analysis results
    """
    from pdfscalpel.core.exceptions import PDFEncryptedError
    
    try:
        with PDFDocument.open(input_pdf) as doc:
            analyzer = PDFEncryptionAnalyzer(doc)
            info = analyzer.analyze(check_exploits=check_exploits)
            return info.to_dict()
    except PDFEncryptedError:
        # For encrypted PDFs, we need to open without decrypting to analyze encryption parameters
        # Use pikepdf directly with allow_overwriting_input=False
        if pikepdf is None:
            raise
        
        try:
            # Open without password to get encryption info
            pdf = pikepdf.open(input_pdf, allow_overwriting_input=False, access_mode=pikepdf.AccessMode.stream)
        except pikepdf.PasswordError:
            # Expected for encrypted PDFs - create a minimal PDF wrapper to extract encryption info
            # We'll use a different approach - read the PDF structure without decrypting
            return _analyze_encrypted_pdf_structure(input_pdf, check_exploits)
        except Exception:
            raise


def _analyze_encrypted_pdf_structure(input_pdf: Path, check_exploits: bool) -> Dict[str, Any]:
    """Analyze encrypted PDF structure without decrypting"""
    if pikepdf is None:
        return {
            'is_encrypted': True,
            'algorithm': 'Unknown',
            'error': 'Cannot analyze - pikepdf not available'
        }
    
    try:
        # Try to peek at encryption without opening fully
        with open(input_pdf, 'rb') as f:
            content = f.read()
        
        # Extract basic encryption info from raw PDF
        algorithm = None
        key_length = None
        revision = None
        
        # Look for /Encrypt reference in trailer
        if b'/Encrypt' in content:
            # Try to extract R and V values
            import re
            
            # Find R value
            r_match = re.search(rb'/R\s+(\d+)', content)
            if r_match:
                revision = int(r_match.group(1))
            
            # Find V value
            v_match = re.search(rb'/V\s+(\d+)', content)
            if v_match:
                v = int(v_match.group(1))
                
                # Find Length if present
                len_match = re.search(rb'/Length\s+(\d+)', content)
                if len_match:
                    key_length = int(len_match.group(1))
                
                # Determine algorithm
                if v == 1:
                    algorithm = "RC4-40"
                    key_length = 40
                elif v == 2:
                    algorithm = f"RC4-{key_length or 128}"
                elif v == 4:
                    # Check for AES
                    if b'AESV2' in content:
                        algorithm = "AES-128"
                        key_length = 128
                    elif b'AESV3' in content:
                        algorithm = "AES-256"
                        key_length = 256
                    else:
                        algorithm = f"RC4-{key_length or 128}"
                elif v == 5:
                    algorithm = "AES-256"
                    key_length = 256
            
            # Extract permissions
            p_match = re.search(rb'/P\s+(-?\d+)', content)
            p_value = int(p_match.group(1)) if p_match else -1
            
            permissions = {
                'print': bool(p_value & (1 << 2)),
                'modify': bool(p_value & (1 << 3)),
                'extract': bool(p_value & (1 << 4)),
                'annotate': bool(p_value & (1 << 5)),
                'fill_forms': bool(p_value & (1 << 8)),
                'extract_accessibility': bool(p_value & (1 << 9)),
                'assemble': bool(p_value & (1 << 10)),
                'print_high_quality': bool(p_value & (1 << 11)),
            }
            
            # Check for U and O entries
            has_user = b'/U' in content and re.search(rb'/U\s*[(<]', content) is not None
            has_owner = b'/O' in content and re.search(rb'/O\s*[(<]', content) is not None
            
            # Assess crackability
            crackability = None
            owner_weakness = None
            if check_exploits and algorithm and revision:
                # Create minimal assessment
                weaknesses = []
                dictionary_prob = 0.0
                brute_force_time = None
                recommended = "Dictionary attack first"
                
                if "RC4-40" in algorithm:
                    weaknesses.append("RC4-40 is extremely weak")
                    dictionary_prob = 0.9
                    brute_force_time = 60.0
                    recommended = "Brute force (very fast for 40-bit)"
                elif "RC4-128" in algorithm:
                    weaknesses.append("RC4-128 has known weaknesses")
                    dictionary_prob = 0.6
                elif "AES-128" in algorithm:
                    dictionary_prob = 0.5
                elif "AES-256" in algorithm:
                    dictionary_prob = 0.4
                
                if revision <= 4:
                    weaknesses.append(f"R{revision} may have owner password weakness")
                    owner_weakness = f"R{revision} encryption may be vulnerable to owner password exploitation"
                
                crackability = {
                    'dictionary_attack_probability': dictionary_prob,
                    'brute_force_estimate_seconds': brute_force_time,
                    'recommended_approach': recommended,
                    'weaknesses': weaknesses,
                    'exploitable_owner_password': revision <= 4,
                    'permission_bypass_possible': revision <= 4,
                }
            
            return {
                'is_encrypted': True,
                'algorithm': algorithm or 'Unknown',
                'key_length': key_length,
                'revision': revision,
                'has_user_password': has_user,
                'has_owner_password': has_owner,
                'permissions': permissions,
                'crackability': crackability,
                'encryption_handler': 'Standard',
                'filter_type': None,
                'owner_password_weakness': owner_weakness,
                'certificate_based': b'/adbe.pkcs7' in content.lower() or b'/pubsec' in content.lower(),
            }
        
        # Not encrypted
        return {
            'is_encrypted': False,
            'algorithm': None,
            'key_length': None,
            'revision': None,
            'has_user_password': False,
            'has_owner_password': False,
            'permissions': {},
            'crackability': None,
            'encryption_handler': None,
            'filter_type': None,
            'owner_password_weakness': None,
            'certificate_based': False,
        }
        
    except Exception as e:
        logger.warning(f"Error analyzing encrypted PDF structure: {e}")
        return {
            'is_encrypted': True,
            'algorithm': 'Unknown',
            'error': str(e)
        }
