"""PDF analysis modules"""

from pdfscalpel.analyze.structure import (
    PDFStructureAnalyzer,
    PDFComplianceChecker,
    analyze_structure,
    check_compliance,
)
from pdfscalpel.analyze.metadata import (
    PDFMetadataAnalyzer,
    analyze_metadata,
)
from pdfscalpel.analyze.encryption import (
    PDFEncryptionAnalyzer,
    EncryptionInfo,
    CrackabilityAssessment,
    analyze_encryption,
)
from pdfscalpel.analyze.intelligence import (
    PDFIntelligenceEngine,
    IntelligenceReport,
    Recommendation,
    Finding,
    RenderingDifference,
    analyze_intelligence,
    analyze_rendering_differences,
)
from pdfscalpel.analyze.graph import (
    PDFObjectGraphGenerator,
    PDFEntropyAnalyzer,
    analyze_object_graph,
    analyze_entropy,
)
from pdfscalpel.analyze.malware import (
    PDFMalwareAnalyzer,
    MalwareAnalysisResult,
    MalwareFinding,
    MalwareSeverity,
    ThreatType,
)
from pdfscalpel.analyze.signatures import (
    PDFSignatureAnalyzer,
    SignatureAnalysisResult,
    SignatureValidation,
    SignatureFinding,
    CertificateInfo,
)
from pdfscalpel.analyze.form_security import (
    PDFFormSecurityAnalyzer,
    FormSecurityResult,
    FormVulnerability,
    FormField,
    XFAInfo,
)
from pdfscalpel.analyze.anti_forensics import (
    PDFAntiForensicsDetector,
    AntiForensicsResult,
    AntiForensicsFinding,
    ToolFingerprint,
)
from pdfscalpel.analyze.advanced_stego import (
    PDFAdvancedStegoDetector,
    StegoAnalysisResult,
    StegoFinding,
    StegoTechnique,
)

__all__ = [
    'PDFStructureAnalyzer',
    'PDFComplianceChecker',
    'analyze_structure',
    'check_compliance',
    'PDFMetadataAnalyzer',
    'analyze_metadata',
    'PDFEncryptionAnalyzer',
    'EncryptionInfo',
    'CrackabilityAssessment',
    'analyze_encryption',
    'PDFIntelligenceEngine',
    'IntelligenceReport',
    'Recommendation',
    'Finding',
    'RenderingDifference',
    'analyze_intelligence',
    'analyze_rendering_differences',
    'PDFObjectGraphGenerator',
    'PDFEntropyAnalyzer',
    'analyze_object_graph',
    'analyze_entropy',
    'PDFMalwareAnalyzer',
    'MalwareAnalysisResult',
    'MalwareFinding',
    'MalwareSeverity',
    'ThreatType',
    'PDFSignatureAnalyzer',
    'SignatureAnalysisResult',
    'SignatureValidation',
    'SignatureFinding',
    'CertificateInfo',
    'PDFFormSecurityAnalyzer',
    'FormSecurityResult',
    'FormVulnerability',
    'FormField',
    'XFAInfo',
    'PDFAntiForensicsDetector',
    'AntiForensicsResult',
    'AntiForensicsFinding',
    'ToolFingerprint',
    'PDFAdvancedStegoDetector',
    'StegoAnalysisResult',
    'StegoFinding',
    'StegoTechnique',
]
