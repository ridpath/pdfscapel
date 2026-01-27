"""PDF intelligence layer - provides contextual recommendations and analysis"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
import re
from enum import Enum

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger
from pdfscalpel.analyze.structure import PDFStructureAnalyzer
from pdfscalpel.analyze.metadata import PDFMetadataAnalyzer
from pdfscalpel.analyze.encryption import PDFEncryptionAnalyzer
from pdfscalpel.analyze.watermark import WatermarkAnalyzer

logger = get_logger()


@dataclass
class Recommendation:
    """Actionable recommendation with confidence score"""
    action: str
    reasoning: str
    confidence: float
    command: Optional[str] = None
    priority: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A specific finding from analysis"""
    type: str
    description: str
    confidence: float
    severity: str
    location: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntelligenceReport:
    """Comprehensive intelligence report"""
    file_path: str
    timestamp: datetime
    creator_analysis: Dict[str, Any]
    encryption_analysis: Optional[Dict[str, Any]]
    structural_analysis: Dict[str, Any]
    watermark_analysis: Optional[Dict[str, Any]]
    rendering_risks: List[Dict[str, Any]]
    findings: List[Finding]
    recommendations: List[Recommendation]
    executive_summary: str
    suggested_workflow: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        result['findings'] = [f.to_dict() for f in self.findings]
        result['recommendations'] = [r.to_dict() for r in self.recommendations]
        return result


@dataclass
class RenderingDifference:
    """Rendering difference between PDF readers"""
    reader: str
    feature: str
    behavior: str
    risk_level: str
    exploitation_potential: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PDFIntelligenceEngine:
    """
    PDF Intelligence Engine - provides contextual analysis and recommendations
    
    This module correlates findings from other analyzers and provides
    actionable recommendations for next steps.
    """
    
    READER_CAPABILITIES = {
        "adobe": {
            "javascript": True,
            "xfa_forms": True,
            "3d_content": True,
            "flash": True,
            "launch_actions": True,
            "transparency_groups": True,
            "security_handler_versions": [2, 3, 4, 5],
        },
        "foxit": {
            "javascript": True,
            "xfa_forms": True,
            "3d_content": False,
            "flash": False,
            "launch_actions": True,
            "transparency_groups": True,
            "security_handler_versions": [2, 3, 4],
        },
        "chrome": {
            "javascript": False,
            "xfa_forms": False,
            "3d_content": False,
            "flash": False,
            "launch_actions": False,
            "transparency_groups": True,
            "security_handler_versions": [2, 3, 4],
        },
        "firefox": {
            "javascript": False,
            "xfa_forms": False,
            "3d_content": False,
            "flash": False,
            "launch_actions": False,
            "transparency_groups": True,
            "security_handler_versions": [2, 3, 4],
        },
    }
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
        self.findings: List[Finding] = []
        self.recommendations: List[Recommendation] = []
        
    def analyze(self, deep: bool = True) -> IntelligenceReport:
        """
        Perform comprehensive intelligence analysis
        
        Args:
            deep: Perform deep analysis including all sub-analyzers
            
        Returns:
            IntelligenceReport with findings and recommendations
        """
        logger.info(f"Running intelligence analysis: {self.pdf_doc.path}")
        
        self.findings = []
        self.recommendations = []
        
        creator_info = self._analyze_creator()
        encryption_info = self._analyze_encryption() if deep else None
        structure_info = self._analyze_structure() if deep else None
        watermark_info = self._analyze_watermarks() if deep else None
        rendering_risks = self._analyze_rendering_differences()
        
        self._correlate_findings()
        self._generate_recommendations()
        
        executive_summary = self._generate_executive_summary(
            creator_info, encryption_info, structure_info, watermark_info
        )
        
        workflow = self._generate_suggested_workflow()
        
        report = IntelligenceReport(
            file_path=str(self.pdf_doc.path),
            timestamp=datetime.now(),
            creator_analysis=creator_info,
            encryption_analysis=encryption_info,
            structural_analysis=structure_info or {},
            watermark_analysis=watermark_info,
            rendering_risks=rendering_risks,
            findings=self.findings,
            recommendations=self.recommendations,
            executive_summary=executive_summary,
            suggested_workflow=workflow,
        )
        
        return report
    
    def _analyze_creator(self) -> Dict[str, Any]:
        """Analyze PDF creator tool and implications"""
        metadata_analyzer = PDFMetadataAnalyzer(self.pdf_doc)
        metadata = metadata_analyzer.analyze()
        
        tool_info = metadata.get('tool_fingerprint', {})
        tool_name = tool_info.get('primary_tool', 'Unknown')
        confidence = tool_info.get('confidence', 0.0)
        
        implications = self._get_tool_implications(tool_name)
        
        if confidence > 0.8:
            self.findings.append(Finding(
                type="creator_tool",
                description=f"PDF created with {tool_name}",
                confidence=confidence,
                severity="info",
                details={"implications": implications}
            ))
        
        return {
            "tool": tool_name,
            "confidence": confidence,
            "implications": implications,
            "metadata_patterns": tool_info,
        }
    
    def _get_tool_implications(self, tool_name: str) -> List[str]:
        """Get security/forensic implications of creation tool"""
        implications_map = {
            "Adobe": [
                "Metadata likely accurate",
                "May contain XMP metadata",
                "Check for embedded JavaScript",
                "May use advanced PDF features",
            ],
            "Microsoft": [
                "Metadata likely accurate but may be redacted",
                "Check for form fields",
                "Often uses simple PDF structure",
                "May contain Office metadata in XMP",
            ],
            "LibreOffice": [
                "Metadata typically untouched",
                "Focus on content layers",
                "May contain uncompressed streams",
                "Usually clean structure",
            ],
            "LaTeX": [
                "Highly structured output",
                "Font-based watermarks common",
                "Check for embedded fonts",
                "Metadata often minimal",
            ],
            "Google": [
                "Browser-based conversion",
                "Limited metadata",
                "Simple structure",
                "May have rendering artifacts",
            ],
            "Ghostscript": [
                "Possible post-processing tool",
                "Check for optimization artifacts",
                "May indicate sanitization",
                "Metadata may be stripped",
            ],
            "QPDF": [
                "Post-processing tool detected",
                "PDF may have been repaired/modified",
                "Check revision history for changes",
                "Possible anti-forensics",
            ],
        }
        
        for tool_pattern, implications in implications_map.items():
            if tool_pattern.lower() in tool_name.lower():
                return implications
        
        return ["Unknown tool - investigate metadata thoroughly"]
    
    def _analyze_encryption(self) -> Optional[Dict[str, Any]]:
        """Analyze encryption and provide cracking recommendations"""
        try:
            enc_analyzer = PDFEncryptionAnalyzer(self.pdf_doc)
            enc_info = enc_analyzer.analyze(check_exploits=True)
            
            if not enc_info.is_encrypted:
                return None
            
            enc_dict = enc_info.to_dict()
            
            if enc_info.crackability:
                crack = enc_info.crackability
                
                if crack.dictionary_attack_probability > 0.7:
                    self.findings.append(Finding(
                        type="weak_encryption",
                        description=f"Weak encryption: {enc_info.algorithm}",
                        confidence=crack.dictionary_attack_probability,
                        severity="high",
                        details={
                            "algorithm": enc_info.algorithm,
                            "recommended_approach": crack.recommended_approach,
                        }
                    ))
                    
                    self.recommendations.append(Recommendation(
                        action=f"Attempt password cracking using {crack.recommended_approach}",
                        reasoning=f"Encryption is {enc_info.algorithm} which is crackable",
                        confidence=crack.dictionary_attack_probability,
                        command="pdfautopsy solve password INPUT --ctf-mode --dictionary",
                        priority="high",
                    ))
                
                if crack.exploitable_owner_password:
                    self.findings.append(Finding(
                        type="owner_password_exploit",
                        description="Owner password may be exploitable",
                        confidence=0.85,
                        severity="medium",
                        details={"weakness": enc_info.owner_password_weakness}
                    ))
                    
                    self.recommendations.append(Recommendation(
                        action="Exploit owner password weakness for permission bypass",
                        reasoning=enc_info.owner_password_weakness or "Owner password vulnerability detected",
                        confidence=0.85,
                        command="pdfautopsy solve password INPUT --exploit-owner",
                        priority="medium",
                    ))
            
            return enc_dict
            
        except Exception as e:
            logger.warning(f"Encryption analysis failed: {e}")
            return None
    
    def _analyze_structure(self) -> Optional[Dict[str, Any]]:
        """Analyze PDF structure for anomalies"""
        try:
            struct_analyzer = PDFStructureAnalyzer(self.pdf_doc)
            struct_info = struct_analyzer.analyze()
            
            if struct_info.get('incremental_updates', 0) > 0:
                updates = struct_info['incremental_updates']
                self.findings.append(Finding(
                    type="incremental_updates",
                    description=f"{updates} incremental updates detected",
                    confidence=1.0,
                    severity="info",
                    details={"update_count": updates}
                ))
                
                self.recommendations.append(Recommendation(
                    action="Extract and analyze revision timeline",
                    reasoning="Incremental updates may hide deleted objects or previous versions",
                    confidence=0.9,
                    command="pdfautopsy extract revisions INPUT --output-dir revisions/",
                    priority="high",
                ))
            
            anomalies = struct_info.get('anomalies', [])
            for anomaly in anomalies:
                self.findings.append(Finding(
                    type="structural_anomaly",
                    description=anomaly.get('description', 'Unknown anomaly'),
                    confidence=anomaly.get('confidence', 0.5),
                    severity=anomaly.get('severity', 'low'),
                    location=anomaly.get('location'),
                ))
            
            return struct_info
            
        except Exception as e:
            logger.warning(f"Structure analysis failed: {e}")
            return None
    
    def _analyze_watermarks(self) -> Optional[Dict[str, Any]]:
        """Analyze watermarks and provide removal strategies"""
        try:
            wm_analyzer = WatermarkAnalyzer(self.pdf_doc.path)
            result = wm_analyzer.analyze()
            
            if not result.watermarks:
                return None
            
            wm_data = {
                "count": len(result.watermarks),
                "watermarks": [self._watermark_to_dict(wm) for wm in result.watermarks],
                "total_pages": result.total_pages,
                "analysis_confidence": result.analysis_confidence,
            }
            
            for wm in result.watermarks:
                self.findings.append(Finding(
                    type="watermark",
                    description=f"Watermark detected: {wm.type}",
                    confidence=wm.confidence,
                    severity="info",
                    details={
                        "type": wm.type,
                        "difficulty": wm.removal_difficulty,
                        "strategy": wm.removal_strategy,
                    }
                ))
                
                self.recommendations.append(Recommendation(
                    action=f"Remove watermark using {wm.removal_strategy}",
                    reasoning=f"Watermark type {wm.type} with {wm.removal_difficulty} difficulty",
                    confidence=wm.confidence,
                    command=f"pdfautopsy mutate watermark INPUT OUTPUT --remove {wm.removal_strategy.lower()}",
                    priority="medium" if wm.removal_difficulty in ["TRIVIAL", "EASY"] else "low",
                ))
            
            return wm_data
            
        except Exception as e:
            logger.warning(f"Watermark analysis failed: {e}")
            return None
    
    def _analyze_rendering_differences(self) -> List[Dict[str, Any]]:
        """
        Analyze potential rendering differences between PDF readers
        
        Returns:
            List of potential rendering differences and security implications
        """
        risks = []
        
        has_javascript = self._has_javascript()
        has_xfa = self._has_xfa_forms()
        has_launch_actions = self._has_launch_actions()
        has_3d = self._has_3d_content()
        has_transparency = self._has_transparency_groups()
        
        if has_javascript:
            risks.append({
                "feature": "JavaScript",
                "adobe": "Executes JavaScript",
                "foxit": "Executes JavaScript",
                "chrome": "Ignores JavaScript",
                "firefox": "Ignores JavaScript",
                "risk_level": "high",
                "exploitation_potential": "JavaScript-based exploits only work in Adobe/Foxit",
            })
            
            self.findings.append(Finding(
                type="rendering_difference",
                description="JavaScript execution varies by reader",
                confidence=1.0,
                severity="high",
                details={
                    "feature": "JavaScript",
                    "risk": "Reader-specific behavior",
                }
            ))
        
        if has_xfa:
            risks.append({
                "feature": "XFA Forms",
                "adobe": "Full XFA support",
                "foxit": "Partial XFA support",
                "chrome": "No XFA support",
                "firefox": "No XFA support",
                "risk_level": "medium",
                "exploitation_potential": "XFA-based attacks only work in Adobe",
            })
        
        if has_launch_actions:
            risks.append({
                "feature": "Launch Actions",
                "adobe": "Prompts user before launching",
                "foxit": "Prompts user before launching",
                "chrome": "Blocks launch actions",
                "firefox": "Blocks launch actions",
                "risk_level": "critical",
                "exploitation_potential": "Command execution possible in Adobe/Foxit",
            })
            
            self.findings.append(Finding(
                type="launch_action",
                description="Launch action detected - potential command execution",
                confidence=1.0,
                severity="critical",
                details={
                    "risk": "Command execution in Adobe/Foxit",
                }
            ))
            
            self.recommendations.append(Recommendation(
                action="Inspect launch actions for malicious commands",
                reasoning="Launch actions can execute arbitrary commands",
                confidence=1.0,
                command="pdfautopsy extract javascript INPUT --include-actions",
                priority="critical",
            ))
        
        if has_3d:
            risks.append({
                "feature": "3D Content",
                "adobe": "Renders 3D content",
                "foxit": "No 3D support",
                "chrome": "No 3D support",
                "firefox": "No 3D support",
                "risk_level": "medium",
                "exploitation_potential": "3D-based exploits Adobe-only",
            })
        
        if has_transparency:
            risks.append({
                "feature": "Transparency Groups",
                "adobe": "Full transparency support",
                "foxit": "Full transparency support",
                "chrome": "Limited transparency support",
                "firefox": "Limited transparency support",
                "risk_level": "low",
                "exploitation_potential": "Visual differences only",
            })
        
        encryption_version = self._get_encryption_version()
        if encryption_version and encryption_version > 4:
            risks.append({
                "feature": f"Security Handler V{encryption_version}",
                "adobe": f"Supports V{encryption_version}",
                "foxit": "May not support newer versions",
                "chrome": "Limited support",
                "firefox": "Limited support",
                "risk_level": "medium",
                "exploitation_potential": "Encryption may fail in older readers",
            })
        
        return risks
    
    def analyze_rendering_for_readers(self, readers: List[str]) -> Dict[str, List[RenderingDifference]]:
        """
        Analyze rendering differences for specific readers
        
        Args:
            readers: List of reader names (adobe, foxit, chrome, firefox)
            
        Returns:
            Dictionary mapping reader name to list of rendering differences
        """
        results = {}
        
        for reader in readers:
            if reader not in self.READER_CAPABILITIES:
                logger.warning(f"Unknown reader: {reader}")
                continue
            
            differences = []
            capabilities = self.READER_CAPABILITIES[reader]
            
            if self._has_javascript() and not capabilities["javascript"]:
                differences.append(RenderingDifference(
                    reader=reader,
                    feature="JavaScript",
                    behavior="JavaScript will not execute",
                    risk_level="high",
                    exploitation_potential="JavaScript-based features will fail",
                ))
            
            if self._has_xfa_forms() and not capabilities["xfa_forms"]:
                differences.append(RenderingDifference(
                    reader=reader,
                    feature="XFA Forms",
                    behavior="XFA forms will not render properly",
                    risk_level="medium",
                    exploitation_potential="Form functionality limited",
                ))
            
            if self._has_launch_actions() and not capabilities["launch_actions"]:
                differences.append(RenderingDifference(
                    reader=reader,
                    feature="Launch Actions",
                    behavior="Launch actions will be blocked",
                    risk_level="info",
                    exploitation_potential="Safer - blocks command execution",
                ))
            
            if self._has_3d_content() and not capabilities["3d_content"]:
                differences.append(RenderingDifference(
                    reader=reader,
                    feature="3D Content",
                    behavior="3D content will not display",
                    risk_level="low",
                ))
            
            results[reader] = differences
        
        return results
    
    def _has_javascript(self) -> bool:
        """Check if PDF contains JavaScript"""
        try:
            for page in self.pdf.pages:
                if '/AA' in page or '/OpenAction' in page:
                    return True
            
            if '/Names' in self.pdf.Root and '/JavaScript' in self.pdf.Root.Names:
                return True
            
            return False
        except:
            return False
    
    def _has_xfa_forms(self) -> bool:
        """Check if PDF contains XFA forms"""
        try:
            if '/AcroForm' in self.pdf.Root:
                acroform = self.pdf.Root.AcroForm
                if '/XFA' in acroform:
                    return True
            return False
        except:
            return False
    
    def _has_launch_actions(self) -> bool:
        """Check if PDF contains launch actions"""
        try:
            for obj in self.pdf.objects:
                if isinstance(obj, pikepdf.Dictionary):
                    if '/S' in obj and obj.S == '/Launch':
                        return True
            return False
        except:
            return False
    
    def _has_3d_content(self) -> bool:
        """Check if PDF contains 3D content"""
        try:
            for page in self.pdf.pages:
                if '/Annots' in page:
                    for annot in page.Annots:
                        if isinstance(annot, pikepdf.Dictionary):
                            if annot.get('/Subtype') == '/3D':
                                return True
            return False
        except:
            return False
    
    def _has_transparency_groups(self) -> bool:
        """Check if PDF uses transparency groups"""
        try:
            for page in self.pdf.pages:
                if '/Group' in page:
                    group = page.Group
                    if isinstance(group, pikepdf.Dictionary):
                        if group.get('/S') == '/Transparency':
                            return True
            return False
        except:
            return False
    
    def _watermark_to_dict(self, wm) -> Dict[str, Any]:
        """Convert WatermarkInfo to dictionary"""
        result = asdict(wm)
        if hasattr(wm.type, 'value'):
            result['type'] = wm.type.value
        if hasattr(wm.removal_difficulty, 'value'):
            result['removal_difficulty'] = wm.removal_difficulty.value
        return result
    
    def _get_encryption_version(self) -> Optional[int]:
        """Get encryption security handler version"""
        try:
            if self.pdf.is_encrypted and '/Encrypt' in self.pdf.trailer:
                encrypt = self.pdf.trailer.Encrypt
                if '/V' in encrypt:
                    return int(encrypt.V)
            return None
        except:
            return None
    
    def _correlate_findings(self):
        """Correlate findings to identify patterns"""
        
        has_incremental_updates = any(f.type == "incremental_updates" for f in self.findings)
        has_weak_encryption = any(f.type == "weak_encryption" for f in self.findings)
        has_watermark = any(f.type == "watermark" for f in self.findings)
        
        if has_incremental_updates and has_weak_encryption:
            self.findings.append(Finding(
                type="correlation",
                description="Weak encryption + incremental updates suggests CTF challenge",
                confidence=0.8,
                severity="info",
                details={
                    "pattern": "CTF challenge pattern",
                    "reasoning": "Common CTF technique to hide flags in revisions",
                }
            ))
        
        if has_incremental_updates:
            for finding in self.findings:
                if finding.type == "watermark":
                    self.findings.append(Finding(
                        type="correlation",
                        description="Watermark + revisions may indicate removed watermark in earlier version",
                        confidence=0.7,
                        severity="info",
                        details={
                            "pattern": "Watermark evolution",
                        }
                    ))
                    break
    
    def _generate_recommendations(self):
        """Generate additional recommendations based on all findings"""
        
        has_javascript = any(f.type == "rendering_difference" and "JavaScript" in f.description for f in self.findings)
        
        if has_javascript:
            existing = any(r.action.startswith("Inspect launch actions") for r in self.recommendations)
            if not existing:
                self.recommendations.append(Recommendation(
                    action="Extract and analyze all JavaScript code",
                    reasoning="JavaScript detected - may contain hidden logic or exploits",
                    confidence=0.9,
                    command="pdfautopsy extract javascript INPUT --output js/",
                    priority="high",
                ))
        
        if len(self.findings) > 5:
            self.recommendations.append(Recommendation(
                action="Generate comprehensive intelligence report",
                reasoning=f"{len(self.findings)} findings detected - full report recommended",
                confidence=1.0,
                command="pdfautopsy analyze intelligence INPUT --report full_report.txt",
                priority="medium",
            ))
    
    def _generate_executive_summary(
        self,
        creator_info: Dict[str, Any],
        encryption_info: Optional[Dict[str, Any]],
        structure_info: Optional[Dict[str, Any]],
        watermark_info: Optional[Dict[str, Any]],
    ) -> str:
        """Generate executive summary for forensic reports"""
        
        summary_parts = []
        
        tool = creator_info.get("tool", "Unknown")
        confidence = creator_info.get("confidence", 0.0)
        
        summary_parts.append(f"PDF created with {tool} (confidence: {confidence:.2f})")
        
        if encryption_info and encryption_info.get('is_encrypted'):
            algo = encryption_info.get('algorithm', 'Unknown')
            summary_parts.append(f"Encrypted with {algo}")
            
            if encryption_info.get('crackability'):
                crack = encryption_info['crackability']
                if crack.get('dictionary_attack_probability', 0) > 0.7:
                    summary_parts.append("Weak encryption - crackable with dictionary attack")
        else:
            summary_parts.append("No encryption")
        
        if structure_info:
            updates = structure_info.get('incremental_updates', 0)
            if updates > 0:
                summary_parts.append(f"{updates} incremental updates detected - check revision history")
            
            anomalies = structure_info.get('anomalies', [])
            if anomalies:
                summary_parts.append(f"{len(anomalies)} structural anomalies found")
        
        if watermark_info:
            count = watermark_info.get('count', 0)
            summary_parts.append(f"{count} watermark(s) detected")
        
        critical_findings = [f for f in self.findings if f.severity == "critical"]
        high_findings = [f for f in self.findings if f.severity == "high"]
        
        if critical_findings:
            summary_parts.append(f"{len(critical_findings)} CRITICAL security findings")
        if high_findings:
            summary_parts.append(f"{len(high_findings)} high-severity findings")
        
        return ". ".join(summary_parts) + "."
    
    def _generate_suggested_workflow(self) -> List[str]:
        """Generate suggested workflow based on findings"""
        workflow = []
        
        high_priority_recs = [r for r in self.recommendations if r.priority == "critical" or r.priority == "high"]
        high_priority_recs.sort(key=lambda r: 0 if r.priority == "critical" else 1)
        
        for i, rec in enumerate(high_priority_recs[:5], 1):
            workflow.append(f"{i}. {rec.action}")
        
        if any(f.type == "incremental_updates" for f in self.findings):
            if not any("revision" in step.lower() for step in workflow):
                workflow.append(f"{len(workflow) + 1}. Extract and analyze revision timeline")
        
        if any(f.type == "watermark" for f in self.findings):
            if not any("watermark" in step.lower() for step in workflow):
                workflow.append(f"{len(workflow) + 1}. Analyze and remove watermarks")
        
        workflow.append(f"{len(workflow) + 1}. Search all layers for flags/hidden data")
        
        return workflow


def analyze_intelligence(pdf_path: Path, deep: bool = True) -> IntelligenceReport:
    """
    Analyze PDF and generate intelligence report
    
    Args:
        pdf_path: Path to PDF file
        deep: Perform deep analysis including all sub-analyzers
        
    Returns:
        IntelligenceReport with findings and recommendations
    """
    with PDFDocument.open(pdf_path) as pdf_doc:
        engine = PDFIntelligenceEngine(pdf_doc)
        return engine.analyze(deep=deep)


def analyze_rendering_differences(
    pdf_path: Path,
    readers: Optional[List[str]] = None
) -> Dict[str, List[RenderingDifference]]:
    """
    Analyze rendering differences between PDF readers
    
    Args:
        pdf_path: Path to PDF file
        readers: List of reader names to analyze (default: all)
        
    Returns:
        Dictionary mapping reader name to list of rendering differences
    """
    if readers is None:
        readers = ["adobe", "foxit", "chrome", "firefox"]
    
    with PDFDocument.open(pdf_path) as pdf_doc:
        engine = PDFIntelligenceEngine(pdf_doc)
        return engine.analyze_rendering_for_readers(readers)
