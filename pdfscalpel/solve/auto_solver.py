"""
Automated PDF CTF challenge solver

Orchestrates multiple solving techniques to automatically analyze and solve PDF challenges.
Provides comprehensive solver report with findings.
"""

from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import json

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError, PDFEncryptedError
from pdfscalpel.analyze.intelligence import PDFIntelligenceEngine
from pdfscalpel.solve.password import PasswordCracker
from pdfscalpel.solve.flag_hunter import FlagHunter
from pdfscalpel.solve.stego_solver import StegoSolver
from pdfscalpel.extract.revisions import RevisionExtractor
from pdfscalpel.solve.ctf_mode import CTFModeContext, validate_ctf_mode

logger = get_logger()


class SolverStage(Enum):
    """Auto solver execution stages"""
    INTELLIGENCE = "intelligence_analysis"
    PASSWORD_CRACKING = "password_cracking"
    FLAG_HUNTING = "flag_hunting"
    STEGANOGRAPHY = "steganography_detection"
    REVISION_ANALYSIS = "revision_analysis"
    FINAL_ANALYSIS = "final_analysis"


@dataclass
class SolverStageResult:
    """Result from a solver stage"""
    stage: SolverStage
    success: bool
    findings: List[Any] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['stage'] = self.stage.value
        return result


@dataclass
class AutoSolverReport:
    """Comprehensive auto solver report"""
    input_pdf: str
    timestamp: datetime
    ctf_mode: bool
    challenge_id: Optional[str]
    stages_executed: List[str]
    stage_results: List[SolverStageResult]
    flags_found: List[Dict[str, Any]]
    stego_findings: List[Dict[str, Any]]
    intelligence_summary: Optional[Dict[str, Any]]
    recommendations: List[str]
    total_duration_seconds: float
    solved: bool
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        result['stage_results'] = [s.to_dict() for s in self.stage_results]
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    def save(self, output_path: Path):
        """Save report to file"""
        output_path.write_text(self.to_json())


class AutoSolver:
    """
    Automated PDF CTF challenge solver
    
    Orchestrates multiple solving techniques in an intelligent order:
    1. Intelligence analysis (understand the challenge)
    2. Password cracking (if encrypted)
    3. Flag hunting (search all layers)
    4. Steganography detection
    5. Revision analysis
    6. Final synthesis and recommendations
    """
    
    def __init__(
        self,
        pdf_path: Path,
        ctf_mode: bool = False,
        challenge_id: Optional[str] = None,
        quick_mode: bool = False,
        max_password_attempts: int = 10000,
    ):
        """
        Initialize auto solver
        
        Args:
            pdf_path: Path to PDF file
            ctf_mode: Enable CTF mode (required for ethical use)
            challenge_id: Challenge identifier for audit trail
            quick_mode: Skip time-intensive operations
            max_password_attempts: Maximum password attempts for quick mode
        """
        self.pdf_path = pdf_path
        self.ctf_mode = ctf_mode
        self.challenge_id = challenge_id
        self.quick_mode = quick_mode
        self.max_password_attempts = max_password_attempts
        
        self.stage_results: List[SolverStageResult] = []
        self.decrypted_pdf_path: Optional[Path] = None
        self.flags_found: List[Dict[str, Any]] = []
        self.stego_findings: List[Dict[str, Any]] = []
        self.intelligence_summary: Optional[Dict[str, Any]] = None
        
        self.start_time = datetime.now()
    
    def solve(self) -> AutoSolverReport:
        """
        Run automated solving workflow
        
        Returns:
            AutoSolverReport with comprehensive findings
        """
        logger.info(f"Starting auto solver on: {self.pdf_path}")
        
        try:
            self._stage_intelligence_analysis()
            
            needs_decryption = self._check_encryption()
            if needs_decryption:
                self._stage_password_cracking()
            
            self._stage_flag_hunting()
            
            self._stage_steganography()
            
            self._stage_revision_analysis()
            
            report = self._generate_report()
            
            logger.info(f"Auto solver complete. Solved: {report.solved}")
            return report
        
        except Exception as e:
            logger.error(f"Auto solver failed: {e}", exc_info=True)
            return self._generate_report(error=str(e))
    
    def _stage_intelligence_analysis(self) -> SolverStageResult:
        """Stage 1: Intelligence analysis"""
        stage = SolverStage.INTELLIGENCE
        stage_start = datetime.now()
        
        try:
            logger.info("Stage: Intelligence analysis")
            
            engine = PDFIntelligenceEngine()
            
            try:
                report = engine.analyze(self.pdf_path)
                
                self.intelligence_summary = {
                    'creator': report.creator_analysis,
                    'encryption': report.encryption_analysis,
                    'watermark': report.watermark_analysis,
                    'recommendations': [r.to_dict() for r in report.recommendations],
                    'findings': [f.to_dict() for f in report.findings],
                    'summary': report.executive_summary,
                }
                
                result = SolverStageResult(
                    stage=stage,
                    success=True,
                    data=self.intelligence_summary,
                    duration_seconds=(datetime.now() - stage_start).total_seconds()
                )
            
            except PDFEncryptedError:
                logger.warning("PDF is encrypted, intelligence analysis limited")
                result = SolverStageResult(
                    stage=stage,
                    success=True,
                    data={'status': 'encrypted', 'analysis': 'limited'},
                    duration_seconds=(datetime.now() - stage_start).total_seconds()
                )
            
            self.stage_results.append(result)
            return result
        
        except Exception as e:
            logger.error(f"Intelligence analysis failed: {e}")
            result = SolverStageResult(
                stage=stage,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - stage_start).total_seconds()
            )
            self.stage_results.append(result)
            return result
    
    def _check_encryption(self) -> bool:
        """Check if PDF is encrypted"""
        try:
            if pikepdf:
                try:
                    with pikepdf.Pdf.open(self.pdf_path) as pdf:
                        return False
                except pikepdf.PasswordError:
                    return True
            else:
                with PDFDocument.open(self.pdf_path) as doc:
                    return doc.is_encrypted
        except PDFEncryptedError:
            return True
        except Exception:
            return False
    
    def _stage_password_cracking(self) -> SolverStageResult:
        """Stage 2: Password cracking"""
        stage = SolverStage.PASSWORD_CRACKING
        stage_start = datetime.now()
        
        try:
            logger.info("Stage: Password cracking")
            
            if not self.ctf_mode:
                raise PDFScalpelError("CTF mode required for password cracking")
            
            cracker = PasswordCracker(self.pdf_path)
            
            password = None
            
            logger.info("Trying intelligent attack...")
            password = cracker.intelligent_attack()
            
            if not password and not self.quick_mode:
                logger.info("Trying common CTF passwords...")
                password = cracker.common_ctf_passwords()
            
            if password:
                logger.info(f"Password found: {password}")
                
                decrypted_path = self.pdf_path.parent / f"{self.pdf_path.stem}_decrypted.pdf"
                
                if pikepdf:
                    try:
                        with pikepdf.Pdf.open(self.pdf_path, password=password) as pdf:
                            pdf.save(decrypted_path)
                        self.decrypted_pdf_path = decrypted_path
                        logger.info(f"Decrypted PDF saved to: {decrypted_path}")
                    except Exception as e:
                        logger.warning(f"Failed to save decrypted PDF: {e}")
                
                result = SolverStageResult(
                    stage=stage,
                    success=True,
                    data={'password': password, 'decrypted_path': str(decrypted_path) if self.decrypted_pdf_path else None},
                    duration_seconds=(datetime.now() - stage_start).total_seconds()
                )
            else:
                logger.warning("Password not found with quick methods")
                result = SolverStageResult(
                    stage=stage,
                    success=False,
                    data={'status': 'not_found'},
                    duration_seconds=(datetime.now() - stage_start).total_seconds()
                )
            
            self.stage_results.append(result)
            return result
        
        except Exception as e:
            logger.error(f"Password cracking failed: {e}")
            result = SolverStageResult(
                stage=stage,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - stage_start).total_seconds()
            )
            self.stage_results.append(result)
            return result
    
    def _stage_flag_hunting(self) -> SolverStageResult:
        """Stage 3: Flag hunting"""
        stage = SolverStage.FLAG_HUNTING
        stage_start = datetime.now()
        
        try:
            logger.info("Stage: Flag hunting")
            
            pdf_to_analyze = self.decrypted_pdf_path if self.decrypted_pdf_path else self.pdf_path
            
            with PDFDocument.open(pdf_to_analyze) as pdf_doc:
                hunter = FlagHunter(pdf_doc, builtin_patterns=['ctf', 'md5', 'sha1', 'sha256'])
                candidates = hunter.hunt()
                
                high_confidence = [c for c in candidates if c.confidence >= 0.6]
                
                self.flags_found = [c.to_dict() for c in high_confidence]
                
                logger.info(f"Found {len(high_confidence)} high-confidence flag candidates")
                
                result = SolverStageResult(
                    stage=stage,
                    success=True,
                    findings=self.flags_found,
                    data={'total_candidates': len(candidates), 'high_confidence': len(high_confidence)},
                    duration_seconds=(datetime.now() - stage_start).total_seconds()
                )
                
                self.stage_results.append(result)
                return result
        
        except Exception as e:
            logger.error(f"Flag hunting failed: {e}")
            result = SolverStageResult(
                stage=stage,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - stage_start).total_seconds()
            )
            self.stage_results.append(result)
            return result
    
    def _stage_steganography(self) -> SolverStageResult:
        """Stage 4: Steganography detection"""
        stage = SolverStage.STEGANOGRAPHY
        stage_start = datetime.now()
        
        try:
            logger.info("Stage: Steganography detection")
            
            pdf_to_analyze = self.decrypted_pdf_path if self.decrypted_pdf_path else self.pdf_path
            
            with PDFDocument.open(pdf_to_analyze) as pdf_doc:
                solver = StegoSolver(pdf_doc)
                findings = solver.detect_all()
                
                medium_confidence = [f for f in findings if f.confidence >= 0.5]
                
                self.stego_findings = [f.to_dict() for f in medium_confidence]
                
                logger.info(f"Found {len(medium_confidence)} steganography findings")
                
                result = SolverStageResult(
                    stage=stage,
                    success=True,
                    findings=self.stego_findings,
                    data={'total_findings': len(findings), 'medium_confidence': len(medium_confidence)},
                    duration_seconds=(datetime.now() - stage_start).total_seconds()
                )
                
                self.stage_results.append(result)
                return result
        
        except Exception as e:
            logger.error(f"Steganography detection failed: {e}")
            result = SolverStageResult(
                stage=stage,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - stage_start).total_seconds()
            )
            self.stage_results.append(result)
            return result
    
    def _stage_revision_analysis(self) -> SolverStageResult:
        """Stage 5: Revision analysis"""
        stage = SolverStage.REVISION_ANALYSIS
        stage_start = datetime.now()
        
        try:
            logger.info("Stage: Revision analysis")
            
            pdf_to_analyze = self.decrypted_pdf_path if self.decrypted_pdf_path else self.pdf_path
            
            extractor = RevisionExtractor(pdf_to_analyze)
            revisions = extractor.list_revisions()
            
            revision_data = {
                'total_revisions': len(revisions),
                'has_multiple_revisions': len(revisions) > 1,
                'revisions': [r.to_dict() for r in revisions]
            }
            
            logger.info(f"Found {len(revisions)} revisions")
            
            result = SolverStageResult(
                stage=stage,
                success=True,
                data=revision_data,
                duration_seconds=(datetime.now() - stage_start).total_seconds()
            )
            
            self.stage_results.append(result)
            return result
        
        except Exception as e:
            logger.error(f"Revision analysis failed: {e}")
            result = SolverStageResult(
                stage=stage,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - stage_start).total_seconds()
            )
            self.stage_results.append(result)
            return result
    
    def _generate_report(self, error: Optional[str] = None) -> AutoSolverReport:
        """Generate comprehensive solver report"""
        total_duration = (datetime.now() - self.start_time).total_seconds()
        
        recommendations = []
        
        if self.flags_found:
            recommendations.append(f"Found {len(self.flags_found)} potential flags - review high confidence matches")
        
        if self.stego_findings:
            recommendations.append(f"Detected {len(self.stego_findings)} steganography patterns - investigate findings")
        
        password_result = next((r for r in self.stage_results if r.stage == SolverStage.PASSWORD_CRACKING), None)
        if password_result and not password_result.success:
            recommendations.append("Password not cracked with quick methods - try dictionary or brute force attack")
        
        revision_result = next((r for r in self.stage_results if r.stage == SolverStage.REVISION_ANALYSIS), None)
        if revision_result and revision_result.data.get('has_multiple_revisions'):
            recommendations.append("Multiple PDF revisions detected - check previous versions for hidden data")
        
        if self.intelligence_summary:
            intel_recs = self.intelligence_summary.get('recommendations', [])
            for rec in intel_recs[:3]:
                if isinstance(rec, dict):
                    recommendations.append(rec.get('action', ''))
        
        if not recommendations:
            recommendations.append("No immediate findings - try manual analysis or advanced techniques")
        
        solved = len(self.flags_found) > 0 or len(self.stego_findings) > 0
        
        stages_executed = [r.stage.value for r in self.stage_results]
        
        report = AutoSolverReport(
            input_pdf=str(self.pdf_path),
            timestamp=self.start_time,
            ctf_mode=self.ctf_mode,
            challenge_id=self.challenge_id,
            stages_executed=stages_executed,
            stage_results=self.stage_results,
            flags_found=self.flags_found,
            stego_findings=self.stego_findings,
            intelligence_summary=self.intelligence_summary,
            recommendations=recommendations,
            total_duration_seconds=total_duration,
            solved=solved
        )
        
        return report


def solve_auto(
    pdf_path: Path,
    ctf_mode: bool = False,
    challenge_id: Optional[str] = None,
    quick_mode: bool = False,
    output_report: Optional[Path] = None
) -> AutoSolverReport:
    """
    Automatically solve PDF CTF challenge
    
    Args:
        pdf_path: Path to PDF file
        ctf_mode: Enable CTF mode (required)
        challenge_id: Challenge identifier
        quick_mode: Skip time-intensive operations
        output_report: Path to save report
    
    Returns:
        AutoSolverReport with findings
    """
    if ctf_mode:
        validate_ctf_mode(ctf_mode, challenge_id)
    
    solver = AutoSolver(
        pdf_path=pdf_path,
        ctf_mode=ctf_mode,
        challenge_id=challenge_id,
        quick_mode=quick_mode
    )
    
    report = solver.solve()
    
    if output_report:
        report.save(output_report)
        logger.info(f"Report saved to: {output_report}")
    
    return report
