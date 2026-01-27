"""PDF revision timeline extraction and analysis"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import io

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import DependencyMissingError, PDFScalpelError
from pdfscalpel.core.logging import get_logger

logger = get_logger()


@dataclass
class RevisionInfo:
    """Information about a PDF revision"""
    revision_number: int
    timestamp: Optional[datetime] = None
    new_objects: List[int] = field(default_factory=list)
    modified_objects: List[int] = field(default_factory=list)
    deleted_objects: List[int] = field(default_factory=list)
    metadata_changes: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)
    encryption_changes: Optional[str] = None
    suspicious_activities: List[str] = field(default_factory=list)
    object_count: int = 0
    page_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'revision_number': self.revision_number,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'new_objects': self.new_objects,
            'modified_objects': self.modified_objects,
            'deleted_objects': self.deleted_objects,
            'metadata_changes': {
                k: (str(v[0]), str(v[1])) for k, v in self.metadata_changes.items()
            },
            'encryption_changes': self.encryption_changes,
            'suspicious_activities': self.suspicious_activities,
            'object_count': self.object_count,
            'page_count': self.page_count,
        }


class RevisionExtractor:
    """Extract and analyze PDF revision history"""
    
    def __init__(self, pdf_doc: PDFDocument):
        if pikepdf is None:
            raise DependencyMissingError(
                dependency="pikepdf",
                install_hint="Install with: pip install pikepdf>=8.0.0"
            )
        
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
        self.path = pdf_doc.path
    
    def extract_all_revisions(self) -> List[RevisionInfo]:
        """
        Extract all revisions from PDF
        
        Returns:
            List of RevisionInfo objects
        """
        logger.info(f"Extracting revisions from {self.path}")
        
        try:
            revisions = self._parse_revisions()
            logger.info(f"Found {len(revisions)} revision(s)")
            return revisions
        except Exception as e:
            logger.error(f"Error extracting revisions: {e}")
            raise PDFScalpelError(f"Failed to extract revisions: {e}")
    
    def _parse_revisions(self) -> List[RevisionInfo]:
        """Parse revisions from PDF structure"""
        revisions = []
        
        with open(self.path, 'rb') as f:
            raw_data = f.read()
        
        xref_positions = self._find_xref_positions(raw_data)
        
        if len(xref_positions) <= 1:
            logger.info("No incremental updates found")
            initial_revision = self._analyze_initial_revision()
            return [initial_revision]
        
        logger.info(f"Found {len(xref_positions)} cross-reference table(s)")
        
        previous_objects = {}
        
        for idx, xref_pos in enumerate(xref_positions):
            revision = self._analyze_revision_at_position(
                raw_data, 
                xref_pos, 
                idx + 1,
                previous_objects
            )
            
            revisions.append(revision)
            
            current_objects = self._get_objects_at_revision(idx + 1)
            previous_objects = current_objects
        
        return revisions
    
    def _find_xref_positions(self, data: bytes) -> List[int]:
        """Find all xref table positions in the PDF"""
        positions = []
        
        xref_markers = [b'xref', b'/XRef']
        
        offset = 0
        while True:
            found_pos = -1
            for marker in xref_markers:
                pos = data.find(marker, offset)
                if pos != -1 and (found_pos == -1 or pos < found_pos):
                    found_pos = pos
            
            if found_pos == -1:
                break
            
            positions.append(found_pos)
            offset = found_pos + 4
        
        return sorted(set(positions))
    
    def _analyze_initial_revision(self) -> RevisionInfo:
        """Analyze the initial (current) revision"""
        revision = RevisionInfo(revision_number=1)
        
        try:
            revision.object_count = len(list(self.pdf.objects))
            revision.page_count = len(self.pdf.pages)
        except Exception as e:
            logger.warning(f"Error counting objects/pages: {e}")
        
        try:
            revision.timestamp = self._extract_timestamp()
        except Exception as e:
            logger.debug(f"Could not extract timestamp: {e}")
        
        try:
            all_obj_ids = [obj.objgen[0] for obj in self.pdf.objects]
            revision.new_objects = sorted(all_obj_ids)
        except Exception as e:
            logger.warning(f"Could not enumerate objects: {e}")
        
        return revision
    
    def _analyze_revision_at_position(
        self, 
        data: bytes, 
        xref_pos: int,
        revision_num: int,
        previous_objects: Dict[int, Any]
    ) -> RevisionInfo:
        """Analyze a specific revision"""
        revision = RevisionInfo(revision_number=revision_num)
        
        try:
            current_objects = self._get_objects_at_revision(revision_num)
            
            current_obj_ids = set(current_objects.keys())
            previous_obj_ids = set(previous_objects.keys())
            
            revision.new_objects = sorted(list(current_obj_ids - previous_obj_ids))
            
            revision.deleted_objects = sorted(list(previous_obj_ids - current_obj_ids))
            
            modified = []
            for obj_id in current_obj_ids & previous_obj_ids:
                if self._objects_differ(current_objects[obj_id], previous_objects.get(obj_id)):
                    modified.append(obj_id)
            revision.modified_objects = sorted(modified)
            
            revision.object_count = len(current_obj_ids)
            
        except Exception as e:
            logger.debug(f"Error analyzing revision {revision_num}: {e}")
        
        try:
            revision.timestamp = self._extract_timestamp()
        except Exception:
            pass
        
        try:
            metadata_changes = self._detect_metadata_changes(previous_objects, current_objects)
            revision.metadata_changes = metadata_changes
        except Exception as e:
            logger.debug(f"Error detecting metadata changes: {e}")
        
        try:
            encryption_change = self._detect_encryption_changes(previous_objects, current_objects)
            revision.encryption_changes = encryption_change
        except Exception as e:
            logger.debug(f"Error detecting encryption changes: {e}")
        
        revision.suspicious_activities = self._detect_suspicious_activities(revision, previous_objects)
        
        return revision
    
    def _get_objects_at_revision(self, revision_num: int) -> Dict[int, Any]:
        """Get all objects at a specific revision"""
        objects = {}
        
        try:
            for obj in self.pdf.objects:
                try:
                    obj_id = obj.objgen[0]
                    objects[obj_id] = obj
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Error enumerating objects: {e}")
        
        return objects
    
    def _objects_differ(self, obj1: Any, obj2: Any) -> bool:
        """Check if two objects are different"""
        if obj1 is None or obj2 is None:
            return True
        
        try:
            return str(obj1) != str(obj2)
        except Exception:
            return True
    
    def _extract_timestamp(self) -> Optional[datetime]:
        """Extract modification timestamp from metadata"""
        try:
            if hasattr(self.pdf, 'docinfo') and self.pdf.docinfo:
                if '/ModDate' in self.pdf.docinfo:
                    mod_date = str(self.pdf.docinfo['/ModDate'])
                    return self._parse_pdf_date(mod_date)
                elif '/CreationDate' in self.pdf.docinfo:
                    creation_date = str(self.pdf.docinfo['/CreationDate'])
                    return self._parse_pdf_date(creation_date)
        except Exception as e:
            logger.debug(f"Could not extract timestamp: {e}")
        
        return None
    
    def _parse_pdf_date(self, date_str: str) -> Optional[datetime]:
        """Parse PDF date format (D:YYYYMMDDHHmmSS)"""
        try:
            if date_str.startswith('D:'):
                date_str = date_str[2:]
            
            date_str = date_str.split('+')[0].split('-')[0].split('Z')[0].strip("'")
            
            if len(date_str) >= 14:
                return datetime.strptime(date_str[:14], '%Y%m%d%H%M%S')
            elif len(date_str) >= 8:
                return datetime.strptime(date_str[:8], '%Y%m%d')
        except Exception as e:
            logger.debug(f"Could not parse date '{date_str}': {e}")
        
        return None
    
    def _detect_metadata_changes(
        self, 
        previous_objects: Dict[int, Any],
        current_objects: Dict[int, Any]
    ) -> Dict[str, Tuple[Any, Any]]:
        """Detect metadata changes between revisions"""
        changes = {}
        
        try:
            prev_metadata = self._extract_metadata_from_objects(previous_objects)
            curr_metadata = self._extract_metadata_from_objects(current_objects)
            
            all_keys = set(prev_metadata.keys()) | set(curr_metadata.keys())
            
            for key in all_keys:
                prev_val = prev_metadata.get(key)
                curr_val = curr_metadata.get(key)
                
                if prev_val != curr_val:
                    changes[key] = (prev_val, curr_val)
        
        except Exception as e:
            logger.debug(f"Error detecting metadata changes: {e}")
        
        return changes
    
    def _extract_metadata_from_objects(self, objects: Dict[int, Any]) -> Dict[str, Any]:
        """Extract metadata dictionary from objects"""
        metadata = {}
        
        try:
            for obj in objects.values():
                if hasattr(obj, 'get') and callable(obj.get):
                    if obj.get('/Type') == '/Catalog' or obj.get('/Type') == '/Info':
                        for key in obj.keys():
                            try:
                                metadata[str(key)] = str(obj[key])
                            except Exception:
                                continue
        except Exception as e:
            logger.debug(f"Error extracting metadata: {e}")
        
        return metadata
    
    def _detect_encryption_changes(
        self,
        previous_objects: Dict[int, Any],
        current_objects: Dict[int, Any]
    ) -> Optional[str]:
        """Detect encryption changes"""
        try:
            prev_encrypted = any(
                hasattr(obj, 'get') and obj.get('/Type') == '/Encrypt'
                for obj in previous_objects.values()
            )
            
            curr_encrypted = any(
                hasattr(obj, 'get') and obj.get('/Type') == '/Encrypt'
                for obj in current_objects.values()
            )
            
            if not prev_encrypted and curr_encrypted:
                return "Encryption added"
            elif prev_encrypted and not curr_encrypted:
                return "Encryption removed"
            elif prev_encrypted and curr_encrypted:
                return "Encryption modified"
        
        except Exception as e:
            logger.debug(f"Error detecting encryption changes: {e}")
        
        return None
    
    def _detect_suspicious_activities(
        self,
        revision: RevisionInfo,
        previous_objects: Dict[int, Any]
    ) -> List[str]:
        """Detect suspicious activities in this revision"""
        suspicious = []
        
        if revision.encryption_changes:
            if "added" in revision.encryption_changes.lower():
                suspicious.append("Password protection added")
        
        if any(key for key in revision.metadata_changes.keys() if '/Author' in key):
            old_author, new_author = revision.metadata_changes.get('/Author', (None, None))
            if old_author and not new_author:
                suspicious.append("Author metadata removed")
        
        if any(key for key in revision.metadata_changes.keys() if '/Title' in key):
            suspicious.append("Title metadata modified")
        
        if len(revision.deleted_objects) > 0:
            has_js = False
            for obj_id in revision.deleted_objects:
                obj = previous_objects.get(obj_id)
                if obj and '/JavaScript' in str(obj):
                    has_js = True
                    break
            
            if has_js:
                suspicious.append("JavaScript objects deleted")
        
        if len(revision.new_objects) > 10 and len(revision.deleted_objects) == 0:
            suspicious.append("Large number of new objects added")
        
        return suspicious
    
    def export_revision(self, revision_num: int, output_path: Path) -> bool:
        """
        Export a specific revision as a separate PDF
        
        Args:
            revision_num: Revision number to export
            output_path: Path to save the exported PDF
        
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Exporting revision {revision_num} to {output_path}")
        
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.pdf.save(output_path)
            
            logger.info(f"Successfully exported revision to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export revision {revision_num}: {e}")
            return False
    
    def export_all_revisions(self, output_dir: Path) -> List[Path]:
        """
        Export all revisions to separate PDF files
        
        Args:
            output_dir: Directory to save exported PDFs
        
        Returns:
            List of paths to exported PDFs
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        exported = []
        revisions = self.extract_all_revisions()
        
        for revision in revisions:
            output_path = output_dir / f"revision_{revision.revision_number}.pdf"
            
            if self.export_revision(revision.revision_number, output_path):
                exported.append(output_path)
        
        return exported
    
    def generate_timeline(self, revisions: Optional[List[RevisionInfo]] = None) -> str:
        """
        Generate a text timeline visualization
        
        Args:
            revisions: List of RevisionInfo objects (will extract if not provided)
        
        Returns:
            Formatted timeline string
        """
        if revisions is None:
            revisions = self.extract_all_revisions()
        
        output = []
        output.append("=" * 70)
        output.append("PDF REVISION TIMELINE")
        output.append("=" * 70)
        output.append(f"\nTotal Revisions: {len(revisions)}\n")
        
        for revision in revisions:
            output.append(f"\nRevision {revision.revision_number}")
            if revision.revision_number == 1:
                output.append(" (Initial)")
            else:
                output.append(" (Update)")
            
            if revision.timestamp:
                output.append(f" - {revision.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            
            output.append("\n" + "-" * 70)
            
            if revision.new_objects:
                output.append(f"  New Objects: {len(revision.new_objects)}")
                if len(revision.new_objects) <= 10:
                    output.append(f" ({', '.join(map(str, revision.new_objects))})")
                else:
                    output.append(f" ({', '.join(map(str, revision.new_objects[:10]))}...)")
            else:
                output.append("  New Objects: None")
            
            if revision.modified_objects:
                output.append(f"\n  Modified Objects: {len(revision.modified_objects)}")
                if len(revision.modified_objects) <= 10:
                    output.append(f" ({', '.join(map(str, revision.modified_objects))})")
            
            if revision.deleted_objects:
                output.append(f"\n  Deleted Objects: {len(revision.deleted_objects)}")
                if len(revision.deleted_objects) <= 10:
                    output.append(f" ({', '.join(map(str, revision.deleted_objects))})")
            
            output.append(f"\n  Total Objects: {revision.object_count}")
            
            if revision.metadata_changes:
                output.append(f"\n  Metadata Changes:")
                for key, (old, new) in revision.metadata_changes.items():
                    output.append(f"    {key}: {old} -> {new}")
            
            if revision.encryption_changes:
                output.append(f"\n  Encryption: {revision.encryption_changes}")
            
            if revision.suspicious_activities:
                output.append(f"\n  ⚠ Suspicious Activities:")
                for activity in revision.suspicious_activities:
                    output.append(f"    - {activity}")
        
        if len(revisions) > 1:
            output.append("\n" + "=" * 70)
            output.append("FORENSIC FINDINGS")
            output.append("=" * 70)
            
            findings = self._generate_forensic_findings(revisions)
            for finding in findings:
                output.append(f"  - {finding}")
        
        return '\n'.join(output)
    
    def _generate_forensic_findings(self, revisions: List[RevisionInfo]) -> List[str]:
        """Generate forensic findings from revision analysis"""
        findings = []
        
        for revision in revisions:
            if revision.deleted_objects:
                findings.append(
                    f"Revision {revision.revision_number}: {len(revision.deleted_objects)} "
                    f"object(s) deleted - may contain hidden data"
                )
            
            if '/Author' in str(revision.metadata_changes):
                findings.append(
                    f"Revision {revision.revision_number}: Author metadata modified - "
                    f"possible identity hiding"
                )
            
            if revision.encryption_changes and 'added' in revision.encryption_changes.lower():
                findings.append(
                    f"Revision {revision.revision_number}: Encryption added - "
                    f"check if password is weak"
                )
        
        if not findings:
            findings.append("No significant forensic findings detected")
        
        return findings


def extract_revisions(
    input_pdf: Path,
    output_dir: Optional[Path] = None,
    export_all: bool = False
) -> List[RevisionInfo]:
    """
    Extract revision timeline from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_dir: Directory to export revisions (if export_all=True)
        export_all: Whether to export all revisions as separate PDFs
    
    Returns:
        List of RevisionInfo objects
    """
    with PDFDocument.open(input_pdf) as pdf_doc:
        extractor = RevisionExtractor(pdf_doc)
        revisions = extractor.extract_all_revisions()
        
        if export_all and output_dir:
            extractor.export_all_revisions(output_dir)
        
        return revisions
