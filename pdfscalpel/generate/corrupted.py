"""
Broken PDF Generator for CTF challenges and recovery testing

Generates PDFs with intentional corruption for educational purposes,
testing PDF recovery tools, and creating repair challenges.
"""

from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum
import random
import struct
import io

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError

logger = get_logger()


class CorruptionType(Enum):
    """Types of PDF corruption"""
    XREF_OFFSET = "xref_offset"
    TRUNCATED_STREAM = "truncated_stream"
    FAKE_EOF = "fake_eof"
    DUPLICATE_XREF = "duplicate_xref"
    MISSING_HEADER = "missing_header"
    CORRUPTED_OBJECT_NUM = "corrupted_object_num"
    INVALID_STREAM_LENGTH = "invalid_stream_length"
    BROKEN_LINEARIZATION = "broken_linearization"
    INVALID_ENCRYPTION = "invalid_encryption"
    MISSING_OBJECTS = "missing_objects"
    INVALID_TRAILER = "invalid_trailer"
    CORRUPTED_CONTENT_STREAM = "corrupted_content_stream"
    MIXED = "mixed"


class CorruptionDifficulty(Enum):
    """Difficulty levels for recovery"""
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


@dataclass
class RecoveryHint:
    """Hint for recovering corrupted PDF"""
    difficulty: str
    hint_text: str
    tool_suggestion: Optional[str] = None
    expected_approach: Optional[str] = None


@dataclass
class CorruptionMetadata:
    """Metadata about the corruption applied"""
    corruption_type: str
    difficulty: str
    corruption_offset: Optional[int] = None
    original_value: Optional[str] = None
    corrupted_value: Optional[str] = None
    recovery_hints: List[RecoveryHint] = None
    
    def __post_init__(self):
        if self.recovery_hints is None:
            self.recovery_hints = []


class BrokenPDFGenerator:
    """
    Generator for intentionally corrupted PDFs
    
    Creates PDFs with various types of corruption for:
    - CTF challenges
    - PDF recovery tool testing
    - Teaching PDF structure and repair
    """
    
    def __init__(self):
        if pikepdf is None:
            raise DependencyMissingError("pikepdf", "PDF corruption generation")
        if not HAS_REPORTLAB:
            raise DependencyMissingError("reportlab", "PDF creation for corruption")
    
    def generate_corrupted_pdf(
        self,
        output_path: Path,
        corruption_type: CorruptionType,
        difficulty: CorruptionDifficulty = CorruptionDifficulty.MEDIUM,
        content: Optional[str] = None,
        include_hints: bool = True
    ) -> CorruptionMetadata:
        """
        Generate a corrupted PDF
        
        Args:
            output_path: Output file path
            corruption_type: Type of corruption to apply
            difficulty: Recovery difficulty level
            content: Content to include in PDF (default: sample text)
            include_hints: Include recovery hints in metadata
            
        Returns:
            CorruptionMetadata with details about the corruption
        """
        logger.info(f"Generating corrupted PDF: {corruption_type.value} (difficulty: {difficulty.value})")
        
        temp_pdf = output_path.with_suffix('.tmp.pdf')
        
        try:
            self._create_base_pdf(temp_pdf, content or self._get_default_content())
            
            if corruption_type == CorruptionType.MIXED:
                metadata = self._apply_mixed_corruption(temp_pdf, output_path, difficulty, include_hints)
            else:
                corruption_func = getattr(self, f'_corrupt_{corruption_type.value}')
                metadata = corruption_func(temp_pdf, output_path, difficulty, include_hints)
            
            temp_pdf.unlink(missing_ok=True)
            
            logger.info(f"Corrupted PDF created: {output_path}")
            return metadata
            
        except Exception as e:
            temp_pdf.unlink(missing_ok=True)
            raise PDFScalpelError(f"Failed to generate corrupted PDF: {e}") from e
    
    def _create_base_pdf(self, output_path: Path, content: str):
        """Create a clean base PDF"""
        c = canvas.Canvas(str(output_path), pagesize=letter)
        c.setTitle("Corrupted PDF Challenge")
        
        c.setFont("Helvetica", 12)
        y = 750
        for line in content.split('\n'):
            if y < 50:
                c.showPage()
                y = 750
            c.drawString(50, y, line)
            y -= 15
        
        c.save()
    
    def _get_default_content(self) -> str:
        """Get default content for the PDF"""
        return """This is a deliberately corrupted PDF for educational purposes.

Your task is to repair this PDF and recover the content.

This challenge tests your understanding of:
- PDF file structure
- Cross-reference tables
- Object streams
- PDF recovery techniques

Good luck with the recovery!

Flag format: CTF{recovered_successfully}
"""
    
    def _corrupt_xref_offset(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Corrupt cross-reference table offset"""
        with open(input_pdf, 'rb') as f:
            data = f.read()
        
        startxref_pos = data.rfind(b'startxref')
        if startxref_pos == -1:
            raise PDFScalpelError("No startxref found in PDF")
        
        xref_line_start = startxref_pos + len(b'startxref') + 1
        xref_line_end = data.find(b'\n', xref_line_start)
        original_offset = data[xref_line_start:xref_line_end].strip()
        
        offset_value = int(original_offset)
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            new_offset = offset_value + 10
        elif difficulty == CorruptionDifficulty.EASY:
            new_offset = offset_value + 100
        elif difficulty == CorruptionDifficulty.MEDIUM:
            new_offset = offset_value + 1000
        elif difficulty == CorruptionDifficulty.HARD:
            new_offset = offset_value // 2
        else:
            new_offset = 12345
        
        corrupted_data = (
            data[:xref_line_start] +
            str(new_offset).encode() +
            data[xref_line_end:]
        )
        
        with open(output_pdf, 'wb') as f:
            f.write(corrupted_data)
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="The startxref value points to the wrong location",
                    tool_suggestion="qpdf --check or manual xref table search",
                    expected_approach="Rebuild xref table or find correct offset"
                ),
                RecoveryHint(
                    difficulty="medium",
                    hint_text="Search for 'xref' keyword in the file",
                    tool_suggestion="Hex editor or grep",
                    expected_approach="Calculate actual xref offset from file"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.XREF_OFFSET.value,
            difficulty=difficulty.value,
            corruption_offset=startxref_pos,
            original_value=original_offset.decode(),
            corrupted_value=str(new_offset),
            recovery_hints=hints
        )
    
    def _corrupt_truncated_stream(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Truncate a stream prematurely"""
        pdf = pikepdf.Pdf.open(input_pdf)
        
        stream_objs = [obj for obj in pdf.objects if isinstance(obj, pikepdf.Stream)]
        if not stream_objs:
            pdf.close()
            raise PDFScalpelError("No streams found to truncate")
        
        target_stream = random.choice(stream_objs)
        original_data = bytes(target_stream.read_bytes())
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            truncate_ratio = 0.9
        elif difficulty == CorruptionDifficulty.EASY:
            truncate_ratio = 0.7
        elif difficulty == CorruptionDifficulty.MEDIUM:
            truncate_ratio = 0.5
        elif difficulty == CorruptionDifficulty.HARD:
            truncate_ratio = 0.3
        else:
            truncate_ratio = 0.1
        
        truncate_len = int(len(original_data) * truncate_ratio)
        truncated_data = original_data[:truncate_len]
        
        target_stream.write(truncated_data)
        
        pdf.save(output_pdf)
        pdf.close()
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="A stream ends prematurely",
                    tool_suggestion="pdf-parser.py or pikepdf",
                    expected_approach="Identify truncated stream and pad or remove"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Stream length doesn't match actual data",
                    tool_suggestion="Manual inspection with hex editor",
                    expected_approach="Recalculate stream lengths"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.TRUNCATED_STREAM.value,
            difficulty=difficulty.value,
            original_value=f"{len(original_data)} bytes",
            corrupted_value=f"{len(truncated_data)} bytes",
            recovery_hints=hints
        )
    
    def _corrupt_fake_eof(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Add fake EOF markers"""
        with open(input_pdf, 'rb') as f:
            data = f.read()
        
        eof_marker = b'%%EOF'
        real_eof_pos = data.rfind(eof_marker)
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            fake_eof_pos = len(data) // 4
            num_fakes = 1
        elif difficulty == CorruptionDifficulty.EASY:
            fake_eof_pos = len(data) // 3
            num_fakes = 2
        elif difficulty == CorruptionDifficulty.MEDIUM:
            fake_eof_pos = len(data) // 2
            num_fakes = 3
        elif difficulty == CorruptionDifficulty.HARD:
            fake_eof_pos = real_eof_pos - 100
            num_fakes = 5
        else:
            fake_eof_pos = real_eof_pos - 10
            num_fakes = 10
        
        corrupted_data = bytearray(data)
        
        for i in range(num_fakes):
            insert_pos = fake_eof_pos + (i * 50)
            if insert_pos < real_eof_pos:
                corrupted_data[insert_pos:insert_pos] = eof_marker + b'\n'
        
        with open(output_pdf, 'wb') as f:
            f.write(corrupted_data)
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="Multiple EOF markers present",
                    tool_suggestion="grep or text search for %%EOF",
                    expected_approach="Find the real EOF (usually the last one)"
                ),
                RecoveryHint(
                    difficulty="medium",
                    hint_text="Some PDF readers stop at first EOF",
                    tool_suggestion="Manual inspection",
                    expected_approach="Remove fake EOF markers"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.FAKE_EOF.value,
            difficulty=difficulty.value,
            corrupted_value=f"{num_fakes} fake EOF markers",
            recovery_hints=hints
        )
    
    def _corrupt_duplicate_xref(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Create duplicate cross-reference tables"""
        with open(input_pdf, 'rb') as f:
            data = f.read()
        
        xref_pos = data.find(b'xref\n')
        if xref_pos == -1:
            raise PDFScalpelError("No xref table found")
        
        startxref_pos = data.rfind(b'startxref')
        xref_end = startxref_pos
        
        xref_section = data[xref_pos:xref_end]
        
        if difficulty in [CorruptionDifficulty.TRIVIAL, CorruptionDifficulty.EASY]:
            corrupted_data = data[:xref_pos] + xref_section + b'\n' + data[xref_pos:]
        else:
            modified_xref = xref_section.replace(b'0000000000 65535 f', b'0000000001 65535 f')
            corrupted_data = data[:xref_pos] + modified_xref + b'\n' + data[xref_pos:]
        
        with open(output_pdf, 'wb') as f:
            f.write(corrupted_data)
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="Two xref tables exist in the file",
                    tool_suggestion="qpdf --check",
                    expected_approach="Remove duplicate or reconcile differences"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Xref tables may have conflicting object definitions",
                    tool_suggestion="pdf-parser.py",
                    expected_approach="Determine which xref is authoritative"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.DUPLICATE_XREF.value,
            difficulty=difficulty.value,
            recovery_hints=hints
        )
    
    def _corrupt_missing_header(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Remove or corrupt PDF header"""
        with open(input_pdf, 'rb') as f:
            data = f.read()
        
        header_end = data.find(b'\n') + 1
        original_header = data[:header_end]
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            corrupted_data = b'%PDF-1.X\n' + data[header_end:]
        elif difficulty == CorruptionDifficulty.EASY:
            corrupted_data = b'%XDF-1.4\n' + data[header_end:]
        elif difficulty == CorruptionDifficulty.MEDIUM:
            corrupted_data = b'CORRUPTED\n' + data[header_end:]
        elif difficulty == CorruptionDifficulty.HARD:
            corrupted_data = data[header_end:]
        else:
            corrupted_data = data[5:]
        
        with open(output_pdf, 'wb') as f:
            f.write(corrupted_data)
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="PDF header is missing or corrupted",
                    tool_suggestion="Hex editor",
                    expected_approach="Add valid PDF header: %PDF-1.4 or higher"
                ),
                RecoveryHint(
                    difficulty="medium",
                    hint_text="PDF magic bytes should be %PDF-",
                    expected_approach="Prepend correct header to file"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.MISSING_HEADER.value,
            difficulty=difficulty.value,
            original_value=original_header.decode('latin1'),
            corrupted_value="<missing or corrupted>",
            recovery_hints=hints
        )
    
    def _corrupt_corrupted_object_num(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Corrupt object numbers"""
        with open(input_pdf, 'rb') as f:
            data = f.read()
        
        import re
        obj_pattern = rb'(\d+) (\d+) obj'
        matches = list(re.finditer(obj_pattern, data))
        
        if not matches:
            raise PDFScalpelError("No objects found to corrupt")
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            num_to_corrupt = 1
        elif difficulty == CorruptionDifficulty.EASY:
            num_to_corrupt = 2
        elif difficulty == CorruptionDifficulty.MEDIUM:
            num_to_corrupt = min(3, len(matches))
        elif difficulty == CorruptionDifficulty.HARD:
            num_to_corrupt = min(5, len(matches))
        else:
            num_to_corrupt = min(10, len(matches))
        
        corrupted_data = bytearray(data)
        targets = random.sample(matches, min(num_to_corrupt, len(matches)))
        
        offset_shift = 0
        for match in sorted(targets, key=lambda m: m.start()):
            obj_num = int(match.group(1))
            gen_num = match.group(2)
            
            new_obj_num = (obj_num + 1000) % 9999
            new_obj_str = f"{new_obj_num} {gen_num.decode()} obj".encode()
            
            start = match.start() + offset_shift
            end = match.end() + offset_shift
            
            corrupted_data[start:end] = new_obj_str
            offset_shift += len(new_obj_str) - (end - start)
        
        with open(output_pdf, 'wb') as f:
            f.write(corrupted_data)
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="medium",
                    hint_text="Object numbers don't match xref table",
                    tool_suggestion="pdf-parser.py or qpdf",
                    expected_approach="Rebuild xref table based on actual objects"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Cross-reference mismatches detected",
                    tool_suggestion="Manual inspection",
                    expected_approach="Renumber objects or fix xref entries"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.CORRUPTED_OBJECT_NUM.value,
            difficulty=difficulty.value,
            corrupted_value=f"{num_to_corrupt} objects renumbered",
            recovery_hints=hints
        )
    
    def _corrupt_invalid_stream_length(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Set incorrect stream length values"""
        pdf = pikepdf.Pdf.open(input_pdf)
        
        stream_objs = [obj for obj in pdf.objects if isinstance(obj, pikepdf.Stream)]
        if not stream_objs:
            pdf.close()
            raise PDFScalpelError("No streams found")
        
        target = random.choice(stream_objs)
        actual_length = len(bytes(target.read_bytes()))
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            wrong_length = actual_length + 1
        elif difficulty == CorruptionDifficulty.EASY:
            wrong_length = actual_length + 10
        elif difficulty == CorruptionDifficulty.MEDIUM:
            wrong_length = actual_length * 2
        elif difficulty == CorruptionDifficulty.HARD:
            wrong_length = actual_length // 2
        else:
            wrong_length = 12345
        
        target.Length = wrong_length
        
        pdf.save(output_pdf)
        pdf.close()
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="Stream /Length doesn't match actual data",
                    tool_suggestion="qpdf --check",
                    expected_approach="Recalculate and fix /Length values"
                ),
                RecoveryHint(
                    difficulty="medium",
                    hint_text="Look for stream...endstream markers",
                    tool_suggestion="Manual inspection",
                    expected_approach="Calculate actual stream size"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.INVALID_STREAM_LENGTH.value,
            difficulty=difficulty.value,
            original_value=str(actual_length),
            corrupted_value=str(wrong_length),
            recovery_hints=hints
        )
    
    def _corrupt_broken_linearization(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Break linearization (fast web view)"""
        pdf = pikepdf.Pdf.open(input_pdf)
        
        if '/Linearized' not in pdf.Root:
            linearized_dict = pikepdf.Dictionary({
                '/Linearized': 1.0,
                '/L': 999999,
                '/H': pikepdf.Array([0, 100]),
                '/O': 1,
                '/E': 10000,
                '/N': 1,
                '/T': 888888,
            })
            pdf.Root['/Linearized'] = linearized_dict
        else:
            pdf.Root['/Linearized']['/L'] = 999999
            pdf.Root['/Linearized']['/T'] = 888888
        
        pdf.save(output_pdf, linearize=False)
        pdf.close()
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="Linearization dictionary is invalid",
                    tool_suggestion="qpdf --check or Adobe Reader warnings",
                    expected_approach="Remove linearization or rebuild correctly"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Fast web view optimization is corrupted",
                    tool_suggestion="qpdf --linearize to rebuild",
                    expected_approach="Re-linearize the PDF"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.BROKEN_LINEARIZATION.value,
            difficulty=difficulty.value,
            recovery_hints=hints
        )
    
    def _corrupt_invalid_encryption(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Create invalid encryption dictionary"""
        pdf = pikepdf.Pdf.open(input_pdf)
        
        fake_encrypt = pikepdf.Dictionary({
            '/Filter': pikepdf.Name('/Standard'),
            '/V': 999,
            '/R': 999,
            '/O': b'fake_owner_string_123456789012345678901234567890ab',
            '/U': b'fake_user_string_1234567890123456789012345678901a',
            '/P': -1,
            '/Length': 12345,
        })
        
        pdf.trailer['/Encrypt'] = fake_encrypt
        
        pdf.save(output_pdf, encryption=False)
        pdf.close()
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="medium",
                    hint_text="Encryption dictionary is malformed",
                    tool_suggestion="pikepdf or qpdf",
                    expected_approach="Remove /Encrypt from trailer"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Invalid encryption version or revision",
                    tool_suggestion="Manual trailer editing",
                    expected_approach="Delete encryption dictionary"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.INVALID_ENCRYPTION.value,
            difficulty=difficulty.value,
            recovery_hints=hints
        )
    
    def _corrupt_missing_objects(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Remove objects referenced in xref but not present"""
        with open(input_pdf, 'rb') as f:
            data = f.read()
        
        import re
        obj_pattern = rb'(\d+) \d+ obj.*?endobj'
        matches = list(re.finditer(obj_pattern, data, re.DOTALL))
        
        if len(matches) < 3:
            raise PDFScalpelError("Not enough objects to remove")
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            num_to_remove = 1
        elif difficulty == CorruptionDifficulty.EASY:
            num_to_remove = 1
        elif difficulty == CorruptionDifficulty.MEDIUM:
            num_to_remove = 2
        elif difficulty == CorruptionDifficulty.HARD:
            num_to_remove = 3
        else:
            num_to_remove = min(5, len(matches) // 2)
        
        to_remove = random.sample(matches[:-1], min(num_to_remove, len(matches) - 1))
        
        corrupted_data = bytearray(data)
        offset = 0
        for match in sorted(to_remove, key=lambda m: m.start()):
            start = match.start() - offset
            end = match.end() - offset
            del corrupted_data[start:end]
            offset += (end - start)
        
        with open(output_pdf, 'wb') as f:
            f.write(corrupted_data)
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="medium",
                    hint_text="Referenced objects are missing from file",
                    tool_suggestion="qpdf --check",
                    expected_approach="Remove references or recreate objects"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Xref points to non-existent objects",
                    tool_suggestion="Manual xref rebuilding",
                    expected_approach="Rebuild xref table from actual objects"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.MISSING_OBJECTS.value,
            difficulty=difficulty.value,
            corrupted_value=f"{num_to_remove} objects removed",
            recovery_hints=hints
        )
    
    def _corrupt_invalid_trailer(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Corrupt trailer dictionary"""
        with open(input_pdf, 'rb') as f:
            data = f.read()
        
        trailer_pos = data.rfind(b'trailer')
        if trailer_pos == -1:
            raise PDFScalpelError("No trailer found")
        
        startxref_pos = data.find(b'startxref', trailer_pos)
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            corrupted_data = data[:trailer_pos] + b'trailer\n<<\n/Size 999\n>>\n' + data[startxref_pos:]
        elif difficulty == CorruptionDifficulty.EASY:
            corrupted_data = data[:trailer_pos] + b'trailer\n<<\n/Root 999 0 R\n>>\n' + data[startxref_pos:]
        elif difficulty == CorruptionDifficulty.MEDIUM:
            corrupted_data = data[:trailer_pos] + b'trailer\n<<\n>>\n' + data[startxref_pos:]
        elif difficulty == CorruptionDifficulty.HARD:
            corrupted_data = data[:trailer_pos] + b'CORRUPTED_TRAILER\n' + data[startxref_pos:]
        else:
            corrupted_data = data[:trailer_pos] + data[startxref_pos:]
        
        with open(output_pdf, 'wb') as f:
            f.write(corrupted_data)
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="easy",
                    hint_text="Trailer dictionary is malformed",
                    tool_suggestion="qpdf or manual inspection",
                    expected_approach="Rebuild trailer with correct /Root and /Size"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Missing required trailer entries",
                    tool_suggestion="PDF specification reference",
                    expected_approach="Construct valid trailer from scratch"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.INVALID_TRAILER.value,
            difficulty=difficulty.value,
            recovery_hints=hints
        )
    
    def _corrupt_corrupted_content_stream(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Corrupt page content stream"""
        pdf = pikepdf.Pdf.open(input_pdf)
        
        page = pdf.pages[0]
        if '/Contents' not in page:
            pdf.close()
            raise PDFScalpelError("No content stream found")
        
        content_stream = page.Contents
        if not isinstance(content_stream, pikepdf.Stream):
            pdf.close()
            raise PDFScalpelError("Content is not a stream")
        
        original_data = bytes(content_stream.read_bytes())
        
        if difficulty == CorruptionDifficulty.TRIVIAL:
            corrupted = original_data[:-5]
        elif difficulty == CorruptionDifficulty.EASY:
            corrupted = original_data[:len(original_data)//2] + b'CORRUPT' + original_data[len(original_data)//2:]
        elif difficulty == CorruptionDifficulty.MEDIUM:
            corrupted = original_data.replace(b'Tj', b'XX').replace(b'Tf', b'YY')
        elif difficulty == CorruptionDifficulty.HARD:
            corrupted = b'CORRUPTED_STREAM_DATA_' + original_data[100:]
        else:
            corrupted = b'COMPLETELY_INVALID_CONTENT'
        
        content_stream.write(corrupted)
        
        pdf.save(output_pdf)
        pdf.close()
        
        hints = []
        if include_hints:
            hints = [
                RecoveryHint(
                    difficulty="medium",
                    hint_text="Page content stream has invalid operators",
                    tool_suggestion="pdf-parser.py or manual stream inspection",
                    expected_approach="Fix or remove corrupted operators"
                ),
                RecoveryHint(
                    difficulty="hard",
                    hint_text="Content stream doesn't follow PDF syntax",
                    tool_suggestion="PDF reference manual",
                    expected_approach="Reconstruct valid content stream"
                )
            ]
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.CORRUPTED_CONTENT_STREAM.value,
            difficulty=difficulty.value,
            original_value=f"{len(original_data)} bytes",
            corrupted_value=f"{len(corrupted)} bytes",
            recovery_hints=hints
        )
    
    def _apply_mixed_corruption(
        self,
        input_pdf: Path,
        output_pdf: Path,
        difficulty: CorruptionDifficulty,
        include_hints: bool
    ) -> CorruptionMetadata:
        """Apply multiple corruption types"""
        if difficulty == CorruptionDifficulty.TRIVIAL:
            corruption_types = [CorruptionType.XREF_OFFSET]
        elif difficulty == CorruptionDifficulty.EASY:
            corruption_types = [CorruptionType.XREF_OFFSET, CorruptionType.FAKE_EOF]
        elif difficulty == CorruptionDifficulty.MEDIUM:
            corruption_types = [
                CorruptionType.XREF_OFFSET,
                CorruptionType.FAKE_EOF,
                CorruptionType.INVALID_STREAM_LENGTH
            ]
        elif difficulty == CorruptionDifficulty.HARD:
            corruption_types = [
                CorruptionType.MISSING_HEADER,
                CorruptionType.DUPLICATE_XREF,
                CorruptionType.TRUNCATED_STREAM,
                CorruptionType.CORRUPTED_OBJECT_NUM
            ]
        else:
            corruption_types = [
                CorruptionType.MISSING_HEADER,
                CorruptionType.DUPLICATE_XREF,
                CorruptionType.FAKE_EOF,
                CorruptionType.INVALID_TRAILER,
                CorruptionType.MISSING_OBJECTS,
                CorruptionType.CORRUPTED_CONTENT_STREAM
            ]
        
        temp_path = input_pdf
        all_hints = []
        
        for i, corruption_type in enumerate(corruption_types):
            next_temp = input_pdf.with_suffix(f'.tmp{i}.pdf')
            
            corruption_func = getattr(self, f'_corrupt_{corruption_type.value}')
            metadata = corruption_func(
                temp_path,
                next_temp,
                CorruptionDifficulty.EASY,
                include_hints
            )
            
            all_hints.extend(metadata.recovery_hints)
            
            if temp_path != input_pdf:
                temp_path.unlink(missing_ok=True)
            
            temp_path = next_temp
        
        temp_path.rename(output_pdf)
        
        return CorruptionMetadata(
            corruption_type=CorruptionType.MIXED.value,
            difficulty=difficulty.value,
            corrupted_value=f"{len(corruption_types)} different corruptions applied",
            recovery_hints=all_hints
        )


def generate_corrupted_pdf(
    output_path: Path,
    corruption_type: str = "xref_offset",
    difficulty: str = "medium",
    content: Optional[str] = None,
    include_hints: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to generate corrupted PDF
    
    Args:
        output_path: Output file path
        corruption_type: Type of corruption
        difficulty: Recovery difficulty
        content: Custom content
        include_hints: Include recovery hints
        
    Returns:
        Dictionary with corruption metadata
    """
    generator = BrokenPDFGenerator()
    
    try:
        c_type = CorruptionType(corruption_type)
    except ValueError:
        raise PDFScalpelError(f"Invalid corruption type: {corruption_type}")
    
    try:
        c_diff = CorruptionDifficulty(difficulty)
    except ValueError:
        raise PDFScalpelError(f"Invalid difficulty: {difficulty}")
    
    metadata = generator.generate_corrupted_pdf(
        output_path,
        c_type,
        c_diff,
        content,
        include_hints
    )
    
    return {
        'corruption_type': metadata.corruption_type,
        'difficulty': metadata.difficulty,
        'corruption_offset': metadata.corruption_offset,
        'original_value': metadata.original_value,
        'corrupted_value': metadata.corrupted_value,
        'hints': [
            {
                'difficulty': h.difficulty,
                'hint': h.hint_text,
                'tool': h.tool_suggestion,
                'approach': h.expected_approach
            }
            for h in metadata.recovery_hints
        ]
    }
