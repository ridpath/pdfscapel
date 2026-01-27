"""
CTF Challenge Generator for PDF-based challenges

Creates various types of CTF challenges with configurable difficulty levels.
Generates solution metadata for validation and learning.
"""

from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import random
import string
import json
import hashlib
import base64
from datetime import datetime

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError
from pdfscalpel.core.constants import CTF_FLAG_PATTERNS

logger = get_logger()


class ChallengeType(Enum):
    """Types of PDF CTF challenges"""
    PASSWORD = "password"
    STEGANOGRAPHY = "steganography"
    WATERMARK = "watermark"
    REVISION = "revision"
    JAVASCRIPT = "javascript"
    METADATA = "metadata"
    MULTI_STAGE = "multi_stage"
    CORRUPTION = "corruption"
    POLYGLOT = "polyglot"
    MIXED = "mixed"


class Difficulty(Enum):
    """Challenge difficulty levels"""
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


@dataclass
class HintConfig:
    """Configuration for hints at different difficulty levels"""
    include_hints: bool = True
    delayed_hints: bool = False
    hint_count: int = 1
    hint_delay_minutes: Optional[int] = None


@dataclass
class SolutionMetadata:
    """Metadata about challenge solution"""
    challenge_type: str
    difficulty: str
    flag: str
    password: Optional[str] = None
    techniques_required: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    solution_steps: List[str] = field(default_factory=list)
    estimated_time_minutes: int = 5
    tools_suggested: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    creator: str = "PDFAutopsy Challenge Generator"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    def save(self, path: Path):
        """Save solution metadata to file"""
        with open(path, 'w') as f:
            f.write(self.to_json())


class ChallengeGenerator:
    """Generate CTF challenges for PDF forensics and analysis"""
    
    def __init__(self):
        if not HAS_REPORTLAB:
            raise DependencyMissingError(
                "reportlab is required for challenge generation",
                "pip install reportlab"
            )
        if not pikepdf:
            raise DependencyMissingError(
                "pikepdf is required for challenge generation",
                "pip install pikepdf"
            )
    
    def generate(
        self,
        output_path: Path,
        flag: str,
        challenge_type: ChallengeType = ChallengeType.PASSWORD,
        difficulty: Difficulty = Difficulty.EASY,
        hint_config: Optional[HintConfig] = None,
        save_solution: bool = True,
        **kwargs
    ) -> SolutionMetadata:
        """
        Generate a CTF challenge
        
        Args:
            output_path: Output PDF path
            flag: Flag to hide in challenge
            challenge_type: Type of challenge to create
            difficulty: Difficulty level
            hint_config: Hint configuration
            save_solution: Save solution metadata to .solution.json
            **kwargs: Type-specific parameters
            
        Returns:
            SolutionMetadata object
        """
        logger.info(f"Generating {challenge_type.value} challenge (difficulty: {difficulty.value})")
        
        output_path = Path(output_path)
        hint_config = hint_config or HintConfig()
        
        if challenge_type == ChallengeType.PASSWORD:
            solution = self._generate_password_challenge(
                output_path, flag, difficulty, hint_config, **kwargs
            )
        elif challenge_type == ChallengeType.STEGANOGRAPHY:
            solution = self._generate_stego_challenge(
                output_path, flag, difficulty, hint_config, **kwargs
            )
        elif challenge_type == ChallengeType.WATERMARK:
            solution = self._generate_watermark_challenge(
                output_path, flag, difficulty, hint_config, **kwargs
            )
        elif challenge_type == ChallengeType.REVISION:
            solution = self._generate_revision_challenge(
                output_path, flag, difficulty, hint_config, **kwargs
            )
        elif challenge_type == ChallengeType.JAVASCRIPT:
            solution = self._generate_javascript_challenge(
                output_path, flag, difficulty, hint_config, **kwargs
            )
        elif challenge_type == ChallengeType.METADATA:
            solution = self._generate_metadata_challenge(
                output_path, flag, difficulty, hint_config, **kwargs
            )
        elif challenge_type == ChallengeType.MULTI_STAGE:
            solution = self._generate_multi_stage_challenge(
                output_path, flag, difficulty, hint_config, **kwargs
            )
        else:
            raise PDFScalpelError(f"Challenge type {challenge_type} not yet implemented")
        
        if save_solution:
            solution_path = output_path.with_suffix('.solution.json')
            solution.save(solution_path)
            logger.info(f"Solution metadata saved to: {solution_path}")
        
        logger.info(f"Challenge created: {output_path}")
        return solution
    
    def _generate_password_challenge(
        self,
        output_path: Path,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig,
        **kwargs
    ) -> SolutionMetadata:
        """Generate password-protected challenge"""
        temp_path = output_path.with_suffix('.temp.pdf')
        
        c = canvas.Canvas(str(temp_path), pagesize=letter)
        c.setTitle("Password Challenge")
        
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, 700, "CTF Password Challenge")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, 650, f"The flag is: {flag}")
        c.drawString(100, 630, "Good luck!")
        
        password, hints, solution_steps, tools = self._generate_password_config(
            flag, difficulty, hint_config
        )
        
        if hint_config.include_hints and hints:
            c.setFont("Helvetica-Oblique", 12)
            y_pos = 580
            for i, hint in enumerate(hints, 1):
                c.drawString(100, y_pos, f"Hint {i}: {hint}")
                y_pos -= 20
        
        c.save()
        
        encryption_r = self._get_encryption_r(difficulty)
        
        with pikepdf.Pdf.open(temp_path) as pdf:
            pdf.save(
                output_path,
                encryption=pikepdf.Encryption(
                    user=password,
                    owner=password,
                    R=encryption_r
                )
            )
        
        temp_path.unlink()
        
        est_time = self._estimate_time(difficulty, ChallengeType.PASSWORD)
        
        return SolutionMetadata(
            challenge_type=ChallengeType.PASSWORD.value,
            difficulty=difficulty.value,
            flag=flag,
            password=password,
            techniques_required=["password_cracking", "pdf_encryption_analysis"],
            hints=hints,
            solution_steps=solution_steps,
            estimated_time_minutes=est_time,
            tools_suggested=tools
        )
    
    def _generate_password_config(
        self,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig
    ) -> Tuple[str, List[str], List[str], List[str]]:
        """Generate password and related metadata based on difficulty"""
        hints = []
        solution_steps = []
        tools = ["pdfautopsy", "john", "hashcat", "pikepdf"]
        
        if difficulty == Difficulty.TRIVIAL:
            password = "1234"
            if hint_config.include_hints:
                hints = ["The password is a common 4-digit PIN"]
            solution_steps = [
                "Try common passwords like '1234', 'password', etc.",
                "Use: pdfautopsy solve password INPUT --ctf-mode"
            ]
            
        elif difficulty == Difficulty.EASY:
            password = "ctf2024"
            if hint_config.include_hints:
                hints = ["The password relates to CTF", "It's 7 characters long"]
            solution_steps = [
                "Use intelligent attack with CTF-related passwords",
                "Use: pdfautopsy solve password INPUT --ctf-mode --challenge-id easy_pwd"
            ]
            
        elif difficulty == Difficulty.MEDIUM:
            if flag.startswith("CTF{") and len(flag) >= 8:
                password = flag[4:10].lower()
            else:
                password = flag[:6].lower() if len(flag) >= 6 else "medium"
            
            if hint_config.include_hints:
                hints = [
                    "The password is derived from the flag",
                    "Extract characters from the flag format"
                ]
            solution_steps = [
                "Analyze the encryption parameters",
                "Try passwords derived from common flag formats",
                "Use: pdfautopsy analyze encryption INPUT",
                "Use: pdfautopsy solve password INPUT --mask 'CTF???'"
            ]
            
        elif difficulty == Difficulty.HARD:
            charset = string.ascii_lowercase + string.digits
            password = ''.join(random.choices(charset, k=8))
            if hint_config.include_hints:
                hints = [
                    "8 characters, lowercase + digits",
                    "Brute force or dictionary attack required"
                ]
            solution_steps = [
                "Check encryption algorithm (likely RC4-128 or AES-128)",
                "Use dictionary attack with rockyou.txt",
                "Use: pdfautopsy solve password INPUT --wordlist rockyou.txt",
                "If no wordlist match, use brute force: --brute-force --max-length 8"
            ]
            
        else:
            charset = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choices(charset, k=12))
            if hint_config.include_hints:
                hints = ["Good luck, you'll need it", "12+ characters, full charset"]
            solution_steps = [
                "Check encryption algorithm (likely AES-256)",
                "This requires significant computing power",
                "Use: pdfautopsy solve password INPUT --wordlist large_wordlist.txt",
                "Consider GPU acceleration with hashcat",
                "Estimated time: hours to days depending on hardware"
            ]
        
        return password, hints, solution_steps, tools
    
    def _generate_stego_challenge(
        self,
        output_path: Path,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig,
        **kwargs
    ) -> SolutionMetadata:
        """Generate steganography challenge"""
        stego_type = kwargs.get('stego_type', 'whitespace')
        
        c = canvas.Canvas(str(output_path), pagesize=letter)
        c.setTitle("Steganography Challenge")
        
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, 700, "Steganography Challenge")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, 650, "The flag is hidden somewhere in this PDF.")
        c.drawString(100, 630, "Look closely at the structure...")
        
        hints = []
        solution_steps = []
        techniques = ["steganography_detection"]
        
        if difficulty == Difficulty.TRIVIAL or difficulty == Difficulty.EASY:
            c.setFont("Courier", 8)
            spaces = ' ' * 200
            c.drawString(100, 600, f"Nothing to see here.{spaces}{flag}")
            
            if hint_config.include_hints:
                hints = ["Check for whitespace", "Look for extra spaces in the text"]
            solution_steps = [
                "Extract text from PDF",
                "Look for long whitespace sequences",
                "Use: pdfautopsy extract text INPUT --preserve-layout"
            ]
            techniques.append("whitespace_analysis")
            
        elif difficulty == Difficulty.MEDIUM:
            invisible_text = flag
            c.setFillColorRGB(1, 1, 1)
            c.drawString(100, 500, invisible_text)
            c.setFillColorRGB(0, 0, 0)
            
            if hint_config.include_hints:
                hints = [
                    "Not all text is visible",
                    "Check the PDF content streams"
                ]
            solution_steps = [
                "Extract all text including invisible layers",
                "Use: pdfautopsy extract hidden INPUT",
                "Look for white-on-white text"
            ]
            techniques.append("invisible_text_detection")
            
        else:
            c.drawString(100, 600, "Advanced steganography challenge")
            if hint_config.include_hints:
                hints = [
                    "Check zero-width characters",
                    "Examine object ordering",
                    "Look at incremental updates"
                ]
            solution_steps = [
                "Run comprehensive stego scan",
                "Use: pdfautopsy solve stego INPUT",
                "Check multiple steganography techniques"
            ]
            techniques.extend([
                "zero_width_characters",
                "object_ordering",
                "incremental_updates"
            ])
        
        c.save()
        
        with pikepdf.Pdf.open(output_path, allow_overwriting_input=True) as pdf:
            if difficulty in (Difficulty.MEDIUM, Difficulty.HARD, Difficulty.EXPERT):
                pdf.docinfo['/CTF_Metadata'] = base64.b64encode(flag.encode()).decode()
            pdf.save(output_path)
        
        est_time = self._estimate_time(difficulty, ChallengeType.STEGANOGRAPHY)
        
        return SolutionMetadata(
            challenge_type=ChallengeType.STEGANOGRAPHY.value,
            difficulty=difficulty.value,
            flag=flag,
            techniques_required=techniques,
            hints=hints,
            solution_steps=solution_steps,
            estimated_time_minutes=est_time,
            tools_suggested=["pdfautopsy", "pdfplumber", "strings"]
        )
    
    def _generate_watermark_challenge(
        self,
        output_path: Path,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig,
        **kwargs
    ) -> SolutionMetadata:
        """Generate watermark removal challenge"""
        watermark_text = kwargs.get('watermark_text', 'WATERMARK')
        
        c = canvas.Canvas(str(output_path), pagesize=letter)
        c.setTitle("Watermark Challenge")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, 700, f"Remove the watermark to see the flag: {flag}")
        
        c.saveState()
        c.setFont("Helvetica-Bold", 72)
        c.setFillColorRGB(0.8, 0.8, 0.8)
        c.rotate(45)
        c.drawString(200, 0, watermark_text)
        c.restoreState()
        
        c.save()
        
        hints = []
        solution_steps = []
        
        if difficulty == Difficulty.EASY:
            if hint_config.include_hints:
                hints = [
                    "Try cropping the watermark",
                    "The watermark is on the edges"
                ]
            solution_steps = [
                "Detect watermark type",
                "Use: pdfautopsy analyze watermark INPUT",
                "Remove with: pdfautopsy mutate watermark INPUT OUTPUT --remove crop"
            ]
            
        elif difficulty == Difficulty.MEDIUM:
            if hint_config.include_hints:
                hints = [
                    "Watermark is in content stream",
                    "Parse PDF operators to remove it"
                ]
            solution_steps = [
                "Analyze watermark technique",
                "Use: pdfautopsy analyze watermark INPUT --verbose",
                "Try multiple removal methods",
                "Use: pdfautopsy mutate watermark INPUT OUTPUT --remove-all"
            ]
        else:
            if hint_config.include_hints:
                hints = [
                    "Advanced watermark removal required",
                    "May need image inpainting"
                ]
            solution_steps = [
                "Analyze watermark embedding",
                "Use advanced removal techniques",
                "Use: pdfautopsy mutate watermark INPUT OUTPUT --remove inpaint"
            ]
        
        est_time = self._estimate_time(difficulty, ChallengeType.WATERMARK)
        
        return SolutionMetadata(
            challenge_type=ChallengeType.WATERMARK.value,
            difficulty=difficulty.value,
            flag=flag,
            techniques_required=["watermark_detection", "watermark_removal"],
            hints=hints,
            solution_steps=solution_steps,
            estimated_time_minutes=est_time,
            tools_suggested=["pdfautopsy", "ghostscript", "imagemagick"]
        )
    
    def _generate_revision_challenge(
        self,
        output_path: Path,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig,
        **kwargs
    ) -> SolutionMetadata:
        """Generate revision-based challenge with flag in previous version"""
        temp_path = output_path.with_suffix('.temp.pdf')
        
        c = canvas.Canvas(str(temp_path), pagesize=letter)
        c.setTitle("Revision Challenge")
        
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, 700, "Version History Challenge")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, 650, f"SECRET FLAG: {flag}")
        c.drawString(100, 630, "This will be removed in the next version...")
        
        c.save()
        
        with pikepdf.Pdf.open(temp_path) as pdf:
            pdf.save(output_path)
        
        with pikepdf.Pdf.open(output_path, allow_overwriting_input=True) as pdf:
            page = pdf.pages[0]
            
            new_content = b"""
q
BT
/Helvetica-Bold 24 Tf
100 700 Td
(Version History Challenge) Tj
ET
BT
/Helvetica 14 Tf
100 650 Td
(The flag has been removed.) Tj
ET
BT
/Helvetica 14 Tf
100 630 Td
(Can you find it in the history?) Tj
ET
Q
"""
            page.Contents = pikepdf.Stream(pdf, new_content)
            pdf.save(output_path)
        
        temp_path.unlink(missing_ok=True)
        
        hints = []
        solution_steps = []
        
        if hint_config.include_hints:
            if difficulty in (Difficulty.TRIVIAL, Difficulty.EASY):
                hints = [
                    "PDFs keep previous versions",
                    "Check incremental updates"
                ]
            else:
                hints = ["Version control in PDFs is interesting"]
        
        solution_steps = [
            "Extract PDF revision history",
            "Use: pdfautopsy extract revisions INPUT --output-dir revisions/",
            "Check earlier versions for the flag",
            "Use: pdfautopsy solve flag-hunt revisions/*.pdf"
        ]
        
        est_time = self._estimate_time(difficulty, ChallengeType.REVISION)
        
        return SolutionMetadata(
            challenge_type=ChallengeType.REVISION.value,
            difficulty=difficulty.value,
            flag=flag,
            techniques_required=["revision_extraction", "incremental_update_analysis"],
            hints=hints,
            solution_steps=solution_steps,
            estimated_time_minutes=est_time,
            tools_suggested=["pdfautopsy", "qpdf", "pdfresurrect"]
        )
    
    def _generate_javascript_challenge(
        self,
        output_path: Path,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig,
        **kwargs
    ) -> SolutionMetadata:
        """Generate JavaScript-based challenge"""
        c = canvas.Canvas(str(output_path), pagesize=letter)
        c.setTitle("JavaScript Challenge")
        
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, 700, "JavaScript Challenge")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, 650, "The flag is hidden in the JavaScript code.")
        c.drawString(100, 630, "Extract and analyze the embedded scripts.")
        
        c.save()
        
        if difficulty == Difficulty.EASY:
            js_code = f'app.alert("Flag: {flag}");'
        elif difficulty == Difficulty.MEDIUM:
            encoded_flag = base64.b64encode(flag.encode()).decode()
            js_code = f'var encodedFlag = "{encoded_flag}"; app.alert(atob(encodedFlag));'
        else:
            obfuscated = self._obfuscate_javascript(flag)
            js_code = obfuscated
        
        with pikepdf.Pdf.open(output_path, allow_overwriting_input=True) as pdf:
            pdf.Root.OpenAction = pikepdf.Dictionary(
                S=pikepdf.Name.JavaScript,
                JS=js_code
            )
            pdf.save(output_path)
        
        hints = []
        solution_steps = []
        
        if hint_config.include_hints:
            if difficulty == Difficulty.EASY:
                hints = ["Extract JavaScript from the PDF"]
            elif difficulty == Difficulty.MEDIUM:
                hints = ["JavaScript is base64 encoded", "Decode the flag"]
            else:
                hints = ["JavaScript is obfuscated", "Deobfuscate to find the flag"]
        
        solution_steps = [
            "Extract JavaScript from PDF",
            "Use: pdfautopsy extract javascript INPUT",
            "Analyze/deobfuscate the code",
            "Run or decode to get the flag"
        ]
        
        est_time = self._estimate_time(difficulty, ChallengeType.JAVASCRIPT)
        
        return SolutionMetadata(
            challenge_type=ChallengeType.JAVASCRIPT.value,
            difficulty=difficulty.value,
            flag=flag,
            techniques_required=["javascript_extraction", "code_deobfuscation"],
            hints=hints,
            solution_steps=solution_steps,
            estimated_time_minutes=est_time,
            tools_suggested=["pdfautopsy", "pdf-parser.py", "js beautifier"]
        )
    
    def _generate_metadata_challenge(
        self,
        output_path: Path,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig,
        **kwargs
    ) -> SolutionMetadata:
        """Generate metadata-based challenge"""
        c = canvas.Canvas(str(output_path), pagesize=letter)
        c.setTitle("Metadata Challenge")
        
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, 700, "Metadata Challenge")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, 650, "The flag is hidden in the document metadata.")
        c.drawString(100, 630, "Dig deeper...")
        
        c.save()
        
        with pikepdf.Pdf.open(output_path, allow_overwriting_input=True) as pdf:
            if difficulty == Difficulty.EASY:
                pdf.docinfo['/Flag'] = flag
            elif difficulty == Difficulty.MEDIUM:
                encoded = base64.b64encode(flag.encode()).decode()
                pdf.docinfo['/Custom'] = encoded
            else:
                parts = [flag[i:i+4] for i in range(0, len(flag), 4)]
                pdf.docinfo['/Part1'] = parts[0] if len(parts) > 0 else ''
                pdf.docinfo['/Part2'] = parts[1] if len(parts) > 1 else ''
                pdf.docinfo['/Part3'] = parts[2] if len(parts) > 2 else ''
                pdf.docinfo['/Encoding'] = 'parts'
            
            pdf.save(output_path)
        
        hints = []
        solution_steps = []
        
        if hint_config.include_hints:
            if difficulty == Difficulty.EASY:
                hints = ["Check standard metadata fields"]
            elif difficulty == Difficulty.MEDIUM:
                hints = ["Check custom metadata", "Flag is encoded"]
            else:
                hints = ["Flag is split across multiple fields", "Reassemble the parts"]
        
        solution_steps = [
            "Dump all PDF metadata",
            "Use: pdfautopsy analyze metadata INPUT",
            "Look for custom or unusual fields",
            "Decode/reassemble if needed"
        ]
        
        est_time = self._estimate_time(difficulty, ChallengeType.METADATA)
        
        return SolutionMetadata(
            challenge_type=ChallengeType.METADATA.value,
            difficulty=difficulty.value,
            flag=flag,
            techniques_required=["metadata_extraction", "encoding_detection"],
            hints=hints,
            solution_steps=solution_steps,
            estimated_time_minutes=est_time,
            tools_suggested=["pdfautopsy", "exiftool", "pdfinfo"]
        )
    
    def _generate_multi_stage_challenge(
        self,
        output_path: Path,
        flag: str,
        difficulty: Difficulty,
        hint_config: HintConfig,
        **kwargs
    ) -> SolutionMetadata:
        """Generate multi-stage challenge combining multiple techniques"""
        temp_path = output_path.with_suffix('.temp.pdf')
        
        c = canvas.Canvas(str(temp_path), pagesize=letter)
        c.setTitle("Multi-Stage Challenge")
        
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, 700, "Multi-Stage CTF Challenge")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, 650, "This challenge requires multiple steps.")
        c.drawString(100, 630, f"Final flag: {flag}")
        
        c.save()
        
        stage1_password = "stage1"
        
        with pikepdf.Pdf.open(temp_path) as pdf:
            pdf.docinfo['/Hint1'] = "Password for stage 1: stage1"
            pdf.save(
                output_path,
                encryption=pikepdf.Encryption(
                    user=stage1_password,
                    owner=stage1_password,
                    R=4
                )
            )
        
        temp_path.unlink(missing_ok=True)
        
        hints = []
        solution_steps = []
        
        if hint_config.include_hints:
            hints = [
                "Start by extracting metadata",
                "Use the password hint to decrypt",
                "Look for the final flag in the content"
            ]
        
        solution_steps = [
            "Stage 1: Extract metadata to find password hint",
            "Use: pdfautopsy analyze metadata INPUT",
            "Stage 2: Decrypt with found password",
            "Use: pdfautopsy solve password INPUT --ctf-mode",
            "Stage 3: Extract flag from decrypted PDF",
            "Use: pdfautopsy solve flag-hunt decrypted.pdf"
        ]
        
        techniques = [
            "metadata_extraction",
            "password_cracking",
            "flag_extraction"
        ]
        
        est_time = self._estimate_time(difficulty, ChallengeType.MULTI_STAGE)
        
        return SolutionMetadata(
            challenge_type=ChallengeType.MULTI_STAGE.value,
            difficulty=difficulty.value,
            flag=flag,
            password=stage1_password,
            techniques_required=techniques,
            hints=hints,
            solution_steps=solution_steps,
            estimated_time_minutes=est_time,
            tools_suggested=["pdfautopsy", "exiftool", "strings"]
        )
    
    def _get_encryption_r(self, difficulty: Difficulty) -> int:
        """Get encryption R value based on difficulty"""
        if difficulty == Difficulty.TRIVIAL:
            return 4
        elif difficulty == Difficulty.EASY:
            return 4
        elif difficulty == Difficulty.MEDIUM:
            return 4
        elif difficulty == Difficulty.HARD:
            return 6
        else:
            return 6
    
    def _estimate_time(self, difficulty: Difficulty, challenge_type: ChallengeType) -> int:
        """Estimate solving time in minutes"""
        base_times = {
            ChallengeType.PASSWORD: 5,
            ChallengeType.STEGANOGRAPHY: 10,
            ChallengeType.WATERMARK: 8,
            ChallengeType.REVISION: 7,
            ChallengeType.JAVASCRIPT: 6,
            ChallengeType.METADATA: 3,
            ChallengeType.MULTI_STAGE: 15,
        }
        
        multipliers = {
            Difficulty.TRIVIAL: 0.5,
            Difficulty.EASY: 1.0,
            Difficulty.MEDIUM: 2.0,
            Difficulty.HARD: 5.0,
            Difficulty.EXPERT: 15.0,
        }
        
        base = base_times.get(challenge_type, 10)
        mult = multipliers.get(difficulty, 1.0)
        
        return int(base * mult)
    
    def _obfuscate_javascript(self, flag: str) -> str:
        """Simple JavaScript obfuscation"""
        encoded = base64.b64encode(flag.encode()).decode()
        
        return f"""
var _0x1234 = ['{encoded}', 'fromCharCode', 'charCodeAt', 'alert'];
var _0xabcd = function(s) {{
    var r = '';
    for (var i = 0; i < s.length; i++) {{
        r += String[_0x1234[1]](s[_0x1234[2]](i));
    }}
    return r;
}};
var decoded = atob(_0x1234[0]);
app[_0x1234[3]](decoded);
"""


def generate_challenge(
    output_path: Path,
    flag: str,
    challenge_type: str = "password",
    difficulty: str = "easy",
    save_solution: bool = True,
    **kwargs
) -> SolutionMetadata:
    """
    Convenience function to generate a challenge
    
    Args:
        output_path: Output PDF path
        flag: Flag to hide
        challenge_type: Type of challenge (password, steganography, etc.)
        difficulty: Difficulty level (trivial, easy, medium, hard, expert)
        save_solution: Save solution metadata
        **kwargs: Additional type-specific parameters
        
    Returns:
        SolutionMetadata object
    """
    generator = ChallengeGenerator()
    
    try:
        ctype = ChallengeType(challenge_type.lower())
    except ValueError:
        raise PDFScalpelError(
            f"Invalid challenge type: {challenge_type}. "
            f"Valid types: {', '.join(t.value for t in ChallengeType)}"
        )
    
    try:
        diff = Difficulty(difficulty.lower())
    except ValueError:
        raise PDFScalpelError(
            f"Invalid difficulty: {difficulty}. "
            f"Valid levels: {', '.join(d.value for d in Difficulty)}"
        )
    
    return generator.generate(
        output_path=Path(output_path),
        flag=flag,
        challenge_type=ctype,
        difficulty=diff,
        save_solution=save_solution,
        **kwargs
    )
