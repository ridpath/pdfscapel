"""John the Ripper integration for PDF password cracking"""

import subprocess
import tempfile
import re
from pathlib import Path
from typing import Optional, Dict, Any

from pdfscalpel.core.dependencies import check_external_tool, require_dependency
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import ExternalToolError

logger = get_logger()


class JohnIntegration:
    """Wrapper for John the Ripper operations"""
    
    def __init__(self):
        self.status = check_external_tool("john")
        self.available = self.status.available
        self.path = self.status.path
        self.version = self.status.version
    
    def require(self):
        """Raise error if John not available"""
        require_dependency("tool:john", "John the Ripper operations")
    
    def extract_hash(self, pdf_path: Path) -> Optional[str]:
        """Extract PDF hash for John"""
        self.require()
        
        pdf2john_path = self._find_pdf2john()
        if not pdf2john_path:
            logger.error("pdf2john.py not found")
            return None
        
        try:
            cmd = ["python", str(pdf2john_path), str(pdf_path)]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"pdf2john error: {result.stderr}")
                return None
            
            hash_line = result.stdout.strip()
            if hash_line:
                return hash_line
            
            return None
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("John the Ripper", "Hash extraction timed out")
        except Exception as e:
            raise ExternalToolError("John the Ripper", str(e))
    
    def crack_password(
        self,
        pdf_path: Path,
        wordlist: Optional[Path] = None,
        max_time: Optional[int] = None,
        rules: Optional[str] = None
    ) -> Optional[str]:
        """Crack PDF password using John"""
        self.require()
        
        hash_str = self.extract_hash(pdf_path)
        if not hash_str:
            return None
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            hash_file = Path(f.name)
            f.write(hash_str + '\n')
        
        try:
            cmd = [self.path, str(hash_file)]
            
            if wordlist:
                cmd.extend([f"--wordlist={wordlist}"])
            
            if max_time:
                cmd.extend([f"--max-run-time={max_time}"])
            
            if rules:
                cmd.extend([f"--rules={rules}"])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_time + 10 if max_time else None
            )
            
            show_cmd = [self.path, "--show", str(hash_file)]
            show_result = subprocess.run(
                show_cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if show_result.returncode == 0:
                output = show_result.stdout
                match = re.search(r':(.+?)$', output, re.MULTILINE)
                if match:
                    password = match.group(1).strip()
                    return password
            
            return None
        
        except subprocess.TimeoutExpired:
            logger.warning("John the Ripper timed out")
            return None
        except Exception as e:
            raise ExternalToolError("John the Ripper", str(e))
        finally:
            if hash_file.exists():
                hash_file.unlink()
    
    def benchmark(self) -> Dict[str, float]:
        """Run John benchmark for PDF formats"""
        self.require()
        
        cmd = [
            self.path,
            "--test",
            "--format=pdf"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            speeds = {}
            if result.returncode == 0:
                output = result.stdout
                
                speed_pattern = r'(\d+(?:\.\d+)?[KMG]?)\s+c/s'
                matches = re.findall(speed_pattern, output)
                
                if matches:
                    speed_str = matches[0]
                    speed = self._parse_speed(speed_str)
                    speeds['pdf'] = speed
            
            return speeds
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("John the Ripper", "Benchmark timed out")
        except Exception as e:
            raise ExternalToolError("John the Ripper", str(e))
    
    def _find_pdf2john(self) -> Optional[Path]:
        """Find pdf2john.py script"""
        if not self.path:
            return None
        
        john_dir = Path(self.path).parent
        
        search_paths = [
            john_dir / "pdf2john.py",
            john_dir / "pdf2john",
            john_dir.parent / "share" / "john" / "pdf2john.py",
            john_dir.parent / "run" / "pdf2john.py",
        ]
        
        for path in search_paths:
            if path.exists():
                return path
        
        import shutil
        pdf2john = shutil.which("pdf2john.py")
        if pdf2john:
            return Path(pdf2john)
        
        pdf2john = shutil.which("pdf2john")
        if pdf2john:
            return Path(pdf2john)
        
        return None
    
    def _parse_speed(self, speed_str: str) -> float:
        """Parse speed string to float (passwords/sec)"""
        speed_str = speed_str.strip()
        
        multipliers = {
            'K': 1000,
            'M': 1000000,
            'G': 1000000000,
        }
        
        for suffix, mult in multipliers.items():
            if speed_str.endswith(suffix):
                return float(speed_str[:-1]) * mult
        
        return float(speed_str)
    
    def get_info(self) -> Dict[str, Any]:
        """Get John the Ripper information"""
        pdf2john = self._find_pdf2john()
        
        return {
            "available": self.available,
            "version": self.version,
            "path": str(self.path) if self.path else None,
            "pdf2john_available": pdf2john is not None,
            "pdf2john_path": str(pdf2john) if pdf2john else None,
        }
