"""Hashcat integration for GPU-accelerated PDF password cracking"""

import subprocess
import tempfile
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

from pdfscalpel.core.dependencies import check_external_tool, require_dependency
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import ExternalToolError

logger = get_logger()


class HashcatIntegration:
    """Wrapper for Hashcat GPU-accelerated cracking"""
    
    HASH_MODES = {
        'pdf_1.4_1.6': 10500,
        'pdf_1.7_level3': 10600,
        'pdf_1.7_level8': 10700,
    }
    
    def __init__(self):
        self.status = check_external_tool("hashcat")
        self.available = self.status.available
        self.path = self.status.path
        self.version = self.status.version
        self._gpu_available = None
    
    def require(self):
        """Raise error if Hashcat not available"""
        require_dependency("tool:hashcat", "Hashcat operations")
    
    def check_gpu(self) -> bool:
        """Check if GPU is available for Hashcat"""
        if self._gpu_available is not None:
            return self._gpu_available
        
        self.require()
        
        cmd = [
            self.path,
            "-I"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout
                self._gpu_available = 'OpenCL' in output or 'CUDA' in output
            else:
                self._gpu_available = False
            
            return self._gpu_available
        
        except Exception as e:
            logger.warning(f"GPU check failed: {e}")
            self._gpu_available = False
            return False
    
    def extract_hash(
        self,
        pdf_path: Path,
        hash_mode: str = 'auto'
    ) -> Optional[Dict[str, Any]]:
        """Extract hash from PDF for Hashcat"""
        try:
            import pikepdf
            
            with pikepdf.open(pdf_path) as pdf:
                if not pdf.is_encrypted:
                    return None
                
                encryption_dict = pdf.trailer.get('/Encrypt')
                if not encryption_dict:
                    return None
                
                r_value = encryption_dict.get('/R', 0)
                v_value = encryption_dict.get('/V', 0)
                
                if hash_mode == 'auto':
                    if r_value in (2, 3, 4):
                        mode_key = 'pdf_1.4_1.6'
                    elif r_value == 5:
                        mode_key = 'pdf_1.7_level3'
                    elif r_value == 6:
                        mode_key = 'pdf_1.7_level8'
                    else:
                        logger.error(f"Unsupported R value: {r_value}")
                        return None
                else:
                    mode_key = hash_mode
                
                hash_mode_num = self.HASH_MODES.get(mode_key)
                if not hash_mode_num:
                    logger.error(f"Unknown hash mode: {mode_key}")
                    return None
                
                o_string = encryption_dict.get('/O', b'')
                u_string = encryption_dict.get('/U', b'')
                p_value = encryption_dict.get('/P', 0)
                
                if isinstance(o_string, bytes):
                    o_hex = o_string.hex()
                else:
                    o_hex = str(o_string).encode().hex()
                
                if isinstance(u_string, bytes):
                    u_hex = u_string.hex()
                else:
                    u_hex = str(u_string).encode().hex()
                
                hash_string = f"$pdf${v_value}*{r_value}*128*{p_value}*{o_hex}*{u_hex}"
                
                return {
                    'hash': hash_string,
                    'mode': hash_mode_num,
                    'mode_name': mode_key,
                    'r_value': r_value,
                    'v_value': v_value,
                }
        
        except ImportError:
            logger.error("pikepdf required for hash extraction")
            return None
        except Exception as e:
            logger.error(f"Hash extraction failed: {e}")
            return None
    
    def crack_password(
        self,
        pdf_path: Path,
        wordlist: Optional[Path] = None,
        max_time: Optional[int] = None,
        attack_mode: int = 0,
        custom_charset: Optional[str] = None
    ) -> Optional[str]:
        """Crack PDF password using Hashcat"""
        self.require()
        
        hash_info = self.extract_hash(pdf_path)
        if not hash_info:
            logger.error("Could not extract hash")
            return None
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            hash_file = Path(f.name)
            f.write(hash_info['hash'] + '\n')
        
        potfile = Path(tempfile.gettempdir()) / f"hashcat_{hash_file.stem}.pot"
        
        try:
            cmd = [
                self.path,
                "-m", str(hash_info['mode']),
                "-a", str(attack_mode),
                "--potfile-path", str(potfile),
                "--quiet"
            ]
            
            if max_time:
                cmd.extend(["--runtime", str(max_time)])
            
            if self.check_gpu():
                cmd.extend(["-O"])
            
            cmd.append(str(hash_file))
            
            if attack_mode == 0:
                if not wordlist:
                    logger.error("Wordlist required for dictionary attack")
                    return None
                cmd.append(str(wordlist))
            elif attack_mode == 3:
                if not custom_charset:
                    custom_charset = "?a?a?a?a?a?a"
                cmd.append(custom_charset)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_time + 10 if max_time else None
            )
            
            if potfile.exists():
                pot_content = potfile.read_text()
                
                match = re.search(r':(.+?)$', pot_content, re.MULTILINE)
                if match:
                    password = match.group(1).strip()
                    return password
            
            return None
        
        except subprocess.TimeoutExpired:
            logger.warning("Hashcat timed out")
            return None
        except Exception as e:
            raise ExternalToolError("Hashcat", str(e))
        finally:
            if hash_file.exists():
                hash_file.unlink()
            if potfile.exists():
                potfile.unlink()
    
    def benchmark(self) -> Dict[str, float]:
        """Run Hashcat benchmark for PDF formats"""
        self.require()
        
        speeds = {}
        
        for mode_name, mode_num in self.HASH_MODES.items():
            cmd = [
                self.path,
                "-m", str(mode_num),
                "-b",
                "--quiet"
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    output = result.stdout
                    
                    speed_pattern = r'Speed\.#\d+\.*:\s+(\d+(?:\.\d+)?)\s*([kMGT]?)H/s'
                    matches = re.findall(speed_pattern, output)
                    
                    if matches:
                        speed_str, unit = matches[0]
                        speed = self._parse_speed(speed_str, unit)
                        speeds[mode_name] = speed
            
            except subprocess.TimeoutExpired:
                logger.warning(f"Benchmark for {mode_name} timed out")
            except Exception as e:
                logger.warning(f"Benchmark for {mode_name} failed: {e}")
        
        return speeds
    
    def _parse_speed(self, speed_str: str, unit: str) -> float:
        """Parse speed string to float (hashes/sec)"""
        speed = float(speed_str)
        
        multipliers = {
            'k': 1000,
            'M': 1000000,
            'G': 1000000000,
            'T': 1000000000000,
        }
        
        if unit in multipliers:
            speed *= multipliers[unit]
        
        return speed
    
    def get_info(self) -> Dict[str, Any]:
        """Get Hashcat information"""
        return {
            "available": self.available,
            "version": self.version,
            "path": str(self.path) if self.path else None,
            "gpu_available": self.check_gpu() if self.available else False,
            "supported_modes": list(self.HASH_MODES.keys()),
        }
