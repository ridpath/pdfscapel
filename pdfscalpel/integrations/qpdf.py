"""QPDF integration for PDF structure manipulation and repair"""

import subprocess
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

from pdfscalpel.core.dependencies import check_external_tool, require_dependency
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import ExternalToolError

logger = get_logger()


class QPDFIntegration:
    """Wrapper for QPDF operations"""
    
    def __init__(self):
        self.status = check_external_tool("qpdf")
        self.available = self.status.available
        self.path = self.status.path
        self.version = self.status.version
    
    def require(self):
        """Raise error if QPDF not available"""
        require_dependency("tool:qpdf", "QPDF operations")
    
    def check_pdf(self, pdf_path: Path) -> Dict[str, Any]:
        """Check PDF structure and report errors"""
        self.require()
        
        cmd = [
            self.path,
            "--check",
            str(pdf_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "valid": result.returncode == 0,
                "errors": result.stderr if result.returncode != 0 else "",
                "warnings": result.stdout,
            }
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "Check operation timed out")
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def repair_pdf(
        self,
        input_path: Path,
        output_path: Path,
        password: Optional[str] = None
    ) -> bool:
        """Repair damaged PDF"""
        self.require()
        
        cmd = [
            self.path,
            str(input_path),
            str(output_path)
        ]
        
        if password:
            cmd.extend(["--password", password])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"QPDF repair error: {result.stderr}")
                return False
            
            return output_path.exists()
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "Repair operation timed out")
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def linearize_pdf(
        self,
        input_path: Path,
        output_path: Path
    ) -> bool:
        """Linearize PDF for fast web viewing"""
        self.require()
        
        cmd = [
            self.path,
            "--linearize",
            str(input_path),
            str(output_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"QPDF linearization error: {result.stderr}")
                return False
            
            return output_path.exists()
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "Linearization timed out")
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def decrypt_pdf(
        self,
        input_path: Path,
        output_path: Path,
        password: str
    ) -> bool:
        """Decrypt PDF with password"""
        self.require()
        
        cmd = [
            self.path,
            "--decrypt",
            "--password",
            password,
            str(input_path),
            str(output_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"QPDF decryption error: {result.stderr}")
                return False
            
            return output_path.exists()
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "Decryption timed out")
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def get_json_info(self, pdf_path: Path) -> Dict[str, Any]:
        """Get PDF structure as JSON"""
        self.require()
        
        cmd = [
            self.path,
            "--json",
            str(pdf_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"QPDF JSON error: {result.stderr}")
                return {}
            
            return json.loads(result.stdout)
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "JSON extraction timed out")
        except json.JSONDecodeError as e:
            logger.error(f"QPDF JSON decode error: {e}")
            return {}
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def extract_attachments(
        self,
        pdf_path: Path,
        output_dir: Path
    ) -> List[Path]:
        """Extract embedded files using QPDF"""
        self.require()
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            self.path,
            "--show-attachment",
            "--",
            str(pdf_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            attachments = []
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        attachment_name = line.strip()
                        
                        output_path = output_dir / attachment_name
                        extract_cmd = [
                            self.path,
                            "--show-attachment",
                            attachment_name,
                            "--",
                            str(pdf_path)
                        ]
                        
                        extract_result = subprocess.run(
                            extract_cmd,
                            capture_output=True,
                            timeout=30
                        )
                        
                        if extract_result.returncode == 0:
                            output_path.write_bytes(extract_result.stdout)
                            attachments.append(output_path)
            
            return attachments
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "Attachment extraction timed out")
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def compress_streams(
        self,
        input_path: Path,
        output_path: Path
    ) -> bool:
        """Compress PDF streams"""
        self.require()
        
        cmd = [
            self.path,
            "--compress-streams=y",
            str(input_path),
            str(output_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"QPDF compression error: {result.stderr}")
                return False
            
            return output_path.exists()
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "Compression timed out")
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def normalize_content(
        self,
        input_path: Path,
        output_path: Path
    ) -> bool:
        """Normalize PDF content (QDF mode)"""
        self.require()
        
        cmd = [
            self.path,
            "--qdf",
            str(input_path),
            str(output_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"QPDF normalization error: {result.stderr}")
                return False
            
            return output_path.exists()
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("QPDF", "Normalization timed out")
        except Exception as e:
            raise ExternalToolError("QPDF", str(e))
    
    def get_info(self) -> Dict[str, Any]:
        """Get QPDF information"""
        return {
            "available": self.available,
            "version": self.version,
            "path": str(self.path) if self.path else None,
        }
