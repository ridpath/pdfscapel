"""Ghostscript integration for PDF rendering and manipulation"""

import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any

from pdfscalpel.core.dependencies import check_external_tool, require_dependency
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import ExternalToolError

logger = get_logger()


class GhostscriptIntegration:
    """Wrapper for Ghostscript operations"""
    
    def __init__(self):
        self.status = check_external_tool("ghostscript")
        self.available = self.status.available
        self.path = self.status.path
        self.version = self.status.version
    
    def require(self):
        """Raise error if Ghostscript not available"""
        require_dependency("tool:ghostscript", "Ghostscript operations")
    
    def render_page(
        self,
        pdf_path: Path,
        page_num: int,
        output_path: Path,
        resolution: int = 300,
        format: str = "png"
    ) -> bool:
        """Render PDF page to image"""
        self.require()
        
        device_map = {
            "png": "png16m",
            "jpg": "jpeg",
            "tiff": "tiff24nc",
        }
        device = device_map.get(format.lower(), "png16m")
        
        cmd = [
            self.path,
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            f"-sDEVICE={device}",
            f"-r{resolution}",
            f"-dFirstPage={page_num}",
            f"-dLastPage={page_num}",
            f"-sOutputFile={output_path}",
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
                logger.error(f"Ghostscript error: {result.stderr}")
                return False
            
            return output_path.exists()
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("Ghostscript", "Rendering timed out")
        except Exception as e:
            raise ExternalToolError("Ghostscript", str(e))
    
    def render_all_pages(
        self,
        pdf_path: Path,
        output_dir: Path,
        resolution: int = 300,
        format: str = "png"
    ) -> List[Path]:
        """Render all PDF pages to images"""
        self.require()
        
        device_map = {
            "png": "png16m",
            "jpg": "jpeg",
            "tiff": "tiff24nc",
        }
        device = device_map.get(format.lower(), "png16m")
        
        output_dir.mkdir(parents=True, exist_ok=True)
        output_pattern = output_dir / f"page_%03d.{format}"
        
        cmd = [
            self.path,
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            f"-sDEVICE={device}",
            f"-r{resolution}",
            f"-sOutputFile={output_pattern}",
            str(pdf_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                logger.error(f"Ghostscript error: {result.stderr}")
                return []
            
            rendered = sorted(output_dir.glob(f"page_*.{format}"))
            return rendered
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("Ghostscript", "Rendering timed out")
        except Exception as e:
            raise ExternalToolError("Ghostscript", str(e))
    
    def optimize_pdf(
        self,
        input_path: Path,
        output_path: Path,
        quality: str = "default"
    ) -> bool:
        """Optimize PDF using Ghostscript"""
        self.require()
        
        settings_map = {
            "screen": "/screen",
            "ebook": "/ebook",
            "printer": "/printer",
            "prepress": "/prepress",
            "default": "/default"
        }
        settings = settings_map.get(quality.lower(), "/default")
        
        cmd = [
            self.path,
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            "-sDEVICE=pdfwrite",
            f"-dPDFSETTINGS={settings}",
            "-dCompatibilityLevel=1.4",
            f"-sOutputFile={output_path}",
            str(input_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"Ghostscript error: {result.stderr}")
                return False
            
            return output_path.exists()
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("Ghostscript", "Optimization timed out")
        except Exception as e:
            raise ExternalToolError("Ghostscript", str(e))
    
    def extract_text(
        self,
        pdf_path: Path,
        output_path: Optional[Path] = None
    ) -> str:
        """Extract text from PDF using Ghostscript"""
        self.require()
        
        if output_path is None:
            output_path = Path(tempfile.mktemp(suffix=".txt"))
        
        cmd = [
            self.path,
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            "-sDEVICE=txtwrite",
            f"-sOutputFile={output_path}",
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
                logger.error(f"Ghostscript error: {result.stderr}")
                return ""
            
            if output_path.exists():
                text = output_path.read_text(encoding='utf-8', errors='ignore')
                if output_path.parent == Path(tempfile.gettempdir()):
                    output_path.unlink()
                return text
            
            return ""
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("Ghostscript", "Text extraction timed out")
        except Exception as e:
            raise ExternalToolError("Ghostscript", str(e))
    
    def get_info(self) -> Dict[str, Any]:
        """Get Ghostscript information"""
        return {
            "available": self.available,
            "version": self.version,
            "path": str(self.path) if self.path else None,
        }
