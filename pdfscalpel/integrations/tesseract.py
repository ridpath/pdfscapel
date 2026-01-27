"""Tesseract OCR integration"""

import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

from pdfscalpel.core.dependencies import check_external_tool, require_dependency
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import ExternalToolError

logger = get_logger()


class TesseractIntegration:
    """Wrapper for Tesseract OCR operations"""
    
    def __init__(self):
        self.status = check_external_tool("tesseract")
        self.available = self.status.available
        self.path = self.status.path
        self.version = self.version = self.status.version
    
    def require(self):
        """Raise error if Tesseract not available"""
        require_dependency("tool:tesseract", "Tesseract OCR operations")
    
    def ocr_image(
        self,
        image_path: Path,
        output_path: Optional[Path] = None,
        language: str = "eng",
        config: Optional[str] = None
    ) -> str:
        """Run OCR on an image"""
        self.require()
        
        if output_path is None:
            output_base = image_path.with_suffix('')
        else:
            output_base = output_path.with_suffix('')
        
        cmd = [
            self.path,
            str(image_path),
            str(output_base),
            "-l", language
        ]
        
        if config:
            cmd.extend(config.split())
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"Tesseract error: {result.stderr}")
                return ""
            
            output_txt = output_base.with_suffix('.txt')
            if output_txt.exists():
                text = output_txt.read_text(encoding='utf-8', errors='ignore')
                if output_path is None:
                    output_txt.unlink()
                return text
            
            return ""
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("Tesseract", "OCR timed out")
        except Exception as e:
            raise ExternalToolError("Tesseract", str(e))
    
    def get_languages(self) -> List[str]:
        """Get available Tesseract languages"""
        self.require()
        
        cmd = [
            self.path,
            "--list-langs"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                logger.error(f"Tesseract error: {result.stderr}")
                return []
            
            lines = result.stdout.strip().split('\n')
            
            languages = []
            for line in lines[1:]:
                lang = line.strip()
                if lang:
                    languages.append(lang)
            
            return languages
        
        except subprocess.TimeoutExpired:
            raise ExternalToolError("Tesseract", "Language list timed out")
        except Exception as e:
            raise ExternalToolError("Tesseract", str(e))
    
    def ocr_pdf(
        self,
        pdf_path: Path,
        output_path: Path,
        language: str = "eng",
        dpi: int = 300
    ) -> bool:
        """Run OCR on PDF (requires ocrmypdf)"""
        try:
            import ocrmypdf
            
            ocrmypdf.ocr(
                input_file=pdf_path,
                output_file=output_path,
                language=language,
                deskew=True,
                optimize=1,
                jobs=4,
                progress_bar=False
            )
            
            return output_path.exists()
        
        except ImportError:
            logger.error("ocrmypdf package required for PDF OCR")
            return False
        except Exception as e:
            logger.error(f"OCR failed: {e}")
            return False
    
    def get_info(self) -> Dict[str, Any]:
        """Get Tesseract information"""
        languages = self.get_languages() if self.available else []
        
        return {
            "available": self.available,
            "version": self.version,
            "path": str(self.path) if self.path else None,
            "languages": languages,
        }
