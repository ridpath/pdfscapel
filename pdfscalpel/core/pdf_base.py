"""Base PDF operations wrapper"""

from pathlib import Path
from typing import Optional, List, Dict, Any
import tempfile
import shutil

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.exceptions import (
    PDFOpenError,
    PDFEncryptedError,
    PDFCorruptedError,
    PDFNotFoundError,
    DependencyMissingError,
)
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class PDFDocument:
    """Wrapper around pikepdf.Pdf with enhanced error handling"""
    
    def __init__(self, path: Path, pdf: 'pikepdf.Pdf', password: Optional[str] = None):
        if pikepdf is None:
            raise DependencyMissingError(
                dependency="pikepdf",
                install_hint="Install with: pip install pikepdf>=8.0.0"
            )
        
        self.path = Path(path)
        self.pdf = pdf
        self.password = password
        self._temp_dir: Optional[Path] = None
    
    def __enter__(self) -> 'PDFDocument':
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup on exit"""
        self.close()
    
    @classmethod
    def open(cls, path: Path, password: Optional[str] = None) -> 'PDFDocument':
        """
        Open a PDF file with error handling
        
        Args:
            path: Path to PDF file
            password: Optional password for encrypted PDFs
        
        Returns:
            PDFDocument instance
        
        Raises:
            PDFNotFoundError: If file doesn't exist
            PDFEncryptedError: If PDF is encrypted and no/wrong password
            PDFCorruptedError: If PDF is corrupted
            PDFOpenError: For other opening errors
        """
        if pikepdf is None:
            raise DependencyMissingError(
                dependency="pikepdf",
                install_hint="Install with: pip install pikepdf>=8.0.0"
            )
        
        path = Path(path)
        
        if not path.exists():
            raise PDFNotFoundError(f"PDF file not found: {path}")
        
        try:
            pdf = pikepdf.open(path, password=password if password is not None else "")
            logger.debug(f"Opened PDF: {path}")
            return cls(path, pdf, password)
        
        except pikepdf.PasswordError as e:
            encryption_info = cls._detect_encryption(path)
            raise PDFEncryptedError(
                message=f"PDF is encrypted: {path}",
                algorithm=encryption_info.get("algorithm"),
                details=encryption_info,
            ) from e
        
        except pikepdf.PdfError as e:
            error_str = str(e).lower()
            if "damaged" in error_str or "corrupt" in error_str:
                raise PDFCorruptedError(
                    message=f"PDF is corrupted: {path}",
                    details={"error": str(e)},
                ) from e
            else:
                raise PDFOpenError(f"Failed to open PDF: {e}") from e
        
        except Exception as e:
            raise PDFOpenError(f"Unexpected error opening PDF: {e}") from e
    
    @staticmethod
    def _detect_encryption(path: Path) -> Dict[str, Any]:
        """Attempt to detect encryption details without opening"""
        try:
            with open(path, 'rb') as f:
                content = f.read(4096)
                
                info = {
                    "encrypted": b"/Encrypt" in content,
                    "algorithm": None,
                }
                
                if b"/V 1" in content:
                    info["algorithm"] = "RC4-40"
                elif b"/V 2" in content:
                    info["algorithm"] = "RC4-128"
                elif b"/V 4" in content:
                    info["algorithm"] = "AES-128 or RC4-128"
                elif b"/V 5" in content:
                    info["algorithm"] = "AES-256"
                
                return info
        except Exception:
            return {"encrypted": True}
    
    def close(self):
        """Close PDF and cleanup resources"""
        if self.pdf:
            self.pdf.close()
            logger.debug(f"Closed PDF: {self.path}")
        
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
    
    def save(self, output_path: Path, **kwargs):
        """
        Save PDF to file
        
        Args:
            output_path: Destination path
            **kwargs: Additional arguments for pikepdf.Pdf.save()
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.pdf.save(output_path, **kwargs)
        logger.info(f"Saved PDF: {output_path}")
    
    def get_temp_dir(self) -> Path:
        """Get or create temporary directory for this PDF"""
        if self._temp_dir is None:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="pdfautopsy_"))
        return self._temp_dir
    
    @property
    def num_pages(self) -> int:
        """Get number of pages"""
        return len(self.pdf.pages)
    
    def get_pages(self) -> List[Any]:
        """Get all pages"""
        return list(self.pdf.pages)
    
    def get_page(self, index: int) -> Any:
        """Get a specific page (0-indexed)"""
        return self.pdf.pages[index]
    
    @property
    def is_encrypted(self) -> bool:
        """Check if PDF is encrypted"""
        return self.pdf.is_encrypted if hasattr(self.pdf, 'is_encrypted') else False
    
    @property
    def metadata(self) -> Dict[str, Any]:
        """Get PDF metadata"""
        try:
            with self.pdf.open_metadata() as meta:
                return dict(meta)
        except Exception:
            return {}
    
    def get_info_dict(self) -> Dict[str, Any]:
        """Get Info dictionary metadata"""
        try:
            if hasattr(self.pdf, 'docinfo'):
                info = {}
                for key, value in self.pdf.docinfo.items():
                    try:
                        info[str(key)] = str(value)
                    except Exception:
                        info[str(key)] = repr(value)
                return info
        except Exception:
            pass
        return {}
    
    def get_objects(self) -> List[Any]:
        """Get all PDF objects"""
        objects = []
        try:
            for obj_id in self.pdf.objects:
                try:
                    obj = self.pdf.get_object(obj_id)
                    objects.append(obj)
                except Exception:
                    pass
        except Exception:
            pass
        return objects
    
    def get_object(self, obj_id: tuple) -> Optional[Any]:
        """Get a specific object by ID"""
        try:
            return self.pdf.get_object(obj_id)
        except Exception:
            return None
    
    @property
    def trailer(self) -> Any:
        """Get PDF trailer"""
        return self.pdf.trailer
    
    @property
    def root(self) -> Any:
        """Get PDF root object"""
        return self.pdf.Root
    
    def check_encryption(self) -> Optional[Dict[str, Any]]:
        """Get encryption information"""
        if not self.is_encrypted:
            return None
        
        try:
            encryption_dict = self.pdf.trailer.get('/Encrypt')
            if encryption_dict is None:
                return None
            
            info = {}
            
            if '/V' in encryption_dict:
                v = int(encryption_dict['/V'])
                info['version'] = v
                
                if v == 1:
                    info['algorithm'] = 'RC4-40'
                elif v == 2:
                    info['algorithm'] = 'RC4-128'
                elif v == 4:
                    info['algorithm'] = 'AES-128 or RC4-128'
                elif v == 5:
                    info['algorithm'] = 'AES-256'
            
            if '/R' in encryption_dict:
                info['revision'] = int(encryption_dict['/R'])
            
            if '/Length' in encryption_dict:
                info['key_length'] = int(encryption_dict['/Length'])
            
            if '/P' in encryption_dict:
                info['permissions'] = int(encryption_dict['/P'])
            
            return info
        
        except Exception as e:
            logger.debug(f"Failed to extract encryption info: {e}")
            return {"error": str(e)}
    
    def __repr__(self) -> str:
        return f"PDFDocument(path={self.path}, pages={self.num_pages}, encrypted={self.is_encrypted})"
