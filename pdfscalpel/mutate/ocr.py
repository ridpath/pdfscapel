"""OCR functionality for making PDFs searchable"""

from pathlib import Path
from typing import Optional

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.dependencies import require_dependency, check_python_package, check_external_tool
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError
from pdfscalpel.core.constants import DEFAULT_OCR_LANGUAGE, DEFAULT_OCR_JOBS

logger = get_logger()


class OCRError(PDFScalpelError):
    """OCR operation failed"""
    pass


def run_ocr(
    input_path: Path,
    output_path: Path,
    language: str = DEFAULT_OCR_LANGUAGE,
    jobs: int = DEFAULT_OCR_JOBS,
    deskew: bool = True,
    force_ocr: bool = False,
    skip_text: bool = True,
    optimize: bool = True,
    output_type: str = 'pdfa',
    progress_bar: bool = True,
) -> Path:
    """
    Run OCR on PDF to make it searchable
    
    Args:
        input_path: Input PDF file path
        output_path: Output PDF file path
        language: Tesseract language code (eng, spa, fra, deu, etc.)
        jobs: Number of CPU cores to use for OCR
        deskew: Apply deskewing to straighten pages
        force_ocr: Force OCR even if text already exists
        skip_text: Skip pages that already have text (unless force_ocr=True)
        optimize: Apply compression to reduce file size
        output_type: Output format ('pdfa', 'pdf', 'pdfa-1', 'pdfa-2', 'pdfa-3')
        progress_bar: Show progress bar during OCR
        
    Returns:
        Path to output PDF file
        
    Raises:
        DependencyMissingError: If ocrmypdf or tesseract is not installed
        OCRError: If OCR operation fails
    """
    import os
    
    tesseract_paths = [
        r'C:\Program Files\Tesseract-OCR',
        r'C:\Program Files (x86)\Tesseract-OCR',
        Path.home() / 'AppData' / 'Local' / 'Programs' / 'Tesseract-OCR'
    ]
    
    for path in tesseract_paths:
        path_str = str(path)
        if Path(path_str).exists() and path_str not in os.environ.get('PATH', ''):
            os.environ['PATH'] = path_str + os.pathsep + os.environ['PATH']
            logger.debug(f"Added {path_str} to PATH")
    
    require_dependency("py:ocrmypdf", "OCR")
    require_dependency("tool:tesseract", "OCR")
    
    try:
        import ocrmypdf
    except ImportError as e:
        raise DependencyMissingError(
            dependency="ocrmypdf",
            install_hint="Install ocrmypdf: pip install ocrmypdf>=15.0.0"
        )
    
    input_path = Path(input_path)
    output_path = Path(output_path)
    
    if not input_path.exists():
        raise OCRError(f"Input file not found: {input_path}")
    
    logger.info(f"Running OCR on {input_path.name}")
    logger.info(f"Language: {language}, CPU cores: {jobs}")
    logger.info(f"Deskew: {deskew}, Force OCR: {force_ocr}, Optimize: {optimize}")
    
    try:
        optimize_level = 1 if optimize else 0
        
        ocrmypdf.ocr(
            input_path,
            output_path,
            deskew=deskew,
            optimize=optimize_level,
            output_type=output_type,
            language=language,
            progress_bar=progress_bar,
            jobs=jobs,
            force_ocr=force_ocr,
            skip_text=skip_text,
        )
        
        logger.info(f"OCR complete: {output_path.name}")
        return output_path
        
    except ocrmypdf.exceptions.PriorOcrFoundError:
        logger.warning("PDF already contains text. Use force_ocr=True to OCR anyway.")
        raise OCRError(
            "PDF already contains text. Use --force-ocr to OCR anyway, or --skip-text to process only pages without text."
        )
    
    except ocrmypdf.exceptions.MissingDependencyError as e:
        logger.error(f"OCR dependency missing: {e}")
        raise DependencyMissingError(
            dependency="Tesseract OCR",
            install_hint=str(e)
        )
    
    except ocrmypdf.exceptions.InputFileError as e:
        logger.error(f"Invalid input PDF: {e}")
        raise OCRError(f"Invalid input PDF: {e}")
    
    except ocrmypdf.exceptions.EncryptedPdfError as e:
        logger.error("PDF is encrypted")
        raise OCRError("Cannot OCR encrypted PDF. Decrypt it first using 'pdfautopsy mutate decrypt'.")
    
    except ocrmypdf.exceptions.TesseractConfigError as e:
        logger.error(f"Tesseract configuration error: {e}")
        raise OCRError(f"Tesseract configuration error: {e}")
    
    except Exception as e:
        logger.error(f"OCR failed: {e}")
        raise OCRError(f"OCR operation failed: {e}")


def check_ocr_dependencies(verbose: bool = False) -> bool:
    """
    Check if OCR dependencies are available
    
    Args:
        verbose: Print detailed status
        
    Returns:
        True if all OCR dependencies are available
    """
    ocrmypdf_status = check_python_package("ocrmypdf")
    tesseract_status = check_external_tool("tesseract")
    
    if verbose:
        if ocrmypdf_status.available:
            version_str = f" ({ocrmypdf_status.version})" if ocrmypdf_status.version else ""
            logger.info(f"[OK] ocrmypdf{version_str}")
        else:
            logger.warning("[MISSING] ocrmypdf - Install: pip install ocrmypdf>=15.0.0")
        
        if tesseract_status.available:
            version_str = f" ({tesseract_status.version})" if tesseract_status.version else ""
            logger.info(f"[OK] Tesseract OCR{version_str}")
        else:
            logger.warning(f"[MISSING] Tesseract OCR - {tesseract_status.error}")
    
    return ocrmypdf_status.available and tesseract_status.available


def get_available_languages() -> list[str]:
    """
    Get list of available Tesseract language models
    
    Returns:
        List of available language codes
        
    Raises:
        DependencyMissingError: If tesseract is not installed
    """
    require_dependency("tool:tesseract", "language detection")
    
    import subprocess
    
    try:
        result = subprocess.run(
            ['tesseract', '--list-langs'],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            languages = [line.strip() for line in lines[1:] if line.strip()]
            return languages
        else:
            logger.warning("Could not list Tesseract languages")
            return []
            
    except Exception as e:
        logger.warning(f"Could not list Tesseract languages: {e}")
        return []
