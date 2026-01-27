"""PDF optimization operations"""

from pathlib import Path
from typing import Optional, Dict, Any
import subprocess
import shutil

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import (
    PDFScalpelError,
    DependencyMissingError,
)
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class OptimizationResult:
    """Results from PDF optimization"""
    
    def __init__(
        self,
        original_size: int,
        optimized_size: int,
        compression_ratio: float,
        operations_performed: list,
    ):
        self.original_size = original_size
        self.optimized_size = optimized_size
        self.compression_ratio = compression_ratio
        self.operations_performed = operations_performed
    
    @property
    def size_reduction(self) -> int:
        """Size reduction in bytes"""
        return self.original_size - self.optimized_size
    
    @property
    def size_reduction_percent(self) -> float:
        """Size reduction as percentage"""
        if self.original_size == 0:
            return 0.0
        return (self.size_reduction / self.original_size) * 100
    
    def __repr__(self):
        return (
            f"OptimizationResult("
            f"original={self.original_size}, "
            f"optimized={self.optimized_size}, "
            f"reduction={self.size_reduction_percent:.1f}%)"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'original_size': self.original_size,
            'optimized_size': self.optimized_size,
            'size_reduction': self.size_reduction,
            'size_reduction_percent': round(self.size_reduction_percent, 2),
            'compression_ratio': round(self.compression_ratio, 2),
            'operations_performed': self.operations_performed,
        }


def compress_pdf(
    input_path: Path,
    output_path: Path,
    compression_level: str = 'balanced',
) -> OptimizationResult:
    """
    Compress PDF using pikepdf
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        compression_level: 'maximum', 'balanced', or 'fast'
    
    Returns:
        OptimizationResult object
    
    Raises:
        PDFScalpelError: If compression fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    if compression_level not in ['maximum', 'balanced', 'fast']:
        raise PDFScalpelError("compression_level must be 'maximum', 'balanced', or 'fast'")
    
    logger.info(f"Compressing PDF: {input_path} (level: {compression_level})")
    
    try:
        original_size = input_path.stat().st_size
        operations = []
        
        save_options = {
            'compress_streams': True,
            'object_stream_mode': pikepdf.ObjectStreamMode.generate,
        }
        
        if compression_level == 'maximum':
            save_options.update({
                'stream_decode_level': pikepdf.StreamDecodeLevel.all,
                'recompress_flate': True,
            })
            operations.append('stream_recompression')
            operations.append('object_streams')
        elif compression_level == 'balanced':
            save_options.update({
                'stream_decode_level': pikepdf.StreamDecodeLevel.generalized,
            })
            operations.append('stream_compression')
            operations.append('object_streams')
        else:
            operations.append('basic_compression')
        
        with pikepdf.Pdf.open(input_path) as pdf:
            pdf.save(output_path, **save_options)
        
        optimized_size = output_path.stat().st_size
        compression_ratio = optimized_size / original_size if original_size > 0 else 1.0
        
        result = OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            compression_ratio=compression_ratio,
            operations_performed=operations,
        )
        
        logger.info(
            f"Compressed {input_path.name}: "
            f"{original_size:,} -> {optimized_size:,} bytes "
            f"({result.size_reduction_percent:.1f}% reduction)"
        )
        
        return result
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to compress PDF: {e}") from e


def remove_unused_objects(
    input_path: Path,
    output_path: Path,
) -> OptimizationResult:
    """
    Remove unused objects from PDF
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
    
    Returns:
        OptimizationResult object
    
    Raises:
        PDFScalpelError: If cleanup fails
    """
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Removing unused objects from {input_path}")
    
    try:
        original_size = input_path.stat().st_size
        
        with pikepdf.Pdf.open(input_path) as pdf:
            original_objects = len(list(pdf.objects))
            
            pdf.remove_unreferenced_resources()
            
            final_objects = len(list(pdf.objects))
            removed_objects = original_objects - final_objects
            
            pdf.save(
                output_path,
                compress_streams=True,
                object_stream_mode=pikepdf.ObjectStreamMode.generate,
            )
        
        optimized_size = output_path.stat().st_size
        compression_ratio = optimized_size / original_size if original_size > 0 else 1.0
        
        operations = [f'removed_{removed_objects}_unused_objects']
        
        result = OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            compression_ratio=compression_ratio,
            operations_performed=operations,
        )
        
        logger.info(
            f"Removed {removed_objects} objects, "
            f"size reduced by {result.size_reduction_percent:.1f}%"
        )
        
        return result
    
    except PDFScalpelError:
        raise
    except Exception as e:
        raise PDFScalpelError(f"Failed to remove unused objects: {e}") from e


def linearize_pdf(
    input_path: Path,
    output_path: Path,
    use_qpdf: bool = True,
) -> Path:
    """
    Linearize PDF for fast web viewing (using QPDF if available)
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        use_qpdf: Use QPDF tool if available (recommended)
    
    Returns:
        Path to output PDF
    
    Raises:
        PDFScalpelError: If linearization fails
    
    Note:
        Linearization optimizes PDFs for streaming/web viewing.
        QPDF does this better than pikepdf.
    """
    if use_qpdf and shutil.which('qpdf'):
        logger.info(f"Linearizing PDF with QPDF: {input_path}")
        
        try:
            result = subprocess.run(
                [
                    'qpdf',
                    '--linearize',
                    str(input_path),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            
            logger.info(f"Successfully linearized with QPDF: {output_path}")
            return output_path
        
        except subprocess.CalledProcessError as e:
            logger.warning(f"QPDF linearization failed: {e.stderr}")
            logger.info("Falling back to pikepdf linearization")
    
    if pikepdf is None:
        raise DependencyMissingError(
            dependency="pikepdf",
            install_hint="Install with: pip install pikepdf>=8.0.0"
        )
    
    logger.info(f"Linearizing PDF with pikepdf: {input_path}")
    
    try:
        with pikepdf.Pdf.open(input_path) as pdf:
            pdf.save(
                output_path,
                linearize=True,
                compress_streams=True,
            )
        
        logger.info(f"Successfully linearized with pikepdf: {output_path}")
        return output_path
    
    except Exception as e:
        raise PDFScalpelError(f"Failed to linearize PDF: {e}") from e


def optimize_pdf(
    input_path: Path,
    output_path: Path,
    level: str = 'balanced',
    remove_unused: bool = True,
    linearize: bool = False,
) -> OptimizationResult:
    """
    Comprehensive PDF optimization
    
    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        level: Compression level ('maximum', 'balanced', 'fast')
        remove_unused: Remove unused objects
        linearize: Linearize for web viewing
    
    Returns:
        OptimizationResult object
    
    Raises:
        PDFScalpelError: If optimization fails
    """
    logger.info(f"Optimizing PDF: {input_path}")
    
    try:
        original_size = input_path.stat().st_size
        temp_path = output_path.with_suffix('.tmp.pdf')
        current_input = input_path
        operations = []
        
        if remove_unused:
            logger.debug("Removing unused objects...")
            result = remove_unused_objects(current_input, temp_path)
            operations.extend(result.operations_performed)
            current_input = temp_path
            temp_path = output_path.with_suffix('.tmp2.pdf')
        
        logger.debug("Compressing...")
        result = compress_pdf(current_input, temp_path, compression_level=level)
        operations.extend(result.operations_performed)
        current_input = temp_path
        
        if linearize:
            logger.debug("Linearizing...")
            linearize_pdf(current_input, output_path)
            operations.append('linearization')
        else:
            if current_input != output_path:
                shutil.move(str(current_input), str(output_path))
        
        for temp_file in [
            output_path.with_suffix('.tmp.pdf'),
            output_path.with_suffix('.tmp2.pdf'),
        ]:
            if temp_file.exists():
                temp_file.unlink()
        
        optimized_size = output_path.stat().st_size
        compression_ratio = optimized_size / original_size if original_size > 0 else 1.0
        
        final_result = OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            compression_ratio=compression_ratio,
            operations_performed=operations,
        )
        
        logger.info(
            f"Optimization complete: "
            f"{original_size:,} -> {optimized_size:,} bytes "
            f"({final_result.size_reduction_percent:.1f}% reduction)"
        )
        
        return final_result
    
    except PDFScalpelError:
        raise
    except Exception as e:
        for temp_file in [
            output_path.with_suffix('.tmp.pdf'),
            output_path.with_suffix('.tmp2.pdf'),
        ]:
            if temp_file.exists():
                temp_file.unlink()
        raise PDFScalpelError(f"Failed to optimize PDF: {e}") from e


def check_qpdf_available() -> bool:
    """Check if QPDF is available"""
    return shutil.which('qpdf') is not None
