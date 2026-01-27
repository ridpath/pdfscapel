"""
Watermark Template Generator

Generates watermarked PDFs with various watermark styles for testing
watermark detection and removal capabilities.
"""

from pathlib import Path
from typing import Optional, Tuple, List, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum
import io

try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    if TYPE_CHECKING:
        from reportlab.pdfgen import canvas

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError

logger = get_logger()


class WatermarkStyle(Enum):
    """Watermark style types"""
    TEXT_OVERLAY = "text_overlay"
    TEXT_DIAGONAL = "text_diagonal"
    TEXT_HEADER = "text_header"
    TEXT_FOOTER = "text_footer"
    IMAGE_OVERLAY = "image_overlay"
    VECTOR_PATTERN = "vector_pattern"
    TRANSPARENCY = "transparency"
    BACKGROUND = "background"
    GRID = "grid"


@dataclass
class WatermarkConfig:
    """Configuration for watermark generation"""
    text: str
    style: WatermarkStyle
    opacity: float = 0.3
    color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    font_size: int = 60
    rotation: int = 45
    position: Tuple[int, int] = (300, 400)
    repeat: bool = False
    repeat_spacing: Tuple[int, int] = (200, 200)


class WatermarkGenerator:
    """Generate watermarked PDFs with various styles"""
    
    def __init__(self):
        if not HAS_REPORTLAB:
            raise DependencyMissingError("reportlab", "watermark generation")
        if not HAS_PIKEPDF:
            raise DependencyMissingError("pikepdf", "watermark generation")
    
    def create_watermarked_pdf(
        self,
        output_path: Path,
        content: Optional[str] = None,
        config: Optional[WatermarkConfig] = None
    ) -> Path:
        """
        Create a watermarked PDF
        
        Args:
            output_path: Output PDF path
            content: Main PDF content text
            config: Watermark configuration
        
        Returns:
            Path to created PDF
        """
        if config is None:
            config = WatermarkConfig(
                text="CONFIDENTIAL",
                style=WatermarkStyle.TEXT_DIAGONAL
            )
        
        if content is None:
            content = """
This is a sample document with a watermark.

Watermarks are commonly used to:
- Protect intellectual property
- Mark documents as confidential or draft
- Brand documents with company logos
- Track document distribution

This document is watermarked for testing purposes.
"""
        
        logger.info(f"Creating watermarked PDF: {output_path} (style: {config.style.value})")
        
        if config.style == WatermarkStyle.TEXT_OVERLAY:
            return self._create_text_overlay(output_path, content, config)
        elif config.style == WatermarkStyle.TEXT_DIAGONAL:
            return self._create_text_diagonal(output_path, content, config)
        elif config.style == WatermarkStyle.TEXT_HEADER:
            return self._create_text_header(output_path, content, config)
        elif config.style == WatermarkStyle.TEXT_FOOTER:
            return self._create_text_footer(output_path, content, config)
        elif config.style == WatermarkStyle.TRANSPARENCY:
            return self._create_transparency_watermark(output_path, content, config)
        elif config.style == WatermarkStyle.BACKGROUND:
            return self._create_background_watermark(output_path, content, config)
        elif config.style == WatermarkStyle.GRID:
            return self._create_grid_watermark(output_path, content, config)
        else:
            raise PDFScalpelError(f"Unsupported watermark style: {config.style}")
    
    def _create_text_overlay(
        self,
        output_path: Path,
        content: str,
        config: WatermarkConfig
    ) -> Path:
        """Create simple text overlay watermark"""
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        self._draw_content(c, content)
        
        c.saveState()
        c.setFillColorRGB(*config.color, alpha=config.opacity)
        c.setFont("Helvetica-Bold", config.font_size)
        c.drawString(config.position[0], config.position[1], config.text)
        c.restoreState()
        
        c.save()
        output_path.write_bytes(buffer.getvalue())
        
        return output_path
    
    def _create_text_diagonal(
        self,
        output_path: Path,
        content: str,
        config: WatermarkConfig
    ) -> Path:
        """Create diagonal text watermark"""
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        self._draw_content(c, content)
        
        c.saveState()
        c.translate(letter[0] / 2, letter[1] / 2)
        c.rotate(config.rotation)
        c.setFillColorRGB(*config.color, alpha=config.opacity)
        c.setFont("Helvetica-Bold", config.font_size)
        c.drawCentredString(0, 0, config.text)
        c.restoreState()
        
        c.save()
        output_path.write_bytes(buffer.getvalue())
        
        return output_path
    
    def _create_text_header(
        self,
        output_path: Path,
        content: str,
        config: WatermarkConfig
    ) -> Path:
        """Create header watermark"""
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.saveState()
        c.setFillColorRGB(*config.color, alpha=config.opacity)
        c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(letter[0] / 2, letter[1] - 50, config.text)
        c.restoreState()
        
        self._draw_content(c, content, start_y=letter[1] - 100)
        
        c.save()
        output_path.write_bytes(buffer.getvalue())
        
        return output_path
    
    def _create_text_footer(
        self,
        output_path: Path,
        content: str,
        config: WatermarkConfig
    ) -> Path:
        """Create footer watermark"""
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        self._draw_content(c, content)
        
        c.saveState()
        c.setFillColorRGB(*config.color, alpha=config.opacity)
        c.setFont("Helvetica-Bold", 18)
        c.drawCentredString(letter[0] / 2, 30, config.text)
        c.restoreState()
        
        c.save()
        output_path.write_bytes(buffer.getvalue())
        
        return output_path
    
    def _create_transparency_watermark(
        self,
        output_path: Path,
        content: str,
        config: WatermarkConfig
    ) -> Path:
        """Create highly transparent watermark"""
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        self._draw_content(c, content)
        
        c.saveState()
        c.setFillColorRGB(*config.color, alpha=0.1)
        c.setFont("Helvetica-Bold", 100)
        c.translate(letter[0] / 2, letter[1] / 2)
        c.rotate(45)
        c.drawCentredString(0, 0, config.text)
        c.restoreState()
        
        c.save()
        output_path.write_bytes(buffer.getvalue())
        
        return output_path
    
    def _create_background_watermark(
        self,
        output_path: Path,
        content: str,
        config: WatermarkConfig
    ) -> Path:
        """Create background-layer watermark"""
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.saveState()
        c.setFillColorRGB(0.95, 0.95, 0.95)
        c.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
        c.restoreState()
        
        c.saveState()
        c.setFillColorRGB(*config.color, alpha=0.15)
        c.setFont("Helvetica-Bold", 80)
        c.translate(letter[0] / 2, letter[1] / 2)
        c.rotate(45)
        c.drawCentredString(0, 0, config.text)
        c.restoreState()
        
        self._draw_content(c, content)
        
        c.save()
        output_path.write_bytes(buffer.getvalue())
        
        return output_path
    
    def _create_grid_watermark(
        self,
        output_path: Path,
        content: str,
        config: WatermarkConfig
    ) -> Path:
        """Create repeating grid watermark"""
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        self._draw_content(c, content)
        
        c.saveState()
        c.setFillColorRGB(*config.color, alpha=0.2)
        c.setFont("Helvetica-Bold", 30)
        
        x_spacing = config.repeat_spacing[0]
        y_spacing = config.repeat_spacing[1]
        
        for x in range(50, int(letter[0]), x_spacing):
            for y in range(50, int(letter[1]), y_spacing):
                c.saveState()
                c.translate(x, y)
                c.rotate(config.rotation)
                c.drawCentredString(0, 0, config.text)
                c.restoreState()
        
        c.restoreState()
        
        c.save()
        output_path.write_bytes(buffer.getvalue())
        
        return output_path
    
    def _draw_content(
        self,
        c: "canvas.Canvas",
        content: str,
        start_y: float = None
    ):
        """Draw main content on canvas"""
        
        if start_y is None:
            start_y = letter[1] - 100
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, start_y, "Sample Document")
        
        c.setFont("Helvetica", 11)
        y = start_y - 40
        
        for line in content.strip().split('\n'):
            if y < 100:
                break
            c.drawString(100, y, line.strip())
            y -= 18
    
    def create_multi_style_samples(
        self,
        output_dir: Path,
        text: str = "SAMPLE"
    ) -> List[Path]:
        """
        Create sample PDFs with all watermark styles
        
        Args:
            output_dir: Directory to save samples
            text: Watermark text
        
        Returns:
            List of created PDF paths
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        
        styles = [
            WatermarkStyle.TEXT_OVERLAY,
            WatermarkStyle.TEXT_DIAGONAL,
            WatermarkStyle.TEXT_HEADER,
            WatermarkStyle.TEXT_FOOTER,
            WatermarkStyle.TRANSPARENCY,
            WatermarkStyle.BACKGROUND,
            WatermarkStyle.GRID,
        ]
        
        created_files = []
        
        for style in styles:
            output_path = output_dir / f"watermark_{style.value}.pdf"
            config = WatermarkConfig(text=text, style=style)
            
            logger.info(f"Creating sample: {style.value}")
            self.create_watermarked_pdf(output_path, config=config)
            created_files.append(output_path)
        
        logger.info(f"Created {len(created_files)} watermark samples in {output_dir}")
        
        return created_files


def create_watermarked_pdf(
    output_path: Path,
    watermark_text: str,
    style: str = "text_diagonal",
    content: Optional[str] = None,
    opacity: float = 0.3
) -> Path:
    """
    Convenience function to create watermarked PDF
    
    Args:
        output_path: Output PDF path
        watermark_text: Watermark text
        style: Watermark style (text_overlay, text_diagonal, etc.)
        content: Main PDF content
        opacity: Watermark opacity (0.0-1.0)
    
    Returns:
        Path to created PDF
    """
    generator = WatermarkGenerator()
    
    config = WatermarkConfig(
        text=watermark_text,
        style=WatermarkStyle(style),
        opacity=opacity
    )
    
    return generator.create_watermarked_pdf(output_path, content, config)


def create_watermark_samples(
    output_dir: Path,
    watermark_text: str = "CONFIDENTIAL"
) -> List[Path]:
    """
    Create sample watermarked PDFs with all styles
    
    Args:
        output_dir: Directory to save samples
        watermark_text: Watermark text
    
    Returns:
        List of created PDF paths
    """
    generator = WatermarkGenerator()
    return generator.create_multi_style_samples(output_dir, watermark_text)
