"""
Polyglot PDF Generator

Creates polyglot files that are valid in multiple formats simultaneously.
Useful for CTF challenges, format confusion attacks, and parser testing.
"""

from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass
import struct
import zlib
import io

try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError

logger = get_logger()


@dataclass
class PolyglotValidation:
    """Validation results for polyglot files"""
    is_valid_pdf: bool
    is_valid_secondary: bool
    secondary_format: str
    pdf_readable: bool
    secondary_readable: bool
    warnings: List[str]
    notes: List[str]


class PolyglotGenerator:
    """Generate polyglot files combining PDF with other formats"""
    
    def __init__(self):
        if not HAS_REPORTLAB:
            raise DependencyMissingError("reportlab", "polyglot generation")
        if not HAS_PIKEPDF:
            raise DependencyMissingError("pikepdf", "polyglot generation")
    
    def create_pdf_zip_polyglot(
        self,
        output_path: Path,
        pdf_content: Optional[str] = None,
        zip_files: Optional[List[Tuple[str, bytes]]] = None,
        method: str = "append"
    ) -> PolyglotValidation:
        """
        Create a PDF+ZIP polyglot file
        
        Args:
            output_path: Output file path
            pdf_content: Text content for PDF (default: "PDF+ZIP Polyglot")
            zip_files: List of (filename, content) tuples to include in ZIP
            method: "append" (ZIP after PDF) or "prepend" (PDF comment before ZIP)
        
        Returns:
            PolyglotValidation with validation results
        
        The file will be valid as both PDF and ZIP simultaneously.
        """
        logger.info(f"Creating PDF+ZIP polyglot: {output_path} (method: {method})")
        
        if pdf_content is None:
            pdf_content = "PDF+ZIP Polyglot\n\nThis file is both a valid PDF and a valid ZIP archive."
        
        if zip_files is None:
            zip_files = [
                ("readme.txt", b"This is embedded in a PDF+ZIP polyglot!\n"),
                ("flag.txt", b"CTF{polyglot_files_are_fun}\n")
            ]
        
        if method == "append":
            return self._create_pdf_zip_append(output_path, pdf_content, zip_files)
        elif method == "prepend":
            return self._create_pdf_zip_prepend(output_path, pdf_content, zip_files)
        else:
            raise ValueError(f"Unknown method: {method}")
    
    def _create_pdf_zip_append(
        self,
        output_path: Path,
        pdf_content: str,
        zip_files: List[Tuple[str, bytes]]
    ) -> PolyglotValidation:
        """Append ZIP data after PDF EOF marker"""
        
        pdf_buffer = io.BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "PDF+ZIP Polyglot")
        c.setFont("Helvetica", 12)
        
        lines = pdf_content.split('\n')
        y = 700
        for line in lines:
            c.drawString(100, y, line)
            y -= 20
            if y < 100:
                c.showPage()
                y = 750
        
        c.save()
        pdf_data = pdf_buffer.getvalue()
        
        zip_buffer = io.BytesIO()
        self._write_zip_archive(zip_buffer, zip_files)
        zip_data = zip_buffer.getvalue()
        
        with open(output_path, 'wb') as f:
            f.write(pdf_data)
            f.write(zip_data)
        
        validation = self._validate_polyglot(output_path, "zip")
        
        if validation.is_valid_pdf and validation.is_valid_secondary:
            logger.info(f"Successfully created PDF+ZIP polyglot: {output_path}")
        else:
            logger.warning(f"Polyglot validation incomplete: PDF={validation.is_valid_pdf}, ZIP={validation.is_valid_secondary}")
        
        return validation
    
    def _create_pdf_zip_prepend(
        self,
        output_path: Path,
        pdf_content: str,
        zip_files: List[Tuple[str, bytes]]
    ) -> PolyglotValidation:
        """
        Create ZIP with PDF as comment (experimental)
        
        This method embeds a PDF inside a ZIP comment field.
        Less reliable but more challenging for CTF.
        """
        
        zip_buffer = io.BytesIO()
        self._write_zip_archive(zip_buffer, zip_files)
        zip_data = zip_buffer.getvalue()
        
        pdf_buffer = io.BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=letter)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "ZIP+PDF Polyglot (Experimental)")
        c.setFont("Helvetica", 12)
        
        lines = pdf_content.split('\n')
        y = 700
        for line in lines:
            c.drawString(100, y, line)
            y -= 20
        
        c.save()
        pdf_data = pdf_buffer.getvalue()
        
        combined = zip_data + pdf_data
        
        with open(output_path, 'wb') as f:
            f.write(combined)
        
        validation = self._validate_polyglot(output_path, "zip")
        validation.warnings.append("Prepend method is experimental and may not work with all readers")
        
        return validation
    
    def _write_zip_archive(self, buffer: io.BytesIO, files: List[Tuple[str, bytes]]):
        """Write a minimal ZIP archive"""
        import zipfile
        
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filename, content in files:
                zf.writestr(filename, content)
    
    def create_pdf_html_polyglot(
        self,
        output_path: Path,
        pdf_content: Optional[str] = None,
        html_content: Optional[str] = None
    ) -> PolyglotValidation:
        """
        Create a PDF+HTML polyglot file
        
        Args:
            output_path: Output file path
            pdf_content: Text content for PDF
            html_content: HTML content to embed
        
        Returns:
            PolyglotValidation with validation results
        
        The file will render as HTML in browsers and as PDF in PDF readers.
        """
        logger.info(f"Creating PDF+HTML polyglot: {output_path}")
        
        if pdf_content is None:
            pdf_content = "PDF+HTML Polyglot\n\nThis file displays differently in browsers vs PDF readers."
        
        if html_content is None:
            html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>PDF+HTML Polyglot</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { color: #2c3e50; }
        .content { margin-top: 20px; line-height: 1.6; }
        .flag { background: #f39c12; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1 class="header">PDF+HTML Polyglot Challenge</h1>
    <div class="content">
        <p>This file is both a valid PDF and valid HTML!</p>
        <p>Open it in a browser to see this HTML content.</p>
        <p>Open it in a PDF reader to see the PDF content.</p>
        <div class="flag">
            <strong>Flag:</strong> CTF{polyglot_html_pdf_duality}
        </div>
    </div>
</body>
</html>
"""
        
        pdf_buffer = io.BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "PDF+HTML Polyglot")
        c.setFont("Helvetica", 12)
        
        lines = pdf_content.split('\n')
        y = 700
        for line in lines:
            c.drawString(100, y, line)
            y -= 20
        
        c.save()
        pdf_data = pdf_buffer.getvalue()
        
        html_comment = f"<!--\n{html_content}\n-->"
        html_bytes = html_comment.encode('utf-8')
        
        with open(output_path, 'wb') as f:
            f.write(b"%PDF-1.4\n")
            f.write(html_bytes)
            f.write(b"\n")
            f.write(pdf_data[9:])
        
        validation = self._validate_polyglot(output_path, "html")
        
        if validation.is_valid_pdf:
            logger.info(f"Successfully created PDF+HTML polyglot: {output_path}")
        else:
            logger.warning("PDF validation failed for HTML polyglot")
        
        return validation
    
    def _validate_polyglot(self, path: Path, secondary_format: str) -> PolyglotValidation:
        """Validate that polyglot is valid in both formats"""
        
        warnings = []
        notes = []
        
        is_valid_pdf = False
        pdf_readable = False
        try:
            with pikepdf.open(path) as pdf:
                is_valid_pdf = True
                if len(pdf.pages) > 0:
                    pdf_readable = True
                    notes.append(f"PDF has {len(pdf.pages)} page(s)")
        except Exception as e:
            warnings.append(f"PDF validation failed: {e}")
        
        is_valid_secondary = False
        secondary_readable = False
        
        if secondary_format == "zip":
            try:
                import zipfile
                with zipfile.ZipFile(path, 'r') as zf:
                    is_valid_secondary = True
                    files = zf.namelist()
                    if files:
                        secondary_readable = True
                        notes.append(f"ZIP contains {len(files)} file(s): {', '.join(files)}")
            except Exception as e:
                warnings.append(f"ZIP validation failed: {e}")
        
        elif secondary_format == "html":
            try:
                with open(path, 'rb') as f:
                    content = f.read()
                    if b"<!DOCTYPE html>" in content or b"<html>" in content:
                        is_valid_secondary = True
                        secondary_readable = True
                        notes.append("HTML markers detected in file")
                    else:
                        warnings.append("No HTML markers found")
            except Exception as e:
                warnings.append(f"HTML validation failed: {e}")
        
        return PolyglotValidation(
            is_valid_pdf=is_valid_pdf,
            is_valid_secondary=is_valid_secondary,
            secondary_format=secondary_format,
            pdf_readable=pdf_readable,
            secondary_readable=secondary_readable,
            warnings=warnings,
            notes=notes
        )


def generate_pdf_zip_polyglot(
    output_path: Path,
    pdf_content: Optional[str] = None,
    zip_files: Optional[List[Tuple[str, bytes]]] = None,
    method: str = "append"
) -> PolyglotValidation:
    """
    Convenience function to generate PDF+ZIP polyglot
    
    Args:
        output_path: Output file path
        pdf_content: Text content for PDF
        zip_files: List of (filename, content) tuples
        method: "append" or "prepend"
    
    Returns:
        PolyglotValidation
    """
    generator = PolyglotGenerator()
    return generator.create_pdf_zip_polyglot(output_path, pdf_content, zip_files, method)


def generate_pdf_html_polyglot(
    output_path: Path,
    pdf_content: Optional[str] = None,
    html_content: Optional[str] = None
) -> PolyglotValidation:
    """
    Convenience function to generate PDF+HTML polyglot
    
    Args:
        output_path: Output file path
        pdf_content: Text content for PDF
        html_content: HTML content
    
    Returns:
        PolyglotValidation
    """
    generator = PolyglotGenerator()
    return generator.create_pdf_html_polyglot(output_path, pdf_content, html_content)
