"""
PDF Steganography Generator

Embeds hidden data in PDFs using various steganographic techniques:
- LSB embedding in images
- Whitespace encoding (zero-width characters)
- Metadata encoding
- Invisible text layers
- Content stream manipulation
"""

from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import io
import struct
import base64

try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.colors import white, black
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError

logger = get_logger()


@dataclass
class StegoEmbedResult:
    """Results of steganographic embedding"""
    technique: str
    data_size: int
    capacity_used: float
    extraction_hint: str
    metadata: Dict[str, Any]


class SteganographyGenerator:
    """Generate PDFs with embedded steganographic data"""
    
    ZWSP = '\u200B'  # Zero Width Space
    ZWNJ = '\u200C'  # Zero Width Non-Joiner
    ZWJ = '\u200D'   # Zero Width Joiner
    ZWNBSP = '\uFEFF'  # Zero Width No-Break Space (BOM)
    
    def __init__(self):
        if not HAS_REPORTLAB:
            raise DependencyMissingError("reportlab", "steganography generation")
        if not HAS_PIKEPDF:
            raise DependencyMissingError("pikepdf", "steganography generation")
    
    def embed_whitespace_stego(
        self,
        output_path: Path,
        hidden_data: str,
        cover_text: Optional[str] = None,
        encoding_scheme: str = "binary"
    ) -> StegoEmbedResult:
        """
        Embed data using zero-width Unicode characters
        
        Args:
            output_path: Output PDF path
            hidden_data: Data to hide
            cover_text: Visible text (hidden data embedded between words)
            encoding_scheme: "binary" (ZWSP=0, ZWNJ=1) or "base4" (4 chars)
        
        Returns:
            StegoEmbedResult with embedding details
        """
        logger.info(f"Embedding whitespace steganography: {len(hidden_data)} chars")
        
        if cover_text is None:
            cover_text = """
            Welcome to the PDF Steganography Challenge!
            
            This document contains hidden information embedded using advanced techniques.
            The data is invisible to the naked eye but can be extracted with proper tools.
            
            Your mission is to find and extract the secret message.
            Look carefully at the structure and content of this PDF.
            
            Good luck!
            """
        
        encoded = self._encode_whitespace(hidden_data, encoding_scheme)
        
        stego_text = self._inject_whitespace_into_text(cover_text, encoded)
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "Steganography Challenge")
        
        c.setFont("Helvetica", 11)
        y = 700
        for line in stego_text.split('\n'):
            c.drawString(100, y, line.strip())
            y -= 18
            if y < 100:
                c.showPage()
                c.setFont("Helvetica", 11)
                y = 750
        
        c.save()
        pdf_data = buffer.getvalue()
        
        output_path.write_bytes(pdf_data)
        
        return StegoEmbedResult(
            technique="whitespace_unicode",
            data_size=len(hidden_data),
            capacity_used=len(encoded) / len(stego_text),
            extraction_hint="Extract text and analyze zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF)",
            metadata={
                "encoding_scheme": encoding_scheme,
                "zero_width_chars": len(encoded),
                "cover_text_length": len(cover_text)
            }
        )
    
    def _encode_whitespace(self, data: str, scheme: str) -> str:
        """Encode data as zero-width characters"""
        
        data_bytes = data.encode('utf-8')
        binary = ''.join(format(byte, '08b') for byte in data_bytes)
        
        if scheme == "binary":
            encoded = ''.join(self.ZWSP if bit == '0' else self.ZWNJ for bit in binary)
        elif scheme == "base4":
            encoded = []
            for i in range(0, len(binary), 2):
                chunk = binary[i:i+2].ljust(2, '0')
                if chunk == '00':
                    encoded.append(self.ZWSP)
                elif chunk == '01':
                    encoded.append(self.ZWNJ)
                elif chunk == '10':
                    encoded.append(self.ZWJ)
                else:
                    encoded.append(self.ZWNBSP)
            encoded = ''.join(encoded)
        else:
            raise ValueError(f"Unknown encoding scheme: {scheme}")
        
        return encoded
    
    def _inject_whitespace_into_text(self, cover_text: str, encoded: str) -> str:
        """Inject zero-width characters into text"""
        
        words = cover_text.split()
        
        if not words:
            return encoded
        
        chars_per_word = len(encoded) // len(words) + 1
        
        result = []
        idx = 0
        
        for word in words:
            result.append(word)
            
            chunk = encoded[idx:idx + chars_per_word]
            result.append(chunk)
            idx += chars_per_word
            
            if idx >= len(encoded):
                result.extend(words[len(result):])
                break
        
        remaining = encoded[idx:]
        if remaining:
            result.append(remaining)
        
        return ' '.join(result)
    
    def embed_metadata_stego(
        self,
        output_path: Path,
        hidden_data: str,
        cover_text: Optional[str] = None,
        encoding: str = "base64"
    ) -> StegoEmbedResult:
        """
        Embed data in PDF metadata fields
        
        Args:
            output_path: Output PDF path
            hidden_data: Data to hide
            cover_text: Visible PDF content
            encoding: "base64", "hex", or "raw"
        
        Returns:
            StegoEmbedResult
        """
        logger.info(f"Embedding metadata steganography: {len(hidden_data)} chars")
        
        if cover_text is None:
            cover_text = "This PDF contains hidden data in its metadata.\n\nUse a metadata extraction tool to find it."
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "Metadata Steganography")
        
        c.setFont("Helvetica", 12)
        y = 700
        for line in cover_text.split('\n'):
            c.drawString(100, y, line)
            y -= 20
        
        c.save()
        pdf_data = buffer.getvalue()
        
        temp_path = output_path.with_suffix('.tmp.pdf')
        temp_path.write_bytes(pdf_data)
        
        if encoding == "base64":
            encoded_data = base64.b64encode(hidden_data.encode()).decode()
        elif encoding == "hex":
            encoded_data = hidden_data.encode().hex()
        else:
            encoded_data = hidden_data
        
        with pikepdf.open(temp_path) as pdf:
            metadata_fields = [
                ('Keywords', encoded_data[:200]),
                ('Subject', encoded_data[200:400] if len(encoded_data) > 200 else ''),
                ('Comments', encoded_data[400:600] if len(encoded_data) > 400 else ''),
            ]
            
            with pdf.open_metadata() as meta:
                meta['dc:description'] = encoded_data[:500]
                meta['dc:source'] = encoded_data[500:] if len(encoded_data) > 500 else ''
            
            for key, value in metadata_fields:
                if value:
                    pdf.docinfo[f'/{key}'] = value
            
            pdf.save(output_path)
        
        temp_path.unlink()
        
        return StegoEmbedResult(
            technique="metadata_embedding",
            data_size=len(hidden_data),
            capacity_used=len(encoded_data) / 2000,
            extraction_hint="Extract metadata using 'pdfautopsy extract metadata' or exiftool",
            metadata={
                "encoding": encoding,
                "fields_used": ["Keywords", "Subject", "dc:description", "dc:source"]
            }
        )
    
    def embed_invisible_text(
        self,
        output_path: Path,
        hidden_data: str,
        cover_text: Optional[str] = None,
        method: str = "white_on_white"
    ) -> StegoEmbedResult:
        """
        Embed invisible text in PDF
        
        Args:
            output_path: Output PDF path
            hidden_data: Data to hide as invisible text
            cover_text: Visible content
            method: "white_on_white", "tiny_font", or "off_page"
        
        Returns:
            StegoEmbedResult
        """
        logger.info(f"Embedding invisible text: {len(hidden_data)} chars (method: {method})")
        
        if cover_text is None:
            cover_text = "This PDF has a hidden text layer.\n\nTry extracting all text to reveal the secret."
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "Invisible Text Steganography")
        
        c.setFont("Helvetica", 12)
        y = 700
        for line in cover_text.split('\n'):
            c.drawString(100, y, line)
            y -= 20
        
        if method == "white_on_white":
            c.setFillColor(white)
            c.setFont("Helvetica", 10)
            c.drawString(100, 50, hidden_data)
        
        elif method == "tiny_font":
            c.setFillColor(black)
            c.setFont("Helvetica", 0.1)
            c.drawString(500, 50, hidden_data)
        
        elif method == "off_page":
            c.setFont("Helvetica", 12)
            c.drawString(1000, 1000, hidden_data)
        
        c.save()
        pdf_data = buffer.getvalue()
        
        output_path.write_bytes(pdf_data)
        
        return StegoEmbedResult(
            technique="invisible_text",
            data_size=len(hidden_data),
            capacity_used=0.1,
            extraction_hint=f"Extract all text using 'pdfautopsy extract text' (method: {method})",
            metadata={
                "method": method,
                "text_length": len(hidden_data)
            }
        )
    
    def embed_lsb_image_stego(
        self,
        output_path: Path,
        hidden_data: str,
        cover_text: Optional[str] = None,
        image_size: tuple = (400, 300)
    ) -> StegoEmbedResult:
        """
        Embed data in image using LSB steganography, then embed image in PDF
        
        Args:
            output_path: Output PDF path
            hidden_data: Data to hide in image
            cover_text: Visible PDF content
            image_size: Size of generated image (width, height)
        
        Returns:
            StegoEmbedResult
        """
        if not HAS_PIL:
            raise DependencyMissingError("PIL/Pillow", "image steganography")
        
        logger.info(f"Embedding LSB image steganography: {len(hidden_data)} chars")
        
        if cover_text is None:
            cover_text = "This PDF contains an image with hidden data.\n\nExtract the image and analyze it."
        
        img = Image.new('RGB', image_size, color='lightblue')
        pixels = img.load()
        
        data_bytes = hidden_data.encode('utf-8')
        binary = ''.join(format(byte, '08b') for byte in data_bytes)
        
        max_capacity = image_size[0] * image_size[1] * 3
        if len(binary) > max_capacity:
            raise PDFScalpelError(f"Data too large for image: {len(binary)} bits > {max_capacity} bits")
        
        idx = 0
        for y in range(image_size[1]):
            for x in range(image_size[0]):
                if idx >= len(binary):
                    break
                
                r, g, b = pixels[x, y]
                
                if idx < len(binary):
                    r = (r & 0xFE) | int(binary[idx])
                    idx += 1
                if idx < len(binary):
                    g = (g & 0xFE) | int(binary[idx])
                    idx += 1
                if idx < len(binary):
                    b = (b & 0xFE) | int(binary[idx])
                    idx += 1
                
                pixels[x, y] = (r, g, b)
        
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "Image Steganography Challenge")
        
        c.setFont("Helvetica", 12)
        y_pos = 700
        for line in cover_text.split('\n'):
            c.drawString(100, y_pos, line)
            y_pos -= 20
        
        temp_img_path = output_path.with_suffix('.stego_temp.png')
        with open(temp_img_path, 'wb') as f:
            f.write(img_buffer.getvalue())
        
        c.drawImage(str(temp_img_path), 100, 250, width=400, height=300)
        
        c.save()
        pdf_data = buffer.getvalue()
        
        output_path.write_bytes(pdf_data)
        temp_img_path.unlink()
        
        capacity_used = len(binary) / max_capacity
        
        return StegoEmbedResult(
            technique="lsb_image_embedding",
            data_size=len(hidden_data),
            capacity_used=capacity_used,
            extraction_hint="Extract image and perform LSB analysis on RGB channels",
            metadata={
                "image_size": image_size,
                "bits_embedded": len(binary),
                "max_capacity_bits": max_capacity
            }
        )


def embed_whitespace_stego(
    output_path: Path,
    hidden_data: str,
    cover_text: Optional[str] = None
) -> StegoEmbedResult:
    """Convenience function for whitespace steganography"""
    gen = SteganographyGenerator()
    return gen.embed_whitespace_stego(output_path, hidden_data, cover_text)


def embed_metadata_stego(
    output_path: Path,
    hidden_data: str,
    cover_text: Optional[str] = None
) -> StegoEmbedResult:
    """Convenience function for metadata steganography"""
    gen = SteganographyGenerator()
    return gen.embed_metadata_stego(output_path, hidden_data, cover_text)


def embed_invisible_text(
    output_path: Path,
    hidden_data: str,
    cover_text: Optional[str] = None,
    method: str = "white_on_white"
) -> StegoEmbedResult:
    """Convenience function for invisible text steganography"""
    gen = SteganographyGenerator()
    return gen.embed_invisible_text(output_path, hidden_data, cover_text, method)


def embed_lsb_image_stego(
    output_path: Path,
    hidden_data: str,
    cover_text: Optional[str] = None
) -> StegoEmbedResult:
    """Convenience function for LSB image steganography"""
    gen = SteganographyGenerator()
    return gen.embed_lsb_image_stego(output_path, hidden_data, cover_text)
