"""Image extraction from PDF files"""

from pathlib import Path
from typing import Optional, List, Dict, Any
import io

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    from PIL import Image
except ImportError:
    Image = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.exceptions import DependencyMissingError
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class ImageExtractor:
    """Extract images from PDF files"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
    
    def extract_all(self, output_dir: Path, prefix: str = "image") -> List[Dict[str, Any]]:
        """
        Extract all images from PDF
        
        Args:
            output_dir: Directory to save extracted images
            prefix: Prefix for output filenames
        
        Returns:
            List of extracted image info
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        images = []
        image_counter = 0
        
        for page_num in range(self.pdf_doc.num_pages):
            page_images = self.extract_from_page(page_num, output_dir, f"{prefix}_p{page_num + 1}")
            
            for img_info in page_images:
                img_info['global_index'] = image_counter
                image_counter += 1
                images.append(img_info)
        
        logger.info(f"Extracted {len(images)} images to {output_dir}")
        return images
    
    def extract_from_page(
        self,
        page_num: int,
        output_dir: Path,
        prefix: str = "image"
    ) -> List[Dict[str, Any]]:
        """
        Extract images from a specific page
        
        Args:
            page_num: Page number (0-indexed)
            output_dir: Directory to save extracted images
            prefix: Prefix for output filenames
        
        Returns:
            List of extracted image info
        """
        if page_num < 0 or page_num >= self.pdf_doc.num_pages:
            raise ValueError(f"Invalid page number: {page_num}")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        page = self.pdf_doc.get_page(page_num)
        images = []
        
        try:
            if '/Resources' not in page:
                return images
            
            resources = page['/Resources']
            if '/XObject' not in resources:
                return images
            
            xobjects = resources['/XObject']
            
            image_index = 0
            for obj_name in xobjects:
                obj = xobjects[obj_name]
                
                if not isinstance(obj, pikepdf.Object):
                    continue
                
                if obj.get('/Subtype') == '/Image':
                    img_info = self._extract_image(
                        obj,
                        output_dir,
                        f"{prefix}_{image_index}",
                        page_num,
                        str(obj_name)
                    )
                    if img_info:
                        images.append(img_info)
                        image_index += 1
        
        except Exception as e:
            logger.debug(f"Error extracting images from page {page_num}: {e}")
        
        return images
    
    def _extract_image(
        self,
        obj: Any,
        output_dir: Path,
        filename: str,
        page_num: int,
        obj_name: str
    ) -> Optional[Dict[str, Any]]:
        """Extract a single image object"""
        try:
            width = obj.get('/Width', 0)
            height = obj.get('/Height', 0)
            color_space = str(obj.get('/ColorSpace', 'Unknown'))
            bits_per_component = obj.get('/BitsPerComponent', 0)
            filter_type = obj.get('/Filter', 'None')
            
            if isinstance(filter_type, list):
                filter_type = [str(f) for f in filter_type]
            else:
                filter_type = str(filter_type)
            
            img_format = self._detect_format(filter_type, color_space)
            output_path = output_dir / f"{filename}.{img_format.lower()}"
            
            try:
                raw_image = pikepdf.PdfImage(obj)
                pil_image = raw_image.as_pil_image()
                
                pil_image.save(output_path, format=img_format)
                
                logger.debug(f"Extracted image: {output_path}")
                
                return {
                    'filename': output_path.name,
                    'path': str(output_path),
                    'page': page_num,
                    'object_name': obj_name,
                    'width': width,
                    'height': height,
                    'format': img_format,
                    'color_space': color_space,
                    'bits_per_component': bits_per_component,
                    'filter': filter_type,
                    'size_bytes': output_path.stat().st_size,
                }
            
            except Exception as e:
                logger.debug(f"Failed to extract image using pikepdf: {e}, trying raw extraction")
                return self._extract_image_raw(obj, output_path, page_num, obj_name, width, height, filter_type)
        
        except Exception as e:
            logger.debug(f"Failed to extract image {obj_name}: {e}")
            return None
    
    def _extract_image_raw(
        self,
        obj: Any,
        output_path: Path,
        page_num: int,
        obj_name: str,
        width: int,
        height: int,
        filter_type: Any
    ) -> Optional[Dict[str, Any]]:
        """Raw image extraction fallback"""
        try:
            raw_data = obj.read_raw_bytes()
            
            if '/DCTDecode' in str(filter_type) or 'DCTDecode' in str(filter_type):
                output_path = output_path.with_suffix('.jpg')
                output_path.write_bytes(raw_data)
                img_format = 'JPEG'
            
            elif '/JPXDecode' in str(filter_type) or 'JPXDecode' in str(filter_type):
                output_path = output_path.with_suffix('.jp2')
                output_path.write_bytes(raw_data)
                img_format = 'JPEG2000'
            
            else:
                output_path = output_path.with_suffix('.bin')
                output_path.write_bytes(raw_data)
                img_format = 'RAW'
            
            logger.debug(f"Extracted raw image: {output_path}")
            
            return {
                'filename': output_path.name,
                'path': str(output_path),
                'page': page_num,
                'object_name': obj_name,
                'width': width,
                'height': height,
                'format': img_format,
                'filter': filter_type,
                'size_bytes': len(raw_data),
                'raw_extraction': True,
            }
        
        except Exception as e:
            logger.debug(f"Raw extraction failed: {e}")
            return None
    
    def _detect_format(self, filter_type: Any, color_space: str) -> str:
        """Detect image format from filter and color space"""
        filter_str = str(filter_type)
        
        if 'DCTDecode' in filter_str:
            return 'JPEG'
        elif 'JPXDecode' in filter_str:
            return 'JPEG2000'
        elif 'CCITTFaxDecode' in filter_str:
            return 'TIFF'
        elif 'JBIG2Decode' in filter_str:
            return 'JBIG2'
        else:
            return 'PNG'


def extract_images(
    input_pdf: Path,
    output_dir: Path,
    page_num: Optional[int] = None,
    prefix: str = "image",
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Extract images from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_dir: Directory to save extracted images
        page_num: Optional specific page number (0-indexed), None for all pages
        prefix: Prefix for output filenames
        password: Optional password for encrypted PDFs
    
    Returns:
        List of extracted image info
    """
    if Image is None:
        raise DependencyMissingError(
            dependency="Pillow",
            install_hint="Install with: pip install Pillow"
        )
    
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = ImageExtractor(pdf_doc)
        
        if page_num is not None:
            images = extractor.extract_from_page(page_num, output_dir, prefix)
        else:
            images = extractor.extract_all(output_dir, prefix)
        
        return images
