"""Embedded file extraction from PDF files"""

from pathlib import Path
from typing import Optional, List, Dict, Any
import struct

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


MAGIC_BYTES = {
    b'\xFF\xD8\xFF': {'ext': 'jpg', 'type': 'JPEG Image'},
    b'\x89PNG\r\n\x1a\n': {'ext': 'png', 'type': 'PNG Image'},
    b'GIF87a': {'ext': 'gif', 'type': 'GIF Image'},
    b'GIF89a': {'ext': 'gif', 'type': 'GIF Image'},
    b'%PDF-': {'ext': 'pdf', 'type': 'PDF Document'},
    b'PK\x03\x04': {'ext': 'zip', 'type': 'ZIP Archive'},
    b'PK\x05\x06': {'ext': 'zip', 'type': 'ZIP Archive (empty)'},
    b'PK\x07\x08': {'ext': 'zip', 'type': 'ZIP Archive (spanned)'},
    b'\x1f\x8b\x08': {'ext': 'gz', 'type': 'GZIP Archive'},
    b'BM': {'ext': 'bmp', 'type': 'BMP Image'},
    b'II*\x00': {'ext': 'tiff', 'type': 'TIFF Image (little-endian)'},
    b'MM\x00*': {'ext': 'tiff', 'type': 'TIFF Image (big-endian)'},
    b'RIFF': {'ext': 'wav', 'type': 'WAV Audio'},
    b'<?xml': {'ext': 'xml', 'type': 'XML Document'},
    b'<html': {'ext': 'html', 'type': 'HTML Document'},
    b'<!DOCTYPE': {'ext': 'html', 'type': 'HTML Document'},
    b'MZ': {'ext': 'exe', 'type': 'Windows Executable'},
    b'\x7fELF': {'ext': 'elf', 'type': 'Linux Executable'},
}


class AttachmentExtractor:
    """Extract embedded files from PDF"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.attachments: List[Dict[str, Any]] = []
    
    def extract_all(self) -> List[Dict[str, Any]]:
        """
        Extract all embedded files from PDF
        
        Returns:
            List of dictionaries containing attachment metadata
        """
        logger.debug(f"Extracting embedded files from {self.pdf_doc.path}")
        
        self.attachments = []
        
        self._extract_from_names_tree()
        self._extract_from_file_annotations()
        
        logger.info(f"Found {len(self.attachments)} embedded files")
        return self.attachments
    
    def _extract_from_names_tree(self):
        """Extract embedded files from Names/EmbeddedFiles tree"""
        try:
            root = self.pdf_doc.root
            if '/Names' not in root:
                return
            
            names = root['/Names']
            if '/EmbeddedFiles' not in names:
                return
            
            embedded_files = names['/EmbeddedFiles']
            if '/Names' in embedded_files:
                names_array = embedded_files['/Names']
                
                for i in range(0, len(names_array), 2):
                    try:
                        filename = str(names_array[i])
                        filespec = names_array[i + 1]
                        
                        self._extract_filespec(filespec, filename, 'Names tree')
                    except Exception as e:
                        logger.debug(f"Failed to extract embedded file from Names tree: {e}")
        
        except Exception as e:
            logger.debug(f"Failed to extract from Names tree: {e}")
    
    def _extract_from_file_annotations(self):
        """Extract embedded files from file attachment annotations"""
        try:
            for page_num, page in enumerate(self.pdf_doc.get_pages()):
                if '/Annots' not in page:
                    continue
                
                annots = page['/Annots']
                for i, annot in enumerate(annots):
                    try:
                        if '/Subtype' in annot and annot['/Subtype'] == '/FileAttachment':
                            if '/FS' in annot:
                                filespec = annot['/FS']
                                filename = self._get_filename_from_filespec(filespec)
                                self._extract_filespec(
                                    filespec,
                                    filename or f'attachment_page{page_num}_annot{i}',
                                    f'File annotation (page {page_num})'
                                )
                    except Exception as e:
                        logger.debug(f"Failed to extract from file annotation: {e}")
        
        except Exception as e:
            logger.debug(f"Failed to extract from file annotations: {e}")
    
    def _get_filename_from_filespec(self, filespec) -> Optional[str]:
        """Extract filename from filespec dictionary"""
        try:
            if '/UF' in filespec:
                return str(filespec['/UF'])
            elif '/F' in filespec:
                return str(filespec['/F'])
        except Exception:
            pass
        return None
    
    def _extract_filespec(self, filespec, filename: str, source: str):
        """Extract file from filespec dictionary"""
        try:
            if '/EF' not in filespec:
                return
            
            ef_dict = filespec['/EF']
            
            stream_obj = None
            if '/F' in ef_dict:
                stream_obj = ef_dict['/F']
            elif '/UF' in ef_dict:
                stream_obj = ef_dict['/UF']
            
            if not stream_obj:
                return
            
            data = bytes(stream_obj.read_bytes())
            
            params = {}
            if '/Params' in filespec:
                params_dict = filespec['/Params']
                if '/Size' in params_dict:
                    params['size'] = int(params_dict['/Size'])
                if '/CreationDate' in params_dict:
                    params['creation_date'] = str(params_dict['/CreationDate'])
                if '/ModDate' in params_dict:
                    params['modification_date'] = str(params_dict['/ModDate'])
                if '/CheckSum' in params_dict:
                    params['checksum'] = str(params_dict['/CheckSum'])
            
            detected_type = self._detect_file_type(data)
            
            self.attachments.append({
                'filename': filename,
                'source': source,
                'data': data,
                'size': len(data),
                'detected_type': detected_type['type'],
                'detected_extension': detected_type['ext'],
                'metadata': params,
            })
            
            logger.debug(f"Extracted embedded file: {filename} ({len(data)} bytes)")
        
        except Exception as e:
            logger.debug(f"Failed to extract filespec: {e}")
    
    def _detect_file_type(self, data: bytes) -> Dict[str, str]:
        """Detect file type from magic bytes"""
        for magic, info in MAGIC_BYTES.items():
            if data.startswith(magic):
                return info
        
        if data.startswith(b'%!PS-Adobe'):
            return {'ext': 'ps', 'type': 'PostScript'}
        
        if b'<svg' in data[:200].lower():
            return {'ext': 'svg', 'type': 'SVG Image'}
        
        try:
            data.decode('utf-8')
            return {'ext': 'txt', 'type': 'Text File'}
        except UnicodeDecodeError:
            pass
        
        return {'ext': 'bin', 'type': 'Unknown Binary'}


def extract_attachments(
    input_pdf: Path,
    output_dir: Path,
    preserve_metadata: bool = True,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Extract embedded files from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_dir: Output directory for extracted files
        preserve_metadata: Save metadata files alongside extracted files
        password: Optional password for encrypted PDFs
    
    Returns:
        List of extracted attachment metadata
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = AttachmentExtractor(pdf_doc)
        attachments = extractor.extract_all()
        
        for i, attachment in enumerate(attachments):
            filename = attachment['filename']
            
            safe_filename = filename
            for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|']:
                safe_filename = safe_filename.replace(char, '_')
            
            if not Path(safe_filename).suffix:
                safe_filename += f".{attachment['detected_extension']}"
            
            output_path = output_dir / safe_filename
            
            counter = 1
            while output_path.exists():
                stem = Path(safe_filename).stem
                suffix = Path(safe_filename).suffix
                output_path = output_dir / f"{stem}_{counter}{suffix}"
                counter += 1
            
            output_path.write_bytes(attachment['data'])
            logger.info(f"Saved embedded file: {output_path}")
            
            attachment['output_path'] = str(output_path)
            
            if preserve_metadata and attachment['metadata']:
                meta_path = output_path.with_suffix(output_path.suffix + '.meta')
                meta_content = f"Original filename: {filename}\n"
                meta_content += f"Source: {attachment['source']}\n"
                meta_content += f"Detected type: {attachment['detected_type']}\n"
                meta_content += f"Size: {attachment['size']} bytes\n"
                
                for key, value in attachment['metadata'].items():
                    meta_content += f"{key}: {value}\n"
                
                meta_path.write_text(meta_content, encoding='utf-8')
                logger.debug(f"Saved metadata: {meta_path}")
        
        return attachments
