"""Stream extraction and decompression from PDF files"""

from pathlib import Path
from typing import Optional, List, Dict, Any
import mimetypes

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    import magic
except ImportError:
    magic = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class StreamExtractor:
    """Extract and decompress PDF streams"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
    
    def extract_all_streams(
        self,
        output_dir: Path,
        decompress: bool = True,
        detect_type: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Extract all streams from PDF
        
        Args:
            output_dir: Directory to save extracted streams
            decompress: Automatically decompress streams
            detect_type: Detect file types of streams
        
        Returns:
            List of extracted stream info
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        streams = []
        stream_counter = 0
        obj_counter = 0
        
        try:
            for obj in self.pdf_doc.pdf.objects:
                try:
                    obj_id = getattr(obj, 'objgen', (obj_counter, 0))
                    if isinstance(obj_id, tuple):
                        obj_num = obj_id[0]
                    else:
                        obj_num = obj_counter
                    
                    if isinstance(obj, pikepdf.Stream):
                        stream_info = self._extract_stream(
                            obj,
                            obj_num,
                            output_dir,
                            f"stream_{stream_counter}",
                            decompress,
                            detect_type
                        )
                        if stream_info:
                            streams.append(stream_info)
                            stream_counter += 1
                    
                    obj_counter += 1
                
                except Exception as e:
                    logger.debug(f"Failed to process object: {e}")
        
        except Exception as e:
            logger.error(f"Failed to extract streams: {e}")
        
        logger.info(f"Extracted {len(streams)} streams to {output_dir}")
        return streams
    
    def extract_stream_by_id(
        self,
        obj_id: int,
        output_file: Path,
        decompress: bool = True,
        detect_type: bool = True
    ) -> Dict[str, Any]:
        """
        Extract a specific stream by object ID
        
        Args:
            obj_id: Object ID of the stream
            output_file: Output file path
            decompress: Automatically decompress stream
            detect_type: Detect file type
        
        Returns:
            Stream info
        """
        try:
            obj = self.pdf_doc.pdf.get_object((obj_id, 0))
            
            if not isinstance(obj, pikepdf.Stream):
                raise ValueError(f"Object {obj_id} is not a stream")
            
            return self._extract_stream(
                obj,
                obj_id,
                output_file.parent,
                output_file.stem,
                decompress,
                detect_type
            )
        
        except Exception as e:
            logger.error(f"Failed to extract stream {obj_id}: {e}")
            raise
    
    def _extract_stream(
        self,
        stream_obj: Any,
        obj_id: int,
        output_dir: Path,
        filename: str,
        decompress: bool,
        detect_type: bool
    ) -> Optional[Dict[str, Any]]:
        """Extract a single stream object"""
        try:
            filter_type = stream_obj.get('/Filter', 'None')
            if isinstance(filter_type, list):
                filter_type = [str(f) for f in filter_type]
            else:
                filter_type = str(filter_type)
            
            length = int(stream_obj.get('/Length', 0))
            subtype = str(stream_obj.get('/Subtype', '')) if '/Subtype' in stream_obj else None
            
            raw_data = bytes(stream_obj.read_raw_bytes())
            raw_size = len(raw_data)
            
            data_to_save = raw_data
            is_decompressed = False
            decompressed_size = raw_size
            
            if decompress and filter_type != 'None':
                try:
                    decompressed_data = bytes(stream_obj.read_bytes())
                    data_to_save = decompressed_data
                    is_decompressed = True
                    decompressed_size = len(decompressed_data)
                except Exception as e:
                    logger.debug(f"Failed to decompress stream {obj_id}: {e}")
            
            detected_type = None
            file_ext = 'bin'
            
            if detect_type:
                detected_type, file_ext = self._detect_file_type(data_to_save, subtype, filter_type)
            
            output_path = output_dir / f"{filename}.{file_ext}"
            output_path.write_bytes(data_to_save)
            
            logger.debug(f"Extracted stream {obj_id} to {output_path}")
            
            return {
                'object_id': obj_id,
                'filename': output_path.name,
                'path': str(output_path),
                'filter': filter_type,
                'subtype': subtype,
                'declared_length': length,
                'raw_size': raw_size,
                'decompressed': is_decompressed,
                'decompressed_size': decompressed_size,
                'detected_type': detected_type,
                'extension': file_ext,
            }
        
        except Exception as e:
            logger.debug(f"Failed to extract stream {obj_id}: {e}")
            return None
    
    def _detect_file_type(
        self,
        data: bytes,
        subtype: Optional[str],
        filter_type: Any
    ) -> tuple[Optional[str], str]:
        """
        Detect file type from data
        
        Returns:
            (detected_type, file_extension)
        """
        filter_str = str(filter_type)
        
        if subtype:
            if 'Image' in subtype:
                if 'DCTDecode' in filter_str:
                    return ('image/jpeg', 'jpg')
                elif 'JPXDecode' in filter_str:
                    return ('image/jp2', 'jp2')
                elif 'CCITTFaxDecode' in filter_str:
                    return ('image/tiff', 'tif')
                else:
                    return ('image/unknown', 'img')
            
            elif 'Form' in subtype or 'XObject' in subtype:
                return ('application/pdf-xobject', 'xobj')
        
        if data[:4] == b'%PDF':
            return ('application/pdf', 'pdf')
        
        elif data[:2] == b'\xff\xd8':
            return ('image/jpeg', 'jpg')
        
        elif data[:8] == b'\x89PNG\r\n\x1a\n':
            return ('image/png', 'png')
        
        elif data[:6] in [b'GIF87a', b'GIF89a']:
            return ('image/gif', 'gif')
        
        elif data[:4] == b'%!PS':
            return ('application/postscript', 'ps')
        
        elif data[:5] == b'<?xml':
            return ('application/xml', 'xml')
        
        elif data[:4] == b'PK\x03\x04':
            return ('application/zip', 'zip')
        
        try:
            data.decode('utf-8')
            if b'<' in data[:100] and b'>' in data[:100]:
                return ('text/xml', 'xml')
            return ('text/plain', 'txt')
        except Exception:
            pass
        
        if len(data) > 0:
            try:
                if magic:
                    mime = magic.from_buffer(data, mime=True)
                    if mime:
                        ext = mimetypes.guess_extension(mime)
                        if ext:
                            return (mime, ext.lstrip('.'))
                        return (mime, 'bin')
            except Exception:
                pass
        
        return (None, 'bin')


def extract_streams(
    input_pdf: Path,
    output_dir: Path,
    obj_id: Optional[int] = None,
    decompress: bool = True,
    detect_type: bool = True,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Extract streams from PDF
    
    Args:
        input_pdf: Path to input PDF
        output_dir: Directory to save extracted streams
        obj_id: Optional specific object ID, None for all streams
        decompress: Automatically decompress streams
        detect_type: Detect file types
        password: Optional password for encrypted PDFs
    
    Returns:
        List of extracted stream info
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = StreamExtractor(pdf_doc)
        
        if obj_id is not None:
            output_file = Path(output_dir) / f"stream_{obj_id}.bin"
            stream_info = extractor.extract_stream_by_id(obj_id, output_file, decompress, detect_type)
            return [stream_info]
        else:
            return extractor.extract_all_streams(output_dir, decompress, detect_type)
