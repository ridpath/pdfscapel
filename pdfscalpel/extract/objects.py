"""PDF object extraction and dumping"""

from pathlib import Path
from typing import Optional, List, Dict, Any, Set
import json

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class ObjectExtractor:
    """Extract and dump PDF objects"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
    
    def list_objects(self, filter_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List all PDF objects with metadata
        
        Args:
            filter_types: Optional list of object types to include (e.g., ['Stream', 'Dictionary'])
        
        Returns:
            List of object metadata
        """
        objects = []
        
        try:
            obj_counter = 0
            for obj in self.pdf_doc.pdf.objects:
                try:
                    obj_type = self._get_object_type(obj)
                    
                    if filter_types and obj_type not in filter_types:
                        continue
                    
                    obj_id = getattr(obj, 'objgen', (obj_counter, 0))
                    if isinstance(obj_id, tuple):
                        obj_num = obj_id[0]
                        gen = obj_id[1]
                    else:
                        obj_num = obj_counter
                        gen = 0
                    
                    obj_info = {
                        'object_id': obj_num,
                        'generation': gen,
                        'type': obj_type,
                        'subtype': self._get_subtype(obj),
                        'size': self._get_object_size(obj),
                        'is_stream': isinstance(obj, pikepdf.Stream),
                    }
                    
                    if isinstance(obj, pikepdf.Stream):
                        obj_info['filter'] = str(obj.get('/Filter', 'None'))
                        obj_info['length'] = int(obj.get('/Length', 0))
                    
                    objects.append(obj_info)
                    obj_counter += 1
                
                except Exception as e:
                    logger.debug(f"Failed to inspect object: {e}")
        
        except Exception as e:
            logger.error(f"Failed to list objects: {e}")
        
        logger.info(f"Found {len(objects)} objects")
        return objects
    
    def dump_object(self, obj_id: int, output_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Dump a specific object by ID
        
        Args:
            obj_id: Object ID to dump
            output_file: Optional output file path
        
        Returns:
            Object information and data
        """
        try:
            obj = self.pdf_doc.pdf.get_object((obj_id, 0))
            
            obj_info = {
                'object_id': obj_id,
                'generation': 0,
                'type': self._get_object_type(obj),
                'subtype': self._get_subtype(obj),
            }
            
            if isinstance(obj, pikepdf.Stream):
                obj_info['is_stream'] = True
                obj_info['filter'] = str(obj.get('/Filter', 'None'))
                obj_info['raw_data'] = bytes(obj.read_raw_bytes()).hex()
                
                try:
                    decompressed = bytes(obj.read_bytes())
                    obj_info['decompressed_data'] = decompressed.hex()
                    obj_info['decompressed_size'] = len(decompressed)
                    
                    try:
                        obj_info['decompressed_text'] = decompressed.decode('utf-8', errors='replace')
                    except Exception:
                        pass
                
                except Exception as e:
                    logger.debug(f"Failed to decompress stream: {e}")
                
                if output_file:
                    output_file = Path(output_file)
                    output_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    try:
                        decompressed = bytes(obj.read_bytes())
                        output_file.write_bytes(decompressed)
                        logger.info(f"Object {obj_id} saved to: {output_file}")
                    except Exception:
                        output_file.write_bytes(bytes(obj.read_raw_bytes()))
                        logger.info(f"Object {obj_id} (raw) saved to: {output_file}")
            
            else:
                obj_info['is_stream'] = False
                obj_info['representation'] = repr(obj)
                obj_info['string'] = str(obj)
                
                if output_file:
                    output_file = Path(output_file)
                    output_file.parent.mkdir(parents=True, exist_ok=True)
                    output_file.write_text(repr(obj), encoding='utf-8')
                    logger.info(f"Object {obj_id} representation saved to: {output_file}")
            
            return obj_info
        
        except Exception as e:
            logger.error(f"Failed to dump object {obj_id}: {e}")
            raise
    
    def dump_objects_by_type(
        self,
        obj_type: str,
        output_dir: Path,
        prefix: str = "obj"
    ) -> List[Dict[str, Any]]:
        """
        Dump all objects of a specific type
        
        Args:
            obj_type: Type of objects to dump (e.g., 'Stream', 'Dictionary')
            output_dir: Directory to save dumped objects
            prefix: Prefix for output filenames
        
        Returns:
            List of dumped object info
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        objects_list = self.list_objects(filter_types=[obj_type])
        dumped = []
        
        for obj_info in objects_list:
            obj_id = obj_info['object_id']
            
            ext = 'bin' if obj_info['is_stream'] else 'txt'
            output_file = output_dir / f"{prefix}_{obj_id}.{ext}"
            
            try:
                full_info = self.dump_object(obj_id, output_file)
                full_info['output_file'] = str(output_file)
                dumped.append(full_info)
            except Exception as e:
                logger.debug(f"Failed to dump object {obj_id}: {e}")
        
        logger.info(f"Dumped {len(dumped)} objects of type '{obj_type}' to {output_dir}")
        return dumped
    
    def _get_object_type(self, obj: Any) -> str:
        """Get object type name"""
        if isinstance(obj, pikepdf.Stream):
            return 'Stream'
        elif isinstance(obj, pikepdf.Dictionary):
            return 'Dictionary'
        elif isinstance(obj, pikepdf.Array):
            return 'Array'
        elif isinstance(obj, pikepdf.Name):
            return 'Name'
        elif isinstance(obj, (int, float)):
            return 'Number'
        elif isinstance(obj, str):
            return 'String'
        elif isinstance(obj, bool):
            return 'Boolean'
        else:
            return type(obj).__name__
    
    def _get_subtype(self, obj: Any) -> Optional[str]:
        """Get object subtype if available"""
        try:
            if isinstance(obj, (pikepdf.Stream, pikepdf.Dictionary)):
                subtype = obj.get('/Subtype')
                if subtype:
                    return str(subtype)
                
                type_field = obj.get('/Type')
                if type_field:
                    return str(type_field)
        except Exception:
            pass
        
        return None
    
    def _get_object_size(self, obj: Any) -> int:
        """Estimate object size in bytes"""
        try:
            if isinstance(obj, pikepdf.Stream):
                return len(bytes(obj.read_raw_bytes()))
            else:
                return len(repr(obj).encode('utf-8'))
        except Exception:
            return 0


def list_objects(
    input_pdf: Path,
    filter_types: Optional[List[str]] = None,
    output_file: Optional[Path] = None,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    List all objects in PDF
    
    Args:
        input_pdf: Path to input PDF
        filter_types: Optional list of object types to include
        output_file: Optional output file for object list (JSON)
        password: Optional password for encrypted PDFs
    
    Returns:
        List of object metadata
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = ObjectExtractor(pdf_doc)
        objects = extractor.list_objects(filter_types=filter_types)
        
        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(objects, f, indent=2)
            logger.info(f"Object list saved to: {output_file}")
        
        return objects


def dump_object(
    input_pdf: Path,
    obj_id: int,
    output_file: Optional[Path] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Dump a specific PDF object
    
    Args:
        input_pdf: Path to input PDF
        obj_id: Object ID to dump
        output_file: Optional output file path
        password: Optional password for encrypted PDFs
    
    Returns:
        Object information and data
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = ObjectExtractor(pdf_doc)
        return extractor.dump_object(obj_id, output_file)


def dump_objects_by_type(
    input_pdf: Path,
    obj_type: str,
    output_dir: Path,
    prefix: str = "obj",
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Dump all objects of a specific type
    
    Args:
        input_pdf: Path to input PDF
        obj_type: Type of objects to dump
        output_dir: Directory to save dumped objects
        prefix: Prefix for output filenames
        password: Optional password for encrypted PDFs
    
    Returns:
        List of dumped object info
    """
    with PDFDocument.open(input_pdf, password=password) as pdf_doc:
        extractor = ObjectExtractor(pdf_doc)
        return extractor.dump_objects_by_type(obj_type, output_dir, prefix)
