"""Comprehensive watermark addition and removal operations"""

import re
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

import pikepdf
import pdfplumber

from pdfscalpel.core.constants import WatermarkType, RemovalDifficulty
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.dependencies import check_external_tool
from pdfscalpel.analyze.watermark import WatermarkAnalyzer, WatermarkInfo

logger = get_logger()

POINTS_PER_INCH = 72.0


class RemovalMethod(Enum):
    """Available watermark removal methods"""
    AUTO = "auto"
    CROP = "crop"
    OCG = "ocg"
    XOBJECT = "xobject"
    ANNOTATION = "annotation"
    CONTENT_STREAM_TEXT = "content_stream_text"
    CONTENT_STREAM_GRAPHICS = "content_stream_graphics"
    BACKGROUND = "background"
    ZORDER = "zorder"
    INVISIBLE_TEXT = "invisible_text"
    TRANSPARENCY = "transparency"
    INPAINT = "inpaint"
    PATTERN_MATCH = "pattern_match"
    GHOSTSCRIPT = "ghostscript"
    FORENSIC_METADATA = "forensic_metadata"
    ALL = "all"


@dataclass
class RemovalResult:
    """Result of watermark removal operation"""
    success: bool
    method_used: str
    pages_processed: int
    watermarks_removed: int
    message: str
    quality_score: Optional[float] = None


class WatermarkRemover:
    """Comprehensive watermark removal with multiple techniques"""
    
    def __init__(self, pdf_path: Path):
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        
    def remove(
        self,
        output_path: Path,
        method: RemovalMethod = RemovalMethod.AUTO,
        watermark_pattern: Optional[str] = None,
        crop_params: Optional[Dict[str, float]] = None,
        try_all: bool = False
    ) -> RemovalResult:
        """
        Remove watermark using specified method
        
        Args:
            output_path: Output PDF path
            method: Removal method to use
            watermark_pattern: Text pattern for pattern-based removal
            crop_params: Cropping parameters {top, bottom, left, right} in inches
            try_all: Try all methods until one succeeds
        """
        logger.info(f"Removing watermark from: {self.pdf_path}")
        logger.info(f"Method: {method.value}")
        
        if method == RemovalMethod.AUTO:
            return self._auto_remove(output_path, watermark_pattern)
        elif method == RemovalMethod.ALL or try_all:
            return self._try_all_methods(output_path, watermark_pattern, crop_params)
        else:
            return self._remove_with_method(output_path, method, watermark_pattern, crop_params)
    
    def _auto_remove(
        self,
        output_path: Path,
        watermark_pattern: Optional[str]
    ) -> RemovalResult:
        """Automatically detect watermark type and select best removal method"""
        logger.info("Auto-detecting watermark type...")
        
        analyzer = WatermarkAnalyzer(self.pdf_path)
        analysis = analyzer.analyze()
        
        if not analysis.watermarks:
            return RemovalResult(
                success=False,
                method_used="auto",
                pages_processed=0,
                watermarks_removed=0,
                message="No watermarks detected"
            )
        
        watermark = analysis.watermarks[0]
        logger.info(f"Detected watermark type: {watermark.type.value} (confidence: {watermark.confidence:.2f})")
        
        method_map = {
            WatermarkType.OCG_BASED: RemovalMethod.OCG,
            WatermarkType.XOBJECT_REUSE: RemovalMethod.XOBJECT,
            WatermarkType.ANNOTATION_BASED: RemovalMethod.ANNOTATION,
            WatermarkType.TEXT_OVERLAY: RemovalMethod.CONTENT_STREAM_TEXT,
            WatermarkType.IMAGE_OVERLAY: RemovalMethod.CONTENT_STREAM_GRAPHICS,
            WatermarkType.BACKGROUND: RemovalMethod.BACKGROUND,
            WatermarkType.TRANSPARENCY_GROUP: RemovalMethod.TRANSPARENCY,
        }
        
        method = method_map.get(watermark.type, RemovalMethod.CONTENT_STREAM_TEXT)
        logger.info(f"Selected method: {method.value}")
        
        return self._remove_with_method(output_path, method, watermark_pattern, None)
    
    def _try_all_methods(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Try all removal methods in priority order until one succeeds"""
        methods = [
            RemovalMethod.OCG,
            RemovalMethod.ANNOTATION,
            RemovalMethod.XOBJECT,
            RemovalMethod.CONTENT_STREAM_TEXT,
            RemovalMethod.BACKGROUND,
            RemovalMethod.INVISIBLE_TEXT,
            RemovalMethod.CONTENT_STREAM_GRAPHICS,
            RemovalMethod.ZORDER,
            RemovalMethod.TRANSPARENCY,
            RemovalMethod.FORENSIC_METADATA,
            RemovalMethod.CROP,
            RemovalMethod.GHOSTSCRIPT,
        ]
        
        results = []
        for method in methods:
            logger.info(f"Trying method: {method.value}")
            try:
                result = self._remove_with_method(output_path, method, watermark_pattern, crop_params)
                results.append(result)
                
                if result.success and result.watermarks_removed > 0:
                    logger.info(f"Success with method: {method.value}")
                    return result
            except Exception as e:
                logger.debug(f"Method {method.value} failed: {e}")
                continue
        
        return RemovalResult(
            success=False,
            method_used="all",
            pages_processed=0,
            watermarks_removed=0,
            message=f"All {len(methods)} methods failed. Results: {[r.message for r in results]}"
        )
    
    def _remove_with_method(
        self,
        output_path: Path,
        method: RemovalMethod,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove watermark using specific method"""
        method_handlers = {
            RemovalMethod.CROP: self._remove_by_cropping,
            RemovalMethod.OCG: self._remove_ocg,
            RemovalMethod.XOBJECT: self._remove_xobject,
            RemovalMethod.ANNOTATION: self._remove_annotation,
            RemovalMethod.CONTENT_STREAM_TEXT: self._remove_content_stream_text,
            RemovalMethod.CONTENT_STREAM_GRAPHICS: self._remove_content_stream_graphics,
            RemovalMethod.BACKGROUND: self._remove_background,
            RemovalMethod.ZORDER: self._remove_zorder,
            RemovalMethod.INVISIBLE_TEXT: self._remove_invisible_text,
            RemovalMethod.TRANSPARENCY: self._remove_transparency,
            RemovalMethod.FORENSIC_METADATA: self._remove_forensic_metadata,
            RemovalMethod.GHOSTSCRIPT: self._remove_ghostscript,
        }
        
        handler = method_handlers.get(method)
        if not handler:
            raise PDFScalpelError(f"Unsupported removal method: {method.value}")
        
        return handler(output_path, watermark_pattern, crop_params)
    
    def _remove_by_cropping(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove watermark by cropping page edges"""
        if crop_params is None:
            crop_params = {'top': 0.5, 'bottom': 0.5, 'left': 0.5, 'right': 0.5}
        
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                
                for page in pdf.pages:
                    mediabox = page.MediaBox
                    page.MediaBox = [
                        float(mediabox[0]) + crop_params.get('left', 0) * POINTS_PER_INCH,
                        float(mediabox[1]) + crop_params.get('bottom', 0) * POINTS_PER_INCH,
                        float(mediabox[2]) - crop_params.get('right', 0) * POINTS_PER_INCH,
                        float(mediabox[3]) - crop_params.get('top', 0) * POINTS_PER_INCH,
                    ]
                    pages_processed += 1
                
                pdf.save(output_path)
            
            return RemovalResult(
                success=True,
                method_used="crop",
                pages_processed=pages_processed,
                watermarks_removed=pages_processed,
                message=f"Cropped {pages_processed} pages (may lose edge content)"
            )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="crop",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Cropping failed: {e}"
            )
    
    def _remove_ocg(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove Optional Content Groups (layers) containing watermarks"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                if '/OCProperties' not in pdf.Root:
                    return RemovalResult(
                        success=False,
                        method_used="ocg",
                        pages_processed=0,
                        watermarks_removed=0,
                        message="No Optional Content Groups found"
                    )
                
                oc_props = pdf.Root.OCProperties
                if '/OCGs' not in oc_props:
                    return RemovalResult(
                        success=False,
                        method_used="ocg",
                        pages_processed=0,
                        watermarks_removed=0,
                        message="No OCGs in OCProperties"
                    )
                
                ocgs = oc_props.OCGs
                if not isinstance(ocgs, list):
                    ocgs = [ocgs]
                
                watermark_ocgs = []
                for ocg in ocgs:
                    if not isinstance(ocg, pikepdf.Dictionary):
                        continue
                    
                    name = ocg.get('/Name', '')
                    name_str = str(name).lower()
                    
                    if any(keyword in name_str for keyword in ['watermark', 'background', 'logo', 'draft', 'confidential', 'copy', 'sample']):
                        watermark_ocgs.append(ocg)
                        logger.info(f"Detected watermark OCG: {name}")
                
                if not watermark_ocgs:
                    return RemovalResult(
                        success=False,
                        method_used="ocg",
                        pages_processed=0,
                        watermarks_removed=0,
                        message="No watermark OCGs detected"
                    )
                
                for ocg in watermark_ocgs:
                    ocgs.remove(ocg)
                
                if len(oc_props.OCGs) == 0:
                    del pdf.Root.OCProperties
                
                for page in pdf.pages:
                    if '/Resources' in page and '/Properties' in page.Resources:
                        props = page.Resources.Properties
                        for key in list(props.keys()):
                            if props[key] in watermark_ocgs:
                                del props[key]
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=True,
                    method_used="ocg",
                    pages_processed=len(pdf.pages),
                    watermarks_removed=len(watermark_ocgs),
                    message=f"Removed {len(watermark_ocgs)} watermark layers"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="ocg",
                pages_processed=0,
                watermarks_removed=0,
                message=f"OCG removal failed: {e}"
            )
    
    def _remove_xobject(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove reused Form XObjects (common watermark technique)"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                xobject_usage = {}
                
                for page in pdf.pages:
                    if '/Resources' not in page or '/XObject' not in page.Resources:
                        continue
                    
                    xobjects = page.Resources.XObject
                    for name, xobj_ref in xobjects.items():
                        key = str(xobj_ref.objgen)
                        xobject_usage[key] = xobject_usage.get(key, 0) + 1
                
                total_pages = len(pdf.pages)
                threshold = total_pages * 0.5
                
                watermark_xobjects = {
                    key for key, count in xobject_usage.items()
                    if count >= threshold
                }
                
                if not watermark_xobjects:
                    return RemovalResult(
                        success=False,
                        method_used="xobject",
                        pages_processed=0,
                        watermarks_removed=0,
                        message=f"No reused XObjects detected (threshold: {threshold:.0f} pages)"
                    )
                
                logger.info(f"Detected {len(watermark_xobjects)} potentially watermark XObjects")
                
                removed_count = 0
                pages_processed = 0
                
                for page in pdf.pages:
                    if '/Resources' not in page or '/XObject' not in page.Resources:
                        continue
                    
                    xobjects = page.Resources.XObject
                    modified = False
                    
                    for name in list(xobjects.keys()):
                        xobj_ref = xobjects[name]
                        key = str(xobj_ref.objgen)
                        
                        if key in watermark_xobjects:
                            del xobjects[name]
                            modified = True
                            removed_count += 1
                    
                    if modified:
                        self._remove_xobject_from_content_stream(page, watermark_xobjects)
                        pages_processed += 1
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=True,
                    method_used="xobject",
                    pages_processed=pages_processed,
                    watermarks_removed=len(watermark_xobjects),
                    message=f"Removed {len(watermark_xobjects)} reused XObjects from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="xobject",
                pages_processed=0,
                watermarks_removed=0,
                message=f"XObject removal failed: {e}"
            )
    
    def _remove_xobject_from_content_stream(
        self,
        page: pikepdf.Dictionary,
        watermark_xobject_keys: set
    ) -> None:
        """Remove XObject references from page content stream"""
        try:
            if '/Contents' not in page:
                return
            
            contents = page.Contents
            if isinstance(contents, pikepdf.Stream):
                contents = [contents]
            
            modified = False
            for stream in contents:
                if not isinstance(stream, pikepdf.Stream):
                    continue
                
                data = stream.read_bytes()
                data_str = data.decode('latin-1', errors='ignore')
                
                pattern = r'/([A-Za-z0-9]+)\s+Do'
                matches = re.findall(pattern, data_str)
                
                for match in matches:
                    if match in watermark_xobject_keys:
                        data_str = re.sub(rf'/{match}\s+Do', '', data_str)
                        modified = True
                
                if modified:
                    stream.write(data_str.encode('latin-1'))
        
        except Exception as e:
            logger.debug(f"Content stream XObject removal failed: {e}")
    
    def _remove_annotation(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove watermark annotations (Stamp, FreeText, Watermark types)"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                annotations_removed = 0
                
                for page in pdf.pages:
                    if '/Annots' not in page:
                        continue
                    
                    annots = page.Annots
                    if not isinstance(annots, list):
                        continue
                    
                    filtered_annots = []
                    
                    for annot in annots:
                        if not isinstance(annot, pikepdf.Dictionary):
                            filtered_annots.append(annot)
                            continue
                        
                        annot_dict = annot.obj if hasattr(annot, 'obj') else annot
                        subtype = annot_dict.get('/Subtype', '')
                        
                        watermark_types = ['/Watermark', '/Stamp', '/FreeText']
                        is_watermark = False
                        
                        if subtype in watermark_types:
                            contents = str(annot_dict.get('/Contents', '')).lower()
                            if any(kw in contents for kw in ['watermark', 'draft', 'confidential', 'copy', 'sample']):
                                is_watermark = True
                            elif subtype == '/Watermark':
                                is_watermark = True
                        
                        if not is_watermark:
                            filtered_annots.append(annot)
                        else:
                            annotations_removed += 1
                    
                    if len(filtered_annots) != len(annots):
                        if filtered_annots:
                            page.Annots = pikepdf.Array(filtered_annots)
                        else:
                            del page.Annots
                        pages_processed += 1
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=annotations_removed > 0,
                    method_used="annotation",
                    pages_processed=pages_processed,
                    watermarks_removed=annotations_removed,
                    message=f"Removed {annotations_removed} watermark annotations from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="annotation",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Annotation removal failed: {e}"
            )
    
    def _remove_content_stream_text(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove text watermarks by editing content streams"""
        if watermark_pattern is None:
            watermark_pattern = r'(DRAFT|CONFIDENTIAL|COPY|SAMPLE|WATERMARK|PREVIEW)'
        
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                text_removed = 0
                
                for page in pdf.pages:
                    if '/Contents' not in page:
                        continue
                    
                    try:
                        instructions = pikepdf.parse_content_stream(page)
                        filtered = []
                        skip_next_text = False
                        
                        for operands, operator in instructions:
                            op_str = str(operator)
                            
                            if op_str == 'Tj':
                                text = str(operands[0]) if operands else ''
                                if re.search(watermark_pattern, text, re.IGNORECASE):
                                    text_removed += 1
                                    skip_next_text = True
                                    continue
                            
                            elif op_str == 'TJ':
                                text_array = operands[0] if operands else []
                                if isinstance(text_array, list):
                                    combined_text = ''.join(str(item) for item in text_array if isinstance(item, str))
                                    if re.search(watermark_pattern, combined_text, re.IGNORECASE):
                                        text_removed += 1
                                        skip_next_text = True
                                        continue
                            
                            elif op_str in ["'", '"']:
                                text = str(operands[-1]) if operands else ''
                                if re.search(watermark_pattern, text, re.IGNORECASE):
                                    text_removed += 1
                                    skip_next_text = True
                                    continue
                            
                            filtered.append((operands, operator))
                        
                        if len(filtered) < len(instructions):
                            page.Contents = pikepdf.unparse_content_stream(filtered)
                            pages_processed += 1
                    
                    except Exception as e:
                        logger.debug(f"Content stream parsing failed for page: {e}")
                        continue
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=text_removed > 0,
                    method_used="content_stream_text",
                    pages_processed=pages_processed,
                    watermarks_removed=text_removed,
                    message=f"Removed {text_removed} text elements from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="content_stream_text",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Content stream text removal failed: {e}"
            )
    
    def _remove_content_stream_graphics(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove graphics watermarks by editing content streams"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                graphics_removed = 0
                
                for page in pdf.pages:
                    if '/Contents' not in page:
                        continue
                    
                    try:
                        instructions = pikepdf.parse_content_stream(page)
                        filtered = []
                        in_graphics_block = False
                        block_instructions = []
                        has_transparency = False
                        
                        for operands, operator in instructions:
                            op_str = str(operator)
                            
                            if op_str == 'q':
                                in_graphics_block = True
                                block_instructions = [(operands, operator)]
                                has_transparency = False
                            
                            elif in_graphics_block:
                                block_instructions.append((operands, operator))
                                
                                if op_str == 'gs':
                                    has_transparency = True
                                
                                if op_str == 'Q':
                                    if has_transparency and len(block_instructions) < 20:
                                        graphics_removed += 1
                                    else:
                                        filtered.extend(block_instructions)
                                    
                                    in_graphics_block = False
                                    block_instructions = []
                            
                            else:
                                filtered.append((operands, operator))
                        
                        if len(filtered) < len(instructions):
                            page.Contents = pikepdf.unparse_content_stream(filtered)
                            pages_processed += 1
                    
                    except Exception as e:
                        logger.debug(f"Graphics stream parsing failed for page: {e}")
                        continue
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=graphics_removed > 0,
                    method_used="content_stream_graphics",
                    pages_processed=pages_processed,
                    watermarks_removed=graphics_removed,
                    message=f"Removed {graphics_removed} graphics blocks from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="content_stream_graphics",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Content stream graphics removal failed: {e}"
            )
    
    def _remove_background(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove background objects (watermarks placed behind content)"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                backgrounds_removed = 0
                
                for page in pdf.pages:
                    if '/Background' in page:
                        del page.Background
                        backgrounds_removed += 1
                        pages_processed += 1
                    
                    if '/Contents' in page:
                        contents = page.Contents
                        
                        if isinstance(contents, pikepdf.Array) and len(contents) > 1:
                            first_stream = contents[0]
                            
                            if self._is_likely_watermark_stream(first_stream):
                                page.Contents = pikepdf.Array(contents[1:])
                                backgrounds_removed += 1
                                pages_processed += 1
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=backgrounds_removed > 0,
                    method_used="background",
                    pages_processed=pages_processed,
                    watermarks_removed=backgrounds_removed,
                    message=f"Removed {backgrounds_removed} background layers from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="background",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Background removal failed: {e}"
            )
    
    def _is_likely_watermark_stream(self, stream: pikepdf.Stream) -> bool:
        """Heuristic to identify watermark streams"""
        try:
            data = stream.read_bytes()
            
            if len(data) > 2000:
                return False
            
            has_transparency = b'/ExtGState' in data or b'/GS' in data
            has_text = b'Tj' in data or b'TJ' in data
            has_images = b'Do' in data
            
            return has_transparency and (has_text or has_images)
        
        except Exception:
            return False
    
    def _remove_zorder(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove watermarks by reordering content streams (z-order manipulation)"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                streams_removed = 0
                
                for page in pdf.pages:
                    if '/Contents' not in page:
                        continue
                    
                    contents = page.Contents
                    
                    if not isinstance(contents, pikepdf.Array):
                        continue
                    
                    if len(contents) <= 1:
                        continue
                    
                    stream_analysis = []
                    for i, stream in enumerate(contents):
                        analysis = self._analyze_stream(stream)
                        stream_analysis.append((i, analysis))
                    
                    watermark_indices = self._identify_watermark_streams(stream_analysis)
                    
                    if watermark_indices:
                        new_contents = [
                            stream for i, stream in enumerate(contents)
                            if i not in watermark_indices
                        ]
                        
                        if new_contents:
                            page.Contents = pikepdf.Array(new_contents)
                            streams_removed += len(watermark_indices)
                            pages_processed += 1
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=streams_removed > 0,
                    method_used="zorder",
                    pages_processed=pages_processed,
                    watermarks_removed=streams_removed,
                    message=f"Removed {streams_removed} overlay streams from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="zorder",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Z-order manipulation failed: {e}"
            )
    
    def _analyze_stream(self, stream: pikepdf.Stream) -> Dict[str, Any]:
        """Analyze stream properties to identify watermarks"""
        try:
            data = stream.read_bytes()
            
            return {
                'size': len(data),
                'has_transparency': b'/ExtGState' in data or b'/GS' in data,
                'has_text': b'Tj' in data or b'TJ' in data,
                'has_images': b'Do' in data,
                'text_count': data.count(b'Tj') + data.count(b'TJ'),
            }
        
        except Exception:
            return {'size': 0, 'has_transparency': False, 'has_text': False, 'has_images': False, 'text_count': 0}
    
    def _identify_watermark_streams(self, stream_analysis: List[Tuple[int, Dict]]) -> List[int]:
        """Identify watermark streams based on analysis"""
        watermark_indices = []
        
        for idx, analysis in stream_analysis:
            if (analysis['size'] < 1500 and 
                analysis['has_transparency'] and
                (analysis['has_text'] or analysis['has_images'])):
                watermark_indices.append(idx)
        
        return watermark_indices
    
    def _remove_invisible_text(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove invisible text layers (rendering mode 3, white-on-white)"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                invisible_text_removed = 0
                
                for page in pdf.pages:
                    if '/Contents' not in page:
                        continue
                    
                    try:
                        instructions = pikepdf.parse_content_stream(page)
                        filtered = []
                        current_rendering_mode = 0
                        current_color = None
                        
                        for operands, operator in instructions:
                            op_str = str(operator)
                            
                            if op_str == 'Tr':
                                current_rendering_mode = int(operands[0]) if operands else 0
                            
                            elif op_str in ['g', 'rg', 'k']:
                                current_color = operands
                            
                            elif op_str in ['Tj', 'TJ', "'", '"']:
                                if current_rendering_mode == 3:
                                    invisible_text_removed += 1
                                    continue
                                
                                if current_color and self._is_white_color(current_color):
                                    invisible_text_removed += 1
                                    continue
                            
                            filtered.append((operands, operator))
                        
                        if len(filtered) < len(instructions):
                            page.Contents = pikepdf.unparse_content_stream(filtered)
                            pages_processed += 1
                    
                    except Exception as e:
                        logger.debug(f"Invisible text removal failed for page: {e}")
                        continue
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=invisible_text_removed > 0,
                    method_used="invisible_text",
                    pages_processed=pages_processed,
                    watermarks_removed=invisible_text_removed,
                    message=f"Removed {invisible_text_removed} invisible text elements from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="invisible_text",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Invisible text removal failed: {e}"
            )
    
    def _is_white_color(self, color: List) -> bool:
        """Check if color is white (background color)"""
        try:
            if len(color) == 1:
                return float(color[0]) >= 0.95
            elif len(color) == 3:
                return all(float(c) >= 0.95 for c in color)
            elif len(color) == 4:
                return all(float(c) <= 0.05 for c in color)
            return False
        except Exception:
            return False
    
    def _remove_transparency(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove transparency-based watermarks (soft masks, transparency groups)"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                pages_processed = 0
                transparency_removed = 0
                
                for page in pdf.pages:
                    if '/Group' in page:
                        group = page.Group
                        if isinstance(group, pikepdf.Dictionary):
                            if group.get('/S') == pikepdf.Name('/Transparency'):
                                if group.get('/I', False):
                                    transparency_removed += 1
                    
                    if '/Resources' in page and '/ExtGState' in page.Resources:
                        gs_dict = page.Resources.ExtGState
                        
                        for gs_name in list(gs_dict.keys()):
                            gs_obj = gs_dict[gs_name]
                            
                            if isinstance(gs_obj, pikepdf.Dictionary) and '/SMask' in gs_obj:
                                del gs_obj['/SMask']
                                transparency_removed += 1
                                pages_processed += 1
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=transparency_removed > 0,
                    method_used="transparency",
                    pages_processed=pages_processed,
                    watermarks_removed=transparency_removed,
                    message=f"Removed {transparency_removed} transparency elements from {pages_processed} pages"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="transparency",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Transparency removal failed: {e}"
            )
    
    def _remove_forensic_metadata(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Remove forensic/invisible watermarks in metadata and XMP"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                metadata_removed = 0
                
                if '/Metadata' in pdf.Root:
                    del pdf.Root.Metadata
                    metadata_removed += 1
                
                if pdf.docinfo:
                    standard_fields = ['/Title', '/Author', '/Subject', '/Keywords',
                                     '/Creator', '/Producer', '/CreationDate', '/ModDate']
                    
                    for key in list(pdf.docinfo.keys()):
                        if key not in standard_fields:
                            del pdf.docinfo[key]
                            metadata_removed += 1
                
                for page in pdf.pages:
                    if '/PieceInfo' in page:
                        del page.PieceInfo
                        metadata_removed += 1
                
                if '/PieceInfo' in pdf.Root:
                    del pdf.Root.PieceInfo
                    metadata_removed += 1
                
                pdf.save(output_path)
                
                return RemovalResult(
                    success=metadata_removed > 0,
                    method_used="forensic_metadata",
                    pages_processed=len(pdf.pages),
                    watermarks_removed=metadata_removed,
                    message=f"Removed {metadata_removed} metadata elements (forensic watermarks)"
                )
        
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="forensic_metadata",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Forensic metadata removal failed: {e}"
            )
    
    def _remove_ghostscript(
        self,
        output_path: Path,
        watermark_pattern: Optional[str],
        crop_params: Optional[Dict[str, float]]
    ) -> RemovalResult:
        """Use Ghostscript to filter and re-render PDF (lossy fallback)"""
        gs_status = check_external_tool('gs')
        gs_available = gs_status.available
        gs_path = gs_status.path or 'gs'
        
        if not gs_available:
            return RemovalResult(
                success=False,
                method_used="ghostscript",
                pages_processed=0,
                watermarks_removed=0,
                message="Ghostscript not available. Install from: https://www.ghostscript.com/"
            )
        
        try:
            cmd = [
                gs_path,
                '-dBATCH',
                '-dNOPAUSE',
                '-sDEVICE=pdfwrite',
                '-dFILTERTEXT',
                f'-sOutputFile={output_path}',
                str(self.pdf_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and output_path.exists():
                return RemovalResult(
                    success=True,
                    method_used="ghostscript",
                    pages_processed=-1,
                    watermarks_removed=-1,
                    message="PDF re-rendered with Ghostscript (lossy, text filtered)"
                )
            else:
                return RemovalResult(
                    success=False,
                    method_used="ghostscript",
                    pages_processed=0,
                    watermarks_removed=0,
                    message=f"Ghostscript failed: {result.stderr}"
                )
        
        except subprocess.TimeoutExpired:
            return RemovalResult(
                success=False,
                method_used="ghostscript",
                pages_processed=0,
                watermarks_removed=0,
                message="Ghostscript timeout (5 minutes)"
            )
        except Exception as e:
            return RemovalResult(
                success=False,
                method_used="ghostscript",
                pages_processed=0,
                watermarks_removed=0,
                message=f"Ghostscript execution failed: {e}"
            )


class WatermarkAdder:
    """Add watermarks to PDFs"""
    
    def __init__(self, pdf_path: Path):
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
    
    def add_text(
        self,
        output_path: Path,
        text: str,
        position: str = 'center',
        font_size: int = 48,
        opacity: float = 0.3,
        rotation: int = 45,
        color: Tuple[float, float, float] = (0.5, 0.5, 0.5)
    ) -> bool:
        """Add text watermark to PDF"""
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                for page in pdf.pages:
                    mediabox = page.MediaBox
                    page_width = float(mediabox[2]) - float(mediabox[0])
                    page_height = float(mediabox[3]) - float(mediabox[1])
                    
                    if position == 'center':
                        x = page_width / 2
                        y = page_height / 2
                    elif position == 'top':
                        x = page_width / 2
                        y = page_height - 50
                    elif position == 'bottom':
                        x = page_width / 2
                        y = 50
                    else:
                        x = page_width / 2
                        y = page_height / 2
                    
                    watermark_content = f"""
                    q
                    /GS1 gs
                    BT
                    {color[0]} {color[1]} {color[2]} rg
                    /F1 {font_size} Tf
                    1 0 0 1 {x} {y} Tm
                    {rotation} rotate
                    ({text}) Tj
                    ET
                    Q
                    """
                    
                    new_stream = pikepdf.Stream(pdf, watermark_content.encode('latin-1'))
                    
                    if '/Contents' in page:
                        contents = page.Contents
                        if isinstance(contents, pikepdf.Array):
                            contents.append(new_stream)
                        else:
                            page.Contents = pikepdf.Array([contents, new_stream])
                    else:
                        page.Contents = new_stream
                    
                    if '/Resources' not in page:
                        page.Resources = pikepdf.Dictionary()
                    
                    if '/ExtGState' not in page.Resources:
                        page.Resources.ExtGState = pikepdf.Dictionary()
                    
                    page.Resources.ExtGState.GS1 = pikepdf.Dictionary({
                        '/Type': pikepdf.Name('/ExtGState'),
                        '/ca': opacity,
                        '/CA': opacity
                    })
                    
                    if '/Font' not in page.Resources:
                        page.Resources.Font = pikepdf.Dictionary()
                    
                    page.Resources.Font.F1 = pikepdf.Dictionary({
                        '/Type': pikepdf.Name('/Font'),
                        '/Subtype': pikepdf.Name('/Type1'),
                        '/BaseFont': pikepdf.Name('/Helvetica')
                    })
                
                pdf.save(output_path)
                logger.info(f"Added text watermark to {len(pdf.pages)} pages")
                return True
        
        except Exception as e:
            logger.error(f"Failed to add watermark: {e}")
            return False
