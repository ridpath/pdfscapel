"""Watermark detection and classification"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter

import pikepdf
import pdfplumber

from pdfscalpel.core.constants import WatermarkType, RemovalDifficulty
from pdfscalpel.core.exceptions import PDFScalpelError
from pdfscalpel.core.logging import get_logger

logger = get_logger()


WATERMARK_TEXT_PATTERNS = [
    r'\b(DRAFT|CONFIDENTIAL|COPY|SAMPLE|PREVIEW|WATERMARK)\b',
    r'\b(NOT FOR DISTRIBUTION|FOR REVIEW ONLY)\b',
    r'\b(CLASSIFIED|RESTRICTED|SECRET)\b',
]


@dataclass
class WatermarkInfo:
    """Information about detected watermark"""
    type: WatermarkType
    confidence: float
    position: Optional[Tuple[float, float, float, float]] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    removal_difficulty: RemovalDifficulty = RemovalDifficulty.MEDIUM
    removal_strategy: str = ""
    ctf_angle: Optional[str] = None
    pages_affected: List[int] = field(default_factory=list)


@dataclass
class WatermarkAnalysisResult:
    """Complete watermark analysis result"""
    watermarks: List[WatermarkInfo]
    total_pages: int
    analysis_confidence: float
    recommendations: List[str] = field(default_factory=list)


class WatermarkAnalyzer:
    """Comprehensive watermark detection and classification"""
    
    def __init__(self, pdf_path: Path):
        self.pdf_path = pdf_path
        self.watermarks: List[WatermarkInfo] = []
        
    def analyze(self) -> WatermarkAnalysisResult:
        """Perform comprehensive watermark analysis"""
        logger.info(f"Analyzing watermarks in: {self.pdf_path}")
        
        try:
            with pikepdf.Pdf.open(self.pdf_path) as pdf:
                total_pages = len(pdf.pages)
                
                self._detect_ocg_watermarks(pdf)
                self._detect_xobject_watermarks(pdf)
                self._detect_annotation_watermarks(pdf)
                self._detect_background_watermarks(pdf)
                self._detect_text_watermarks(pdf)
                self._detect_transparency_watermarks(pdf)
                
                overall_confidence = self._calculate_overall_confidence()
                recommendations = self._generate_recommendations()
                
                return WatermarkAnalysisResult(
                    watermarks=self.watermarks,
                    total_pages=total_pages,
                    analysis_confidence=overall_confidence,
                    recommendations=recommendations
                )
        
        except Exception as e:
            raise PDFScalpelError(f"Watermark analysis failed: {e}")
    
    def _detect_ocg_watermarks(self, pdf: pikepdf.Pdf) -> None:
        """Detect Optional Content Groups (layers) that contain watermarks"""
        try:
            if '/OCProperties' not in pdf.Root:
                return
            
            oc_props = pdf.Root.OCProperties
            if '/OCGs' not in oc_props:
                return
            
            ocgs = oc_props.OCGs
            if not isinstance(ocgs, list):
                ocgs = [ocgs]
            
            for ocg in ocgs:
                if not isinstance(ocg, pikepdf.Dictionary):
                    continue
                
                name = str(ocg.get('/Name', ''))
                
                if self._is_watermark_layer_name(name):
                    pages_with_ocg = self._find_pages_using_ocg(pdf, ocg)
                    
                    confidence = 0.85
                    if len(pages_with_ocg) > len(pdf.pages) * 0.5:
                        confidence = 0.95
                    
                    watermark = WatermarkInfo(
                        type=WatermarkType.OCG_BASED,
                        confidence=confidence,
                        properties={
                            'layer_name': name,
                            'ocg_reference': str(ocg.objgen),
                        },
                        removal_difficulty=RemovalDifficulty.EASY,
                        removal_strategy="Toggle layer visibility or remove OCG references from page resources",
                        ctf_angle="Extract and analyze OCG content separately; check if flag is hidden in layer metadata",
                        pages_affected=pages_with_ocg
                    )
                    self.watermarks.append(watermark)
                    logger.info(f"Detected OCG watermark: {name}")
        
        except Exception as e:
            logger.debug(f"OCG detection error: {e}")
    
    def _detect_xobject_watermarks(self, pdf: pikepdf.Pdf) -> None:
        """Detect Form XObjects reused across multiple pages"""
        xobject_usage = {}
        xobject_pages = {}
        
        for page_num, page in enumerate(pdf.pages, 1):
            try:
                if '/Resources' not in page or '/XObject' not in page.Resources:
                    continue
                
                xobjects = page.Resources.XObject
                for name, xobj_ref in xobjects.items():
                    obj_id = str(xobj_ref.objgen) if hasattr(xobj_ref, 'objgen') else str(xobj_ref)
                    xobject_usage[obj_id] = xobject_usage.get(obj_id, 0) + 1
                    
                    if obj_id not in xobject_pages:
                        xobject_pages[obj_id] = []
                    xobject_pages[obj_id].append(page_num)
            
            except Exception as e:
                logger.debug(f"XObject detection error on page {page_num}: {e}")
        
        threshold = max(1, len(pdf.pages) * 0.5)
        
        for obj_id, count in xobject_usage.items():
            if count >= threshold:
                confidence = min(0.95, 0.6 + (count / len(pdf.pages)) * 0.35)
                
                watermark = WatermarkInfo(
                    type=WatermarkType.XOBJECT_REUSE,
                    confidence=confidence,
                    properties={
                        'xobject_id': obj_id,
                        'usage_count': count,
                        'total_pages': len(pdf.pages),
                        'usage_percentage': count / len(pdf.pages) * 100
                    },
                    removal_difficulty=RemovalDifficulty.MEDIUM,
                    removal_strategy="Remove 'Do' operators referencing this XObject from page content streams",
                    ctf_angle="Extract XObject content separately; may contain hidden data or flag in stream",
                    pages_affected=xobject_pages[obj_id]
                )
                self.watermarks.append(watermark)
                logger.info(f"Detected reused XObject watermark: {obj_id} ({count}/{len(pdf.pages)} pages)")
    
    def _detect_annotation_watermarks(self, pdf: pikepdf.Pdf) -> None:
        """Detect annotation-based watermarks"""
        for page_num, page in enumerate(pdf.pages, 1):
            try:
                if '/Annots' not in page:
                    continue
                
                annots = page.Annots
                if not isinstance(annots, list):
                    annots = [annots]
                
                for annot in annots:
                    if not isinstance(annot, pikepdf.Dictionary):
                        continue
                    
                    subtype = str(annot.get('/Subtype', ''))
                    
                    if subtype in ['/Watermark', '/Stamp', '/FreeText']:
                        contents = str(annot.get('/Contents', ''))
                        
                        is_watermark, confidence = self._is_watermark_annotation(annot, contents)
                        
                        if is_watermark:
                            rect = annot.get('/Rect', [0, 0, 0, 0])
                            position = tuple(float(x) for x in rect)
                            
                            watermark = WatermarkInfo(
                                type=WatermarkType.ANNOTATION_BASED,
                                confidence=confidence,
                                position=position,
                                properties={
                                    'annotation_type': subtype,
                                    'contents': contents,
                                    'page': page_num
                                },
                                removal_difficulty=RemovalDifficulty.TRIVIAL,
                                removal_strategy="Remove annotation from page.Annots array",
                                ctf_angle="Check annotation contents and appearance stream for hidden data",
                                pages_affected=[page_num]
                            )
                            self.watermarks.append(watermark)
                            logger.info(f"Detected annotation watermark on page {page_num}: {subtype}")
            
            except Exception as e:
                logger.debug(f"Annotation detection error on page {page_num}: {e}")
    
    def _detect_background_watermarks(self, pdf: pikepdf.Pdf) -> None:
        """Detect background objects or first content stream watermarks"""
        for page_num, page in enumerate(pdf.pages, 1):
            try:
                if '/Contents' not in page:
                    continue
                
                contents = page.Contents
                
                if isinstance(contents, pikepdf.Array) and len(contents) > 1:
                    first_stream = contents[0]
                    
                    if self._is_likely_watermark_stream(first_stream):
                        watermark = WatermarkInfo(
                            type=WatermarkType.TEXT_OVERLAY,
                            confidence=0.65,
                            properties={
                                'stream_index': 0,
                                'stream_count': len(contents),
                                'page': page_num
                            },
                            removal_difficulty=RemovalDifficulty.EASY,
                            removal_strategy="Remove first content stream from page.Contents array",
                            ctf_angle="Extract and decode first stream separately",
                            pages_affected=[page_num]
                        )
                        self.watermarks.append(watermark)
                        logger.info(f"Detected background watermark on page {page_num}")
            
            except Exception as e:
                logger.debug(f"Background detection error on page {page_num}: {e}")
    
    def _detect_text_watermarks(self, pdf: pikepdf.Pdf) -> None:
        """Detect text overlay watermarks using pdfplumber"""
        try:
            with pdfplumber.open(self.pdf_path) as pdf_text:
                text_patterns = Counter()
                page_texts = {}
                
                for page_num, page in enumerate(pdf_text.pages, 1):
                    text = page.extract_text() or ""
                    page_texts[page_num] = text
                    
                    for pattern in WATERMARK_TEXT_PATTERNS:
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        for match in matches:
                            text_patterns[match.upper()] += 1
                
                threshold = max(1, len(pdf_text.pages) * 0.3)
                
                for text, count in text_patterns.items():
                    if count >= threshold:
                        pages_with_text = [
                            page_num for page_num, text_content in page_texts.items()
                            if text.lower() in text_content.lower()
                        ]
                        
                        confidence = min(0.90, 0.5 + (count / len(pdf_text.pages)) * 0.4)
                        
                        watermark = WatermarkInfo(
                            type=WatermarkType.TEXT_OVERLAY,
                            confidence=confidence,
                            properties={
                                'text': text,
                                'occurrence_count': count,
                                'total_pages': len(pdf_text.pages)
                            },
                            removal_difficulty=RemovalDifficulty.MEDIUM,
                            removal_strategy="Parse content streams and remove Tj/TJ text operators matching watermark pattern",
                            ctf_angle="Text may be encoded or positioned to hide flag characters",
                            pages_affected=pages_with_text
                        )
                        self.watermarks.append(watermark)
                        logger.info(f"Detected text watermark: '{text}' ({count}/{len(pdf_text.pages)} pages)")
        
        except Exception as e:
            logger.debug(f"Text watermark detection error: {e}")
    
    def _detect_transparency_watermarks(self, pdf: pikepdf.Pdf) -> None:
        """Detect transparency group or graphics state based watermarks"""
        transparency_pages = []
        
        for page_num, page in enumerate(pdf.pages, 1):
            try:
                if '/Resources' not in page:
                    continue
                
                resources = page.Resources
                
                if '/ExtGState' in resources:
                    ext_gstates = resources.ExtGState
                    
                    for name, gs in ext_gstates.items():
                        if not isinstance(gs, pikepdf.Dictionary):
                            continue
                        
                        if '/ca' in gs or '/CA' in gs:
                            transparency_pages.append(page_num)
                            break
                
                if '/Group' in page:
                    group = page.Group
                    if isinstance(group, pikepdf.Dictionary) and group.get('/S') == '/Transparency':
                        if page_num not in transparency_pages:
                            transparency_pages.append(page_num)
            
            except Exception as e:
                logger.debug(f"Transparency detection error on page {page_num}: {e}")
        
        if len(transparency_pages) >= len(pdf.pages) * 0.3:
            watermark = WatermarkInfo(
                type=WatermarkType.TRANSPARENCY_GROUP,
                confidence=0.70,
                properties={
                    'transparency_page_count': len(transparency_pages),
                    'total_pages': len(pdf.pages)
                },
                removal_difficulty=RemovalDifficulty.HARD,
                removal_strategy="Complex: requires content stream parsing to identify and remove transparency operators with watermark content",
                ctf_angle="Transparency may hide layers; try different PDF viewers to see different renderings",
                pages_affected=transparency_pages
            )
            self.watermarks.append(watermark)
            logger.info(f"Detected transparency-based watermark on {len(transparency_pages)} pages")
    
    def _is_watermark_layer_name(self, name: str) -> bool:
        """Check if layer name indicates watermark"""
        watermark_keywords = [
            'watermark', 'background', 'logo', 'draft', 'confidential',
            'copy', 'stamp', 'overlay', 'wm', 'marca'
        ]
        name_lower = name.lower()
        return any(keyword in name_lower for keyword in watermark_keywords)
    
    def _find_pages_using_ocg(self, pdf: pikepdf.Pdf, ocg: pikepdf.Object) -> List[int]:
        """Find pages that reference a specific OCG"""
        pages = []
        for page_num, page in enumerate(pdf.pages, 1):
            try:
                if '/Resources' in page and '/Properties' in page.Resources:
                    props = page.Resources.Properties
                    for prop_name, prop_ref in props.items():
                        if prop_ref == ocg:
                            pages.append(page_num)
                            break
            except Exception:
                pass
        return pages if pages else list(range(1, len(pdf.pages) + 1))
    
    def _is_watermark_annotation(self, annot: pikepdf.Dictionary, contents: str) -> Tuple[bool, float]:
        """Check if annotation is likely a watermark"""
        confidence = 0.0
        
        subtype = str(annot.get('/Subtype', ''))
        if subtype == '/Watermark':
            return True, 0.95
        
        if subtype in ['/Stamp', '/FreeText']:
            confidence = 0.5
            
            for pattern in WATERMARK_TEXT_PATTERNS:
                if re.search(pattern, contents, re.IGNORECASE):
                    confidence = 0.85
                    return True, confidence
            
            if any(kw in contents.lower() for kw in ['watermark', 'draft', 'confidential']):
                return True, 0.80
            
            if confidence > 0:
                return True, confidence
        
        return False, 0.0
    
    def _is_likely_watermark_stream(self, stream: pikepdf.Object) -> bool:
        """Heuristic check if stream contains watermark"""
        try:
            if not isinstance(stream, pikepdf.Stream):
                return False
            
            data = stream.read_bytes()
            
            if len(data) < 500:
                if b'/ExtGState' in data or b'/GS' in data:
                    return True
                
                if b'/Tj' in data or b'/TJ' in data:
                    for pattern_bytes in [b'DRAFT', b'CONFIDENTIAL', b'WATERMARK', b'COPY']:
                        if pattern_bytes in data.upper():
                            return True
            
            return False
        
        except Exception:
            return False
    
    def _calculate_overall_confidence(self) -> float:
        """Calculate overall confidence in watermark detection"""
        if not self.watermarks:
            return 0.0
        
        total_confidence = sum(wm.confidence for wm in self.watermarks)
        return min(1.0, total_confidence / len(self.watermarks))
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []
        
        if not self.watermarks:
            recommendations.append("No watermarks detected")
            return recommendations
        
        recommendations.append(f"Found {len(self.watermarks)} watermark(s)")
        
        easiest = min(self.watermarks, key=lambda w: w.removal_difficulty.value)
        recommendations.append(
            f"Easiest removal: {easiest.type.value} ({easiest.removal_difficulty.value})"
        )
        recommendations.append(f"Strategy: {easiest.removal_strategy}")
        
        ocg_watermarks = [w for w in self.watermarks if w.type == WatermarkType.OCG_BASED]
        if ocg_watermarks:
            recommendations.append(
                f"OCG-based watermarks detected: Use 'pdfautopsy mutate watermark --remove ocg' for quick removal"
            )
        
        xobject_watermarks = [w for w in self.watermarks if w.type == WatermarkType.XOBJECT_REUSE]
        if xobject_watermarks:
            xobj_id = xobject_watermarks[0].properties.get('xobject_id')
            recommendations.append(
                f"Reused XObject detected: Extract XObject {xobj_id} separately for analysis"
            )
        
        if any(w.confidence < 0.7 for w in self.watermarks):
            recommendations.append(
                "Low confidence detections present: Manual verification recommended"
            )
        
        return recommendations


def analyze_watermark(pdf_path: Path, verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze watermarks in PDF
    
    Args:
        pdf_path: Path to PDF file
        verbose: Include detailed analysis
    
    Returns:
        Dictionary containing analysis results
    """
    analyzer = WatermarkAnalyzer(pdf_path)
    result = analyzer.analyze()
    
    output = {
        'total_watermarks': len(result.watermarks),
        'total_pages': result.total_pages,
        'analysis_confidence': result.analysis_confidence,
        'watermarks': [],
        'recommendations': result.recommendations
    }
    
    for wm in result.watermarks:
        wm_dict = {
            'type': wm.type.value,
            'confidence': wm.confidence,
            'removal_difficulty': wm.removal_difficulty.value,
            'removal_strategy': wm.removal_strategy,
            'pages_affected': wm.pages_affected,
            'pages_count': len(wm.pages_affected)
        }
        
        if verbose:
            wm_dict['properties'] = wm.properties
            wm_dict['ctf_angle'] = wm.ctf_angle
            if wm.position:
                wm_dict['position'] = wm.position
        
        output['watermarks'].append(wm_dict)
    
    return output
