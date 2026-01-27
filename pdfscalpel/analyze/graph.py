"""PDF object graph visualization and entropy analysis"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict
import math
import struct

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError, DependencyMissingError

logger = get_logger()


class PDFObjectGraphGenerator:
    """Generate object graph visualizations in DOT format"""
    
    OBJECT_COLORS = {
        'Catalog': '#FF6B6B',
        'Pages': '#4ECDC4',
        'Page': '#45B7D1',
        'Font': '#FFA07A',
        'XObject': '#98D8C8',
        'Image': '#F7DC6F',
        'Metadata': '#BB8FCE',
        'JavaScript': '#E74C3C',
        'Action': '#E67E22',
        'Annotation': '#95A5A6',
        'EmbeddedFile': '#E8DAEF',
        'Stream': '#85C1E9',
        'Encrypt': '#EC7063',
        'Default': '#BDC3C7',
    }
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
        self.visited: Set[str] = set()
        self.edges: List[Tuple[str, str, str]] = []
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.entropy_analyzer = PDFEntropyAnalyzer(pdf_doc)
    
    def generate_graph(
        self,
        max_depth: int = -1,
        include_entropy: bool = True,
        filter_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate PDF object graph
        
        Args:
            max_depth: Maximum traversal depth (-1 for unlimited)
            include_entropy: Include entropy metrics in nodes
            filter_types: Only include specific object types
        
        Returns:
            Graph data structure with nodes and edges
        """
        logger.info(f"Generating object graph: {self.pdf_doc.path}")
        
        self.visited.clear()
        self.edges.clear()
        self.nodes.clear()
        
        if include_entropy:
            entropy_data = self.entropy_analyzer.analyze_all_objects()
        else:
            entropy_data = {}
        
        try:
            root = self.pdf.Root
            self._traverse_object(root, 'Root', depth=0, max_depth=max_depth, 
                                 entropy_data=entropy_data, filter_types=filter_types)
            
            if self.pdf.trailer and '/Encrypt' in self.pdf.trailer:
                encrypt = self.pdf.trailer['/Encrypt']
                self._traverse_object(encrypt, 'Encrypt', depth=0, max_depth=max_depth,
                                     entropy_data=entropy_data, filter_types=filter_types)
        
        except Exception as e:
            logger.warning(f"Failed to traverse object graph: {e}")
        
        return {
            'nodes': self.nodes,
            'edges': self.edges,
            'statistics': self._calculate_graph_statistics(),
        }
    
    def _get_object_id(self, obj: Any) -> Optional[str]:
        """Get object ID as string"""
        try:
            if hasattr(obj, 'objgen'):
                objgen = obj.objgen
                return f"{objgen[0]}_{objgen[1]}"
            return None
        except Exception:
            return None
    
    def _traverse_object(
        self,
        obj: Any,
        label: str,
        depth: int,
        max_depth: int,
        entropy_data: Dict[str, float],
        filter_types: Optional[List[str]],
        parent_id: Optional[str] = None,
    ):
        """Recursively traverse PDF object tree"""
        if max_depth >= 0 and depth > max_depth:
            return
        
        obj_id = self._get_object_id(obj)
        if not obj_id:
            return
        
        if obj_id in self.visited:
            if parent_id:
                self.edges.append((parent_id, obj_id, 'ref'))
            return
        
        self.visited.add(obj_id)
        
        obj_type = self._get_object_type(obj)
        
        if filter_types and obj_type not in filter_types:
            return
        
        entropy = entropy_data.get(obj_id, 0.0)
        
        self.nodes[obj_id] = {
            'label': label,
            'type': obj_type,
            'color': self.OBJECT_COLORS.get(obj_type, self.OBJECT_COLORS['Default']),
            'entropy': entropy,
            'depth': depth,
            'suspicious': self._is_suspicious(obj, entropy),
        }
        
        if parent_id:
            self.edges.append((parent_id, obj_id, self._get_edge_label(obj)))
        
        if isinstance(obj, pikepdf.Dictionary):
            for key, value in obj.items():
                if isinstance(value, (pikepdf.Dictionary, pikepdf.Array)):
                    child_label = str(key).replace('/', '')
                    self._traverse_object(value, child_label, depth + 1, max_depth,
                                         entropy_data, filter_types, obj_id)
                elif isinstance(value, pikepdf.Stream):
                    child_label = f"{str(key).replace('/', '')}_stream"
                    self._traverse_object(value, child_label, depth + 1, max_depth,
                                         entropy_data, filter_types, obj_id)
        
        elif isinstance(obj, pikepdf.Array):
            for i, item in enumerate(obj):
                if isinstance(item, (pikepdf.Dictionary, pikepdf.Array, pikepdf.Stream)):
                    child_label = f"{label}[{i}]"
                    self._traverse_object(item, child_label, depth + 1, max_depth,
                                         entropy_data, filter_types, obj_id)
    
    def _get_object_type(self, obj: Any) -> str:
        """Determine object type"""
        try:
            if isinstance(obj, pikepdf.Dictionary):
                obj_type = obj.get('/Type')
                if obj_type:
                    return str(obj_type).replace('/', '')
                
                if obj.get('/JS') or obj.get('/JavaScript'):
                    return 'JavaScript'
                if obj.get('/S'):
                    s_val = str(obj.get('/S'))
                    if 'Action' in s_val or 'Launch' in s_val or 'URI' in s_val:
                        return 'Action'
                if obj.get('/EF'):
                    return 'EmbeddedFile'
                
                return 'Dictionary'
            
            elif isinstance(obj, pikepdf.Stream):
                obj_type = obj.get('/Type')
                if obj_type:
                    return str(obj_type).replace('/', '')
                
                subtype = obj.get('/Subtype')
                if subtype:
                    subtype_str = str(subtype).replace('/', '')
                    if 'Image' in subtype_str:
                        return 'Image'
                
                return 'Stream'
            
            elif isinstance(obj, pikepdf.Array):
                return 'Array'
            
            else:
                return 'Other'
        
        except Exception:
            return 'Unknown'
    
    def _get_edge_label(self, obj: Any) -> str:
        """Get descriptive edge label"""
        obj_type = self._get_object_type(obj)
        
        if obj_type == 'JavaScript':
            return 'js'
        elif obj_type == 'Action':
            return 'action'
        elif obj_type == 'EmbeddedFile':
            return 'embed'
        elif obj_type == 'Stream':
            return 'stream'
        elif obj_type == 'Image':
            return 'image'
        else:
            return 'ref'
    
    def _is_suspicious(self, obj: Any, entropy: float) -> bool:
        """Determine if object is suspicious"""
        if entropy > 7.5:
            return True
        
        if isinstance(obj, pikepdf.Dictionary):
            if obj.get('/JavaScript') or obj.get('/JS'):
                return True
            
            if obj.get('/Launch') or obj.get('/URI'):
                return True
            
            s_val = obj.get('/S')
            if s_val:
                s_str = str(s_val)
                if any(x in s_str for x in ['Launch', 'ImportData', 'SubmitForm']):
                    return True
        
        return False
    
    def _calculate_graph_statistics(self) -> Dict[str, Any]:
        """Calculate graph statistics"""
        stats = {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'nodes_by_type': defaultdict(int),
            'suspicious_nodes': 0,
            'max_depth': 0,
            'avg_entropy': 0.0,
        }
        
        total_entropy = 0.0
        for node_data in self.nodes.values():
            stats['nodes_by_type'][node_data['type']] += 1
            if node_data['suspicious']:
                stats['suspicious_nodes'] += 1
            stats['max_depth'] = max(stats['max_depth'], node_data['depth'])
            total_entropy += node_data['entropy']
        
        if self.nodes:
            stats['avg_entropy'] = total_entropy / len(self.nodes)
        
        stats['nodes_by_type'] = dict(stats['nodes_by_type'])
        
        return stats
    
    def to_dot(self, graph_data: Dict[str, Any], title: str = "PDF Object Graph") -> str:
        """
        Convert graph data to DOT format
        
        Args:
            graph_data: Graph data from generate_graph()
            title: Graph title
        
        Returns:
            DOT format string
        """
        lines = [
            'digraph PDFObjects {',
            '  rankdir=TB;',
            '  node [shape=box, style=filled];',
            f'  labelloc="t";',
            f'  label="{title}";',
            '',
        ]
        
        for node_id, node_data in graph_data['nodes'].items():
            label = node_data['label']
            entropy = node_data['entropy']
            obj_type = node_data['type']
            color = node_data['color']
            
            if node_data['suspicious']:
                shape = 'box,bold'
                penwidth = '3'
            else:
                shape = 'box'
                penwidth = '1'
            
            node_label = f"{label}\\n({obj_type})\\nH={entropy:.2f}"
            
            lines.append(
                f'  "{node_id}" [label="{node_label}", fillcolor="{color}", '
                f'shape={shape}, penwidth={penwidth}];'
            )
        
        lines.append('')
        
        for src, dst, edge_label in graph_data['edges']:
            if edge_label == 'js':
                style = 'color=red, style=bold'
            elif edge_label == 'action':
                style = 'color=orange, style=dashed'
            elif edge_label == 'embed':
                style = 'color=purple'
            else:
                style = 'color=gray'
            
            lines.append(f'  "{src}" -> "{dst}" [label="{edge_label}", {style}];')
        
        lines.append('}')
        
        return '\n'.join(lines)
    
    def to_html(self, graph_data: Dict[str, Any], title: str = "PDF Object Graph") -> str:
        """
        Generate interactive HTML visualization using vis.js
        
        Args:
            graph_data: Graph data from generate_graph()
            title: Graph title
        
        Returns:
            HTML string with embedded JavaScript
        """
        import json
        
        vis_nodes = []
        for node_id, node_data in graph_data['nodes'].items():
            vis_nodes.append({
                'id': node_id,
                'label': f"{node_data['label']}\n{node_data['type']}\nH={node_data['entropy']:.2f}",
                'color': node_data['color'],
                'shape': 'box',
                'borderWidth': 3 if node_data['suspicious'] else 1,
                'title': f"Type: {node_data['type']}<br>Entropy: {node_data['entropy']:.4f}<br>Suspicious: {node_data['suspicious']}",
            })
        
        vis_edges = []
        for src, dst, edge_label in graph_data['edges']:
            color = {
                'js': '#E74C3C',
                'action': '#E67E22',
                'embed': '#9B59B6',
            }.get(edge_label, '#95A5A6')
            
            vis_edges.append({
                'from': src,
                'to': dst,
                'label': edge_label,
                'color': color,
                'arrows': 'to',
            })
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        #graph {{ width: 100%; height: 900px; border: 1px solid #ccc; }}
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        #stats {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .stat {{ display: inline-block; margin-right: 30px; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div id="stats">
        <div class="stat"><strong>Nodes:</strong> {graph_data['statistics']['total_nodes']}</div>
        <div class="stat"><strong>Edges:</strong> {graph_data['statistics']['total_edges']}</div>
        <div class="stat"><strong>Suspicious:</strong> {graph_data['statistics']['suspicious_nodes']}</div>
        <div class="stat"><strong>Avg Entropy:</strong> {graph_data['statistics']['avg_entropy']:.4f}</div>
        <div class="stat"><strong>Max Depth:</strong> {graph_data['statistics']['max_depth']}</div>
    </div>
    <div id="graph"></div>
    <script type="text/javascript">
        var nodes = new vis.DataSet({json.dumps(vis_nodes)});
        var edges = new vis.DataSet({json.dumps(vis_edges)});
        
        var container = document.getElementById('graph');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            layout: {{
                hierarchical: {{
                    direction: 'UD',
                    sortMethod: 'directed',
                    levelSeparation: 150,
                    nodeSpacing: 200,
                }}
            }},
            physics: false,
            nodes: {{
                font: {{ size: 12, face: 'monospace' }},
            }},
            edges: {{
                font: {{ size: 10, align: 'middle' }},
                smooth: {{ type: 'cubicBezier' }},
            }},
        }};
        
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>'''
        
        return html


class PDFEntropyAnalyzer:
    """Analyze entropy of PDF objects and streams"""
    
    def __init__(self, pdf_doc: PDFDocument):
        self.pdf_doc = pdf_doc
        self.pdf = pdf_doc.pdf
    
    def calculate_shannon_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Byte data
        
        Returns:
            Entropy value (0-8 bits)
        """
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count == 0:
                continue
            
            p = count / data_len
            entropy -= p * math.log2(p)
        
        return entropy
    
    def analyze_object(self, obj: Any) -> Dict[str, Any]:
        """
        Analyze entropy of a single object
        
        Args:
            obj: PDF object
        
        Returns:
            Entropy analysis results
        """
        result = {
            'entropy': 0.0,
            'size': 0,
            'type': 'unknown',
            'classification': 'normal',
        }
        
        try:
            if isinstance(obj, pikepdf.Stream):
                try:
                    raw_data = obj.read_raw_bytes()
                    result['entropy'] = self.calculate_shannon_entropy(raw_data)
                    result['size'] = len(raw_data)
                    result['type'] = 'stream_raw'
                    
                    try:
                        decoded_data = obj.read_bytes()
                        decoded_entropy = self.calculate_shannon_entropy(decoded_data)
                        result['decoded_entropy'] = decoded_entropy
                        result['decoded_size'] = len(decoded_data)
                        result['compression_ratio'] = len(decoded_data) / max(len(raw_data), 1)
                    except Exception:
                        pass
                
                except Exception as e:
                    logger.debug(f"Failed to read stream: {e}")
            
            elif isinstance(obj, pikepdf.Dictionary):
                obj_str = str(obj).encode('utf-8', errors='ignore')
                result['entropy'] = self.calculate_shannon_entropy(obj_str)
                result['size'] = len(obj_str)
                result['type'] = 'dictionary'
            
            elif isinstance(obj, pikepdf.Array):
                obj_str = str(obj).encode('utf-8', errors='ignore')
                result['entropy'] = self.calculate_shannon_entropy(obj_str)
                result['size'] = len(obj_str)
                result['type'] = 'array'
            
            result['classification'] = self._classify_entropy(result['entropy'], result.get('decoded_entropy'))
        
        except Exception as e:
            logger.debug(f"Failed to analyze object entropy: {e}")
        
        return result
    
    def _classify_entropy(self, raw_entropy: float, decoded_entropy: Optional[float] = None) -> str:
        """Classify data based on entropy patterns"""
        if raw_entropy > 7.9:
            return 'encrypted_or_compressed'
        elif raw_entropy > 7.5:
            return 'highly_compressed'
        elif raw_entropy > 6.5:
            return 'compressed'
        elif decoded_entropy is not None and decoded_entropy > 7.5:
            return 'high_entropy_content'
        elif raw_entropy < 3.0:
            return 'low_entropy'
        else:
            return 'normal'
    
    def analyze_all_objects(self) -> Dict[str, float]:
        """
        Analyze entropy of all PDF objects
        
        Returns:
            Dictionary mapping object IDs to entropy values
        """
        entropy_map = {}
        
        try:
            for obj_id in self.pdf.objects:
                try:
                    obj = self.pdf.get_object(obj_id)
                    analysis = self.analyze_object(obj)
                    
                    obj_id_str = f"{obj_id[0]}_{obj_id[1]}"
                    entropy_map[obj_id_str] = analysis['entropy']
                
                except Exception as e:
                    logger.debug(f"Failed to analyze object {obj_id}: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to enumerate objects: {e}")
        
        return entropy_map
    
    def analyze_document_entropy(self) -> Dict[str, Any]:
        """
        Comprehensive document entropy analysis
        
        Returns:
            Complete entropy analysis report
        """
        logger.info(f"Analyzing document entropy: {self.pdf_doc.path}")
        
        results = {
            'file_path': str(self.pdf_doc.path),
            'total_objects': 0,
            'entropy_distribution': {
                'encrypted_or_compressed': 0,
                'highly_compressed': 0,
                'compressed': 0,
                'high_entropy_content': 0,
                'normal': 0,
                'low_entropy': 0,
            },
            'suspicious_objects': [],
            'entropy_statistics': {
                'min': float('inf'),
                'max': 0.0,
                'mean': 0.0,
                'median': 0.0,
            },
            'object_details': [],
        }
        
        entropy_values = []
        
        try:
            for obj_id in self.pdf.objects:
                try:
                    obj = self.pdf.get_object(obj_id)
                    analysis = self.analyze_object(obj)
                    
                    results['total_objects'] += 1
                    entropy_values.append(analysis['entropy'])
                    
                    classification = analysis['classification']
                    results['entropy_distribution'][classification] += 1
                    
                    if classification in ['encrypted_or_compressed', 'high_entropy_content']:
                        obj_id_str = f"{obj_id[0]}_{obj_id[1]}"
                        results['suspicious_objects'].append({
                            'object_id': obj_id_str,
                            'entropy': analysis['entropy'],
                            'size': analysis['size'],
                            'type': analysis['type'],
                            'classification': classification,
                        })
                    
                    if len(results['object_details']) < 100:
                        obj_id_str = f"{obj_id[0]}_{obj_id[1]}"
                        results['object_details'].append({
                            'object_id': obj_id_str,
                            'entropy': analysis['entropy'],
                            'size': analysis['size'],
                            'type': analysis['type'],
                            'classification': classification,
                        })
                
                except Exception as e:
                    logger.debug(f"Failed to analyze object {obj_id}: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to enumerate objects: {e}")
        
        if entropy_values:
            results['entropy_statistics']['min'] = min(entropy_values)
            results['entropy_statistics']['max'] = max(entropy_values)
            results['entropy_statistics']['mean'] = sum(entropy_values) / len(entropy_values)
            
            sorted_values = sorted(entropy_values)
            mid = len(sorted_values) // 2
            if len(sorted_values) % 2 == 0:
                results['entropy_statistics']['median'] = (sorted_values[mid - 1] + sorted_values[mid]) / 2
            else:
                results['entropy_statistics']['median'] = sorted_values[mid]
        
        results['suspicious_objects'].sort(key=lambda x: x['entropy'], reverse=True)
        
        return results
    
    def generate_entropy_heatmap(self, output_path: Path, width: int = 1200, height: int = 800):
        """
        Generate entropy heatmap visualization
        
        Args:
            output_path: Output image path
            width: Image width
            height: Image height
        """
        if Image is None:
            raise DependencyMissingError(
                dependency="Pillow",
                install_hint="Install with: pip install Pillow"
            )
        
        logger.info(f"Generating entropy heatmap: {output_path}")
        
        img = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(img)
        
        try:
            font = ImageFont.truetype("arial.ttf", 12)
        except Exception:
            font = ImageFont.load_default()
        
        entropy_data = self.analyze_document_entropy()
        object_details = entropy_data['object_details']
        
        if not object_details:
            logger.warning("No objects to visualize")
            return
        
        cell_width = width // min(20, len(object_details))
        cell_height = height // ((len(object_details) // 20) + 1)
        
        x, y = 0, 0
        for obj_data in object_details:
            entropy = obj_data['entropy']
            
            intensity = int((entropy / 8.0) * 255)
            
            if entropy > 7.5:
                color = (255, 0, 0)
            elif entropy > 6.5:
                color = (255, 165, 0)
            elif entropy > 5.0:
                color = (255, 255, 0)
            else:
                color = (0, 255, 0)
            
            draw.rectangle([x, y, x + cell_width, y + cell_height], fill=color, outline='black')
            
            x += cell_width
            if x >= width - cell_width:
                x = 0
                y += cell_height
        
        draw.text((10, 10), f"Entropy Heatmap: {self.pdf_doc.path.name}", fill='black', font=font)
        draw.text((10, 30), f"Objects: {len(object_details)}", fill='black', font=font)
        draw.text((10, 50), f"Avg Entropy: {entropy_data['entropy_statistics']['mean']:.4f}", fill='black', font=font)
        
        legend_y = height - 60
        draw.text((10, legend_y), "Legend:", fill='black', font=font)
        draw.rectangle([10, legend_y + 20, 30, legend_y + 40], fill=(255, 0, 0))
        draw.text((35, legend_y + 25), "High (>7.5) - Encrypted/Compressed", fill='black', font=font)
        draw.rectangle([10, legend_y + 45, 30, legend_y + 65], fill=(255, 165, 0))
        draw.text((35, legend_y + 50), "Medium (6.5-7.5) - Compressed", fill='black', font=font)
        
        img.save(output_path)
        logger.info(f"Heatmap saved: {output_path}")
    
    def generate_entropy_histogram(self) -> Dict[str, Any]:
        """
        Generate entropy histogram data
        
        Returns:
            Histogram data suitable for plotting
        """
        entropy_data = self.analyze_document_entropy()
        
        if np is None:
            histogram = {
                'bins': [],
                'counts': [],
                'warning': 'numpy not available - histogram generation limited'
            }
        else:
            entropy_values = [obj['entropy'] for obj in entropy_data['object_details']]
            
            if entropy_values:
                counts, bin_edges = np.histogram(entropy_values, bins=20, range=(0, 8))
                histogram = {
                    'bins': bin_edges.tolist(),
                    'counts': counts.tolist(),
                    'total_objects': len(entropy_values),
                }
            else:
                histogram = {
                    'bins': [],
                    'counts': [],
                }
        
        histogram['statistics'] = entropy_data['entropy_statistics']
        histogram['distribution'] = entropy_data['entropy_distribution']
        
        return histogram


def analyze_object_graph(
    input_path: Path,
    max_depth: int = -1,
    include_entropy: bool = True,
    filter_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Analyze PDF object graph
    
    Args:
        input_path: Path to PDF file
        max_depth: Maximum traversal depth
        include_entropy: Include entropy metrics
        filter_types: Filter by object types
    
    Returns:
        Graph analysis results
    """
    with PDFDocument.open(input_path) as pdf_doc:
        generator = PDFObjectGraphGenerator(pdf_doc)
        return generator.generate_graph(
            max_depth=max_depth,
            include_entropy=include_entropy,
            filter_types=filter_types,
        )


def analyze_entropy(input_path: Path) -> Dict[str, Any]:
    """
    Analyze PDF entropy
    
    Args:
        input_path: Path to PDF file
    
    Returns:
        Entropy analysis results
    """
    with PDFDocument.open(input_path) as pdf_doc:
        analyzer = PDFEntropyAnalyzer(pdf_doc)
        return analyzer.analyze_document_entropy()
