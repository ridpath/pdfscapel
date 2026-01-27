"""
Image processing utilities for watermark removal and analysis.
"""

import io
from typing import Optional, Tuple, List
from enum import Enum
import numpy as np

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageEnhance
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from scipy import ndimage, fft
    from scipy.signal import wiener
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


class ImageFormat(Enum):
    """Supported image formats."""
    JPEG = "JPEG"
    PNG = "PNG"
    TIFF = "TIFF"
    BMP = "BMP"
    GIF = "GIF"


class InpaintMethod(Enum):
    """Inpainting methods for watermark removal."""
    TELEA = "telea"
    NS = "ns"
    BLUR = "blur"
    MEDIAN = "median"


def convert_image_format(
    image_data: bytes,
    source_format: str,
    target_format: ImageFormat
) -> bytes:
    """
    Convert image from one format to another.
    
    Args:
        image_data: Image data as bytes
        source_format: Source image format
        target_format: Target image format
        
    Returns:
        Converted image data
        
    Raises:
        ImportError: If PIL is not available
    """
    if not PIL_AVAILABLE:
        raise ImportError("PIL/Pillow required for image conversion")
    
    img = Image.open(io.BytesIO(image_data))
    
    # Convert to RGB if necessary
    if target_format in [ImageFormat.JPEG, ImageFormat.BMP]:
        if img.mode in ('RGBA', 'LA', 'P'):
            # Create white background
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
    
    output = io.BytesIO()
    img.save(output, format=target_format.value)
    return output.getvalue()


def resize_image(
    image_data: bytes,
    width: Optional[int] = None,
    height: Optional[int] = None,
    maintain_aspect: bool = True
) -> bytes:
    """
    Resize image to specified dimensions.
    
    Args:
        image_data: Image data as bytes
        width: Target width (None to auto-calculate)
        height: Target height (None to auto-calculate)
        maintain_aspect: Maintain aspect ratio
        
    Returns:
        Resized image data
        
    Raises:
        ImportError: If PIL is not available
    """
    if not PIL_AVAILABLE:
        raise ImportError("PIL/Pillow required for image resizing")
    
    img = Image.open(io.BytesIO(image_data))
    original_width, original_height = img.size
    
    if maintain_aspect:
        if width and not height:
            height = int(original_height * (width / original_width))
        elif height and not width:
            width = int(original_width * (height / original_height))
        elif width and height:
            # Use the dimension that results in smaller image
            ratio = min(width / original_width, height / original_height)
            width = int(original_width * ratio)
            height = int(original_height * ratio)
    
    if not width or not height:
        raise ValueError("Must specify at least one dimension")
    
    resized = img.resize((width, height), Image.Resampling.LANCZOS)
    
    output = io.BytesIO()
    resized.save(output, format=img.format or 'PNG')
    return output.getvalue()


def inpaint_region(
    image_data: bytes,
    mask_coords: List[Tuple[int, int, int, int]],
    method: InpaintMethod = InpaintMethod.TELEA
) -> bytes:
    """
    Inpaint (fill) regions of image, useful for watermark removal.
    
    Args:
        image_data: Image data as bytes
        mask_coords: List of (x1, y1, x2, y2) rectangles to inpaint
        method: Inpainting method to use
        
    Returns:
        Inpainted image data
        
    Raises:
        ImportError: If required libraries are not available
    """
    if not PIL_AVAILABLE:
        raise ImportError("PIL/Pillow required for inpainting")
    
    img = Image.open(io.BytesIO(image_data))
    
    # Create mask
    mask = Image.new('L', img.size, 0)
    mask_draw = ImageDraw.Draw(mask)
    for x1, y1, x2, y2 in mask_coords:
        mask_draw.rectangle([x1, y1, x2, y2], fill=255)
    
    if method == InpaintMethod.BLUR:
        # Simple blur-based inpainting
        result = _inpaint_blur(img, mask)
    elif method == InpaintMethod.MEDIAN:
        # Median filter inpainting
        result = _inpaint_median(img, mask)
    elif CV2_AVAILABLE and method in [InpaintMethod.TELEA, InpaintMethod.NS]:
        # OpenCV inpainting (higher quality)
        result = _inpaint_opencv(img, mask, method)
    else:
        # Fallback to blur
        result = _inpaint_blur(img, mask)
    
    output = io.BytesIO()
    result.save(output, format=img.format or 'PNG')
    return output.getvalue()


def _inpaint_blur(img: Image.Image, mask: Image.Image) -> Image.Image:
    """
    Simple blur-based inpainting (fallback method).
    
    Args:
        img: Source image
        mask: Binary mask (255 = inpaint, 0 = keep)
        
    Returns:
        Inpainted image
    """
    # Apply strong blur
    blurred = img.filter(ImageFilter.GaussianBlur(radius=10))
    
    # Composite original and blurred based on mask
    result = Image.composite(blurred, img, mask)
    return result


def _inpaint_median(img: Image.Image, mask: Image.Image) -> Image.Image:
    """
    Median filter inpainting.
    
    Args:
        img: Source image
        mask: Binary mask
        
    Returns:
        Inpainted image
    """
    # Apply median filter
    filtered = img.filter(ImageFilter.MedianFilter(size=5))
    
    # Composite
    result = Image.composite(filtered, img, mask)
    return result


def _inpaint_opencv(img: Image.Image, mask: Image.Image, method: InpaintMethod) -> Image.Image:
    """
    OpenCV-based inpainting (high quality).
    
    Args:
        img: Source image
        mask: Binary mask
        method: Inpainting method
        
    Returns:
        Inpainted image
    """
    # Convert PIL to numpy/cv2
    img_array = np.array(img)
    mask_array = np.array(mask)
    
    # Convert RGB to BGR for OpenCV
    if len(img_array.shape) == 3 and img_array.shape[2] == 3:
        img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
    
    # Inpaint
    if method == InpaintMethod.TELEA:
        result_array = cv2.inpaint(img_array, mask_array, 3, cv2.INPAINT_TELEA)
    else:  # NS
        result_array = cv2.inpaint(img_array, mask_array, 3, cv2.INPAINT_NS)
    
    # Convert back to RGB
    if len(result_array.shape) == 3 and result_array.shape[2] == 3:
        result_array = cv2.cvtColor(result_array, cv2.COLOR_BGR2RGB)
    
    return Image.fromarray(result_array)


def detect_watermark_region(image_data: bytes, threshold: float = 0.1) -> List[Tuple[int, int, int, int]]:
    """
    Detect potential watermark regions using edge detection and transparency.
    
    Args:
        image_data: Image data as bytes
        threshold: Detection sensitivity (0.0 to 1.0)
        
    Returns:
        List of (x1, y1, x2, y2) bounding boxes for detected regions
        
    Raises:
        ImportError: If PIL is not available
    """
    if not PIL_AVAILABLE:
        raise ImportError("PIL/Pillow required for watermark detection")
    
    img = Image.open(io.BytesIO(image_data))
    
    # Convert to grayscale for edge detection
    gray = img.convert('L')
    
    # Apply edge detection
    edges = gray.filter(ImageFilter.FIND_EDGES)
    
    # Enhance edges
    enhancer = ImageEnhance.Contrast(edges)
    edges = enhancer.enhance(2.0)
    
    # Threshold to binary
    threshold_val = int(255 * threshold)
    edges = edges.point(lambda x: 255 if x > threshold_val else 0)
    
    # Find connected components (simple bounding box detection)
    regions = _find_connected_regions(np.array(edges))
    
    return regions


def _find_connected_regions(binary_image: np.ndarray) -> List[Tuple[int, int, int, int]]:
    """
    Find connected regions in binary image.
    
    Args:
        binary_image: Binary image array
        
    Returns:
        List of bounding boxes
    """
    if not SCIPY_AVAILABLE:
        # Simple fallback: return whole image as single region
        h, w = binary_image.shape
        return [(0, 0, w, h)]
    
    # Label connected components
    labeled, num_features = ndimage.label(binary_image)
    
    regions = []
    for i in range(1, num_features + 1):
        # Find bounding box
        positions = np.where(labeled == i)
        if len(positions[0]) == 0:
            continue
        
        y1, y2 = positions[0].min(), positions[0].max()
        x1, x2 = positions[1].min(), positions[1].max()
        
        # Filter small regions
        if (x2 - x1) > 10 and (y2 - y1) > 10:
            regions.append((x1, y1, x2, y2))
    
    return regions


def frequency_domain_filter(
    image_data: bytes,
    low_freq_cutoff: float = 0.1,
    high_freq_cutoff: float = 0.9
) -> bytes:
    """
    Apply frequency domain filtering to remove watermarks.
    Useful for watermarks added in frequency domain.
    
    Args:
        image_data: Image data as bytes
        low_freq_cutoff: Low frequency cutoff (0.0 to 1.0)
        high_freq_cutoff: High frequency cutoff (0.0 to 1.0)
        
    Returns:
        Filtered image data
        
    Raises:
        ImportError: If required libraries are not available
    """
    if not PIL_AVAILABLE or not SCIPY_AVAILABLE:
        raise ImportError("PIL and scipy required for frequency domain filtering")
    
    img = Image.open(io.BytesIO(image_data))
    
    # Convert to grayscale for simplicity
    if img.mode != 'L':
        img = img.convert('L')
    
    img_array = np.array(img, dtype=float)
    
    # Apply 2D FFT
    f_transform = fft.fft2(img_array)
    f_shift = fft.fftshift(f_transform)
    
    # Create frequency filter mask
    rows, cols = img_array.shape
    crow, ccol = rows // 2, cols // 2
    
    mask = np.ones((rows, cols))
    for i in range(rows):
        for j in range(cols):
            distance = np.sqrt((i - crow)**2 + (j - ccol)**2)
            max_distance = np.sqrt(crow**2 + ccol**2)
            normalized_distance = distance / max_distance
            
            # Band-pass filter
            if normalized_distance < low_freq_cutoff or normalized_distance > high_freq_cutoff:
                mask[i, j] = 0
    
    # Apply filter
    f_shift_filtered = f_shift * mask
    
    # Inverse FFT
    f_ishift = fft.ifftshift(f_shift_filtered)
    img_filtered = fft.ifft2(f_ishift)
    img_filtered = np.abs(img_filtered)
    
    # Normalize to 0-255
    img_filtered = np.uint8(np.clip(img_filtered, 0, 255))
    
    result = Image.fromarray(img_filtered, mode='L')
    
    output = io.BytesIO()
    result.save(output, format='PNG')
    return output.getvalue()


def extract_alpha_channel(image_data: bytes) -> Optional[bytes]:
    """
    Extract alpha channel from image (useful for watermark analysis).
    
    Args:
        image_data: Image data as bytes
        
    Returns:
        Alpha channel as grayscale image, or None if no alpha
        
    Raises:
        ImportError: If PIL is not available
    """
    if not PIL_AVAILABLE:
        raise ImportError("PIL/Pillow required for alpha extraction")
    
    img = Image.open(io.BytesIO(image_data))
    
    if img.mode not in ('RGBA', 'LA'):
        return None
    
    # Extract alpha channel
    alpha = img.split()[-1]
    
    output = io.BytesIO()
    alpha.save(output, format='PNG')
    return output.getvalue()


def compute_image_entropy(image_data: bytes) -> float:
    """
    Compute Shannon entropy of image (useful for detecting embedded data).
    
    Args:
        image_data: Image data as bytes
        
    Returns:
        Entropy value
        
    Raises:
        ImportError: If PIL is not available
    """
    if not PIL_AVAILABLE:
        raise ImportError("PIL/Pillow required for entropy calculation")
    
    img = Image.open(io.BytesIO(image_data))
    
    # Convert to grayscale
    gray = img.convert('L')
    
    # Compute histogram
    histogram = gray.histogram()
    
    # Compute probabilities
    total_pixels = sum(histogram)
    probabilities = [h / total_pixels for h in histogram if h > 0]
    
    # Compute entropy
    import math
    entropy = -sum(p * math.log2(p) for p in probabilities)
    
    return entropy


def detect_lsb_steganography(image_data: bytes) -> Tuple[bool, float]:
    """
    Detect potential LSB steganography in image.
    
    Args:
        image_data: Image data as bytes
        
    Returns:
        Tuple of (is_suspicious, confidence_score)
        
    Raises:
        ImportError: If PIL is not available
    """
    if not PIL_AVAILABLE:
        raise ImportError("PIL/Pillow required for LSB detection")
    
    img = Image.open(io.BytesIO(image_data))
    img_array = np.array(img)
    
    # Extract LSB plane
    if len(img_array.shape) == 3:
        # RGB image - check each channel
        lsb_planes = img_array[:, :, :] & 1
    else:
        # Grayscale
        lsb_planes = img_array & 1
    
    # Compute entropy of LSB plane
    # Random data has high entropy, natural images have low entropy in LSB
    lsb_flat = lsb_planes.flatten()
    
    # Simple statistical test
    ones = np.sum(lsb_flat)
    zeros = lsb_flat.size - ones
    ratio = ones / lsb_flat.size if lsb_flat.size > 0 else 0.5
    
    # In natural images, LSB is biased; in stego, it's closer to 0.5
    confidence = abs(ratio - 0.5) * 2  # 0.0 = suspicious, 1.0 = clean
    is_suspicious = confidence < 0.3
    
    return is_suspicious, 1.0 - confidence
