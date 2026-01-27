"""Shared constants for PDFAutopsy"""

from enum import Enum

POINTS_PER_INCH = 72

DEFAULT_OCR_LANGUAGE = "eng"
DEFAULT_OCR_JOBS = 4

DEFAULT_WATERMARK_FONT_SIZE = 50
DEFAULT_WATERMARK_OPACITY = 0.3
DEFAULT_WATERMARK_ROTATION = 45

CTF_FLAG_PATTERNS = [
    r'CTF\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'flag\{[^}]+\}',
    r'FLAG-[A-Z0-9]{4}-[A-Z0-9]{4}',
    r'[a-f0-9]{32}',
    r'[a-f0-9]{40}',
    r'[a-f0-9]{64}',
]

BOOKMARK_PATTERNS = [
    r'^#+\s+(.+)$',
    r'^([A-Z][A-Z\s]{3,})$',
    r'^\d+\.\s+([A-Z].+)$',
    r'^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4})$',
]


class WatermarkType(Enum):
    TEXT_OVERLAY = "text_overlay"
    IMAGE_OVERLAY = "image_overlay"
    XOBJECT_REUSE = "xobject_reuse"
    VECTOR_GRAPHICS = "vector_graphics"
    OCG_BASED = "ocg_based"
    ANNOTATION_BASED = "annotation_based"
    TRANSPARENCY_GROUP = "transparency_group"
    FREQUENCY_DOMAIN = "frequency_domain"
    UNKNOWN = "unknown"


class RemovalDifficulty(Enum):
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    VERY_HARD = "very_hard"


class EncryptionAlgorithm(Enum):
    NONE = "none"
    RC4_40 = "rc4_40"
    RC4_128 = "rc4_128"
    AES_128 = "aes_128"
    AES_256 = "aes_256"
    UNKNOWN = "unknown"


class FindingSeverity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PasswordAttackType(Enum):
    INTELLIGENT = "intelligent"
    DICTIONARY = "dictionary"
    BRUTE_FORCE = "brute_force"
    MASK = "mask"
    HYBRID = "hybrid"


class CorruptionType(Enum):
    XREF_OFFSET = "xref_offset"
    TRUNCATED_STREAM = "truncated_stream"
    FAKE_EOF = "fake_EOF"
    DUPLICATE_XREF = "duplicate_xref"
    MISSING_HEADER = "missing_header"
    CORRUPTED_OBJECTS = "corrupted_objects"
    INVALID_STREAM_LENGTH = "invalid_stream_length"
    BROKEN_LINEARIZATION = "broken_linearization"
    INVALID_ENCRYPTION = "invalid_encryption"


EXTERNAL_TOOLS = {
    "tesseract": {
        "name": "Tesseract OCR",
        "command": "tesseract",
        "check_args": ["--version"],
        "windows_paths": [
            r"C:\Program Files\Tesseract-OCR",
            r"C:\Program Files (x86)\Tesseract-OCR",
        ],
        "install": {
            "windows": "Download from https://github.com/UB-Mannheim/tesseract/wiki",
            "linux": "sudo apt install tesseract-ocr",
            "wsl": "sudo apt install tesseract-ocr",
        }
    },
    "ghostscript": {
        "name": "Ghostscript",
        "command": "gs",
        "check_args": ["--version"],
        "windows_paths": [
            r"C:\Program Files\gs\gs*\bin",
            r"C:\Program Files (x86)\gs\gs*\bin",
        ],
        "install": {
            "windows": "Download from https://www.ghostscript.com/download/gsdnld.html",
            "linux": "sudo apt install ghostscript",
            "wsl": "sudo apt install ghostscript",
        }
    },
    "qpdf": {
        "name": "QPDF",
        "command": "qpdf",
        "check_args": ["--version"],
        "install": {
            "windows": "Download from https://github.com/qpdf/qpdf/releases",
            "linux": "sudo apt install qpdf",
            "wsl": "sudo apt install qpdf",
        }
    },
    "john": {
        "name": "John the Ripper",
        "command": "john",
        "check_args": ["--version"],
        "install": {
            "windows": "Download from https://www.openwall.com/john/",
            "linux": "sudo apt install john",
            "wsl": "sudo apt install john",
        }
    },
    "hashcat": {
        "name": "Hashcat",
        "command": "hashcat",
        "check_args": ["--version"],
        "install": {
            "windows": "Download from https://hashcat.net/hashcat/",
            "linux": "sudo apt install hashcat",
            "wsl": "sudo apt install hashcat",
        }
    },
    "dot": {
        "name": "GraphViz",
        "command": "dot",
        "check_args": ["-V"],
        "install": {
            "windows": "Download from https://graphviz.org/download/",
            "linux": "sudo apt install graphviz",
            "wsl": "sudo apt install graphviz",
        }
    },
}

PYTHON_PACKAGES = {
    "pikepdf": {
        "name": "pikepdf",
        "required": True,
        "install": "pip install pikepdf>=8.0.0",
    },
    "pdfplumber": {
        "name": "pdfplumber",
        "required": True,
        "install": "pip install pdfplumber>=0.10.0",
    },
    "click": {
        "name": "click",
        "required": True,
        "install": "pip install click>=8.1.0",
    },
    "rich": {
        "name": "rich",
        "required": True,
        "install": "pip install rich>=13.0.0",
    },
    "Pillow": {
        "name": "Pillow",
        "required": False,
        "install": "pip install Pillow>=10.0.0",
        "features": ["watermark removal", "image processing", "steganography"],
    },
    "numpy": {
        "name": "numpy",
        "required": False,
        "install": "pip install numpy>=1.24.0",
        "features": ["frequency domain analysis", "advanced watermark removal"],
    },
    "pycryptodome": {
        "name": "Crypto",
        "import_name": "Crypto",
        "required": False,
        "install": "pip install pycryptodome>=3.18.0",
        "features": ["password cracking", "encryption analysis"],
    },
    "ocrmypdf": {
        "name": "ocrmypdf",
        "required": False,
        "install": "pip install ocrmypdf>=15.0.0",
        "features": ["OCR"],
    },
    "graphviz": {
        "name": "graphviz",
        "required": False,
        "install": "pip install graphviz>=0.20.0",
        "features": ["object graph visualization"],
    },
    "magic": {
        "name": "magic",
        "required": False,
        "install": "pip install python-magic>=0.4.27 (Linux) or python-magic-bin>=0.4.14 (Windows)",
        "features": ["polyglot detection", "file type analysis"],
    },
}
