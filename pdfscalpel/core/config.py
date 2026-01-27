"""Configuration management for PDFAutopsy"""

import sys
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from pdfscalpel.core.exceptions import ConfigurationError
from pdfscalpel.core.constants import (
    DEFAULT_OCR_LANGUAGE,
    DEFAULT_OCR_JOBS,
    DEFAULT_WATERMARK_FONT_SIZE,
    DEFAULT_WATERMARK_OPACITY,
    DEFAULT_WATERMARK_ROTATION,
)


@dataclass
class OCRConfig:
    enabled: bool = True
    language: str = DEFAULT_OCR_LANGUAGE
    jobs: int = DEFAULT_OCR_JOBS
    deskew: bool = True
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OCRConfig":
        return cls(
            enabled=data.get("enabled", True),
            language=data.get("language", DEFAULT_OCR_LANGUAGE),
            jobs=data.get("jobs", DEFAULT_OCR_JOBS),
            deskew=data.get("deskew", True),
        )


@dataclass
class WatermarkConfig:
    font_size: int = DEFAULT_WATERMARK_FONT_SIZE
    opacity: float = DEFAULT_WATERMARK_OPACITY
    rotation: int = DEFAULT_WATERMARK_ROTATION
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WatermarkConfig":
        return cls(
            font_size=data.get("font_size", DEFAULT_WATERMARK_FONT_SIZE),
            opacity=data.get("opacity", DEFAULT_WATERMARK_OPACITY),
            rotation=data.get("rotation", DEFAULT_WATERMARK_ROTATION),
        )


@dataclass
class PasswordConfig:
    wordlists: list = field(default_factory=lambda: ["rockyou.txt"])
    max_brute_length: int = 6
    timeout: Optional[int] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PasswordConfig":
        return cls(
            wordlists=data.get("wordlists", ["rockyou.txt"]),
            max_brute_length=data.get("max_brute_length", 6),
            timeout=data.get("timeout"),
        )


@dataclass
class PluginConfig:
    enabled: bool = True
    directories: list = field(default_factory=lambda: ["plugins"])
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginConfig":
        return cls(
            enabled=data.get("enabled", True),
            directories=data.get("directories", ["plugins"]),
        )


@dataclass
class Config:
    ocr: OCRConfig = field(default_factory=OCRConfig)
    watermark: WatermarkConfig = field(default_factory=WatermarkConfig)
    password: PasswordConfig = field(default_factory=PasswordConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    verbose: bool = False
    debug: bool = False
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        return cls(
            ocr=OCRConfig.from_dict(data.get("ocr", {})),
            watermark=WatermarkConfig.from_dict(data.get("watermark", {})),
            password=PasswordConfig.from_dict(data.get("password", {})),
            plugins=PluginConfig.from_dict(data.get("plugins", {})),
            verbose=data.get("verbose", False),
            debug=data.get("debug", False),
        )
    
    @classmethod
    def from_file(cls, path: Path) -> "Config":
        """Load configuration from TOML file"""
        if tomllib is None:
            raise ConfigurationError(
                "TOML support requires tomli package for Python < 3.11. "
                "Install with: pip install tomli"
            )
        
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")
        
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            return cls.from_dict(data)
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    @classmethod
    def default(cls) -> "Config":
        """Create default configuration"""
        return cls()


_global_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global configuration"""
    global _global_config
    if _global_config is None:
        _global_config = Config.default()
    return _global_config


def set_config(config: Config):
    """Set global configuration"""
    global _global_config
    _global_config = config


def load_config(path: Optional[Path] = None) -> Config:
    """Load configuration from file or use default"""
    if path is None:
        default_paths = [
            Path.cwd() / "pdfautopsy.toml",
            Path.home() / ".config" / "pdfautopsy" / "config.toml",
            Path.home() / ".pdfautopsy.toml",
        ]
        
        for p in default_paths:
            if p.exists():
                path = p
                break
    
    if path and path.exists():
        config = Config.from_file(path)
    else:
        config = Config.default()
    
    set_config(config)
    return config
