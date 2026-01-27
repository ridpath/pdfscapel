"""Input validation utilities for CLI"""

import re
from pathlib import Path
from typing import Optional, List, Tuple

import click


def validate_pdf_path(ctx, param, value) -> Path:
    """Validate that path is a PDF file"""
    if value is None:
        return None
    
    path = Path(value)
    
    if not path.exists():
        raise click.BadParameter(f"File does not exist: {path}")
    
    if not path.is_file():
        raise click.BadParameter(f"Not a file: {path}")
    
    if path.suffix.lower() != '.pdf':
        raise click.BadParameter(f"Not a PDF file: {path}")
    
    return path


def validate_output_path(ctx, param, value) -> Optional[Path]:
    """Validate output path and ensure parent directory exists"""
    if value is None:
        return None
    
    path = Path(value)
    
    if path.exists() and path.is_dir():
        raise click.BadParameter(f"Output path is a directory: {path}")
    
    parent = path.parent
    if not parent.exists():
        raise click.BadParameter(f"Parent directory does not exist: {parent}")
    
    return path


def validate_directory(ctx, param, value) -> Optional[Path]:
    """Validate that path is a directory"""
    if value is None:
        return None
    
    path = Path(value)
    
    if path.exists() and not path.is_dir():
        raise click.BadParameter(f"Not a directory: {path}")
    
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
    
    return path


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """Validate password strength for PDF encryption"""
    issues = []
    
    if len(password) < 4:
        issues.append("Password too short (minimum 4 characters)")
    
    if len(password) > 32:
        issues.append("Password too long (maximum 32 characters)")
    
    if password.isdigit():
        issues.append("Password should not be only digits")
    
    if password.isalpha():
        issues.append("Password should contain numbers or special characters")
    
    return len(issues) == 0, issues


def validate_flag_format(flag: str) -> bool:
    """Validate CTF flag format"""
    common_patterns = [
        r'^FLAG\{.+\}$',
        r'^CTF\{.+\}$',
        r'^flag\{.+\}$',
        r'^[a-zA-Z0-9_-]{32,}$',
    ]
    
    for pattern in common_patterns:
        if re.match(pattern, flag):
            return True
    
    return False


def validate_page_range(ctx, param, value) -> Optional[List[int]]:
    """
    Validate page range specification
    
    Supports formats:
    - Single page: "5"
    - Range: "1-10"
    - Multiple: "1,3,5-7,10"
    - All: "all" or None
    """
    if value is None or value.lower() == 'all':
        return None
    
    pages = set()
    
    try:
        for part in value.split(','):
            part = part.strip()
            
            if '-' in part:
                start, end = part.split('-', 1)
                start = int(start.strip())
                end = int(end.strip())
                
                if start < 1 or end < 1:
                    raise click.BadParameter("Page numbers must be >= 1")
                
                if start > end:
                    raise click.BadParameter(f"Invalid range: {start}-{end}")
                
                pages.update(range(start, end + 1))
            else:
                page = int(part)
                if page < 1:
                    raise click.BadParameter("Page numbers must be >= 1")
                pages.add(page)
    except ValueError as e:
        raise click.BadParameter(f"Invalid page range format: {value}")
    
    return sorted(pages)


def validate_encryption_level(ctx, param, value) -> str:
    """Validate encryption level"""
    valid_levels = ['rc4-40', 'rc4-128', 'aes-128', 'aes-256']
    
    if value is None:
        return 'aes-256'
    
    value = value.lower()
    
    if value not in valid_levels:
        raise click.BadParameter(
            f"Invalid encryption level. Must be one of: {', '.join(valid_levels)}"
        )
    
    return value


def validate_challenge_id(ctx, param, value) -> Optional[str]:
    """Validate CTF challenge ID format"""
    if value is None:
        return None
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', value):
        raise click.BadParameter(
            "Challenge ID must contain only alphanumeric characters, hyphens, and underscores"
        )
    
    if len(value) < 3:
        raise click.BadParameter("Challenge ID must be at least 3 characters")
    
    return value


def validate_difficulty(ctx, param, value) -> str:
    """Validate difficulty level"""
    valid_difficulties = ['easy', 'medium', 'hard', 'expert']
    
    if value is None:
        return 'medium'
    
    value = value.lower()
    
    if value not in valid_difficulties:
        raise click.BadParameter(
            f"Invalid difficulty. Must be one of: {', '.join(valid_difficulties)}"
        )
    
    return value


def validate_charset(charset: str) -> bool:
    """Validate charset for password generation/cracking"""
    valid_charsets = {
        'lowercase': 'abcdefghijklmnopqrstuvwxyz',
        'uppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'digits': '0123456789',
        'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?',
        'hex': '0123456789abcdef',
        'alphanumeric': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    }
    
    return charset in valid_charsets or all(c in ''.join(valid_charsets.values()) for c in charset)


def validate_wordlist(ctx, param, value) -> Optional[Path]:
    """Validate wordlist file exists and is readable"""
    if value is None:
        return None
    
    path = Path(value)
    
    if not path.exists():
        raise click.BadParameter(f"Wordlist file does not exist: {path}")
    
    if not path.is_file():
        raise click.BadParameter(f"Wordlist path is not a file: {path}")
    
    try:
        with path.open('r') as f:
            f.readline()
    except Exception as e:
        raise click.BadParameter(f"Cannot read wordlist file: {e}")
    
    return path


def validate_regex_pattern(ctx, param, value) -> Optional[str]:
    """Validate regex pattern is valid"""
    if value is None:
        return None
    
    try:
        re.compile(value)
    except re.error as e:
        raise click.BadParameter(f"Invalid regex pattern: {e}")
    
    return value


def validate_positive_int(ctx, param, value) -> Optional[int]:
    """Validate positive integer"""
    if value is None:
        return None
    
    if value < 1:
        raise click.BadParameter("Value must be positive (>= 1)")
    
    return value


def validate_percentage(ctx, param, value) -> Optional[float]:
    """Validate percentage (0-100)"""
    if value is None:
        return None
    
    if not 0 <= value <= 100:
        raise click.BadParameter("Percentage must be between 0 and 100")
    
    return value


def validate_hex_string(ctx, param, value) -> Optional[str]:
    """Validate hexadecimal string"""
    if value is None:
        return None
    
    if not re.match(r'^[0-9a-fA-F]+$', value):
        raise click.BadParameter("Must be a valid hexadecimal string")
    
    if len(value) % 2 != 0:
        raise click.BadParameter("Hex string must have even length")
    
    return value.lower()


class PDFPath(click.Path):
    """Custom Click type for PDF files"""
    
    name = "pdf_path"
    
    def __init__(self, **kwargs):
        super().__init__(exists=True, file_okay=True, dir_okay=False, **kwargs)
    
    def convert(self, value, param, ctx):
        path = super().convert(value, param, ctx)
        
        if path and not str(path).lower().endswith('.pdf'):
            self.fail(f"{value} is not a PDF file", param, ctx)
        
        return Path(path) if path else None


class OutputPath(click.Path):
    """Custom Click type for output paths"""
    
    name = "output_path"
    
    def __init__(self, create_dirs=True, **kwargs):
        self.create_dirs = create_dirs
        super().__init__(exists=False, file_okay=True, dir_okay=False, **kwargs)
    
    def convert(self, value, param, ctx):
        if not value:
            return None
        
        path = Path(value)
        
        if self.create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)
        elif not path.parent.exists():
            self.fail(f"Parent directory does not exist: {path.parent}", param, ctx)
        
        return path


class PageRange(click.ParamType):
    """Custom Click type for page ranges"""
    
    name = "page_range"
    
    def convert(self, value, param, ctx):
        if not value or value.lower() == 'all':
            return None
        
        return validate_page_range(ctx, param, value)
