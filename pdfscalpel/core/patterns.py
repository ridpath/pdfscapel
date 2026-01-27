"""
Pattern matching and encoding detection utilities for flag hunting and data extraction.
"""

import re
import base64
import binascii
from typing import List, Tuple, Optional, Dict
from enum import Enum


class FlagFormat(Enum):
    """Common CTF flag formats."""
    CTF_BRACES = r'CTF\{[^}]+\}'
    FLAG_BRACES = r'FLAG\{[^}]+\}'
    PICOCTF = r'picoCTF\{[^}]+\}'
    HTBCTF = r'HTB\{[^}]+\}'
    GENERIC_BRACES = r'[A-Z]{2,10}\{[^}]+\}'
    UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    MD5 = r'\b[a-fA-F0-9]{32}\b'
    SHA1 = r'\b[a-fA-F0-9]{40}\b'
    SHA256 = r'\b[a-fA-F0-9]{64}\b'


class EncodingType(Enum):
    """Detected encoding types."""
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    HEX = "hex"
    ROT13 = "rot13"
    URL = "url"
    HTML = "html"
    BINARY = "binary"
    MORSE = "morse"
    UNKNOWN = "unknown"


# Compiled regex patterns for performance
FLAG_PATTERNS = {
    'ctf': re.compile(FlagFormat.CTF_BRACES.value, re.IGNORECASE),
    'flag': re.compile(FlagFormat.FLAG_BRACES.value, re.IGNORECASE),
    'picoctf': re.compile(FlagFormat.PICOCTF.value),
    'htb': re.compile(FlagFormat.HTBCTF.value),
    'generic': re.compile(FlagFormat.GENERIC_BRACES.value),
    'uuid': re.compile(FlagFormat.UUID.value),
    'md5': re.compile(FlagFormat.MD5.value),
    'sha1': re.compile(FlagFormat.SHA1.value),
    'sha256': re.compile(FlagFormat.SHA256.value),
}


HASH_PATTERNS = {
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'sha512': re.compile(r'\b[a-fA-F0-9]{128}\b'),
}


SENSITIVE_PATTERNS = {
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    'url': re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
    'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
}


def find_flags(text: str, pattern_names: Optional[List[str]] = None) -> List[Tuple[str, str, int]]:
    """
    Search for CTF flags in text using multiple patterns.
    
    Args:
        text: Text to search
        pattern_names: List of pattern names to use (None = all)
        
    Returns:
        List of (pattern_name, matched_text, position) tuples
    """
    if pattern_names is None:
        pattern_names = list(FLAG_PATTERNS.keys())
    
    results = []
    
    for name in pattern_names:
        if name not in FLAG_PATTERNS:
            continue
        
        pattern = FLAG_PATTERNS[name]
        for match in pattern.finditer(text):
            results.append((name, match.group(), match.start()))
    
    return results


def find_hashes(text: str, hash_types: Optional[List[str]] = None) -> List[Tuple[str, str, int]]:
    """
    Search for hash values in text.
    
    Args:
        text: Text to search
        hash_types: List of hash types to find (None = all)
        
    Returns:
        List of (hash_type, matched_text, position) tuples
    """
    if hash_types is None:
        hash_types = list(HASH_PATTERNS.keys())
    
    results = []
    
    for hash_type in hash_types:
        if hash_type not in HASH_PATTERNS:
            continue
        
        pattern = HASH_PATTERNS[hash_type]
        for match in pattern.finditer(text):
            results.append((hash_type, match.group(), match.start()))
    
    return results


def find_sensitive_data(text: str, data_types: Optional[List[str]] = None) -> List[Tuple[str, str, int]]:
    """
    Search for sensitive data patterns (PII, credentials, etc.).
    
    Args:
        text: Text to search
        data_types: List of data types to find (None = all)
        
    Returns:
        List of (data_type, matched_text, position) tuples
    """
    if data_types is None:
        data_types = list(SENSITIVE_PATTERNS.keys())
    
    results = []
    
    for data_type in data_types:
        if data_type not in SENSITIVE_PATTERNS:
            continue
        
        pattern = SENSITIVE_PATTERNS[data_type]
        for match in pattern.finditer(text):
            results.append((data_type, match.group(), match.start()))
    
    return results


def detect_encoding(data: bytes) -> List[Tuple[EncodingType, float]]:
    """
    Detect potential encodings of data.
    
    Args:
        data: Data to analyze
        
    Returns:
        List of (encoding_type, confidence) sorted by confidence (descending)
    """
    results = []
    
    # Try decoding as text
    try:
        text = data.decode('utf-8', errors='ignore')
    except:
        text = ""
    
    # Check for base64
    base64_confidence = _check_base64(data)
    if base64_confidence > 0:
        results.append((EncodingType.BASE64, base64_confidence))
    
    # Check for hex
    hex_confidence = _check_hex(data)
    if hex_confidence > 0:
        results.append((EncodingType.HEX, hex_confidence))
    
    # Check for binary
    binary_confidence = _check_binary(text)
    if binary_confidence > 0:
        results.append((EncodingType.BINARY, binary_confidence))
    
    # Check for ROT13
    rot13_confidence = _check_rot13(text)
    if rot13_confidence > 0:
        results.append((EncodingType.ROT13, rot13_confidence))
    
    # Check for URL encoding
    url_confidence = _check_url_encoding(text)
    if url_confidence > 0:
        results.append((EncodingType.URL, url_confidence))
    
    # Check for HTML entities
    html_confidence = _check_html_encoding(text)
    if html_confidence > 0:
        results.append((EncodingType.HTML, html_confidence))
    
    # Check for Morse code
    morse_confidence = _check_morse(text)
    if morse_confidence > 0:
        results.append((EncodingType.MORSE, morse_confidence))
    
    # If nothing detected, assume plaintext
    if not results:
        results.append((EncodingType.PLAINTEXT, 0.5))
    
    # Sort by confidence
    results.sort(key=lambda x: x[1], reverse=True)
    
    return results


def _check_base64(data: bytes) -> float:
    """Check if data is base64 encoded."""
    # Base64 alphabet
    base64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    
    # Count valid base64 characters
    valid_chars = sum(1 for b in data if b in base64_chars)
    
    if len(data) == 0:
        return 0.0
    
    ratio = valid_chars / len(data)
    
    # Must be mostly base64 chars and correct length
    if ratio > 0.95 and len(data) % 4 == 0:
        # Try to decode
        try:
            decoded = base64.b64decode(data, validate=True)
            # Successfully decoded
            return 0.9
        except:
            return ratio * 0.5
    
    return 0.0


def _check_hex(data: bytes) -> float:
    """Check if data is hex encoded."""
    hex_chars = set(b'0123456789abcdefABCDEF')
    
    valid_chars = sum(1 for b in data if b in hex_chars)
    
    if len(data) == 0:
        return 0.0
    
    ratio = valid_chars / len(data)
    
    # Must be all hex chars and even length
    if ratio > 0.95 and len(data) % 2 == 0:
        try:
            binascii.unhexlify(data)
            return 0.9
        except:
            return ratio * 0.5
    
    return 0.0


def _check_binary(text: str) -> float:
    """Check if text is binary (01010101...)."""
    binary_chars = set('01 \n\r\t')
    
    valid_chars = sum(1 for c in text if c in binary_chars)
    
    if len(text) == 0:
        return 0.0
    
    ratio = valid_chars / len(text)
    
    if ratio > 0.95:
        # Count actual binary digits
        binary_digits = sum(1 for c in text if c in '01')
        if binary_digits > len(text) * 0.8:
            return 0.8
    
    return 0.0


def _check_rot13(text: str) -> float:
    """Check if text might be ROT13 encoded."""
    # Apply ROT13 and check for English words
    import codecs
    decoded = codecs.decode(text, 'rot13')
    
    # Simple heuristic: check for common English words
    common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her', 'was', 'one', 'our', 'out', 'flag', 'ctf']
    
    decoded_lower = decoded.lower()
    word_count = sum(1 for word in common_words if word in decoded_lower)
    
    if word_count >= 3:
        return 0.7
    elif word_count >= 1:
        return 0.4
    
    return 0.0


def _check_url_encoding(text: str) -> float:
    """Check if text is URL encoded."""
    # Count percent-encoded sequences
    percent_pattern = re.compile(r'%[0-9a-fA-F]{2}')
    matches = percent_pattern.findall(text)
    
    if len(text) == 0:
        return 0.0
    
    # If > 10% of text is percent-encoded
    ratio = (len(matches) * 3) / len(text)
    
    if ratio > 0.1:
        return min(ratio * 5, 0.9)
    
    return 0.0


def _check_html_encoding(text: str) -> float:
    """Check if text contains HTML entities."""
    # Count HTML entities
    entity_pattern = re.compile(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;')
    matches = entity_pattern.findall(text)
    
    if len(text) == 0:
        return 0.0
    
    # If > 5% of text is HTML entities
    ratio = sum(len(m) for m in matches) / len(text)
    
    if ratio > 0.05:
        return min(ratio * 10, 0.9)
    
    return 0.0


def _check_morse(text: str) -> float:
    """Check if text is Morse code."""
    morse_chars = set('.- /\n\r\t')
    
    valid_chars = sum(1 for c in text if c in morse_chars)
    
    if len(text) == 0:
        return 0.0
    
    ratio = valid_chars / len(text)
    
    if ratio > 0.95:
        # Count dots and dashes
        morse_symbols = sum(1 for c in text if c in '.-')
        if morse_symbols > len(text) * 0.5:
            return 0.7
    
    return 0.0


def decode_data(data: bytes, encoding: EncodingType) -> Optional[bytes]:
    """
    Decode data using specified encoding.
    
    Args:
        data: Encoded data
        encoding: Encoding type
        
    Returns:
        Decoded data, or None if decoding fails
    """
    try:
        if encoding == EncodingType.BASE64:
            return base64.b64decode(data)
        
        elif encoding == EncodingType.HEX:
            return binascii.unhexlify(data)
        
        elif encoding == EncodingType.ROT13:
            import codecs
            text = data.decode('utf-8', errors='ignore')
            decoded = codecs.decode(text, 'rot13')
            return decoded.encode('utf-8')
        
        elif encoding == EncodingType.URL:
            from urllib.parse import unquote
            text = data.decode('utf-8', errors='ignore')
            decoded = unquote(text)
            return decoded.encode('utf-8')
        
        elif encoding == EncodingType.HTML:
            import html
            text = data.decode('utf-8', errors='ignore')
            decoded = html.unescape(text)
            return decoded.encode('utf-8')
        
        elif encoding == EncodingType.BINARY:
            text = data.decode('utf-8', errors='ignore')
            # Remove whitespace
            binary_str = ''.join(c for c in text if c in '01')
            # Convert to bytes
            if len(binary_str) % 8 != 0:
                return None
            result = int(binary_str, 2).to_bytes(len(binary_str) // 8, 'big')
            return result
        
        elif encoding == EncodingType.MORSE:
            return _decode_morse(data)
        
        else:
            return data
    
    except Exception:
        return None


def _decode_morse(data: bytes) -> Optional[bytes]:
    """Decode Morse code."""
    morse_code = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z',
        '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9',
    }
    
    try:
        text = data.decode('utf-8', errors='ignore')
        words = text.split(' / ')
        decoded_words = []
        
        for word in words:
            letters = word.split()
            decoded_word = ''.join(morse_code.get(letter, '?') for letter in letters)
            decoded_words.append(decoded_word)
        
        result = ' '.join(decoded_words)
        return result.encode('utf-8')
    
    except Exception:
        return None


def create_custom_pattern(pattern: str, flags: int = 0) -> re.Pattern:
    """
    Create a custom regex pattern for searching.
    
    Args:
        pattern: Regex pattern string
        flags: Regex flags (e.g., re.IGNORECASE)
        
    Returns:
        Compiled regex pattern
    """
    return re.compile(pattern, flags)


def search_pattern(text: str, pattern: re.Pattern) -> List[Tuple[str, int]]:
    """
    Search for custom pattern in text.
    
    Args:
        text: Text to search
        pattern: Compiled regex pattern
        
    Returns:
        List of (matched_text, position) tuples
    """
    results = []
    for match in pattern.finditer(text):
        results.append((match.group(), match.start()))
    return results


def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from text.
    
    Args:
        text: Text to search
        
    Returns:
        List of URLs
    """
    matches = SENSITIVE_PATTERNS['url'].findall(text)
    return matches


def extract_emails(text: str) -> List[str]:
    """
    Extract all email addresses from text.
    
    Args:
        text: Text to search
        
    Returns:
        List of email addresses
    """
    matches = SENSITIVE_PATTERNS['email'].findall(text)
    return matches


def extract_ip_addresses(text: str) -> Dict[str, List[str]]:
    """
    Extract all IP addresses from text.
    
    Args:
        text: Text to search
        
    Returns:
        Dictionary with 'ipv4' and 'ipv6' lists
    """
    return {
        'ipv4': SENSITIVE_PATTERNS['ipv4'].findall(text),
        'ipv6': SENSITIVE_PATTERNS['ipv6'].findall(text),
    }
