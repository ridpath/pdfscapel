"""
Cryptographic utilities for PDF password cracking and encryption handling.
"""

import hashlib
import secrets
from typing import Optional, Tuple, Union
from enum import Enum

try:
    from Crypto.Cipher import AES, ARC4
    from Crypto.Hash import MD5, SHA256, SHA512
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False


class EncryptionAlgorithm(Enum):
    """PDF encryption algorithms."""
    RC4_40 = "RC4-40"
    RC4_128 = "RC4-128"
    AES_128 = "AES-128"
    AES_256 = "AES-256"
    UNKNOWN = "Unknown"


class HashAlgorithm(Enum):
    """Hash algorithms for password validation."""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"


def compute_md5(data: bytes) -> bytes:
    """
    Compute MD5 hash of data.
    
    Args:
        data: Input bytes
        
    Returns:
        MD5 hash bytes
    """
    return hashlib.md5(data).digest()


def compute_sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash of data.
    
    Args:
        data: Input bytes
        
    Returns:
        SHA256 hash bytes
    """
    return hashlib.sha256(data).digest()


def compute_sha512(data: bytes) -> bytes:
    """
    Compute SHA512 hash of data.
    
    Args:
        data: Input bytes
        
    Returns:
        SHA512 hash bytes
    """
    return hashlib.sha512(data).digest()


def compute_hash(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """
    Compute hash using specified algorithm.
    
    Args:
        data: Input bytes
        algorithm: Hash algorithm to use
        
    Returns:
        Hash bytes
    """
    if algorithm == HashAlgorithm.MD5:
        return hashlib.md5(data).digest()
    elif algorithm == HashAlgorithm.SHA1:
        return hashlib.sha1(data).digest()
    elif algorithm == HashAlgorithm.SHA256:
        return hashlib.sha256(data).digest()
    elif algorithm == HashAlgorithm.SHA512:
        return hashlib.sha512(data).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def derive_pdf_key(
    password: str,
    o_entry: bytes,
    p_entry: int,
    id_entry: bytes,
    key_length: int = 5,
    revision: int = 2
) -> bytes:
    """
    Derive PDF encryption key from password (PDF Reference 1.4-1.6).
    
    Args:
        password: User password
        o_entry: Owner password entry from encryption dict
        p_entry: Permission flags
        id_entry: First element of ID array
        key_length: Key length in bytes (5 for 40-bit, 16 for 128-bit)
        revision: Security handler revision number
        
    Returns:
        Derived encryption key
    """
    # Pad password to 32 bytes
    pwd_bytes = password.encode('latin-1')[:32]
    pwd_bytes = pwd_bytes + b'\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56\xff\xfa\x01\x08\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c\xa9\xfe\x64\x53\x69\x7a'
    pwd_bytes = pwd_bytes[:32]
    
    # Build hash input
    hash_input = pwd_bytes + o_entry + p_entry.to_bytes(4, 'little') + id_entry
    
    # Compute MD5 hash
    hash_val = hashlib.md5(hash_input).digest()
    
    # For revision 3+, apply additional iterations
    if revision >= 3:
        for _ in range(50):
            hash_val = hashlib.md5(hash_val[:key_length]).digest()
    
    return hash_val[:key_length]


def rc4_encrypt(key: bytes, data: bytes) -> bytes:
    """
    Encrypt data using RC4 algorithm.
    
    Args:
        key: Encryption key
        data: Data to encrypt
        
    Returns:
        Encrypted data
    """
    if not PYCRYPTODOME_AVAILABLE:
        # Fallback pure Python RC4
        return _rc4_pure_python(key, data)
    
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decrypt data using RC4 algorithm.
    
    Args:
        key: Decryption key
        data: Data to decrypt
        
    Returns:
        Decrypted data
    """
    # RC4 is symmetric
    return rc4_encrypt(key, data)


def _rc4_pure_python(key: bytes, data: bytes) -> bytes:
    """
    Pure Python RC4 implementation (fallback).
    
    Args:
        key: Encryption/decryption key
        data: Data to encrypt/decrypt
        
    Returns:
        Encrypted/decrypted data
    """
    S = list(range(256))
    j = 0
    
    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)
    
    return bytes(result)


def aes_decrypt_cbc(key: bytes, data: bytes, iv: bytes) -> bytes:
    """
    Decrypt data using AES in CBC mode.
    
    Args:
        key: Decryption key
        data: Data to decrypt
        iv: Initialization vector
        
    Returns:
        Decrypted data
    """
    if not PYCRYPTODOME_AVAILABLE:
        raise ImportError("pycryptodome required for AES decryption")
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


def aes_encrypt_cbc(key: bytes, data: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES in CBC mode.
    
    Args:
        key: Encryption key
        data: Data to encrypt
        iv: Initialization vector (generated if None)
        
    Returns:
        Tuple of (encrypted_data, iv)
    """
    if not PYCRYPTODOME_AVAILABLE:
        raise ImportError("pycryptodome required for AES encryption")
    
    if iv is None:
        iv = secrets.token_bytes(16)
    
    # Pad data to AES block size (16 bytes)
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_data)
    
    return encrypted, iv


def remove_pkcs7_padding(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from decrypted data.
    
    Args:
        data: Padded data
        
    Returns:
        Unpadded data
    """
    if not data:
        return data
    
    padding_length = data[-1]
    
    # Validate padding
    if padding_length > 16 or padding_length == 0:
        return data
    
    for i in range(1, padding_length + 1):
        if data[-i] != padding_length:
            return data
    
    return data[:-padding_length]


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def estimate_password_entropy(password: str) -> float:
    """
    Estimate password entropy in bits.
    
    Args:
        password: Password string
        
    Returns:
        Entropy in bits
    """
    import math
    
    # Character set size estimation
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32  # Approximation
    
    if charset_size == 0:
        return 0.0
    
    # Entropy = length * log2(charset_size)
    return len(password) * math.log2(charset_size)


def classify_encryption_algorithm(
    v: int,
    length: int,
    cf: Optional[dict] = None
) -> EncryptionAlgorithm:
    """
    Classify PDF encryption algorithm from encryption dictionary.
    
    Args:
        v: Version number from encryption dict
        length: Key length in bits
        cf: CryptFilter dictionary (for V=4, V=5)
        
    Returns:
        EncryptionAlgorithm enum
    """
    if v == 1:
        return EncryptionAlgorithm.RC4_40
    elif v == 2:
        if length <= 40:
            return EncryptionAlgorithm.RC4_40
        else:
            return EncryptionAlgorithm.RC4_128
    elif v == 4:
        # Check CryptFilter for algorithm
        if cf and 'StdCF' in cf:
            cfm = cf['StdCF'].get('/CFM', '')
            if cfm == '/AESV2':
                return EncryptionAlgorithm.AES_128
            elif cfm == '/V2':
                return EncryptionAlgorithm.RC4_128
    elif v == 5:
        return EncryptionAlgorithm.AES_256
    
    return EncryptionAlgorithm.UNKNOWN
