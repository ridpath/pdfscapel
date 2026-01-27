"""PDF encryption operations"""

from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum

try:
    import pikepdf
except ImportError:
    pikepdf = None

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError

logger = get_logger()


class EncryptionLevel(Enum):
    RC4_40 = "rc4_40"
    RC4_128 = "rc4_128"
    AES_128 = "aes_128"
    AES_256 = "aes_256"


class PDFEncryptor:
    """Add encryption to PDF files"""
    
    ENCRYPTION_PARAMS = {
        EncryptionLevel.RC4_40: {"R": 2},
        EncryptionLevel.RC4_128: {"R": 3},
        EncryptionLevel.AES_128: {"R": 4},
        EncryptionLevel.AES_256: {"R": 6},
    }
    
    def __init__(self):
        if pikepdf is None:
            raise PDFScalpelError("pikepdf is required for encryption operations")
    
    def encrypt_pdf(
        self,
        input_path: Path,
        output_path: Path,
        user_password: Optional[str] = None,
        owner_password: Optional[str] = None,
        level: EncryptionLevel = EncryptionLevel.AES_256,
        allow_print: bool = True,
        allow_modify: bool = False,
        allow_extract: bool = True,
        allow_annotate: bool = True,
        allow_form: bool = True,
        allow_accessibility: bool = True,
        allow_assemble: bool = False,
        allow_print_highres: bool = True,
    ) -> Dict[str, Any]:
        """
        Encrypt a PDF with password protection and permission controls
        
        Args:
            input_path: Path to input PDF
            output_path: Path to output encrypted PDF
            user_password: User password (for opening the PDF)
            owner_password: Owner password (for full permissions). If not provided, uses user_password
            level: Encryption level (RC4_40, RC4_128, AES_128, AES_256)
            allow_print: Allow printing
            allow_modify: Allow modifying content
            allow_extract: Allow extracting text/images
            allow_annotate: Allow annotations
            allow_form: Allow filling forms
            allow_accessibility: Allow accessibility features
            allow_assemble: Allow assembling document
            allow_print_highres: Allow high-resolution printing
            
        Returns:
            Dict with encryption result information
        """
        logger.info(f"Encrypting PDF: {input_path} -> {output_path}")
        
        if not user_password and not owner_password:
            raise PDFScalpelError("At least one password (user or owner) must be provided")
        
        if not owner_password:
            owner_password = user_password
        
        try:
            pdf = pikepdf.Pdf.open(input_path)
            
            if pdf.is_encrypted:
                logger.warning(f"Input PDF is already encrypted")
            
            encryption_params = self.ENCRYPTION_PARAMS[level]
            R = encryption_params["R"]
            
            encryption = pikepdf.Encryption(
                user=user_password or "",
                owner=owner_password,
                R=R,
                allow=pikepdf.Permissions(
                    print_lowres=allow_print,
                    print_highres=allow_print_highres,
                    modify_annotation=allow_annotate,
                    modify_form=allow_form,
                    modify_assembly=allow_assemble,
                    modify_other=allow_modify,
                    extract=allow_extract,
                    accessibility=allow_accessibility,
                )
            )
            
            pdf.save(output_path, encryption=encryption)
            pdf.close()
            
            result = {
                "success": True,
                "input_path": str(input_path),
                "output_path": str(output_path),
                "encryption_level": level.value,
                "revision": R,
                "has_user_password": bool(user_password),
                "has_owner_password": bool(owner_password),
                "permissions": {
                    "print": allow_print,
                    "modify": allow_modify,
                    "extract": allow_extract,
                    "annotate": allow_annotate,
                    "form": allow_form,
                    "accessibility": allow_accessibility,
                    "assemble": allow_assemble,
                    "print_highres": allow_print_highres,
                }
            }
            
            logger.info(f"Successfully encrypted PDF with {level.value}")
            return result
            
        except pikepdf.PasswordError as e:
            raise PDFScalpelError(f"Password error: {e}")
        except Exception as e:
            error_msg = str(e)
            if "metadata" in error_msg.lower() and R < 4:
                raise PDFScalpelError(
                    f"Failed to encrypt with {level.value}: RC4 encryption (R<4) has limited support in pikepdf. "
                    "Consider using AES-128 or AES-256 for better compatibility."
                )
            raise PDFScalpelError(f"Failed to encrypt PDF: {e}")


class PDFDecryptor:
    """Remove encryption from PDF files"""
    
    def __init__(self):
        if pikepdf is None:
            raise PDFScalpelError("pikepdf is required for decryption operations")
    
    def decrypt_pdf(
        self,
        input_path: Path,
        output_path: Path,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Remove encryption from a PDF file
        
        Args:
            input_path: Path to encrypted PDF
            output_path: Path to output decrypted PDF
            password: Password to open the PDF (if required)
            
        Returns:
            Dict with decryption result information
        """
        logger.info(f"Decrypting PDF: {input_path} -> {output_path}")
        
        try:
            if password:
                pdf = pikepdf.Pdf.open(input_path, password=password)
            else:
                pdf = pikepdf.Pdf.open(input_path)
            
            was_encrypted = pdf.is_encrypted
            
            if not was_encrypted:
                logger.warning("Input PDF is not encrypted")
            
            pdf.save(output_path)
            pdf.close()
            
            result = {
                "success": True,
                "input_path": str(input_path),
                "output_path": str(output_path),
                "was_encrypted": was_encrypted,
                "password_required": password is not None,
            }
            
            logger.info("Successfully decrypted PDF")
            return result
            
        except pikepdf.PasswordError:
            raise PDFScalpelError(
                "Password required or incorrect password provided. "
                "Cannot decrypt without valid password."
            )
        except Exception as e:
            raise PDFScalpelError(f"Failed to decrypt PDF: {e}")


def encrypt_pdf(
    input_path: Path,
    output_path: Path,
    password: str,
    owner_password: Optional[str] = None,
    level: str = "aes_256",
    **permissions
) -> Dict[str, Any]:
    """
    Convenience function to encrypt a PDF
    
    Args:
        input_path: Path to input PDF
        output_path: Path to output encrypted PDF
        password: User password
        owner_password: Owner password (optional)
        level: Encryption level (rc4_40, rc4_128, aes_128, aes_256)
        **permissions: Permission flags (allow_print, allow_modify, etc.)
    
    Returns:
        Dict with encryption result
    """
    level_map = {
        "rc4_40": EncryptionLevel.RC4_40,
        "rc4_128": EncryptionLevel.RC4_128,
        "aes_128": EncryptionLevel.AES_128,
        "aes_256": EncryptionLevel.AES_256,
    }
    
    encryption_level = level_map.get(level.lower(), EncryptionLevel.AES_256)
    
    encryptor = PDFEncryptor()
    return encryptor.encrypt_pdf(
        input_path=input_path,
        output_path=output_path,
        user_password=password,
        owner_password=owner_password,
        level=encryption_level,
        **permissions
    )


def decrypt_pdf(
    input_path: Path,
    output_path: Path,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function to decrypt a PDF
    
    Args:
        input_path: Path to encrypted PDF
        output_path: Path to output decrypted PDF
        password: Password to open the PDF
    
    Returns:
        Dict with decryption result
    """
    decryptor = PDFDecryptor()
    return decryptor.decrypt_pdf(
        input_path=input_path,
        output_path=output_path,
        password=password,
    )
