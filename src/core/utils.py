"""
Utility functions for CipherVault
Handles hashing, sanitization, and other helper functions
"""

import hashlib
import secrets
import os
import base64
from typing import Union, Optional


class SecurityUtils:
    """Security utilities for password hashing and key derivation"""
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """Generate a random salt for password hashing"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        """Hash password using SHA-512 with salt"""
        password_bytes = password.encode('utf-8')
        hash_obj = hashlib.sha512(password_bytes + salt)
        return hash_obj.hexdigest()
    
    @staticmethod
    def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        """Generate a random nonce for encryption"""
        return secrets.token_bytes(length)


class FileUtils:
    """File handling utilities"""
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal attacks"""
        # Remove path separators and dangerous characters
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        sanitized = filename
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        return sanitized
    
    @staticmethod
    def get_file_extension(filename: str) -> str:
        """Get file extension"""
        return os.path.splitext(filename)[1].lower()
    
    @staticmethod
    def is_valid_file_path(filepath: str) -> bool:
        """Check if file path is valid and exists"""
        return os.path.exists(filepath) and os.path.isfile(filepath)
    
    @staticmethod
    def is_valid_directory_path(dirpath: str) -> bool:
        """Check if directory path is valid and exists"""
        return os.path.exists(dirpath) and os.path.isdir(dirpath)
    
    @staticmethod
    def get_file_size(filepath: str) -> int:
        """Get file size in bytes"""
        return os.path.getsize(filepath)
    
    @staticmethod
    def create_directory(dirpath: str) -> bool:
        """Create directory if it doesn't exist"""
        try:
            os.makedirs(dirpath, exist_ok=True)
            return True
        except Exception:
            return False


class EncodingUtils:
    """Encoding and decoding utilities"""
    
    @staticmethod
    def encode_base64(data: bytes) -> str:
        """Encode bytes to base64 string"""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode_base64(data: str) -> bytes:
        """Decode base64 string to bytes"""
        return base64.b64decode(data.encode('utf-8'))
    
    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        """Convert bytes to hex string"""
        return data.hex()
    
    @staticmethod
    def hex_to_bytes(hex_string: str) -> bytes:
        """Convert hex string to bytes"""
        return bytes.fromhex(hex_string)


class ValidationUtils:
    """Input validation utilities"""
    
    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        strength_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if strength_score < 2:
            return False, "Password should contain uppercase, lowercase, numbers, and special characters"
        
        return True, "Password strength is acceptable"
    
    @staticmethod
    def validate_encryption_algorithm(algorithm: str) -> bool:
        """Validate if encryption algorithm is supported"""
        supported_algorithms = ['AES-256', 'ChaCha20', 'RSA', 'XOR', 'CUSTOM']
        return algorithm.upper() in supported_algorithms


class StealthUtils:
    """Stealth mode utilities for disguising encrypted files"""
    
    @staticmethod
    def get_stealth_extension(original_extension: str) -> str:
        """Get appropriate stealth extension based on original file type"""
        stealth_extensions = {
            '.txt': '.pdf',
            '.doc': '.pdf',
            '.docx': '.pdf',
            '.py': '.jpg',
            '.js': '.jpg',
            '.html': '.jpg',
            '.json': '.png',
            '.xml': '.png',
            '.csv': '.xlsx',
            '.sql': '.xlsx'
        }
        return stealth_extensions.get(original_extension, '.jpg')
    
    @staticmethod
    def create_stealth_header(file_extension: str) -> bytes:
        """Create fake file header for stealth mode"""
        headers = {
            '.jpg': b'\xFF\xD8\xFF\xE0\x00\x10JFIF',
            '.png': b'\x89PNG\r\n\x1a\n',
            '.pdf': b'%PDF-1.4\n',
            '.xlsx': b'PK\x03\x04'
        }
        return headers.get(file_extension, b'\xFF\xD8\xFF\xE0\x00\x10JFIF')


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f}{size_names[i]}"


def generate_random_filename(extension: str = ".enc") -> str:
    """Generate a random filename"""
    random_name = secrets.token_hex(8)
    return f"{random_name}{extension}"
