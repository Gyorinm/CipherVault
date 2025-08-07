"""
Key generation and management for CipherVault
Handles encryption key generation, storage, and QR code creation
"""

import secrets
import json
import qrcode
from io import BytesIO
from typing import Dict, Optional, Tuple
from .utils import SecurityUtils, EncodingUtils


class KeyGenerator:
    """Handles encryption key generation and management"""
    
    def __init__(self):
        self.security_utils = SecurityUtils()
        self.encoding_utils = EncodingUtils()
    
    def generate_aes_key(self, key_size: int = 32) -> bytes:
        """Generate AES encryption key (256-bit by default)"""
        return secrets.token_bytes(key_size)
    
    def generate_chacha20_key(self) -> bytes:
        """Generate ChaCha20 encryption key (256-bit)"""
        return secrets.token_bytes(32)
    
    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """Generate RSA key pair (public, private)"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem, private_pem
    
    def generate_xor_key(self, length: int) -> bytes:
        """Generate XOR encryption key"""
        return secrets.token_bytes(length)
    
    def derive_key_from_password(self, password: str, salt: bytes, algorithm: str = "AES-256") -> bytes:
        """Derive encryption key from user password"""
        key_lengths = {
            "AES-256": 32,
            "CHACHA20": 32,
            "XOR": 32
        }
        
        key_length = key_lengths.get(algorithm.upper(), 32)
        return self.security_utils.derive_key(password, salt, key_length)
    
    def generate_master_key_data(self, password: str, algorithm: str = "AES-256") -> Dict:
        """Generate complete key data structure"""
        salt = self.security_utils.generate_salt()
        nonce = self.security_utils.generate_nonce()
        
        # Derive key from password
        encryption_key = self.derive_key_from_password(password, salt, algorithm)
        
        # Hash password for verification
        password_hash = self.security_utils.hash_password(password, salt)
        
        key_data = {
            "algorithm": algorithm,
            "salt": self.encoding_utils.encode_base64(salt),
            "nonce": self.encoding_utils.encode_base64(nonce),
            "password_hash": password_hash,
            "key_id": secrets.token_hex(16),
            "created_timestamp": self._get_timestamp()
        }
        
        return key_data, encryption_key
    
    def verify_password(self, password: str, key_data: Dict) -> bool:
        """Verify password against stored hash"""
        salt = self.encoding_utils.decode_base64(key_data["salt"])
        stored_hash = key_data["password_hash"]
        computed_hash = self.security_utils.hash_password(password, salt)
        return stored_hash == computed_hash
    
    def recreate_key_from_password(self, password: str, key_data: Dict) -> bytes:
        """Recreate encryption key from password and key data"""
        salt = self.encoding_utils.decode_base64(key_data["salt"])
        algorithm = key_data["algorithm"]
        return self.derive_key_from_password(password, salt, algorithm)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()


class QRCodeGenerator:
    """Generate QR codes for encryption keys and data"""
    
    def __init__(self):
        self.encoding_utils = EncodingUtils()
    
    def generate_key_qr(self, key_data: Dict, password: str = None) -> bytes:
        """Generate QR code for key data"""
        # Create QR data structure
        qr_data = {
            "type": "CipherVault_Key",
            "key_id": key_data["key_id"],
            "algorithm": key_data["algorithm"],
            "salt": key_data["salt"],
            "nonce": key_data["nonce"],
            "password_hash": key_data["password_hash"]
        }
        
        # Convert to JSON string
        qr_json = json.dumps(qr_data, separators=(',', ':'))
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_json)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        return img_buffer.getvalue()
    
    def generate_text_qr(self, text: str) -> bytes:
        """Generate QR code for encrypted text"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        return img_buffer.getvalue()
    
    def parse_key_qr(self, qr_data: str) -> Optional[Dict]:
        """Parse QR code data back to key information"""
        try:
            data = json.loads(qr_data)
            if data.get("type") == "CipherVault_Key":
                return data
            return None
        except (json.JSONDecodeError, KeyError):
            return None


class KeyManager:
    """Manages encryption keys and their lifecycle"""
    
    def __init__(self, vault_path: str = "storage/vault"):
        self.vault_path = vault_path
        self.key_generator = KeyGenerator()
        self.qr_generator = QRCodeGenerator()
        self.encoding_utils = EncodingUtils()
    
    def create_key_entry(self, password: str, algorithm: str = "AES-256", 
                        generate_qr: bool = False) -> Dict:
        """Create a new key entry"""
        key_data, encryption_key = self.key_generator.generate_master_key_data(password, algorithm)
        
        entry = {
            "key_data": key_data,
            "qr_code": None
        }
        
        if generate_qr:
            qr_bytes = self.qr_generator.generate_key_qr(key_data, password)
            entry["qr_code"] = self.encoding_utils.encode_base64(qr_bytes)
        
        return entry
    
    def validate_key_entry(self, password: str, key_data: Dict) -> bool:
        """Validate password against key entry"""
        return self.key_generator.verify_password(password, key_data)
    
    def get_encryption_key(self, password: str, key_data: Dict) -> Optional[bytes]:
        """Get encryption key from password and key data"""
        if self.validate_key_entry(password, key_data):
            return self.key_generator.recreate_key_from_password(password, key_data)
        return None
    
    def export_key_qr(self, key_data: Dict, output_path: str) -> bool:
        """Export key as QR code image"""
        try:
            qr_bytes = self.qr_generator.generate_key_qr(key_data)
            with open(output_path, 'wb') as f:
                f.write(qr_bytes)
            return True
        except Exception:
            return False
    
    def generate_random_key_phrase(self, word_count: int = 12) -> str:
        """Generate a random passphrase using word list"""
        # Simple word list for demonstration
        words = [
            "apple", "brave", "chair", "dance", "eagle", "flame", "grace", "house",
            "image", "joker", "knife", "light", "magic", "night", "ocean", "peace",
            "queen", "river", "stone", "tiger", "unity", "voice", "water", "xenon",
            "youth", "zebra", "angel", "beach", "cloud", "dream", "earth", "frost"
        ]
        
        selected_words = [secrets.choice(words) for _ in range(word_count)]
        return " ".join(selected_words)
