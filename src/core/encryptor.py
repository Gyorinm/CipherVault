"""
Core encryption and decryption logic for CipherVault
Supports multiple encryption algorithms: AES-256, ChaCha20, RSA, XOR, and custom combinations
"""

import os
import json
import sqlite3
import zipfile
import tempfile
from typing import Union, Dict, List, Optional, Tuple
from .utils import SecurityUtils, FileUtils, EncodingUtils, StealthUtils
from .keygen import KeyManager


class EncryptionEngine:
    """Main encryption engine supporting multiple algorithms"""
    
    def __init__(self):
        self.security_utils = SecurityUtils()
        self.file_utils = FileUtils()
        self.encoding_utils = EncodingUtils()
        self.stealth_utils = StealthUtils()
        self.key_manager = KeyManager()
    
    def encrypt_text(self, text: str, password: str, algorithm: str = "AES-256") -> Dict:
        """Encrypt text data"""
        try:
            # Create key entry
            key_entry = self.key_manager.create_key_entry(password, algorithm)
            key_data = key_entry["key_data"]
            
            # Get encryption key
            encryption_key = self.key_manager.get_encryption_key(password, key_data)
            
            # Encrypt based on algorithm
            if algorithm.upper() == "AES-256":
                encrypted_data = self._encrypt_aes(text.encode('utf-8'), encryption_key, key_data)
            elif algorithm.upper() == "CHACHA20":
                encrypted_data = self._encrypt_chacha20(text.encode('utf-8'), encryption_key, key_data)
            elif algorithm.upper() == "XOR":
                encrypted_data = self._encrypt_xor(text.encode('utf-8'), encryption_key)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            return {
                "type": "text",
                "algorithm": algorithm,
                "key_data": key_data,
                "encrypted_data": self.encoding_utils.encode_base64(encrypted_data),
                "original_size": len(text)
            }
            
        except Exception as e:
            raise Exception(f"Text encryption failed: {str(e)}")
    
    def decrypt_text(self, encrypted_package: Dict, password: str) -> str:
        """Decrypt text data"""
        try:
            key_data = encrypted_package["key_data"]
            algorithm = encrypted_package["algorithm"]
            
            # Verify password and get key
            encryption_key = self.key_manager.get_encryption_key(password, key_data)
            if not encryption_key:
                raise ValueError("Invalid password")
            
            # Decrypt based on algorithm
            encrypted_data = self.encoding_utils.decode_base64(encrypted_package["encrypted_data"])
            
            if algorithm.upper() == "AES-256":
                decrypted_data = self._decrypt_aes(encrypted_data, encryption_key, key_data)
            elif algorithm.upper() == "CHACHA20":
                decrypted_data = self._decrypt_chacha20(encrypted_data, encryption_key, key_data)
            elif algorithm.upper() == "XOR":
                decrypted_data = self._decrypt_xor(encrypted_data, encryption_key)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Text decryption failed: {str(e)}")
    
    def encrypt_file(self, file_path: str, password: str, algorithm: str = "AES-256", 
                    stealth_mode: bool = False, output_path: str = None) -> Dict:
        """Encrypt a single file"""
        try:
            if not self.file_utils.is_valid_file_path(file_path):
                raise ValueError("Invalid file path")
            
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Create key entry
            key_entry = self.key_manager.create_key_entry(password, algorithm)
            key_data = key_entry["key_data"]
            
            # Get encryption key
            encryption_key = self.key_manager.get_encryption_key(password, key_data)
            
            # Create file metadata
            file_metadata = {
                "original_name": os.path.basename(file_path),
                "original_size": len(file_data),
                "file_type": self.file_utils.get_file_extension(file_path),
                "stealth_mode": stealth_mode
            }
            
            # Encrypt file data
            if algorithm.upper() == "AES-256":
                encrypted_data = self._encrypt_aes(file_data, encryption_key, key_data)
            elif algorithm.upper() == "CHACHA20":
                encrypted_data = self._encrypt_chacha20(file_data, encryption_key, key_data)
            elif algorithm.upper() == "XOR":
                encrypted_data = self._encrypt_xor(file_data, encryption_key)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Create encrypted package
            package = {
                "type": "file",
                "algorithm": algorithm,
                "key_data": key_data,
                "file_metadata": file_metadata,
                "encrypted_data": self.encoding_utils.encode_base64(encrypted_data)
            }
            
            # Save encrypted file
            if not output_path:
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                if stealth_mode:
                    stealth_ext = self.stealth_utils.get_stealth_extension(file_metadata["file_type"])
                    output_path = f"{base_name}{stealth_ext}"
                else:
                    output_path = f"{base_name}.enc"
            
            self._save_encrypted_package(package, output_path, stealth_mode)
            
            return {
                "success": True,
                "output_path": output_path,
                "original_size": file_metadata["original_size"],
                "encrypted_size": len(encrypted_data)
            }
            
        except Exception as e:
            raise Exception(f"File encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_file_path: str, password: str, output_path: str = None) -> Dict:
        """Decrypt a single file"""
        try:
            # Load encrypted package
            package = self._load_encrypted_package(encrypted_file_path)
            
            key_data = package["key_data"]
            algorithm = package["algorithm"]
            file_metadata = package["file_metadata"]
            
            # Verify password and get key
            encryption_key = self.key_manager.get_encryption_key(password, key_data)
            if not encryption_key:
                raise ValueError("Invalid password")
            
            # Decrypt file data
            encrypted_data = self.encoding_utils.decode_base64(package["encrypted_data"])
            
            if algorithm.upper() == "AES-256":
                decrypted_data = self._decrypt_aes(encrypted_data, encryption_key, key_data)
            elif algorithm.upper() == "CHACHA20":
                decrypted_data = self._decrypt_chacha20(encrypted_data, encryption_key, key_data)
            elif algorithm.upper() == "XOR":
                decrypted_data = self._decrypt_xor(encrypted_data, encryption_key)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Save decrypted file
            if not output_path:
                output_path = file_metadata["original_name"]
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return {
                "success": True,
                "output_path": output_path,
                "original_name": file_metadata["original_name"],
                "file_size": len(decrypted_data)
            }
            
        except Exception as e:
            raise Exception(f"File decryption failed: {str(e)}")
    
    def encrypt_folder(self, folder_path: str, password: str, algorithm: str = "AES-256", 
                      output_path: str = None) -> Dict:
        """Encrypt entire folder into a single encrypted file"""
        try:
            if not self.file_utils.is_valid_directory_path(folder_path):
                raise ValueError("Invalid folder path")
            
            # Create temporary zip file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                temp_zip_path = temp_zip.name
            
            # Zip the folder
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)
            
            # Encrypt the zip file
            result = self.encrypt_file(temp_zip_path, password, algorithm, False, output_path)
            
            # Clean up temporary file
            os.unlink(temp_zip_path)
            
            # Update result metadata
            result["type"] = "folder"
            result["original_folder"] = os.path.basename(folder_path)
            
            return result
            
        except Exception as e:
            raise Exception(f"Folder encryption failed: {str(e)}")
    
    def decrypt_folder(self, encrypted_file_path: str, password: str, output_folder: str = None) -> Dict:
        """Decrypt folder from encrypted file"""
        try:
            # First decrypt to get zip file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                temp_zip_path = temp_zip.name
            
            decrypt_result = self.decrypt_file(encrypted_file_path, password, temp_zip_path)
            
            # Extract zip file
            if not output_folder:
                output_folder = "decrypted_folder"
            
            self.file_utils.create_directory(output_folder)
            
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                zipf.extractall(output_folder)
            
            # Clean up temporary file
            os.unlink(temp_zip_path)
            
            return {
                "success": True,
                "output_folder": output_folder,
                "extracted_files": len(os.listdir(output_folder))
            }
            
        except Exception as e:
            raise Exception(f"Folder decryption failed: {str(e)}")
    
    def encrypt_database(self, db_path: str, password: str, algorithm: str = "AES-256") -> Dict:
        """Encrypt database files (.sqlite, .db, .json)"""
        try:
            file_ext = self.file_utils.get_file_extension(db_path)
            
            if file_ext in ['.sqlite', '.db']:
                return self._encrypt_sqlite_database(db_path, password, algorithm)
            elif file_ext == '.json':
                return self._encrypt_json_database(db_path, password, algorithm)
            else:
                # Treat as regular file
                return self.encrypt_file(db_path, password, algorithm)
                
        except Exception as e:
            raise Exception(f"Database encryption failed: {str(e)}")
    
    def encrypt_url(self, url: str, password: str, algorithm: str = "AES-256") -> Dict:
        """Encrypt URL/API endpoint"""
        try:
            # Validate URL format
            if not (url.startswith('http://') or url.startswith('https://')):
                raise ValueError("Invalid URL format")
            
            return self.encrypt_text(url, password, algorithm)
            
        except Exception as e:
            raise Exception(f"URL encryption failed: {str(e)}")
    
    # Private helper methods for specific encryption algorithms
    
    def _encrypt_aes(self, data: bytes, key: bytes, key_data: Dict) -> bytes:
        """AES-256 encryption"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        nonce = self.encoding_utils.decode_base64(key_data["nonce"])
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    def _decrypt_aes(self, encrypted_data: bytes, key: bytes, key_data: Dict) -> bytes:
        """AES-256 decryption"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _encrypt_chacha20(self, data: bytes, key: bytes, key_data: Dict) -> bytes:
        """ChaCha20 encryption"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        
        nonce = self.encoding_utils.decode_base64(key_data["nonce"])
        cipher = Cipher(algorithms.ChaCha20(key, nonce), None)
        encryptor = cipher.encryptor()
        
        return nonce + encryptor.update(data) + encryptor.finalize()
    
    def _decrypt_chacha20(self, encrypted_data: bytes, key: bytes, key_data: Dict) -> bytes:
        """ChaCha20 decryption"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), None)
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _encrypt_xor(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption"""
        result = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        return bytes(result)
    
    def _decrypt_xor(self, encrypted_data: bytes, key: bytes) -> bytes:
        """XOR decryption (same as encryption)"""
        return self._encrypt_xor(encrypted_data, key)
    
    def _encrypt_sqlite_database(self, db_path: str, password: str, algorithm: str) -> Dict:
        """Encrypt SQLite database with metadata preservation"""
        # Read database file
        with open(db_path, 'rb') as f:
            db_data = f.read()
        
        # Extract basic database info
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            metadata = {
                "db_type": "sqlite",
                "tables": tables,
                "original_size": len(db_data)
            }
        except:
            metadata = {
                "db_type": "sqlite",
                "tables": [],
                "original_size": len(db_data)
            }
        
        # Encrypt as file with additional metadata
        result = self.encrypt_file(db_path, password, algorithm)
        result["database_metadata"] = metadata
        
        return result
    
    def _encrypt_json_database(self, json_path: str, password: str, algorithm: str) -> Dict:
        """Encrypt JSON database with structure preservation"""
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        metadata = {
            "db_type": "json",
            "keys": list(json_data.keys()) if isinstance(json_data, dict) else [],
            "record_count": len(json_data) if isinstance(json_data, (list, dict)) else 0
        }
        
        result = self.encrypt_file(json_path, password, algorithm)
        result["database_metadata"] = metadata
        
        return result
    
    def _save_encrypted_package(self, package: Dict, output_path: str, stealth_mode: bool = False):
        """Save encrypted package to file"""
        package_json = json.dumps(package, separators=(',', ':'))
        package_bytes = package_json.encode('utf-8')
        
        if stealth_mode:
            # Add fake header for stealth mode
            file_ext = self.stealth_utils.get_stealth_extension(
                package["file_metadata"]["file_type"]
            )
            fake_header = self.stealth_utils.create_stealth_header(file_ext)
            package_bytes = fake_header + b"CVAULT" + package_bytes
        
        with open(output_path, 'wb') as f:
            f.write(package_bytes)
    
    def _load_encrypted_package(self, file_path: str) -> Dict:
        """Load encrypted package from file"""
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Check for stealth mode
        if b"CVAULT" in file_data:
            # Remove fake header and extract package
            cvault_index = file_data.find(b"CVAULT")
            package_bytes = file_data[cvault_index + 6:]  # Skip "CVAULT" marker
        else:
            package_bytes = file_data
        
        package_json = package_bytes.decode('utf-8')
        return json.loads(package_json)
