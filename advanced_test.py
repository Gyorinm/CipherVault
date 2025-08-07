#!/usr/bin/env python3
"""
Advanced CipherVault Test - File encryption and multiple algorithms
"""

import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_key_from_password(password: str, salt: bytes = None, key_length: int = 32) -> tuple:
    """Generate encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_file_aes(file_path: str, password: str) -> dict:
    """Encrypt file using AES-256"""
    try:
        if not os.path.exists(file_path):
            return {'success': False, 'error': 'File not found'}
        
        # Read file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Generate key and salt
        key, salt = generate_key_from_password(password, key_length=32)
        
        # Generate nonce for AES-GCM
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        
        # Combine salt + nonce + tag + ciphertext
        encrypted_data = salt + nonce + encryptor.tag + ciphertext
        
        # Save encrypted file
        encrypted_file_path = file_path + '.aes_encrypted'
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Create metadata
        metadata = {
            'algorithm': 'AES-256-GCM',
            'original_name': os.path.basename(file_path),
            'original_size': len(file_data),
            'encrypted_size': len(encrypted_data)
        }
        
        # Save metadata
        with open(encrypted_file_path + '.meta', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return {
            'success': True,
            'encrypted_file': encrypted_file_path,
            'metadata': metadata,
            'message': f'File encrypted with AES-256: {encrypted_file_path}'
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def decrypt_file_aes(encrypted_file_path: str, password: str) -> dict:
    """Decrypt AES encrypted file"""
    try:
        if not os.path.exists(encrypted_file_path):
            return {'success': False, 'error': 'Encrypted file not found'}
        
        # Read encrypted file
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]
        
        # Recreate key
        key, _ = generate_key_from_password(password, salt, key_length=32)
        
        # Create AES-GCM cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        # Decrypt data
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Save decrypted file
        decrypted_file_path = encrypted_file_path.replace('.aes_encrypted', '_decrypted_aes')
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        return {
            'success': True,
            'decrypted_file': decrypted_file_path,
            'file_size': len(decrypted_data),
            'message': f'File decrypted: {decrypted_file_path}'
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def create_test_files():
    """Create test files for encryption"""
    # Create text file
    with open('test_document.txt', 'w', encoding='utf-8') as f:
        f.write("""🔐 CipherVault Test Document
        
This is a test document for CipherVault encryption.
It contains multiple lines of text and special characters: !@#$%^&*()
Arabic text: مرحبا بك في CipherVault
Numbers: 1234567890

This document will be encrypted using different algorithms to test the functionality.
""")
    
    # Create binary file
    with open('test_binary.dat', 'wb') as f:
        f.write(bytes(range(256)) * 10)  # Binary data
    
    print("✅ Test files created:")
    print("  - test_document.txt")
    print("  - test_binary.dat")

def test_stealth_mode(file_path: str, password: str) -> dict:
    """Test stealth mode encryption (disguise as image)"""
    try:
        if not os.path.exists(file_path):
            return {'success': False, 'error': 'File not found'}
        
        # Read file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Encrypt using Fernet
        key, salt = generate_key_from_password(password)
        fernet_key = base64.urlsafe_b64encode(key[:32])
        f = Fernet(fernet_key)
        encrypted_data = f.encrypt(file_data)
        
        # Create fake JPEG header
        fake_jpeg_header = b'\\xFF\\xD8\\xFF\\xE0\\x00\\x10JFIF\\x00\\x01\\x01\\x01\\x00H\\x00H\\x00\\x00'
        
        # Combine fake header + marker + salt + encrypted data
        stealth_data = fake_jpeg_header + b'CVAULT' + salt + encrypted_data
        
        # Save as fake image
        stealth_file_path = file_path.replace('.txt', '.jpg').replace('.dat', '.jpg')
        with open(stealth_file_path, 'wb') as f:
            f.write(stealth_data)
        
        return {
            'success': True,
            'stealth_file': stealth_file_path,
            'original_size': len(file_data),
            'stealth_size': len(stealth_data),
            'message': f'File hidden in stealth mode: {stealth_file_path}'
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def main():
    """Test advanced CipherVault functionality"""
    print("🔐 CipherVault Advanced Test")
    print("=" * 50)
    
    # Create test files
    print("\\n1. Creating Test Files:")
    create_test_files()
    
    password = "MySecurePassword123!"
    
    # Test AES file encryption
    print("\\n2. Testing AES-256 File Encryption:")
    result = encrypt_file_aes('test_document.txt', password)
    if result['success']:
        print(f"✅ {result['message']}")
        print(f"Original size: {result['metadata']['original_size']} bytes")
        print(f"Encrypted size: {result['metadata']['encrypted_size']} bytes")
        
        # Test decryption
        decrypt_result = decrypt_file_aes(result['encrypted_file'], password)
        if decrypt_result['success']:
            print(f"✅ {decrypt_result['message']}")
            print(f"Decrypted size: {decrypt_result['file_size']} bytes")
        else:
            print(f"❌ Decryption failed: {decrypt_result['error']}")
    else:
        print(f"❌ Encryption failed: {result['error']}")
    
    # Test stealth mode
    print("\\n3. Testing Stealth Mode:")
    stealth_result = test_stealth_mode('test_document.txt', password)
    if stealth_result['success']:
        print(f"✅ {stealth_result['message']}")
        print(f"Original size: {stealth_result['original_size']} bytes")
        print(f"Stealth size: {stealth_result['stealth_size']} bytes")
        print("File now appears as a JPEG image!")
    else:
        print(f"❌ Stealth mode failed: {stealth_result['error']}")
    
    # Test binary file encryption
    print("\\n4. Testing Binary File Encryption:")
    binary_result = encrypt_file_aes('test_binary.dat', password)
    if binary_result['success']:
        print(f"✅ {binary_result['message']}")
        print(f"Binary file encrypted successfully")
    else:
        print(f"❌ Binary encryption failed: {binary_result['error']}")
    
    print("\\n🎉 Advanced tests completed!")
    print("\\nFiles created:")
    for file in os.listdir('.'):
        if any(ext in file for ext in ['.encrypted', '.aes_encrypted', '.jpg', '.meta']):
            size = os.path.getsize(file)
            print(f"  - {file} ({size} bytes)")

if __name__ == "__main__":
    main()
