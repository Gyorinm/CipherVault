#!/usr/bin/env python3
"""
Simple CipherVault Test - Basic encryption functionality
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key_from_password(password: str, salt: bytes = None) -> bytes:
    """Generate encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_text(text: str, password: str) -> dict:
    """Encrypt text with password"""
    try:
        key, salt = generate_key_from_password(password)
        f = Fernet(key)
        encrypted_data = f.encrypt(text.encode())
        
        return {
            'success': True,
            'encrypted_data': base64.b64encode(encrypted_data).decode(),
            'salt': base64.b64encode(salt).decode(),
            'message': 'Text encrypted successfully!'
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def decrypt_text(encrypted_data: str, salt: str, password: str) -> dict:
    """Decrypt text with password"""
    try:
        salt_bytes = base64.b64decode(salt.encode())
        key, _ = generate_key_from_password(password, salt_bytes)
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted_data = f.decrypt(encrypted_bytes)
        
        return {
            'success': True,
            'decrypted_text': decrypted_data.decode(),
            'message': 'Text decrypted successfully!'
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def main():
    """Test CipherVault functionality"""
    print("🔐 CipherVault Simple Test")
    print("=" * 40)
    
    # Test text encryption
    print("\\n1. Testing Text Encryption:")
    test_text = "This is a secret message from CipherVault!"
    password = "mySecretPassword123"
    
    # Encrypt
    result = encrypt_text(test_text, password)
    if result['success']:
        print(f"✅ {result['message']}")
        print(f"Original: {test_text}")
        print(f"Encrypted: {result['encrypted_data'][:50]}...")
        
        # Decrypt
        decrypt_result = decrypt_text(result['encrypted_data'], result['salt'], password)
        if decrypt_result['success']:
            print(f"✅ {decrypt_result['message']}")
            print(f"Decrypted: {decrypt_result['decrypted_text']}")
        else:
            print(f"❌ Decryption failed: {decrypt_result['error']}")
    else:
        print(f"❌ Encryption failed: {result['error']}")

if __name__ == "__main__":
    main()
