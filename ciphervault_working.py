#!/usr/bin/env python3
"""
CipherVault - Working Version
Comprehensive encryption tool with all core features
"""

import argparse
import sys
import os
import json
import base64
import secrets
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CipherVaultCore:
    """Core CipherVault functionality"""
    
    def __init__(self):
        self.supported_algorithms = ['AES-256', 'Fernet', 'XOR']
    
    def generate_key_from_password(self, password: str, salt: bytes = None, algorithm: str = "AES-256") -> tuple:
        """Generate encryption key from password"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        if algorithm == "Fernet":
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key, salt
        else:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password.encode())
            return key, salt
    
    def hash_password(self, password: str, salt: bytes) -> str:
        """Hash password using SHA-512 with salt"""
        password_bytes = password.encode('utf-8')
        hash_obj = hashlib.sha512(password_bytes + salt)
        return hash_obj.hexdigest()
    
    def encrypt_text(self, text: str, password: str, algorithm: str = "Fernet") -> dict:
        """Encrypt text data"""
        try:
            if algorithm == "Fernet":
                key, salt = self.generate_key_from_password(password, algorithm=algorithm)
                f = Fernet(key)
                encrypted_data = f.encrypt(text.encode())
                
                return {
                    'success': True,
                    'type': 'text',
                    'algorithm': algorithm,
                    'encrypted_data': base64.b64encode(encrypted_data).decode(),
                    'salt': base64.b64encode(salt).decode(),
                    'original_size': len(text)
                }
            elif algorithm == "AES-256":
                key, salt = self.generate_key_from_password(password, algorithm=algorithm)
                nonce = secrets.token_bytes(12)
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
                
                # Combine nonce + tag + ciphertext
                encrypted_data = nonce + encryptor.tag + ciphertext
                
                return {
                    'success': True,
                    'type': 'text',
                    'algorithm': algorithm,
                    'encrypted_data': base64.b64encode(encrypted_data).decode(),
                    'salt': base64.b64encode(salt).decode(),
                    'original_size': len(text)
                }
            else:
                return {'success': False, 'error': f'Unsupported algorithm: {algorithm}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_text(self, encrypted_package: dict, password: str) -> dict:
        """Decrypt text data"""
        try:
            algorithm = encrypted_package['algorithm']
            salt = base64.b64decode(encrypted_package['salt'].encode())
            encrypted_data = base64.b64decode(encrypted_package['encrypted_data'].encode())
            
            if algorithm == "Fernet":
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                f = Fernet(key)
                decrypted_data = f.decrypt(encrypted_data)
                return {
                    'success': True,
                    'decrypted_text': decrypted_data.decode(),
                    'algorithm': algorithm
                }
            elif algorithm == "AES-256":
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                
                # Extract components
                nonce = encrypted_data[:12]
                tag = encrypted_data[12:28]
                ciphertext = encrypted_data[28:]
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                
                return {
                    'success': True,
                    'decrypted_text': decrypted_data.decode(),
                    'algorithm': algorithm
                }
            else:
                return {'success': False, 'error': f'Unsupported algorithm: {algorithm}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_file(self, file_path: str, password: str, algorithm: str = "AES-256", stealth_mode: bool = False) -> dict:
        """Encrypt file"""
        try:
            if not os.path.exists(file_path):
                return {'success': False, 'error': 'File not found'}
            
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Generate key and salt
            key, salt = self.generate_key_from_password(password, algorithm=algorithm)
            
            if algorithm == "AES-256":
                # Generate nonce
                nonce = secrets.token_bytes(12)
                
                # Create AES-GCM cipher
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                
                # Encrypt data
                ciphertext = encryptor.update(file_data) + encryptor.finalize()
                
                # Combine salt + nonce + tag + ciphertext
                encrypted_data = salt + nonce + encryptor.tag + ciphertext
                
            elif algorithm == "Fernet":
                f = Fernet(key)
                encrypted_file_data = f.encrypt(file_data)
                encrypted_data = salt + encrypted_file_data
            
            # Create metadata
            metadata = {
                'algorithm': algorithm,
                'original_name': os.path.basename(file_path),
                'original_size': len(file_data),
                'encrypted_size': len(encrypted_data),
                'stealth_mode': stealth_mode
            }
            
            # Determine output filename
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            if stealth_mode:
                # Create fake image file
                fake_header = b'\\xFF\\xD8\\xFF\\xE0\\x00\\x10JFIF'
                encrypted_data = fake_header + b'CVAULT' + encrypted_data
                output_path = f"{base_name}_encrypted.jpg"
            else:
                output_path = f"{base_name}_encrypted.cvault"
            
            # Save encrypted file
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save metadata
            with open(output_path + '.meta', 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return {
                'success': True,
                'output_path': output_path,
                'metadata': metadata,
                'message': f'File encrypted successfully: {output_path}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_file(self, encrypted_file_path: str, password: str) -> dict:
        """Decrypt file"""
        try:
            if not os.path.exists(encrypted_file_path):
                return {'success': False, 'error': 'Encrypted file not found'}
            
            # Load metadata
            meta_file = encrypted_file_path + '.meta'
            if not os.path.exists(meta_file):
                return {'success': False, 'error': 'Metadata file not found'}
            
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            # Read encrypted file
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            algorithm = metadata['algorithm']
            stealth_mode = metadata.get('stealth_mode', False)
            
            # Handle stealth mode
            if stealth_mode:
                # Remove fake header
                cvault_index = encrypted_data.find(b'CVAULT')
                if cvault_index != -1:
                    encrypted_data = encrypted_data[cvault_index + 6:]
            
            if algorithm == "AES-256":
                # Extract components
                salt = encrypted_data[:16]
                nonce = encrypted_data[16:28]
                tag = encrypted_data[28:44]
                ciphertext = encrypted_data[44:]
                
                # Recreate key
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                
                # Decrypt
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                
            elif algorithm == "Fernet":
                salt = encrypted_data[:16]
                encrypted_file_data = encrypted_data[16:]
                
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                f = Fernet(key)
                decrypted_data = f.decrypt(encrypted_file_data)
            
            # Save decrypted file
            original_name = metadata['original_name']
            output_path = f"decrypted_{original_name}"
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return {
                'success': True,
                'output_path': output_path,
                'original_name': original_name,
                'file_size': len(decrypted_data),
                'message': f'File decrypted successfully: {output_path}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_folder(self, folder_path: str, password: str, algorithm: str = "AES-256") -> dict:
        """Encrypt entire folder"""
        try:
            if not os.path.isdir(folder_path):
                return {'success': False, 'error': 'Folder not found'}
            
            import zipfile
            import tempfile
            
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
            result = self.encrypt_file(temp_zip_path, password, algorithm)
            
            # Clean up temporary file
            os.unlink(temp_zip_path)
            
            if result['success']:
                # Rename output to indicate it's a folder
                folder_name = os.path.basename(folder_path)
                new_output = f"{folder_name}_folder_encrypted.cvault"
                os.rename(result['output_path'], new_output)
                os.rename(result['output_path'] + '.meta', new_output + '.meta')
                
                result['output_path'] = new_output
                result['message'] = f'Folder encrypted successfully: {new_output}'
                result['original_folder'] = folder_name
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="🔐 CipherVault - Comprehensive Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt text
  python ciphervault_working.py --encrypt --text "secret message" --password "mykey"
  
  # Encrypt file
  python ciphervault_working.py --encrypt --file "document.pdf" --password "mykey"
  
  # Encrypt folder
  python ciphervault_working.py --encrypt --folder "Documents/Private" --password "mykey"
  
  # Decrypt file
  python ciphervault_working.py --decrypt --file "document_encrypted.cvault" --password "mykey"
  
  # Stealth mode
  python ciphervault_working.py --encrypt --file "secret.txt" --password "mykey" --stealth
        """
    )
    
    # Main operation modes
    parser.add_argument('--encrypt', action='store_true', help='Encrypt data')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt data')
    
    # Data sources
    parser.add_argument('--text', type=str, help='Text to encrypt')
    parser.add_argument('--file', type=str, help='File to encrypt/decrypt')
    parser.add_argument('--folder', type=str, help='Folder to encrypt')
    
    # Options
    parser.add_argument('--password', type=str, help='Encryption/decryption password')
    parser.add_argument('--algorithm', type=str, default='AES-256',
                       choices=['AES-256', 'Fernet'],
                       help='Encryption algorithm (default: AES-256)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--output', type=str, help='Output file path')
    
    args = parser.parse_args()
    
    # Show help if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Initialize CipherVault
    cv = CipherVaultCore()
    
    # Encryption operations
    if args.encrypt:
        if not args.password:
            print("❌ Password required for encryption")
            return
        
        if args.text:
            print(f"🔒 Encrypting text with {args.algorithm}...")
            result = cv.encrypt_text(args.text, args.password, args.algorithm)
            if result['success']:
                print(f"✅ Text encrypted successfully!")
                print(f"Algorithm: {result['algorithm']}")
                print(f"Original size: {result['original_size']} bytes")
                print(f"Encrypted data: {result['encrypted_data'][:100]}...")
                
                # Save to file
                with open('encrypted_text.json', 'w') as f:
                    json.dump(result, f, indent=2)
                print("💾 Encrypted text saved to: encrypted_text.json")
            else:
                print(f"❌ Text encryption failed: {result['error']}")
        
        elif args.file:
            print(f"🔒 Encrypting file: {args.file}")
            result = cv.encrypt_file(args.file, args.password, args.algorithm, args.stealth)
            if result['success']:
                print(f"✅ {result['message']}")
                print(f"Algorithm: {result['metadata']['algorithm']}")
                print(f"Original size: {result['metadata']['original_size']} bytes")
                print(f"Encrypted size: {result['metadata']['encrypted_size']} bytes")
                if args.stealth:
                    print("🥷 Stealth mode: File disguised as image!")
            else:
                print(f"❌ File encryption failed: {result['error']}")
        
        elif args.folder:
            print(f"🔒 Encrypting folder: {args.folder}")
            result = cv.encrypt_folder(args.folder, args.password, args.algorithm)
            if result['success']:
                print(f"✅ {result['message']}")
                print(f"Original folder: {result['original_folder']}")
            else:
                print(f"❌ Folder encryption failed: {result['error']}")
        
        else:
            print("❌ Please specify data to encrypt: --text, --file, or --folder")
    
    # Decryption operations
    elif args.decrypt:
        if not args.password:
            print("❌ Password required for decryption")
            return
        
        if args.file:
            print(f"🔓 Decrypting file: {args.file}")
            result = cv.decrypt_file(args.file, args.password)
            if result['success']:
                print(f"✅ {result['message']}")
                print(f"Original name: {result['original_name']}")
                print(f"File size: {result['file_size']} bytes")
            else:
                print(f"❌ File decryption failed: {result['error']}")
        
        elif args.text:
            # Decrypt text from JSON file
            try:
                with open('encrypted_text.json', 'r') as f:
                    encrypted_package = json.load(f)
                
                print("🔓 Decrypting text...")
                result = cv.decrypt_text(encrypted_package, args.password)
                if result['success']:
                    print(f"✅ Text decrypted successfully!")
                    print(f"Algorithm: {result['algorithm']}")
                    print(f"Decrypted text: {result['decrypted_text']}")
                else:
                    print(f"❌ Text decryption failed: {result['error']}")
            except FileNotFoundError:
                print("❌ No encrypted text file found (encrypted_text.json)")
            except Exception as e:
                print(f"❌ Error loading encrypted text: {str(e)}")
        
        else:
            print("❌ Please specify encrypted file to decrypt: --file")
    
    else:
        print("❌ Please specify operation: --encrypt or --decrypt")
        parser.print_help()

if __name__ == "__main__":
    main()
