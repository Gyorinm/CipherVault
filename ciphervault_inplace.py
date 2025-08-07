#!/usr/bin/env python3
"""
CipherVault In-Place - Direct File/Folder Encryption
Encrypts files and folders directly in their original locations
"""

import argparse
import sys
import os
import json
import base64
import secrets
import hashlib
import shutil
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CipherVaultInPlace:
    """In-place encryption for files and folders"""
    
    def __init__(self):
        self.supported_algorithms = ['AES-256', 'Fernet', 'XOR']
        self.encrypted_extension = '.cvault'
        self.metadata_extension = '.cvmeta'
    
    def find_file_or_folder(self, path: str) -> str:
        """Find file or folder in common locations"""
        # If absolute path and exists, use it
        if os.path.isabs(path) and (os.path.exists(path)):
            return os.path.abspath(path)
        
        # If relative path from current directory exists
        if os.path.exists(path):
            return os.path.abspath(path)
        
        # Search in common locations
        search_paths = [
            Path.home() / "Desktop",
            Path.home() / "Documents", 
            Path.home() / "Downloads",
            Path.home() / "Pictures",
            Path.home() / "Videos",
            Path.home() / "Music",
            Path.cwd(),
        ]
        
        for search_path in search_paths:
            full_path = search_path / path
            if full_path.exists():
                print(f"📍 Found: {full_path}")
                return str(full_path)
        
        return None
    
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
    
    def encrypt_file_inplace(self, file_path: str, password: str, algorithm: str = "AES-256", 
                            stealth_mode: bool = False, backup: bool = True) -> dict:
        """Encrypt file directly in its original location"""
        try:
            # Find the actual file
            actual_path = self.find_file_or_folder(file_path)
            if not actual_path or not os.path.isfile(actual_path):
                return {
                    'success': False, 
                    'error': f'File not found: {file_path}\\nSearched in Desktop, Documents, Downloads, etc.'
                }
            
            print(f"📁 Encrypting file: {actual_path}")
            
            # Create backup if requested
            backup_path = None
            if backup:
                backup_path = actual_path + '.backup'
                shutil.copy2(actual_path, backup_path)
                print(f"💾 Backup created: {backup_path}")
            
            # Read original file
            with open(actual_path, 'rb') as f:
                file_data = f.read()
            
            # Generate key and salt
            key, salt = self.generate_key_from_password(password, algorithm=algorithm)
            
            # Encrypt based on algorithm
            if algorithm == "AES-256":
                nonce = secrets.token_bytes(12)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(file_data) + encryptor.finalize()
                encrypted_data = salt + nonce + encryptor.tag + ciphertext
                
            elif algorithm == "Fernet":
                f = Fernet(key)
                encrypted_file_data = f.encrypt(file_data)
                encrypted_data = salt + encrypted_file_data
                
            elif algorithm == "XOR":
                encrypted_bytes = bytearray()
                for i, byte in enumerate(file_data):
                    encrypted_bytes.append(byte ^ key[i % len(key)])
                encrypted_data = salt + bytes(encrypted_bytes)
            
            # Create metadata
            original_name = os.path.basename(actual_path)
            metadata = {
                'algorithm': algorithm,
                'original_name': original_name,
                'original_path': actual_path,
                'original_size': len(file_data),
                'encrypted_size': len(encrypted_data),
                'stealth_mode': stealth_mode,
                'is_encrypted': True,
                'backup_path': backup_path if backup else None
            }
            
            # Determine new filename
            if stealth_mode:
                # Create fake image header and use image extension
                fake_header = b'\\xFF\\xD8\\xFF\\xE0\\x00\\x10JFIF'
                encrypted_data = fake_header + b'CVAULT' + encrypted_data
                # Change extension to .jpg but keep original name
                base_name = os.path.splitext(actual_path)[0]
                new_path = base_name + '.jpg'
            else:
                # Add .cvault extension
                new_path = actual_path + self.encrypted_extension
            
            # Write encrypted file
            with open(new_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save metadata
            metadata_path = new_path + self.metadata_extension
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Remove original file (since we're doing in-place encryption)
            if new_path != actual_path:  # Only remove if we created a new file
                os.remove(actual_path)
                print(f"🗑️ Original file removed: {actual_path}")
            
            return {
                'success': True,
                'encrypted_path': new_path,
                'metadata_path': metadata_path,
                'backup_path': backup_path,
                'original_path': actual_path,
                'metadata': metadata,
                'message': f'File encrypted in-place: {new_path}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_file_inplace(self, encrypted_path: str, password: str, restore_original: bool = True) -> dict:
        """Decrypt file back to its original location and name"""
        try:
            # Find encrypted file
            actual_path = self.find_file_or_folder(encrypted_path)
            if not actual_path or not os.path.isfile(actual_path):
                return {'success': False, 'error': f'Encrypted file not found: {encrypted_path}'}
            
            # Find metadata file
            metadata_path = actual_path + self.metadata_extension
            if not os.path.exists(metadata_path):
                # Try alternative metadata locations
                possible_meta_paths = [
                    actual_path + self.metadata_extension,
                    actual_path.replace('.jpg', '') + self.encrypted_extension + self.metadata_extension,
                    actual_path.replace('.cvault', '') + self.encrypted_extension + self.metadata_extension
                ]
                
                metadata_path = None
                for meta_path in possible_meta_paths:
                    if os.path.exists(meta_path):
                        metadata_path = meta_path
                        break
                
                if not metadata_path:
                    return {'success': False, 'error': 'Metadata file not found'}
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            print(f"🔓 Decrypting file: {actual_path}")
            
            # Read encrypted file
            with open(actual_path, 'rb') as f:
                encrypted_data = f.read()
            
            algorithm = metadata['algorithm']
            stealth_mode = metadata.get('stealth_mode', False)
            original_name = metadata['original_name']
            original_path = metadata.get('original_path', actual_path)
            
            # Handle stealth mode
            if stealth_mode:
                cvault_index = encrypted_data.find(b'CVAULT')
                if cvault_index != -1:
                    encrypted_data = encrypted_data[cvault_index + 6:]
            
            # Decrypt based on algorithm
            if algorithm == "AES-256":
                salt = encrypted_data[:16]
                nonce = encrypted_data[16:28]
                tag = encrypted_data[28:44]
                ciphertext = encrypted_data[44:]
                
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                
            elif algorithm == "Fernet":
                salt = encrypted_data[:16]
                encrypted_file_data = encrypted_data[16:]
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                f = Fernet(key)
                decrypted_data = f.decrypt(encrypted_file_data)
                
            elif algorithm == "XOR":
                salt = encrypted_data[:16]
                encrypted_file_data = encrypted_data[16:]
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                
                decrypted_bytes = bytearray()
                for i, byte in enumerate(encrypted_file_data):
                    decrypted_bytes.append(byte ^ key[i % len(key)])
                decrypted_data = bytes(decrypted_bytes)
            
            # Determine output path
            if restore_original:
                # Restore to original path and name
                output_path = os.path.dirname(original_path)
                if not output_path:
                    output_path = os.path.dirname(actual_path)
                output_file = os.path.join(output_path, original_name)
            else:
                # Create in current location with original name
                output_file = os.path.join(os.path.dirname(actual_path), original_name)
            
            # Write decrypted file
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            # Remove encrypted file and metadata
            os.remove(actual_path)
            os.remove(metadata_path)
            
            # Remove backup if it exists
            backup_path = metadata.get('backup_path')
            if backup_path and os.path.exists(backup_path):
                os.remove(backup_path)
                print(f"🗑️ Backup removed: {backup_path}")
            
            print(f"✅ File decrypted and restored: {output_file}")
            
            return {
                'success': True,
                'decrypted_path': output_file,
                'original_name': original_name,
                'file_size': len(decrypted_data),
                'message': f'File decrypted in-place: {output_file}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_folder_inplace(self, folder_path: str, password: str, algorithm: str = "AES-256", backup: bool = True) -> dict:
        """Encrypt folder directly in its original location"""
        try:
            # Find folder
            actual_path = self.find_file_or_folder(folder_path)
            if not actual_path or not os.path.isdir(actual_path):
                return {'success': False, 'error': f'Folder not found: {folder_path}'}
            
            print(f"📁 Encrypting folder: {actual_path}")
            
            # Create backup if requested
            backup_path = None
            if backup:
                backup_path = actual_path + '_backup'
                if os.path.exists(backup_path):
                    shutil.rmtree(backup_path)
                shutil.copytree(actual_path, backup_path)
                print(f"💾 Backup created: {backup_path}")
            
            import zipfile
            
            # Create temporary zip file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                temp_zip_path = temp_zip.name
            
            # Zip the folder
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(actual_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, actual_path)
                        zipf.write(file_path, arcname)
            
            # Read zip data
            with open(temp_zip_path, 'rb') as f:
                folder_data = f.read()
            
            # Clean up temp zip
            os.unlink(temp_zip_path)
            
            # Generate key and encrypt
            key, salt = self.generate_key_from_password(password, algorithm=algorithm)
            
            if algorithm == "AES-256":
                nonce = secrets.token_bytes(12)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(folder_data) + encryptor.finalize()
                encrypted_data = salt + nonce + encryptor.tag + ciphertext
                
            elif algorithm == "Fernet":
                f = Fernet(key)
                encrypted_folder_data = f.encrypt(folder_data)
                encrypted_data = salt + encrypted_folder_data
                
            elif algorithm == "XOR":
                encrypted_bytes = bytearray()
                for i, byte in enumerate(folder_data):
                    encrypted_bytes.append(byte ^ key[i % len(key)])
                encrypted_data = salt + bytes(encrypted_bytes)
            
            # Create metadata
            folder_name = os.path.basename(actual_path)
            metadata = {
                'algorithm': algorithm,
                'original_name': folder_name,
                'original_path': actual_path,
                'original_size': len(folder_data),
                'encrypted_size': len(encrypted_data),
                'is_folder': True,
                'is_encrypted': True,
                'backup_path': backup_path if backup else None
            }
            
            # Create encrypted file path
            encrypted_file_path = actual_path + self.encrypted_extension
            
            # Write encrypted data
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save metadata
            metadata_path = encrypted_file_path + self.metadata_extension
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Remove original folder
            shutil.rmtree(actual_path)
            print(f"🗑️ Original folder removed: {actual_path}")
            
            return {
                'success': True,
                'encrypted_path': encrypted_file_path,
                'metadata_path': metadata_path,
                'backup_path': backup_path,
                'original_path': actual_path,
                'metadata': metadata,
                'message': f'Folder encrypted in-place: {encrypted_file_path}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_folder_inplace(self, encrypted_path: str, password: str, restore_original: bool = True) -> dict:
        """Decrypt folder back to its original location"""
        try:
            # Find encrypted file
            actual_path = self.find_file_or_folder(encrypted_path)
            if not actual_path or not os.path.isfile(actual_path):
                return {'success': False, 'error': f'Encrypted folder file not found: {encrypted_path}'}
            
            # Find metadata
            metadata_path = actual_path + self.metadata_extension
            if not os.path.exists(metadata_path):
                return {'success': False, 'error': 'Metadata file not found'}
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            print(f"🔓 Decrypting folder: {actual_path}")
            
            # Read encrypted data
            with open(actual_path, 'rb') as f:
                encrypted_data = f.read()
            
            algorithm = metadata['algorithm']
            original_name = metadata['original_name']
            original_path = metadata.get('original_path', actual_path.replace(self.encrypted_extension, ''))
            
            # Decrypt based on algorithm
            if algorithm == "AES-256":
                salt = encrypted_data[:16]
                nonce = encrypted_data[16:28]
                tag = encrypted_data[28:44]
                ciphertext = encrypted_data[44:]
                
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decrypted_data = decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                
            elif algorithm == "Fernet":
                salt = encrypted_data[:16]
                encrypted_folder_data = encrypted_data[16:]
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                f = Fernet(key)
                decrypted_data = f.decrypt(encrypted_folder_data)
                
            elif algorithm == "XOR":
                salt = encrypted_data[:16]
                encrypted_folder_data = encrypted_data[16:]
                key, _ = self.generate_key_from_password(password, salt, algorithm)
                
                decrypted_bytes = bytearray()
                for i, byte in enumerate(encrypted_folder_data):
                    decrypted_bytes.append(byte ^ key[i % len(key)])
                decrypted_data = bytes(decrypted_bytes)
            
            # Create temporary zip file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                temp_zip_path = temp_zip.name
                temp_zip.write(decrypted_data)
            
            # Determine output folder path
            if restore_original:
                output_folder = original_path
            else:
                output_folder = actual_path.replace(self.encrypted_extension, '')
            
            # Extract zip to folder
            import zipfile
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                zipf.extractall(output_folder)
            
            # Clean up temp zip
            os.unlink(temp_zip_path)
            
            # Remove encrypted file and metadata
            os.remove(actual_path)
            os.remove(metadata_path)
            
            # Remove backup if it exists
            backup_path = metadata.get('backup_path')
            if backup_path and os.path.exists(backup_path):
                shutil.rmtree(backup_path)
                print(f"🗑️ Backup removed: {backup_path}")
            
            print(f"✅ Folder decrypted and restored: {output_folder}")
            
            return {
                'success': True,
                'decrypted_path': output_folder,
                'original_name': original_name,
                'message': f'Folder decrypted in-place: {output_folder}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="🔐 CipherVault In-Place - Direct Encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt file in-place (replaces original)
  python ciphervault_inplace.py --encrypt --file "document.pdf" --password "mykey"
  
  # Encrypt file with stealth mode
  python ciphervault_inplace.py --encrypt --file "secret.txt" --password "mykey" --stealth
  
  # Encrypt folder in-place
  python ciphervault_inplace.py --encrypt --folder "MyFolder" --password "mykey"
  
  # Decrypt file back to original
  python ciphervault_inplace.py --decrypt --file "document.pdf.cvault" --password "mykey"
  
  # Decrypt folder back to original
  python ciphervault_inplace.py --decrypt --folder "MyFolder.cvault" --password "mykey"
  
  # No backup option (dangerous!)
  python ciphervault_inplace.py --encrypt --file "document.pdf" --password "mykey" --no-backup
        """
    )
    
    # Main operation modes
    parser.add_argument('--encrypt', action='store_true', help='Encrypt file/folder in-place')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt file/folder in-place')
    
    # Data sources
    parser.add_argument('--file', type=str, help='File to encrypt/decrypt (name or full path)')
    parser.add_argument('--folder', type=str, help='Folder to encrypt/decrypt (name or full path)')
    
    # Options
    parser.add_argument('--password', type=str, help='Encryption/decryption password')
    parser.add_argument('--algorithm', type=str, default='AES-256',
                       choices=['AES-256', 'Fernet', 'XOR'],
                       help='Encryption algorithm (default: AES-256)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (files only)')
    parser.add_argument('--no-backup', action='store_true', help='Skip creating backup (dangerous!)')
    
    args = parser.parse_args()
    
    # Show help if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Initialize CipherVault
    cv = CipherVaultInPlace()
    
    print("🔐 CipherVault In-Place - Direct Encryption")
    print("=" * 50)
    
    # Encryption operations
    if args.encrypt:
        if not args.password:
            print("❌ Password required for encryption")
            return
        
        create_backup = not args.no_backup
        
        if args.file:
            print(f"🔒 Encrypting file in-place: {args.file}")
            if not create_backup:
                print("⚠️  WARNING: No backup will be created!")
                confirm = input("Continue? (y/N): ")
                if confirm.lower() != 'y':
                    print("❌ Operation cancelled")
                    return
            
            result = cv.encrypt_file_inplace(args.file, args.password, args.algorithm, args.stealth, create_backup)
            if result['success']:
                print(f"✅ {result['message']}")
                print(f"Original path: {result['original_path']}")
                print(f"Encrypted path: {result['encrypted_path']}")
                if result['backup_path']:
                    print(f"Backup created: {result['backup_path']}")
                print(f"Algorithm: {result['metadata']['algorithm']}")
                print(f"Original size: {result['metadata']['original_size']} bytes")
                print(f"Encrypted size: {result['metadata']['encrypted_size']} bytes")
                if args.stealth:
                    print("🥷 Stealth mode: File disguised as image!")
            else:
                print(f"❌ File encryption failed: {result['error']}")
        
        elif args.folder:
            print(f"🔒 Encrypting folder in-place: {args.folder}")
            if not create_backup:
                print("⚠️  WARNING: No backup will be created!")
                confirm = input("Continue? (y/N): ")
                if confirm.lower() != 'y':
                    print("❌ Operation cancelled")
                    return
            
            result = cv.encrypt_folder_inplace(args.folder, args.password, args.algorithm, create_backup)
            if result['success']:
                print(f"✅ {result['message']}")
                print(f"Original path: {result['original_path']}")
                print(f"Encrypted file: {result['encrypted_path']}")
                if result['backup_path']:
                    print(f"Backup created: {result['backup_path']}")
                print(f"Algorithm: {result['metadata']['algorithm']}")
            else:
                print(f"❌ Folder encryption failed: {result['error']}")
        
        else:
            print("❌ Please specify --file or --folder to encrypt")
    
    # Decryption operations
    elif args.decrypt:
        if not args.password:
            print("❌ Password required for decryption")
            return
        
        if args.file:
            print(f"🔓 Decrypting file in-place: {args.file}")
            result = cv.decrypt_file_inplace(args.file, args.password)
            if result['success']:
                print(f"✅ {result['message']}")
                print(f"Decrypted to: {result['decrypted_path']}")
                print(f"File size: {result['file_size']} bytes")
            else:
                print(f"❌ File decryption failed: {result['error']}")
        
        elif args.folder:
            print(f"🔓 Decrypting folder in-place: {args.folder}")
            result = cv.decrypt_folder_inplace(args.folder, args.password)
            if result['success']:
                print(f"✅ {result['message']}")
                print(f"Decrypted to: {result['decrypted_path']}")
            else:
                print(f"❌ Folder decryption failed: {result['error']}")
        
        else:
            print("❌ Please specify --file or --folder to decrypt")
    
    else:
        print("❌ Please specify operation: --encrypt or --decrypt")
        parser.print_help()

if __name__ == "__main__":
    main()
