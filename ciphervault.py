#!/usr/bin/env python3
"""
CipherVault - Comprehensive Encryption Tool
Main entry point supporting both CLI and GUI modes
"""

import argparse
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.encryptor import EncryptionEngine
from src.storage.vault_manager import VaultManager
from src.core.utils import format_file_size, ValidationUtils


class CipherVaultCLI:
    """Command-line interface for CipherVault"""
    
    def __init__(self):
        self.encryption_engine = EncryptionEngine()
        self.vault_manager = VaultManager()
        self.validation_utils = ValidationUtils()
    
    def encrypt_text(self, text: str, password: str, algorithm: str = "AES-256"):
        """Encrypt text via CLI"""
        try:
            result = self.encryption_engine.encrypt_text(text, password, algorithm)
            print(f"✅ Text encrypted successfully using {algorithm}")
            print(f"Encrypted data: {result['encrypted_data'][:100]}...")
            return result
        except Exception as e:
            print(f"❌ Text encryption failed: {str(e)}")
            return None
    
    def encrypt_file(self, file_path: str, password: str, algorithm: str = "AES-256", 
                    stealth_mode: bool = False):
        """Encrypt file via CLI"""
        try:
            if not os.path.exists(file_path):
                print(f"❌ File not found: {file_path}")
                return None
                
            result = self.encryption_engine.encrypt_file(file_path, password, algorithm, stealth_mode)
            print(f"✅ File encrypted successfully: {result['output_path']}")
            print(f"Original size: {format_file_size(result['original_size'])}")
            print(f"Encrypted size: {format_file_size(result['encrypted_size'])}")
            return result
        except Exception as e:
            print(f"❌ File encryption failed: {str(e)}")
            return None
    
    def encrypt_folder(self, folder_path: str, password: str, algorithm: str = "AES-256"):
        """Encrypt folder via CLI"""
        try:
            if not os.path.isdir(folder_path):
                print(f"❌ Folder not found: {folder_path}")
                return None
                
            result = self.encryption_engine.encrypt_folder(folder_path, password, algorithm)
            print(f"✅ Folder encrypted successfully: {result['output_path']}")
            print(f"Original folder: {result['original_folder']}")
            return result
        except Exception as e:
            print(f"❌ Folder encryption failed: {str(e)}")
            return None
    
    def decrypt_file(self, file_path: str, password: str, output_path: str = None):
        """Decrypt file via CLI"""
        try:
            if not os.path.exists(file_path):
                print(f"❌ Encrypted file not found: {file_path}")
                return None
                
            result = self.encryption_engine.decrypt_file(file_path, password, output_path)
            print(f"✅ File decrypted successfully: {result['output_path']}")
            print(f"Original name: {result['original_name']}")
            print(f"File size: {format_file_size(result['file_size'])}")
            return result
        except Exception as e:
            print(f"❌ File decryption failed: {str(e)}")
            return None
    
    def list_vault(self):
        """List vault entries"""
        try:
            entries = self.vault_manager.list_vault_entries()
            if not entries:
                print("📭 Vault is empty")
                return
                
            print(f"📁 Vault contains {len(entries)} entries:")
            print("-" * 80)
            print(f"{'Name':<30} {'Type':<10} {'Algorithm':<12} {'Size':<12} {'Created':<12}")
            print("-" * 80)
            
            for entry in entries:
                size_str = format_file_size(entry['file_size'])
                created = entry['created_timestamp'][:10]
                print(f"{entry['original_name']:<30} {entry['entry_type']:<10} "
                      f"{entry['algorithm']:<12} {size_str:<12} {created:<12}")
                      
        except Exception as e:
            print(f"❌ Failed to list vault: {str(e)}")
    
    def vault_stats(self):
        """Show vault statistics"""
        try:
            stats = self.vault_manager.get_vault_statistics()
            print("📊 Vault Statistics:")
            print("-" * 40)
            print(f"Total Entries: {stats['total_entries']}")
            print(f"Total Original Size: {format_file_size(stats['total_original_size'])}")
            print(f"Vault Disk Size: {format_file_size(stats['vault_disk_size'])}")
            print(f"Vault Version: {stats['vault_version']}")
            
            if stats['type_distribution']:
                print("\nType Distribution:")
                for entry_type, data in stats['type_distribution'].items():
                    print(f"  {entry_type}: {data['count']} files")
                    
            if stats['algorithm_distribution']:
                print("\nAlgorithm Distribution:")
                for algorithm, count in stats['algorithm_distribution'].items():
                    print(f"  {algorithm}: {count} files")
                    
        except Exception as e:
            print(f"❌ Failed to get vault statistics: {str(e)}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="🔐 CipherVault - Comprehensive Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt text
  python ciphervault.py --encrypt --text "secret message" --password "mykey"
  
  # Encrypt file
  python ciphervault.py --encrypt --file "document.pdf" --password "mykey"
  
  # Encrypt folder
  python ciphervault.py --encrypt --folder "Documents/Private" --password "mykey"
  
  # Decrypt file
  python ciphervault.py --decrypt --file "document.pdf.enc" --password "mykey"
  
  # List vault contents
  python ciphervault.py --vault --list
  
  # Show vault statistics
  python ciphervault.py --vault --stats
  
  # Launch GUI
  python ciphervault.py --gui
        """
    )
    
    # Main operation modes
    parser.add_argument('--encrypt', action='store_true', help='Encrypt data')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt data')
    parser.add_argument('--vault', action='store_true', help='Vault operations')
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    
    # Data sources
    parser.add_argument('--text', type=str, help='Text to encrypt')
    parser.add_argument('--file', type=str, help='File to encrypt/decrypt')
    parser.add_argument('--folder', type=str, help='Folder to encrypt')
    parser.add_argument('--url', type=str, help='URL to encrypt')
    
    # Options
    parser.add_argument('--password', type=str, help='Encryption/decryption password')
    parser.add_argument('--algorithm', type=str, default='AES-256',
                       choices=['AES-256', 'ChaCha20', 'RSA', 'XOR'],
                       help='Encryption algorithm (default: AES-256)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--output', type=str, help='Output file path')
    
    # Vault operations
    parser.add_argument('--list', action='store_true', help='List vault entries')
    parser.add_argument('--stats', action='store_true', help='Show vault statistics')
    parser.add_argument('--cleanup', action='store_true', help='Clean up vault')
    
    args = parser.parse_args()
    
    # Show help if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Launch GUI
    if args.gui:
        try:
            from src.ui.interface import CipherVaultGUI
            app = CipherVaultGUI()
            app.run()
        except ImportError as e:
            print(f"❌ GUI dependencies not available: {str(e)}")
            print("Install required packages: pip install tkinter tkinterdnd2")
        return
    
    # Initialize CLI
    cli = CipherVaultCLI()
    
    # Vault operations
    if args.vault:
        if args.list:
            cli.list_vault()
        elif args.stats:
            cli.vault_stats()
        elif args.cleanup:
            try:
                result = cli.vault_manager.cleanup_vault()
                print(f"✅ Vault cleanup completed:")
                print(f"  Orphaned files removed: {result['orphaned_files_removed']}")
                print(f"  Database compressed: {result['database_compressed']}")
            except Exception as e:
                print(f"❌ Vault cleanup failed: {str(e)}")
        else:
            print("❌ Please specify vault operation: --list, --stats, or --cleanup")
        return
    
    # Encryption operations
    if args.encrypt:
        if not args.password:
            print("❌ Password required for encryption")
            return
            
        # Validate password
        validation_utils = ValidationUtils()
        is_valid, message = validation_utils.validate_password_strength(args.password)
        if not is_valid:
            print(f"⚠️  Warning: {message}")
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                return
        
        if args.text:
            cli.encrypt_text(args.text, args.password, args.algorithm)
        elif args.file:
            cli.encrypt_file(args.file, args.password, args.algorithm, args.stealth)
        elif args.folder:
            cli.encrypt_folder(args.folder, args.password, args.algorithm)
        elif args.url:
            try:
                result = cli.encryption_engine.encrypt_url(args.url, args.password, args.algorithm)
                print(f"✅ URL encrypted successfully")
                print(f"Encrypted URL: {result['encrypted_data'][:100]}...")
            except Exception as e:
                print(f"❌ URL encryption failed: {str(e)}")
        else:
            print("❌ Please specify data to encrypt: --text, --file, --folder, or --url")
    
    # Decryption operations
    elif args.decrypt:
        if not args.password:
            print("❌ Password required for decryption")
            return
            
        if args.file:
            cli.decrypt_file(args.file, args.password, args.output)
        else:
            print("❌ Please specify encrypted file to decrypt: --file")
    
    else:
        print("❌ Please specify operation: --encrypt, --decrypt, --vault, or --gui")
        parser.print_help()


if __name__ == "__main__":
    main()
