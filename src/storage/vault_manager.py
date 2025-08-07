"""
Secure storage management for CipherVault
Handles encrypted file storage, metadata, and vault operations
"""

import os
import json
import sqlite3
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from ..core.utils import FileUtils, SecurityUtils, EncodingUtils


class VaultManager:
    """Manages the secure vault storage system"""
    
    def __init__(self, vault_path: str = "storage/vault"):
        self.vault_path = vault_path
        self.metadata_db = os.path.join(vault_path, "vault_metadata.db")
        self.file_utils = FileUtils()
        self.security_utils = SecurityUtils()
        self.encoding_utils = EncodingUtils()
        
        # Initialize vault
        self._initialize_vault()
    
    def _initialize_vault(self):
        """Initialize vault directory and metadata database"""
        # Create vault directory
        self.file_utils.create_directory(self.vault_path)
        self.file_utils.create_directory(os.path.join(self.vault_path, "files"))
        self.file_utils.create_directory(os.path.join(self.vault_path, "temp"))
        
        # Initialize metadata database
        self._initialize_metadata_db()
    
    def _initialize_metadata_db(self):
        """Initialize the metadata database"""
        conn = sqlite3.connect(self.metadata_db)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT UNIQUE NOT NULL,
                entry_type TEXT NOT NULL,
                original_name TEXT NOT NULL,
                encrypted_name TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                file_size INTEGER,
                encrypted_size INTEGER,
                created_timestamp TEXT NOT NULL,
                last_accessed TEXT,
                access_count INTEGER DEFAULT 0,
                tags TEXT,
                description TEXT,
                stealth_mode BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_stats (
                id INTEGER PRIMARY KEY,
                total_entries INTEGER DEFAULT 0,
                total_size INTEGER DEFAULT 0,
                last_cleanup TEXT,
                vault_version TEXT DEFAULT '1.0'
            )
        ''')
        
        # Initialize stats if empty
        cursor.execute('SELECT COUNT(*) FROM vault_stats')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO vault_stats (total_entries, total_size, vault_version)
                VALUES (0, 0, '1.0')
            ''')
        
        conn.commit()
        conn.close()
    
    def store_encrypted_file(self, encrypted_file_path: str, metadata: Dict) -> str:
        """Store encrypted file in vault with metadata"""
        try:
            # Generate unique entry ID
            entry_id = self.security_utils.generate_nonce(16).hex()
            
            # Generate secure filename
            file_extension = ".cvault"
            if metadata.get("stealth_mode", False):
                original_ext = metadata.get("file_metadata", {}).get("file_type", ".txt")
                file_extension = original_ext
            
            encrypted_filename = f"{entry_id}{file_extension}"
            vault_file_path = os.path.join(self.vault_path, "files", encrypted_filename)
            
            # Copy encrypted file to vault
            shutil.copy2(encrypted_file_path, vault_file_path)
            
            # Store metadata
            self._store_entry_metadata(entry_id, encrypted_filename, metadata)
            
            # Update vault stats
            self._update_vault_stats()
            
            return entry_id
            
        except Exception as e:
            raise Exception(f"Failed to store encrypted file: {str(e)}")
    
    def retrieve_encrypted_file(self, entry_id: str, output_path: str = None) -> str:
        """Retrieve encrypted file from vault"""
        try:
            # Get entry metadata
            entry_metadata = self._get_entry_metadata(entry_id)
            if not entry_metadata:
                raise ValueError("Entry not found in vault")
            
            # Get vault file path
            vault_file_path = os.path.join(self.vault_path, "files", entry_metadata["encrypted_name"])
            
            if not os.path.exists(vault_file_path):
                raise ValueError("Encrypted file not found in vault")
            
            # Copy to output location
            if not output_path:
                output_path = os.path.join(self.vault_path, "temp", entry_metadata["encrypted_name"])
            
            shutil.copy2(vault_file_path, output_path)
            
            # Update access statistics
            self._update_access_stats(entry_id)
            
            return output_path
            
        except Exception as e:
            raise Exception(f"Failed to retrieve encrypted file: {str(e)}")
    
    def delete_vault_entry(self, entry_id: str) -> bool:
        """Delete entry from vault"""
        try:
            # Get entry metadata
            entry_metadata = self._get_entry_metadata(entry_id)
            if not entry_metadata:
                return False
            
            # Delete encrypted file
            vault_file_path = os.path.join(self.vault_path, "files", entry_metadata["encrypted_name"])
            if os.path.exists(vault_file_path):
                os.remove(vault_file_path)
            
            # Delete metadata
            conn = sqlite3.connect(self.metadata_db)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM vault_entries WHERE entry_id = ?', (entry_id,))
            conn.commit()
            conn.close()
            
            # Update vault stats
            self._update_vault_stats()
            
            return True
            
        except Exception:
            return False
    
    def list_vault_entries(self, entry_type: str = None, tags: List[str] = None) -> List[Dict]:
        """List all entries in vault with optional filtering"""
        try:
            conn = sqlite3.connect(self.metadata_db)
            cursor = conn.cursor()
            
            query = 'SELECT * FROM vault_entries'
            params = []
            
            conditions = []
            if entry_type:
                conditions.append('entry_type = ?')
                params.append(entry_type)
            
            if tags:
                for tag in tags:
                    conditions.append('tags LIKE ?')
                    params.append(f'%{tag}%')
            
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
            
            query += ' ORDER BY created_timestamp DESC'
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            # Convert to dictionaries
            columns = ['id', 'entry_id', 'entry_type', 'original_name', 'encrypted_name',
                      'algorithm', 'file_size', 'encrypted_size', 'created_timestamp',
                      'last_accessed', 'access_count', 'tags', 'description', 'stealth_mode']
            
            entries = []
            for row in rows:
                entry = dict(zip(columns, row))
                entry['tags'] = entry['tags'].split(',') if entry['tags'] else []
                entries.append(entry)
            
            return entries
            
        except Exception as e:
            raise Exception(f"Failed to list vault entries: {str(e)}")
    
    def search_vault_entries(self, search_term: str) -> List[Dict]:
        """Search vault entries by name, description, or tags"""
        try:
            conn = sqlite3.connect(self.metadata_db)
            cursor = conn.cursor()
            
            query = '''
                SELECT * FROM vault_entries 
                WHERE original_name LIKE ? 
                OR description LIKE ? 
                OR tags LIKE ?
                ORDER BY created_timestamp DESC
            '''
            
            search_pattern = f'%{search_term}%'
            cursor.execute(query, (search_pattern, search_pattern, search_pattern))
            rows = cursor.fetchall()
            conn.close()
            
            # Convert to dictionaries
            columns = ['id', 'entry_id', 'entry_type', 'original_name', 'encrypted_name',
                      'algorithm', 'file_size', 'encrypted_size', 'created_timestamp',
                      'last_accessed', 'access_count', 'tags', 'description', 'stealth_mode']
            
            entries = []
            for row in rows:
                entry = dict(zip(columns, row))
                entry['tags'] = entry['tags'].split(',') if entry['tags'] else []
                entries.append(entry)
            
            return entries
            
        except Exception as e:
            raise Exception(f"Failed to search vault entries: {str(e)}")
    
    def get_vault_statistics(self) -> Dict:
        """Get vault statistics and information"""
        try:
            conn = sqlite3.connect(self.metadata_db)
            cursor = conn.cursor()
            
            # Get basic stats
            cursor.execute('SELECT * FROM vault_stats WHERE id = 1')
            stats_row = cursor.fetchone()
            
            # Get entry type distribution
            cursor.execute('''
                SELECT entry_type, COUNT(*), SUM(file_size), SUM(encrypted_size)
                FROM vault_entries 
                GROUP BY entry_type
            ''')
            type_stats = cursor.fetchall()
            
            # Get algorithm distribution
            cursor.execute('''
                SELECT algorithm, COUNT(*)
                FROM vault_entries 
                GROUP BY algorithm
            ''')
            algorithm_stats = cursor.fetchall()
            
            conn.close()
            
            # Calculate vault size
            vault_size = 0
            files_dir = os.path.join(self.vault_path, "files")
            if os.path.exists(files_dir):
                for filename in os.listdir(files_dir):
                    file_path = os.path.join(files_dir, filename)
                    if os.path.isfile(file_path):
                        vault_size += os.path.getsize(file_path)
            
            return {
                "total_entries": stats_row[1] if stats_row else 0,
                "total_original_size": stats_row[2] if stats_row else 0,
                "vault_disk_size": vault_size,
                "vault_version": stats_row[4] if stats_row else "1.0",
                "last_cleanup": stats_row[3] if stats_row else None,
                "type_distribution": {row[0]: {"count": row[1], "original_size": row[2], "encrypted_size": row[3]} 
                                    for row in type_stats},
                "algorithm_distribution": {row[0]: row[1] for row in algorithm_stats}
            }
            
        except Exception as e:
            raise Exception(f"Failed to get vault statistics: {str(e)}")
    
    def cleanup_vault(self, remove_orphaned: bool = True, compress_db: bool = True) -> Dict:
        """Clean up vault by removing orphaned files and optimizing database"""
        try:
            cleanup_stats = {
                "orphaned_files_removed": 0,
                "database_compressed": False,
                "errors": []
            }
            
            if remove_orphaned:
                # Find orphaned files
                conn = sqlite3.connect(self.metadata_db)
                cursor = conn.cursor()
                cursor.execute('SELECT encrypted_name FROM vault_entries')
                db_files = {row[0] for row in cursor.fetchall()}
                conn.close()
                
                # Check files in vault directory
                files_dir = os.path.join(self.vault_path, "files")
                if os.path.exists(files_dir):
                    for filename in os.listdir(files_dir):
                        if filename not in db_files and filename.endswith(('.cvault', '.enc')):
                            try:
                                os.remove(os.path.join(files_dir, filename))
                                cleanup_stats["orphaned_files_removed"] += 1
                            except Exception as e:
                                cleanup_stats["errors"].append(f"Failed to remove {filename}: {str(e)}")
            
            if compress_db:
                try:
                    conn = sqlite3.connect(self.metadata_db)
                    conn.execute('VACUUM')
                    conn.close()
                    cleanup_stats["database_compressed"] = True
                except Exception as e:
                    cleanup_stats["errors"].append(f"Database compression failed: {str(e)}")
            
            # Update cleanup timestamp
            self._update_cleanup_timestamp()
            
            return cleanup_stats
            
        except Exception as e:
            raise Exception(f"Vault cleanup failed: {str(e)}")
    
    def export_vault_metadata(self, output_path: str) -> bool:
        """Export vault metadata to JSON file"""
        try:
            entries = self.list_vault_entries()
            stats = self.get_vault_statistics()
            
            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "vault_statistics": stats,
                "entries": entries
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception:
            return False
    
    def _store_entry_metadata(self, entry_id: str, encrypted_filename: str, metadata: Dict):
        """Store entry metadata in database"""
        conn = sqlite3.connect(self.metadata_db)
        cursor = conn.cursor()
        
        # Extract metadata
        entry_type = metadata.get("type", "unknown")
        algorithm = metadata.get("algorithm", "AES-256")
        
        if "file_metadata" in metadata:
            file_meta = metadata["file_metadata"]
            original_name = file_meta.get("original_name", "unknown")
            file_size = file_meta.get("original_size", 0)
            stealth_mode = file_meta.get("stealth_mode", False)
        else:
            original_name = metadata.get("original_name", "text_data")
            file_size = metadata.get("original_size", 0)
            stealth_mode = False
        
        encrypted_size = len(metadata.get("encrypted_data", ""))
        tags = ",".join(metadata.get("tags", []))
        description = metadata.get("description", "")
        
        cursor.execute('''
            INSERT INTO vault_entries 
            (entry_id, entry_type, original_name, encrypted_name, algorithm, 
             file_size, encrypted_size, created_timestamp, tags, description, stealth_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, entry_type, original_name, encrypted_filename, algorithm,
              file_size, encrypted_size, datetime.now().isoformat(), tags, description, stealth_mode))
        
        conn.commit()
        conn.close()
    
    def _get_entry_metadata(self, entry_id: str) -> Optional[Dict]:
        """Get entry metadata from database"""
        conn = sqlite3.connect(self.metadata_db)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vault_entries WHERE entry_id = ?', (entry_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        columns = ['id', 'entry_id', 'entry_type', 'original_name', 'encrypted_name',
                  'algorithm', 'file_size', 'encrypted_size', 'created_timestamp',
                  'last_accessed', 'access_count', 'tags', 'description', 'stealth_mode']
        
        metadata = dict(zip(columns, row))
        metadata['tags'] = metadata['tags'].split(',') if metadata['tags'] else []
        
        return metadata
    
    def _update_access_stats(self, entry_id: str):
        """Update access statistics for entry"""
        conn = sqlite3.connect(self.metadata_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE vault_entries 
            SET last_accessed = ?, access_count = access_count + 1
            WHERE entry_id = ?
        ''', (datetime.now().isoformat(), entry_id))
        
        conn.commit()
        conn.close()
    
    def _update_vault_stats(self):
        """Update vault statistics"""
        conn = sqlite3.connect(self.metadata_db)
        cursor = conn.cursor()
        
        # Get current stats
        cursor.execute('SELECT COUNT(*), SUM(file_size) FROM vault_entries')
        total_entries, total_size = cursor.fetchone()
        total_size = total_size or 0
        
        # Update stats table
        cursor.execute('''
            UPDATE vault_stats 
            SET total_entries = ?, total_size = ?
            WHERE id = 1
        ''', (total_entries, total_size))
        
        conn.commit()
        conn.close()
    
    def _update_cleanup_timestamp(self):
        """Update last cleanup timestamp"""
        conn = sqlite3.connect(self.metadata_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE vault_stats 
            SET last_cleanup = ?
            WHERE id = 1
        ''', (datetime.now().isoformat(),))
        
        conn.commit()
        conn.close()
