"""
GUI Interface for CipherVault
Provides intuitive drag-and-drop interface for encryption operations
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import tkinter.font as tkFont
from tkinterdnd2 import DND_FILES, TkinterDnD
import os
import threading
from typing import Optional, Dict, List
from ..core.encryptor import EncryptionEngine
from ..storage.vault_manager import VaultManager
from ..core.utils import format_file_size, ValidationUtils


class CipherVaultGUI:
    """Main GUI application for CipherVault"""
    
    def __init__(self):
        self.root = TkinterDnD.Tk()
        self.root.title("🔐 CipherVault - Secure Encryption Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize core components
        self.encryption_engine = EncryptionEngine()
        self.vault_manager = VaultManager()
        self.validation_utils = ValidationUtils()
        
        # GUI variables
        self.selected_algorithm = tk.StringVar(value="AES-256")
        self.password_var = tk.StringVar()
        self.stealth_mode = tk.BooleanVar()
        self.auto_delete = tk.BooleanVar()
        self.generate_qr = tk.BooleanVar()
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        self.setup_drag_drop()
        
    def setup_styles(self):
        """Setup custom styles for the interface"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), 
                       background='#2b2b2b', foreground='#ffffff')
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'),
                       background='#2b2b2b', foreground='#ffffff')
        style.configure('Custom.TButton', font=('Arial', 10, 'bold'))
        
    def create_widgets(self):
        """Create and layout GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 CipherVault", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_vault_tab()
        self.create_settings_tab()
        
    def create_encrypt_tab(self):
        """Create encryption tab"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="🔒 Encrypt")
        
        # File selection area
        file_frame = ttk.LabelFrame(encrypt_frame, text="Select Files/Folders", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Drag and drop area
        self.drop_area = tk.Label(file_frame, text="📁 Drag & Drop Files/Folders Here\n\nOr click to browse",
                                 bg='#404040', fg='white', font=('Arial', 12),
                                 relief=tk.RAISED, bd=2, height=6)
        self.drop_area.pack(fill=tk.X, pady=5)
        self.drop_area.bind('<Button-1>', self.browse_files)
        
        # Selected files list
        self.selected_files = []
        self.files_listbox = tk.Listbox(file_frame, height=4, bg='#404040', fg='white')
        self.files_listbox.pack(fill=tk.X, pady=5)
        
        # Encryption options
        options_frame = ttk.LabelFrame(encrypt_frame, text="Encryption Options", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Algorithm selection
        ttk.Label(options_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=2)
        algorithm_combo = ttk.Combobox(options_frame, textvariable=self.selected_algorithm,
                                      values=["AES-256", "ChaCha20", "RSA", "XOR"], state="readonly")
        algorithm_combo.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Password entry
        ttk.Label(options_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.password_entry = ttk.Entry(options_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Advanced options
        ttk.Checkbutton(options_frame, text="Stealth Mode", variable=self.stealth_mode).grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Generate QR Code", variable=self.generate_qr).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Action buttons
        button_frame = ttk.Frame(encrypt_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="🔒 Encrypt", command=self.encrypt_files, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🗑️ Clear", command=self.clear_selection).pack(side=tk.LEFT)
        
        # Progress and status
        self.encrypt_progress = ttk.Progressbar(encrypt_frame, mode='indeterminate')
        self.encrypt_progress.pack(fill=tk.X, pady=5)
        
        self.encrypt_status = scrolledtext.ScrolledText(encrypt_frame, height=8, bg='#404040', fg='white')
        self.encrypt_status.pack(fill=tk.BOTH, expand=True, pady=5)
        
    def create_decrypt_tab(self):
        """Create decryption tab"""
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="🔓 Decrypt")
        
        # File selection
        file_frame = ttk.LabelFrame(decrypt_frame, text="Select Encrypted Files", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(file_frame, text="📂 Browse Encrypted Files", command=self.browse_encrypted_files).pack(pady=5)
        
        self.decrypt_files_listbox = tk.Listbox(file_frame, height=4, bg='#404040', fg='white')
        self.decrypt_files_listbox.pack(fill=tk.X, pady=5)
        
        # Decryption options
        decrypt_options_frame = ttk.LabelFrame(decrypt_frame, text="Decryption Options", padding=10)
        decrypt_options_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(decrypt_options_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.decrypt_password_var = tk.StringVar()
        ttk.Entry(decrypt_options_frame, textvariable=self.decrypt_password_var, show="*", width=30).grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Action buttons
        decrypt_button_frame = ttk.Frame(decrypt_frame)
        decrypt_button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(decrypt_button_frame, text="🔓 Decrypt", command=self.decrypt_files, style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(decrypt_button_frame, text="🗑️ Clear", command=self.clear_decrypt_selection).pack(side=tk.LEFT)
        
        # Progress and status
        self.decrypt_progress = ttk.Progressbar(decrypt_frame, mode='indeterminate')
        self.decrypt_progress.pack(fill=tk.X, pady=5)
        
        self.decrypt_status = scrolledtext.ScrolledText(decrypt_frame, height=8, bg='#404040', fg='white')
        self.decrypt_status.pack(fill=tk.BOTH, expand=True, pady=5)
        
    def create_vault_tab(self):
        """Create vault management tab"""
        vault_frame = ttk.Frame(self.notebook)
        self.notebook.add(vault_frame, text="🗄️ Vault")
        
        # Vault controls
        controls_frame = ttk.Frame(vault_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(controls_frame, text="🔄 Refresh", command=self.refresh_vault).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(controls_frame, text="🧹 Cleanup", command=self.cleanup_vault).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(controls_frame, text="📊 Statistics", command=self.show_vault_stats).pack(side=tk.LEFT)
        
        # Search
        search_frame = ttk.Frame(vault_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(5, 10))
        search_entry.bind('<Return>', self.search_vault)
        ttk.Button(search_frame, text="🔍", command=self.search_vault).pack(side=tk.LEFT)
        
        # Vault entries tree
        columns = ('Name', 'Type', 'Algorithm', 'Size', 'Created')
        self.vault_tree = ttk.Treeview(vault_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.vault_tree.heading(col, text=col)
            self.vault_tree.column(col, width=120)
        
        # Scrollbar for tree
        vault_scrollbar = ttk.Scrollbar(vault_frame, orient=tk.VERTICAL, command=self.vault_tree.yview)
        self.vault_tree.configure(yscrollcommand=vault_scrollbar.set)
        
        self.vault_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vault_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Security settings
        security_frame = ttk.LabelFrame(settings_frame, text="Security Settings", padding=10)
        security_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Checkbutton(security_frame, text="Auto-delete source files after encryption", variable=self.auto_delete).pack(anchor=tk.W, pady=2)
        
        # Key management
        key_frame = ttk.LabelFrame(settings_frame, text="Key Management", padding=10)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(key_frame, text="🎲 Generate Random Password", command=self.generate_random_password).pack(pady=5)
        ttk.Button(key_frame, text="📱 Export Key as QR Code", command=self.export_key_qr).pack(pady=5)
        
        # About
        about_frame = ttk.LabelFrame(settings_frame, text="About CipherVault", padding=10)
        about_frame.pack(fill=tk.X, pady=(0, 10))
        
        about_text = """CipherVault v1.0
Secure encryption tool supporting multiple algorithms
Developed for comprehensive data protection"""
        
        ttk.Label(about_frame, text=about_text, justify=tk.LEFT).pack(anchor=tk.W)
        
    def setup_drag_drop(self):
        """Setup drag and drop functionality"""
        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind('<<Drop>>', self.on_drop)
        
    def on_drop(self, event):
        """Handle drag and drop events"""
        files = self.root.tk.splitlist(event.data)
        self.selected_files.extend(files)
        self.update_files_display()
        
    def browse_files(self, event=None):
        """Browse for files to encrypt"""
        files = filedialog.askopenfilenames(title="Select files to encrypt")
        if files:
            self.selected_files.extend(files)
            self.update_files_display()
            
    def browse_encrypted_files(self):
        """Browse for encrypted files to decrypt"""
        files = filedialog.askopenfilenames(
            title="Select encrypted files",
            filetypes=[("Encrypted files", "*.enc *.cvault"), ("All files", "*.*")]
        )
        if files:
            self.decrypt_files_listbox.delete(0, tk.END)
            for file in files:
                self.decrypt_files_listbox.insert(tk.END, os.path.basename(file))
            self.selected_decrypt_files = list(files)
            
    def update_files_display(self):
        """Update the files listbox display"""
        self.files_listbox.delete(0, tk.END)
        for file in self.selected_files:
            self.files_listbox.insert(tk.END, os.path.basename(file))
            
    def encrypt_files(self):
        """Encrypt selected files"""
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select files to encrypt")
            return
            
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password")
            return
            
        # Validate password
        is_valid, message = self.validation_utils.validate_password_strength(password)
        if not is_valid:
            if not messagebox.askyesno("Weak Password", f"{message}\n\nContinue anyway?"):
                return
                
        # Start encryption in separate thread
        threading.Thread(target=self._encrypt_files_thread, daemon=True).start()
        
    def _encrypt_files_thread(self):
        """Encryption thread to prevent GUI freezing"""
        self.encrypt_progress.start()
        self.encrypt_status.delete(1.0, tk.END)
        
        algorithm = self.selected_algorithm.get()
        password = self.password_var.get()
        stealth = self.stealth_mode.get()
        
        for file_path in self.selected_files:
            try:
                self.encrypt_status.insert(tk.END, f"Encrypting: {os.path.basename(file_path)}\n")
                self.encrypt_status.see(tk.END)
                self.root.update()
                
                if os.path.isfile(file_path):
                    result = self.encryption_engine.encrypt_file(file_path, password, algorithm, stealth)
                elif os.path.isdir(file_path):
                    result = self.encryption_engine.encrypt_folder(file_path, password, algorithm)
                else:
                    continue
                    
                self.encrypt_status.insert(tk.END, f"✅ Success: {result['output_path']}\n")
                
                # Auto-delete if enabled
                if self.auto_delete.get():
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    self.encrypt_status.insert(tk.END, f"🗑️ Deleted original: {os.path.basename(file_path)}\n")
                    
            except Exception as e:
                self.encrypt_status.insert(tk.END, f"❌ Error: {str(e)}\n")
                
            self.encrypt_status.see(tk.END)
            self.root.update()
            
        self.encrypt_progress.stop()
        self.encrypt_status.insert(tk.END, "\n🎉 Encryption completed!\n")
        self.encrypt_status.see(tk.END)
        
    def decrypt_files(self):
        """Decrypt selected files"""
        if not hasattr(self, 'selected_decrypt_files') or not self.selected_decrypt_files:
            messagebox.showwarning("No Files", "Please select encrypted files")
            return
            
        password = self.decrypt_password_var.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter the decryption password")
            return
            
        threading.Thread(target=self._decrypt_files_thread, daemon=True).start()
        
    def _decrypt_files_thread(self):
        """Decryption thread"""
        self.decrypt_progress.start()
        self.decrypt_status.delete(1.0, tk.END)
        
        password = self.decrypt_password_var.get()
        
        for file_path in self.selected_decrypt_files:
            try:
                self.decrypt_status.insert(tk.END, f"Decrypting: {os.path.basename(file_path)}\n")
                self.decrypt_status.see(tk.END)
                self.root.update()
                
                result = self.encryption_engine.decrypt_file(file_path, password)
                self.decrypt_status.insert(tk.END, f"✅ Success: {result['output_path']}\n")
                
            except Exception as e:
                self.decrypt_status.insert(tk.END, f"❌ Error: {str(e)}\n")
                
            self.decrypt_status.see(tk.END)
            self.root.update()
            
        self.decrypt_progress.stop()
        self.decrypt_status.insert(tk.END, "\n🎉 Decryption completed!\n")
        self.decrypt_status.see(tk.END)
        
    def clear_selection(self):
        """Clear selected files"""
        self.selected_files.clear()
        self.files_listbox.delete(0, tk.END)
        
    def clear_decrypt_selection(self):
        """Clear selected decrypt files"""
        if hasattr(self, 'selected_decrypt_files'):
            self.selected_decrypt_files.clear()
        self.decrypt_files_listbox.delete(0, tk.END)
        
    def refresh_vault(self):
        """Refresh vault entries display"""
        try:
            entries = self.vault_manager.list_vault_entries()
            
            # Clear existing items
            for item in self.vault_tree.get_children():
                self.vault_tree.delete(item)
                
            # Add entries
            for entry in entries:
                size_str = format_file_size(entry['file_size'])
                created = entry['created_timestamp'][:10]  # Just date
                
                self.vault_tree.insert('', tk.END, values=(
                    entry['original_name'],
                    entry['entry_type'],
                    entry['algorithm'],
                    size_str,
                    created
                ))
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh vault: {str(e)}")
            
    def search_vault(self, event=None):
        """Search vault entries"""
        search_term = self.search_var.get()
        if not search_term:
            self.refresh_vault()
            return
            
        try:
            entries = self.vault_manager.search_vault_entries(search_term)
            
            # Clear and populate
            for item in self.vault_tree.get_children():
                self.vault_tree.delete(item)
                
            for entry in entries:
                size_str = format_file_size(entry['file_size'])
                created = entry['created_timestamp'][:10]
                
                self.vault_tree.insert('', tk.END, values=(
                    entry['original_name'],
                    entry['entry_type'],
                    entry['algorithm'],
                    size_str,
                    created
                ))
                
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {str(e)}")
            
    def cleanup_vault(self):
        """Clean up vault"""
        if messagebox.askyesno("Cleanup Vault", "This will remove orphaned files and optimize the database. Continue?"):
            try:
                result = self.vault_manager.cleanup_vault()
                messagebox.showinfo("Cleanup Complete", 
                                  f"Removed {result['orphaned_files_removed']} orphaned files\n"
                                  f"Database compressed: {result['database_compressed']}")
                self.refresh_vault()
            except Exception as e:
                messagebox.showerror("Error", f"Cleanup failed: {str(e)}")
                
    def show_vault_stats(self):
        """Show vault statistics"""
        try:
            stats = self.vault_manager.get_vault_statistics()
            
            stats_text = f"""Vault Statistics:
            
Total Entries: {stats['total_entries']}
Total Original Size: {format_file_size(stats['total_original_size'])}
Vault Disk Size: {format_file_size(stats['vault_disk_size'])}
Vault Version: {stats['vault_version']}

Type Distribution:
"""
            
            for entry_type, data in stats['type_distribution'].items():
                stats_text += f"  {entry_type}: {data['count']} files\n"
                
            stats_text += "\nAlgorithm Distribution:\n"
            for algorithm, count in stats['algorithm_distribution'].items():
                stats_text += f"  {algorithm}: {count} files\n"
                
            messagebox.showinfo("Vault Statistics", stats_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get statistics: {str(e)}")
            
    def generate_random_password(self):
        """Generate random password"""
        from ..core.keygen import KeyManager
        key_manager = KeyManager()
        password = key_manager.generate_random_key_phrase(8)
        
        # Show in dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Generated Password")
        dialog.geometry("400x200")
        
        ttk.Label(dialog, text="Generated Password:", font=('Arial', 12, 'bold')).pack(pady=10)
        
        password_text = tk.Text(dialog, height=3, width=50)
        password_text.pack(pady=10)
        password_text.insert(1.0, password)
        password_text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Copy to Clipboard", 
                  command=lambda: self.root.clipboard_append(password)).pack(pady=5)
        ttk.Button(dialog, text="Use This Password", 
                  command=lambda: [self.password_var.set(password), dialog.destroy()]).pack(pady=5)
                  
    def export_key_qr(self):
        """Export encryption key as QR code"""
        messagebox.showinfo("QR Export", "QR code export functionality will be available after encryption")
        
    def run(self):
        """Start the GUI application"""
        self.refresh_vault()
        self.root.mainloop()


def main():
    """Main entry point"""
    app = CipherVaultGUI()
    app.run()


if __name__ == "__main__":
    main()
