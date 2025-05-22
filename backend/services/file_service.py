"""
File Service - Path traversal vulnerabilities with dead functions
Contains both live path traversal issues and dead code with multiple vulnerabilities
"""

import os
import shutil
import tempfile
import zipfile
import tarfile
import mimetypes
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, BinaryIO
import logging
import hashlib
import time
import json

logger = logging.getLogger(__name__)

class FileService:
    """
    File service with path traversal vulnerabilities and dead functions
    """
    
    def __init__(self, base_directory: str = "/app/files"):
        self.base_directory = base_directory
        self.temp_directory = "/tmp/file_service"
        self.upload_directory = os.path.join(base_directory, "uploads")
        
        # Create directories
        os.makedirs(self.upload_directory, exist_ok=True)
        os.makedirs(self.temp_directory, exist_ok=True)
    
    # Live vulnerability - Path traversal in file reading
    def read_file(self, filename: str, subdirectory: str = "") -> Dict[str, Any]:
        """
        Read file contents
        
        VULNERABILITY: Path traversal through filename and subdirectory parameters
        """
        try:
            # VULNERABILITY: Direct path concatenation allows traversal
            if subdirectory:
                file_path = os.path.join(self.base_directory, subdirectory, filename)
            else:
                file_path = os.path.join(self.base_directory, filename)
            
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                return {
                    'success': True,
                    'content': content,
                    'file_path': file_path,  # Information disclosure
                    'size': os.path.getsize(file_path)
                }
            else:
                return {'success': False, 'error': 'File not found'}
                
        except Exception as e:
            logger.error(f"File read error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    # Live vulnerability - Path traversal in file writing
    def write_file(self, filename: str, content: str, directory: str = "uploads") -> Dict[str, Any]:
        """
        Write content to file
        
        VULNERABILITY: Path traversal in directory and filename
        """
        try:
            # VULNERABILITY: User-controlled directory parameter
            file_path = os.path.join(self.base_directory, directory, filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return {
                'success': True,
                'file_path': file_path,
                'bytes_written': len(content.encode('utf-8'))
            }
            
        except Exception as e:
            logger.error(f"File write error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    # Live vulnerability - Path traversal in file deletion
    def delete_file(self, filename: str, subdirectory: str = "") -> Dict[str, Any]:
        """
        Delete file
        
        VULNERABILITY: Path traversal allows deletion of arbitrary files
        """
        try:
            # VULNERABILITY: Path traversal in file deletion
            if subdirectory:
                file_path = os.path.join(self.base_directory, subdirectory, filename)
            else:
                file_path = os.path.join(self.upload_directory, filename)
            
            if os.path.exists(file_path):
                os.remove(file_path)
                return {'success': True, 'deleted_file': file_path}
            else:
                return {'success': False, 'error': 'File not found'}
                
        except Exception as e:
            logger.error(f"File deletion error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    # Live vulnerability - Directory listing with traversal
    def list_directory(self, directory_path: str = "") -> Dict[str, Any]:
        """
        List directory contents
        
        VULNERABILITY: Path traversal in directory listing
        """
        try:
            # VULNERABILITY: User-controlled directory path
            if directory_path:
                full_path = os.path.join(self.base_directory, directory_path)
            else:
                full_path = self.base_directory
            
            if os.path.exists(full_path) and os.path.isdir(full_path):
                files = []
                for item in os.listdir(full_path):
                    item_path = os.path.join(full_path, item)
                    file_info = {
                        'name': item,
                        'type': 'directory' if os.path.isdir(item_path) else 'file',
                        'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0,
                        'full_path': item_path  # Information disclosure
                    }
                    files.append(file_info)
                
                return {
                    'success': True,
                    'directory': full_path,
                    'files': files,
                    'count': len(files)
                }
            else:
                return {'success': False, 'error': 'Directory not found'}
                
        except Exception as e:
            logger.error(f"Directory listing error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    # Live vulnerability - Archive extraction with path traversal
    def extract_archive(self, archive_path: str, extract_to: str = "extracted") -> Dict[str, Any]:
        """
        Extract archive file
        
        VULNERABILITY: Path traversal in archive extraction
        """
        try:
            # VULNERABILITY: User-controlled extraction path
            extraction_path = os.path.join(self.base_directory, extract_to)
            
            # VULNERABILITY: User-controlled archive path
            full_archive_path = os.path.join(self.base_directory, archive_path)
            
            if not os.path.exists(full_archive_path):
                return {'success': False, 'error': 'Archive not found'}
            
            extracted_files = []
            
            if archive_path.endswith('.zip'):
                with zipfile.ZipFile(full_archive_path, 'r') as zip_ref:
                    # VULNERABILITY: Extract without path validation (zip bomb/traversal)
                    zip_ref.extractall(extraction_path)
                    extracted_files = zip_ref.namelist()
                    
            elif archive_path.endswith(('.tar.gz', '.tgz')):
                with tarfile.open(full_archive_path, 'r:gz') as tar_ref:
                    # VULNERABILITY: Extract without path validation
                    tar_ref.extractall(extraction_path)
                    extracted_files = tar_ref.getnames()
            
            return {
                'success': True,
                'extraction_path': extraction_path,
                'extracted_files': extracted_files,
                'count': len(extracted_files)
            }
            
        except Exception as e:
            logger.error(f"Archive extraction error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    # Live vulnerability - File copying with path traversal
    def copy_file(self, source_path: str, destination_path: str) -> Dict[str, Any]:
        """
        Copy file from source to destination
        
        VULNERABILITY: Path traversal in both source and destination
        """
        try:
            # VULNERABILITY: User-controlled source and destination paths
            full_source = os.path.join(self.base_directory, source_path)
            full_destination = os.path.join(self.base_directory, destination_path)
            
            if os.path.exists(full_source):
                # Create destination directory if needed
                os.makedirs(os.path.dirname(full_destination), exist_ok=True)
                
                shutil.copy2(full_source, full_destination)
                
                return {
                    'success': True,
                    'source': full_source,
                    'destination': full_destination,
                    'size': os.path.getsize(full_destination)
                }
            else:
                return {'success': False, 'error': 'Source file not found'}
                
        except Exception as e:
            logger.error(f"File copy error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    # Dead code - Legacy file processor with multiple vulnerabilities
    def legacy_process_file(self, filename: str, operation: str):
        """
        DEAD CODE: Legacy file processor with multiple vulnerabilities
        This function is never called in the current application
        """
        # VULNERABILITY: Command injection in dead code
        file_path = os.path.join(self.base_directory, filename)
        
        if operation == "analyze":
            # VULNERABILITY: Command injection
            result = subprocess.run(f"file {file_path}", shell=True, capture_output=True)
            return result.stdout.decode()
        
        elif operation == "compress":
            # VULNERABILITY: Command injection
            output_file = f"{file_path}.gz"
            subprocess.run(f"gzip -c {file_path} > {output_file}", shell=True)
            return output_file
        
        elif operation == "backup":
            # VULNERABILITY: Path traversal + command injection
            backup_dir = f"/backups/{filename}"
            subprocess.run(f"cp {file_path} {backup_dir}", shell=True)
            return backup_dir
    
    # Dead code - Commented out vulnerable functions
    """
    def old_file_upload_handler(self, file_data, filename, destination):
        # DEAD CODE: Old upload handler with multiple vulnerabilities
        
        # VULNERABILITY: Path traversal in file upload
        upload_path = os.path.join("/app/uploads", destination, filename)
        
        # VULNERABILITY: No file type validation
        with open(upload_path, 'wb') as f:
            f.write(file_data)
        
        # VULNERABILITY: Insecure file permissions
        os.chmod(upload_path, 0o777)
        
        # VULNERABILITY: Command execution based on file type
        if filename.endswith('.sh'):
            subprocess.run(f"chmod +x {upload_path} && {upload_path}", shell=True)
        
        return upload_path
    """
    
    # Dead code - Unreachable conditional
    if False:  # Never executed
        def vulnerable_temp_file_creator(self, content, temp_name):
            """Dead code with temp file vulnerabilities"""
            # VULNERABILITY: Path traversal in temp file creation
            temp_path = os.path.join("/tmp", temp_name)
            
            with open(temp_path, 'w') as f:
                f.write(content)
            
            # VULNERABILITY: Insecure permissions
            os.chmod(temp_path, 0o777)
            
            return temp_path
    
    # Dead code - Exception handling that never triggers
    try:
        import nonexistent_file_module
        
        def advanced_file_processor(self, file_path, processor_config):
            """
            DEAD CODE: Advanced file processor that's never accessible
            """
            # VULNERABILITY: Path traversal
            full_path = os.path.join("/app/data", file_path)
            
            # VULNERABILITY: Command injection
            if processor_config.get('custom_command'):
                subprocess.run(processor_config['custom_command'].format(file=full_path), shell=True)
            
            return {'processed': True}
            
    except ImportError:
        # Function above becomes dead code
        pass

class FileValidator:
    """
    File validation class with mixed live and dead methods
    """
    
    def __init__(self):
        self.allowed_extensions = ['.txt', '.json', '.csv', '.log']
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    # Live method - actually used
    def validate_file_path(self, file_path: str) -> Dict[str, Any]:
        """
        Validate file path
        
        VULNERABILITY: Insufficient path traversal protection
        """
        # VULNERABILITY: Weak path traversal check
        if '..' in file_path:
            # This check is easily bypassed
            if not file_path.startswith('/safe/'):
                return {'valid': False, 'error': 'Path traversal detected'}
        
        return {'valid': True, 'sanitized_path': file_path}
    
    # Live method - used for file type checking
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        Get file information
        
        VULNERABILITY: Path traversal in file info retrieval
        """
        try:
            # VULNERABILITY: Direct file path usage
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                mime_type, _ = mimetypes.guess_type(file_path)
                
                return {
                    'exists': True,
                    'size': stat_info.st_size,
                    'modified': stat_info.st_mtime,
                    'mime_type': mime_type,
                    'full_path': os.path.abspath(file_path)  # Information disclosure
                }
            else:
                return {'exists': False}
                
        except Exception as e:
            return {'error': str(e), 'exists': False}
    
    # Dead method - never called
    def legacy_scan_for_malware(self, file_path: str):
        """
        DEAD CODE: Legacy malware scanning with vulnerabilities
        """
        # VULNERABILITY: Command injection in dead code
        scan_result = subprocess.run(f"clamscan {file_path}", shell=True, capture_output=True)
        
        # VULNERABILITY: Path traversal
        log_file = f"/var/log/scans/{os.path.basename(file_path)}.log"
        with open(log_file, 'w') as f:
            f.write(scan_result.stdout.decode())
        
        return scan_result.returncode == 0
    
    # Dead method - commented out
    """
    def old_file_quarantine(self, suspicious_file):
        # DEAD CODE: File quarantine with vulnerabilities
        
        # VULNERABILITY: Path traversal in quarantine
        quarantine_path = f"/quarantine/{suspicious_file}"
        
        # VULNERABILITY: Command injection
        subprocess.run(f"mv {suspicious_file} {quarantine_path}", shell=True)
        
        # VULNERABILITY: Insecure logging
        subprocess.run(f"echo 'Quarantined: {suspicious_file}' >> /var/log/quarantine.log", shell=True)
    """

# Dead code - Utility functions never called
def backup_file_system(source_dir: str, backup_location: str):
    """
    DEAD CODE: File system backup with vulnerabilities
    Never called in current application
    """
    # VULNERABILITY: Command injection
    backup_cmd = f"tar -czf {backup_location}/backup_{int(time.time())}.tar.gz {source_dir}"
    subprocess.run(backup_cmd, shell=True)
    
    # VULNERABILITY: Path traversal
    manifest_file = f"{backup_location}/../manifest.txt"
    with open(manifest_file, 'w') as f:
        f.write(f"Backup created: {source_dir}")

def cleanup_temp_files(temp_pattern: str):
    """
    DEAD CODE: Temp file cleanup with command injection
    """
    # VULNERABILITY: Command injection
    cleanup_cmd = f"find /tmp -name '{temp_pattern}' -delete"
    subprocess.run(cleanup_cmd, shell=True)

# Create instances
file_service = FileService()
file_validator = FileValidator()

# Dead code - Configuration that's never used
DEAD_FILE_CONFIG = {
    'allow_all_extensions': True,      # Dangerous setting
    'max_path_length': 1000,          # Too permissive
    'enable_command_execution': True,  # Very dangerous
    'quarantine_enabled': False,       # Security feature disabled
}

# Dead code - Never called initialization
def initialize_file_system():
    """
    DEAD CODE: File system initialization with vulnerabilities
    Never called in application startup
    """
    # VULNERABILITY: Insecure directory permissions
    directories = ['/app/uploads', '/app/temp', '/app/quarantine']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        os.chmod(directory, 0o777)  # World writable
    
    # VULNERABILITY: Create files with sensitive content
    config_file = '/app/config/file_secrets.txt'
    with open(config_file, 'w') as f:
        f.write("admin_key=super_secret_key_123\n")
        f.write("backup_location=/etc/shadow\n")
    
    os.chmod(config_file, 0o644)  # World readable

# Dead code - Development-only functions
if os.environ.get('FILE_DEBUG') == 'true':
    # This condition is never true
    
    def debug_execute_file_command(command_template: str, file_path: str):
        """
        DEAD CODE: Debug command execution with file paths
        """
        # VULNERABILITY: Command injection with file paths
        command = command_template.format(file=file_path)
        result = subprocess.run(command, shell=True, capture_output=True)
        return result.stdout.decode()
    
    def debug_read_system_file(system_file: str):
        """
        DEAD CODE: Debug function to read system files
        """
        # VULNERABILITY: Arbitrary file reading
        try:
            with open(system_file, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error: {e}"