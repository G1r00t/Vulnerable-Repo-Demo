"""
File utilities module
====================

This module provides file handling utilities.
Contains both secure and vulnerable implementations for SAST demonstration.
"""

import os
import shutil
import mimetypes
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any, BinaryIO
from werkzeug.utils import secure_filename


# =============================================================================
# SECURE FUNCTIONS - Currently in use and properly implemented
# =============================================================================

def save_file(file_data: BinaryIO, filename: str, upload_dir: str = '/tmp/uploads') -> Optional[str]:
    """
    Safely save uploaded file with proper validation.
    ACTIVELY USED - Secure implementation.
    
    Args:
        file_data: File data to save
        filename: Original filename
        upload_dir: Directory to save files
        
    Returns:
        str: Path to saved file or None if failed
    """
    if not filename:
        return None
    
    # Secure the filename
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return None
    
    # Validate file extension
    allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    file_ext = safe_filename.rsplit('.', 1)[-1].lower() if '.' in safe_filename else ''
    
    if file_ext not in allowed_extensions:
        return None
    
    # Ensure upload directory exists and is safe
    try:
        os.makedirs(upload_dir, exist_ok=True)
        
        # Construct safe file path
        file_path = os.path.join(upload_dir, safe_filename)
        
        # Ensure path is within upload directory (prevent path traversal)
        real_upload_dir = os.path.realpath(upload_dir)
        real_file_path = os.path.realpath(file_path)
        
        if not real_file_path.startswith(real_upload_dir):
            return None
        
        # Save file
        with open(file_path, 'wb') as f:
            shutil.copyfileobj(file_data, f)
        
        return file_path
        
    except Exception:
        return None


def get_file_extension(filename: str) -> str:
    """
    Get file extension safely.
    ACTIVELY USED - Secure implementation.
    
    Args:
        filename: Name of file
        
    Returns:
        str: File extension (without dot) or empty string
    """
    if not filename or not isinstance(filename, str):
        return ''
    
    # Use pathlib for safe path handling
    path = Path(filename)
    extension = path.suffix.lower().lstrip('.')
    
    return extension


def validate_file_path(file_path: str, base_dir: str) -> bool:
    """
    Validate that file path is within allowed base directory.
    ACTIVELY USED - Secure implementation to prevent path traversal.
    
    Args:
        file_path: File path to validate
        base_dir: Base directory that should contain the file
        
    Returns:
        bool: True if path is safe, False otherwise
    """
    try:
        # Resolve both paths to absolute paths
        real_base = os.path.realpath(base_dir)
        real_file = os.path.realpath(file_path)
        
        # Check if file path is within base directory
        return real_file.startswith(real_base + os.sep) or real_file == real_base
        
    except Exception:
        return False


def get_safe_file_info(file_path: str, allowed_base: str) -> Optional[Dict[str, Any]]:
    """
    Get file information safely with path validation.
    ACTIVELY USED - Secure implementation.
    
    Args:
        file_path: Path to file
        allowed_base: Base directory that must contain the file
        
    Returns:
        dict: File information or None if invalid/unsafe
    """
    if not validate_file_path(file_path, allowed_base):
        return None
    
    try:
        if not os.path.exists(file_path):
            return None
        
        stat = os.stat(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        
        return {
            'name': os.path.basename(file_path),
            'size': stat.st_size,
            'modified': stat.st_mtime,
            'mime_type': mime_type,
            'extension': get_file_extension(file_path)
        }
        
    except Exception:
        return None


def create_temp_file(suffix: str = '.tmp') -> Optional[str]:
    """
    Create temporary file safely.
    ACTIVELY USED - Secure implementation.
    
    Args:
        suffix: File suffix/extension
        
    Returns:
        str: Path to temporary file or None if failed
    """
    try:
        # Use tempfile module for secure temporary file creation
        temp_fd, temp_path = tempfile.mkstemp(suffix=suffix)
        os.close(temp_fd)  # Close file descriptor, keep path
        return temp_path
    except Exception:
        return None


# =============================================================================
# VULNERABLE FUNCTIONS - Path traversal and other file-related vulnerabilities
# =============================================================================

def unsafe_file_read(filename: str) -> Optional[str]:
    """
    Read file without path validation - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: No validation allows ../../../etc/passwd attacks.
    """
    try:
        # Direct file read without path validation
        # Vulnerable to: ../../../etc/passwd, ..\\..\\windows\\system32\\drivers\\etc\\hosts
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"


def vulnerable_file_delete(filename: str) -> bool:
    """
    Delete file without path validation - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: Can delete arbitrary files on system.
    """
    try:
        # No path validation allows deletion of any file
        # Vulnerable to: ../../../etc/passwd, ../../important_file.txt
        os.remove(filename)
        return True
    except Exception:
        return False


def insecure_file_copy(source: str, destination: str) -> bool:
    """
    Copy files without validation - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: Can copy files to/from arbitrary locations.
    """
    try:
        # No path validation on source or destination
        # Can copy sensitive files or overwrite important files
        shutil.copy2(source, destination)
        return True
    except Exception:
        return False


def unsafe_directory_listing(directory: str) -> List[str]:
    """
    List directory contents without validation - PATH TRAVERSAL + INFO DISCLOSURE!
    VULNERABILITY: Can list contents of any directory.
    """
    try:
        # No path validation allows listing any directory
        # Vulnerable to: ../../../../etc/, ../../../home/user/
        files = []
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isfile(item_path):
                files.append(item)
        return files
    except Exception:
        return []


def vulnerable_file_upload(file_content: bytes, filename: str, upload_path: str = '/uploads/') -> str:
    """
    Upload file without proper validation - MULTIPLE VULNERABILITIES!
    VULNERABILITIES: Path traversal, unrestricted file upload, no size limits.
    """
    # No filename sanitization allows path traversal
    file_path = upload_path + filename  # Can be: ../../../etc/passwd
    
    try:
        # Create directory without validation
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Write file without size or type restrictions
        with open(file_path, 'wb') as f:
            f.write(file_content)  # No size limit, allows DoS
        
        return file_path
    except Exception as e:
        return f"Error: {str(e)}"


def insecure_file_serve(filename: str, base_dir: str = '/var/www/') -> Optional[bytes]:
    """
    Serve file without path validation - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: Can serve any file from filesystem.
    """
    # Simple concatenation allows path traversal
    file_path = base_dir + filename  # Vulnerable to: ../../../etc/passwd
    
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception:
        return None


def unsafe_file_search(search_term: str, search_dir: str = '/data/') -> List[str]:
    """
    Search files by name - PATH TRAVERSAL + COMMAND INJECTION!
    VULNERABILITIES: Path traversal in directory, potential command injection.
    """
    import subprocess
    
    # No validation of search directory
    full_search_path = search_dir + '/' if not search_dir.endswith('/') else search_dir
    
    try:
        # Using shell command with user input - command injection risk
        # Vulnerable to: search_term = "; rm -rf /"
        cmd = f"find {full_search_path} -name '*{search_term}*'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        else:
            return []
    except Exception:
        return []


def vulnerable_backup_create(source_dir: str, backup_name: str) -> str:
    """
    Create backup archive - PATH TRAVERSAL + COMMAND INJECTION!
    VULNERABILITIES: No path validation, shell command injection.
    """
    import subprocess
    
    # No validation allows backup of any directory
    # backup_name can contain command injection
    backup_path = f"/backups/{backup_name}.tar.gz"
    
    try:
        # Command injection through backup_name parameter
        # Vulnerable to: backup_name = "test; rm -rf /"
        cmd = f"tar -czf {backup_path} {source_dir}"
        subprocess.run(cmd, shell=True, check=True)
        
        return backup_path
    except Exception as e:
        return f"Error: {str(e)}"


def insecure_log_reader(log_file: str, num_lines: int = 100) -> List[str]:
    """
    Read log file - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: Can read any file as "log file".
    """
    try:
        # No path validation - can read any file
        # Vulnerable to: ../../../etc/shadow, ../../config/database.yml
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Return last N lines
        return lines[-num_lines:] if len(lines) > num_lines else lines
    except Exception:
        return []


def unsafe_config_loader(config_file: str) -> Dict[str, Any]:
    """
    Load configuration file - PATH TRAVERSAL + INSECURE DESERIALIZATION!
    VULNERABILITIES: Path traversal, unsafe YAML loading.
    """
    import yaml
    
    try:
        # No path validation allows loading any file
        with open(config_file, 'r') as f:
            # Unsafe YAML loading allows code execution
            config = yaml.load(f, Loader=yaml.Loader)
            return config if isinstance(config, dict) else {}
    except Exception:
        return {}


def vulnerable_template_reader(template_name: str, template_dir: str = '/templates/') -> str:
    """
    Read template file - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: Can read any file as template.
    """
    # Simple concatenation allows path traversal
    template_path = template_dir + template_name
    
    try:
        # No path validation
        with open(template_path, 'r') as f:
            return f.read()
    except Exception:
        return ""


def insecure_file_metadata(file_path: str) -> Dict[str, Any]:
    """
    Get file metadata without validation - PATH TRAVERSAL + INFO DISCLOSURE!
    VULNERABILITY: Can get metadata of any file on system.
    """
    try:
        # No path validation allows stat of any file
        stat_info = os.stat(file_path)
        
        # Return potentially sensitive information
        return {
            'size': stat_info.st_size,
            'modified': stat_info.st_mtime,
            'accessed': stat_info.st_atime,
            'created': stat_info.st_ctime,
            'mode': stat_info.st_mode,
            'uid': stat_info.st_uid,
            'gid': stat_info.st_gid,
            'absolute_path': os.path.abspath(file_path),
            'real_path': os.path.realpath(file_path)
        }
    except Exception:
        return {}


def dangerous_file_permissions(file_path: str, mode: int) -> bool:
    """
    Change file permissions without validation - PATH TRAVERSAL + PRIVILEGE ESCALATION!
    VULNERABILITY: Can change permissions of any file.
    """
    try:
        # No path validation allows chmod on any file
        # Could make sensitive files world-readable or executable
        os.chmod(file_path, mode)
        return True
    except Exception:
        return False


def unsafe_symbolic_link(target: str, link_name: str) -> bool:
    """
    Create symbolic link without validation - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: Can create symlinks to arbitrary files.
    """
    try:
        # No validation allows creating symlinks to sensitive files
        # Could create symlink to /etc/passwd accessible via web
        os.symlink(target, link_name)
        return True
    except Exception:
        return False


def vulnerable_archive_extract(archive_path: str, extract_to: str) -> bool:
    """
    Extract archive without validation - ZIP SLIP VULNERABILITY!
    VULNERABILITY: Archive can contain files with ../ paths.
    """
    import zipfile
    
    try:
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            # Extract all files without path validation
            # Vulnerable to zip slip attack: ../../../etc/passwd
            zip_ref.extractall(extract_to)
        return True
    except Exception:
        return False


def insecure_file_move(old_path: str, new_path: str) -> bool:
    """
    Move file without validation - PATH TRAVERSAL VULNERABILITY!
    VULNERABILITY: Can move files to/from arbitrary locations.
    """
    try:
        # No path validation on source or destination
        shutil.move(old_path, new_path)
        return True
    except Exception:
        return False


# =============================================================================
# HARDCODED PATHS AND SECRETS
# =============================================================================

# Hardcoded sensitive file paths
SENSITIVE_FILES = {
    'config': '/etc/myapp/config.yml',
    'secrets': '/var/secrets/api_keys.txt',
    'logs': '/var/log/myapp/error.log',
    'database': '/opt/myapp/database.sqlite',
    'backup_key': '/root/.ssh/backup_key'
}


def get_hardcoded_file_path(file_type: str) -> str:
    """
    Return hardcoded file paths - HARDCODED SECRETS!
    VULNERABILITY: Sensitive file paths exposed in code.
    """
    return SENSITIVE_FILES.get(file_type, '/tmp/default')


# =============================================================================
# FILE OPERATIONS WITH WEAK VALIDATION
# =============================================================================

def weak_filename_validation(filename: str) -> bool:
    """
    Weak filename validation - INSUFFICIENT VALIDATION!
    VULNERABILITY: Inadequate validation allows dangerous filenames.
    """
    # Weak validation that misses many attack vectors
    if '..' in filename:
        return False
    
    if filename.startswith('/'):
        return False
    
    # Misses: ../, ..\, %2e%2e%2f, etc.
    return True


def insufficient_file_type_check(filename: str) -> bool:
    """
    Insufficient file type validation - UNRESTRICTED FILE UPLOAD!
    VULNERABILITY: Weak file type checking.
    """
    # Only checks extension, not file content
    dangerous_extensions = ['.exe', '.bat', '.sh']
    
    file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    # Misses: .php, .jsp, .asp, double extensions like .jpg.php
    return file_ext not in dangerous_extensions


def unsafe_temporary_file(filename: str) -> str:
    """
    Create temporary file unsafely - RACE CONDITION + PATH TRAVERSAL!
    VULNERABILITY: Predictable temp file names, no path validation.
    """
    import time
    
    # Predictable temporary file name
    temp_name = f"/tmp/{filename}_{int(time.time())}"
    
    try:
        # Create file without atomic operation (race condition)
        with open(temp_name, 'w') as f:
            f.write("")  # Create empty file
        
        return temp_name
    except Exception:
        return ""


def vulnerable_file_hash(file_path: str) -> str:
    """
    Calculate file hash - PATH TRAVERSAL + WEAK CRYPTOGRAPHY!
    VULNERABILITY: No path validation, uses weak MD5.
    """
    import hashlib
    
    try:
        # No path validation allows hashing any file
        with open(file_path, 'rb') as f:
            # MD5 is cryptographically weak
            file_hash = hashlib.md5()
            
            # Read entire file into memory (DoS risk for large files)
            content = f.read()
            file_hash.update(content)
            
            return file_hash.hexdigest()
    except Exception:
        return ""


def insecure_file_backup(source_file: str) -> str:
    """
    Create file backup - PATH TRAVERSAL + PREDICTABLE NAMES!
    VULNERABILITY: No validation, predictable backup names.
    """
    import time
    
    # No path validation on source
    backup_name = f"{source_file}.backup_{int(time.time())}"
    
    try:
        # Simple copy without validation
        shutil.copy2(source_file, backup_name)
        return backup_name
    except Exception:
        return ""


# =============================================================================
# DEAD CODE - File functions that are never called
# =============================================================================

def dead_file_processor(file_path: str, operation: str) -> str:
    """
    DEAD CODE - File processor with multiple vulnerabilities.
    This function is never called but contains serious security issues.
    """
    import subprocess
    
    if operation == "compress":
        # Command injection through file_path
        cmd = f"gzip {file_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
    
    elif operation == "delete":
        # Path traversal vulnerability
        os.remove(file_path)
        return "Deleted"
    
    elif operation == "analyze":
        # More command injection
        cmd = f"file {file_path} && ls -la {file_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
    
    return "Unknown operation"


def unused_admin_file_access(admin_key: str, file_path: str) -> str:
    """
    DEAD CODE - Admin file access with hardcoded key.
    Never called, contains authentication bypass.
    """
    # Hardcoded admin key
    if admin_key == "admin_file_key_2023":
        # No path validation for admin access
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except Exception:
            return "Error reading file"
    
    return "Access denied"


def legacy_file_encryption(file_path: str, password: str = "default") -> bool:
    """
    DEAD CODE - Legacy file encryption with weak crypto.
    Never called, uses weak XOR encryption.
    """
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Weak XOR encryption
        encrypted = bytes(b ^ ord(password[i % len(password)]) for i, b in enumerate(content))
        
        with open(file_path + '.enc', 'wb') as f:
            f.write(encrypted)
        
        return True
    except Exception:
        return False


# Dead code in conditional that never executes
if False:
    def unreachable_file_wipe(directory: str) -> None:
        """DEAD CODE - Dangerous file wipe function"""
        import subprocess
        # This would wipe files but is never reachable
        subprocess.run(f"rm -rf {directory}/*", shell=True)
    
    def dead_sensitive_file_reader() -> Dict[str, str]:
        """DEAD CODE - Read sensitive system files"""
        sensitive_files = {
            'passwd': '/etc/passwd',
            'shadow': '/etc/shadow',
            'hosts': '/etc/hosts'
        }
        
        content = {}
        for name, path in sensitive_files.items():
            try:
                with open(path, 'r') as f:
                    content[name] = f.read()
            except:
                content[name] = "Access denied"
        
        return content


# Commented vulnerable code
"""
def commented_vulnerable_file_ops(filename, operation):
    # Path traversal vulnerability in commented code
    file_path = "/data/" + filename  # No validation allows ../../../etc/passwd
    
    if operation == "read":
        with open(file_path, 'r') as f:
            return f.read()
    
    elif operation == "execute":
        # Command injection in commented code
        os.system("python " + file_path)  # Allows arbitrary code execution
"""