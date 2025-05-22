"""
File Controller - Handles file operations with path traversal vulnerabilities
Contains both live and dead vulnerable code for SAST testing
"""

import os
import shutil
import tempfile
from pathlib import Path
from flask import request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
import zipfile
import tarfile

# Live vulnerability - Direct path traversal in file download
def download_file():
    """Download file endpoint with path traversal vulnerability"""
    filename = request.args.get('file')
    if not filename:
        return jsonify({'error': 'No file specified'}), 400
    
    # VULNERABILITY: Direct concatenation allows path traversal
    file_path = os.path.join('/app/uploads', filename)
    
    if os.path.exists(file_path):
        return send_file(file_path)
    else:
        return jsonify({'error': 'File not found'}), 404

# Live vulnerability - Path traversal in file upload
def upload_file():
    """File upload with path traversal in destination"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    # Get custom upload path from request
    upload_path = request.form.get('path', 'uploads')
    
    # VULNERABILITY: User-controlled path allows directory traversal
    destination = os.path.join('/app', upload_path, file.filename)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    file.save(destination)
    
    return jsonify({'message': 'File uploaded successfully', 'path': destination})

# Live vulnerability - Archive extraction without validation
def extract_archive():
    """Extract uploaded archive with path traversal vulnerability"""
    archive_path = request.json.get('archive_path')
    extract_to = request.json.get('extract_to', '/app/extracted')
    
    if not archive_path:
        return jsonify({'error': 'No archive path provided'}), 400
    
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # VULNERABILITY: Extract without path validation
                zip_ref.extractall(extract_to)
        elif archive_path.endswith('.tar.gz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                # VULNERABILITY: Extract without path validation  
                tar_ref.extractall(extract_to)
        
        return jsonify({'message': 'Archive extracted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Live vulnerability - File listing with path traversal
def list_directory():
    """List directory contents with path traversal vulnerability"""
    directory = request.args.get('dir', '.')
    
    # VULNERABILITY: No validation of directory parameter
    full_path = os.path.join('/app', directory)
    
    try:
        files = []
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            files.append({
                'name': item,
                'type': 'directory' if os.path.isdir(item_path) else 'file',
                'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0
            })
        
        return jsonify({'files': files, 'path': full_path})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Live vulnerability - File deletion with path traversal
def delete_file():
    """Delete file with path traversal vulnerability"""
    filename = request.json.get('filename')
    directory = request.json.get('directory', 'uploads')
    
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400
    
    # VULNERABILITY: Path traversal in file deletion
    file_path = os.path.join('/app', directory, filename)
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({'message': 'File deleted successfully'})
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Dead code - Unused vulnerable function
def backup_user_files():
    """
    DEAD CODE: This function is never called but contains vulnerabilities
    """
    user_id = request.args.get('user_id')
    backup_path = request.args.get('path', '/tmp')
    
    # VULNERABILITY: Command injection in dead code
    os.system(f"tar -czf {backup_path}/user_{user_id}_backup.tar.gz /app/user_data/{user_id}")
    
    # VULNERABILITY: Path traversal in dead code
    source_dir = f"/app/users/{user_id}/../../../etc"
    shutil.copytree(source_dir, f"{backup_path}/sensitive_backup")

# Dead code - Commented out vulnerable function
"""
def legacy_file_manager():
    # DEAD CODE: Old file manager with multiple vulnerabilities
    action = request.form.get('action')
    filename = request.form.get('filename')
    
    if action == 'read':
        # Path traversal vulnerability
        with open(f"/app/files/{filename}", 'r') as f:
            return f.read()
    elif action == 'execute':
        # Command injection vulnerability  
        os.system(f"python /app/scripts/{filename}")
    elif action == 'copy':
        dest = request.form.get('destination')
        # Path traversal in copy operation
        shutil.copy(f"/app/files/{filename}", dest)
"""

# Dead code - Unreachable conditional block
if False:  # This block will never execute
    def vulnerable_temp_file_handler():
        """Path traversal in temporary file creation"""
        temp_name = request.args.get('temp_name')
        # VULNERABILITY: User-controlled temp file path
        temp_path = os.path.join('/tmp', temp_name)
        
        with open(temp_path, 'w') as f:
            f.write("sensitive data")
        
        # VULNERABILITY: Insecure file permissions
        os.chmod(temp_path, 0o777)

# Dead code - Unused import and function
try:
    import subprocess
    
    def old_file_processor():
        """
        DEAD CODE: Never called file processor with command injection
        """
        file_type = request.json.get('type')
        filename = request.json.get('filename')
        
        # VULNERABILITY: Command injection in dead code
        result = subprocess.run(f"file /app/uploads/{filename} | grep {file_type}", 
                               shell=True, capture_output=True, text=True)
        
        return result.stdout
        
except ImportError:
    pass

# Mixed code - Some functions called, others dead
class FileManager:
    """File manager class with mixed live and dead vulnerabilities"""
    
    def __init__(self):
        self.base_path = '/app/managed_files'
    
    # Live function - actually used
    def get_file_info(self, filename):
        """Get file information with path traversal vulnerability"""
        # VULNERABILITY: No path validation
        file_path = os.path.join(self.base_path, filename)
        
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            return {
                'name': filename,
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'path': file_path  # Leaks full path
            }
        return None
    
    # Dead function - never called
    def admin_file_access(self, filename):
        """
        DEAD CODE: Admin file access with multiple vulnerabilities
        """
        # VULNERABILITY: Hardcoded admin path
        admin_key = "admin123"  # Hardcoded secret
        
        # VULNERABILITY: Path traversal
        file_path = f"/app/admin/{filename}"
        
        # VULNERABILITY: Command execution
        os.system(f"chmod 777 {file_path}")
        
        with open(file_path, 'r') as f:
            return f.read()
    
    # Dead function - only called in commented code
    def legacy_backup_system(self, source, destination):
        """
        DEAD CODE: Legacy backup with command injection
        """
        # VULNERABILITY: Command injection
        backup_cmd = f"rsync -av {source} {destination}"
        os.system(backup_cmd)

# File manager instance
file_manager = FileManager()

# Routes that use the live functions
def get_managed_file_info():
    """Route that calls live vulnerable function"""
    filename = request.args.get('filename')
    info = file_manager.get_file_info(filename)
    return jsonify(info)

# Dead route - never registered
"""
@app.route('/admin/files')
def admin_file_route():
    # This route is commented out so never accessible
    filename = request.args.get('file')
    return file_manager.admin_file_access(filename)
"""