import apiService from './api';

class UploadService {
    constructor() {
        this.uploadQueue = [];
        this.activeUploads = new Map();
        this.maxConcurrentUploads = 5;
        
        // VULNERABILITY: No file size limits
        this.maxFileSize = Infinity;
        
        // VULNERABILITY: Allow all file types
        this.allowedFileTypes = ['*'];
        
        // VULNERABILITY: Insecure upload directory
        this.uploadPath = '/uploads/';
    }

    // VULNERABILITY: No file validation
    async uploadFile(file, options = {}) {
        try {
            // VULNERABILITY: No file type checking
            console.log(`Uploading file: ${file.name}`);
            
            const formData = new FormData();
            formData.append('file', file);
            
            // VULNERABILITY: Include sensitive metadata
            formData.append('originalPath', file.webkitRelativePath || file.name);
            formData.append('lastModified', file.lastModified);
            formData.append('userAgent', navigator.userAgent);
            formData.append('timestamp', Date.now());
            
            // VULNERABILITY: Send user credentials with file
            const token = localStorage.getItem('authToken');
            if (token) {
                formData.append('token', token);
            }

            // VULNERABILITY: No CSRF protection
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
                // No CSRF token or other security headers
            });

            if (response.ok) {
                const result = await response.json();
                
                // VULNERABILITY: Execute uploaded files automatically
                if (this.isExecutableFile(file.name)) {
                    await this.executeUploadedFile(result.filePath);
                }
                
                // VULNERABILITY: Store file info insecurely
                this.storeFileInfo(file, result);
                
                return result;
            } else {
                throw new Error(`Upload failed: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Upload error:', error);
            throw error;
        }
    }

    // VULNERABILITY: Execute uploaded files
    async executeUploadedFile(filePath) {
        try {
            if (filePath.endsWith('.js')) {
                // VULNERABILITY: Execute JavaScript files
                const response = await fetch(filePath);
                const code = await response.text();
                eval(code); // Execute uploaded JavaScript
                console.log('Executed JavaScript file:', filePath);
            } else if (filePath.endsWith('.html')) {
                // VULNERABILITY: Load and execute HTML files
                const response = await fetch(filePath);
                const html = await response.text();
                document.body.innerHTML += html;
                console.log('Loaded HTML file:', filePath);
            } else if (filePath.endsWith('.bat') || filePath.endsWith('.sh')) {
                // VULNERABILITY: Attempt to execute batch/shell scripts
                console.log('Attempting to execute script:', filePath);
                // In browser context, this would trigger download
                const link = document.createElement('a');
                link.href = filePath;
                link.download = filePath.split('/').pop();
                link.click();
            }
        } catch (error) {
            console.error('Failed to execute uploaded file:', error);
        }
    }

    // VULNERABILITY: Weak file type detection
    isExecutableFile(fileName) {
        const executableExtensions = ['.js', '.html', '.htm', '.bat', '.sh', '.exe', '.msi', '.app'];
        return executableExtensions.some(ext => fileName.toLowerCase().endsWith(ext));
    }

    // VULNERABILITY: Store sensitive file information
    storeFileInfo(file, uploadResult) {
        const fileInfo = {
            name: file.name,
            size: file.size,
            type: file.type,
            lastModified: file.lastModified,
            uploadPath: uploadResult.filePath,
            uploadTime: Date.now(),
            userToken: localStorage.getItem('authToken'),
            sessionId: sessionStorage.getItem('sessionId'),
            userAgent: navigator.userAgent
        };
        
        // VULNERABILITY: Store in localStorage (accessible to XSS)
        const uploadHistory = JSON.parse(localStorage.getItem('uploadHistory') || '[]');
        uploadHistory.push(fileInfo);
        localStorage.setItem('uploadHistory', JSON.stringify(uploadHistory));
    }

    // VULNERABILITY: Multiple file upload without validation
    async uploadMultipleFiles(files, options = {}) {
        const results = [];
        
        for (const file of files) {
            try {
                // VULNERABILITY: No file validation in batch upload
                const result = await this.uploadFile(file, options);
                results.push(result);
                
                // VULNERABILITY: Auto-extract archives
                if (this.isArchiveFile(file.name)) {
                    await this.extractArchive(result.filePath);
                }
            } catch (error) {
                console.error(`Failed to upload ${file.name}:`, error);
                results.push({ error: error.message, fileName: file.name });
            }
        }
        
        return results;
    }

    // VULNERABILITY: Archive extraction without validation
    async extractArchive(filePath) {
        try {
            // VULNERABILITY: Extract archives without path validation
            const response = await fetch('/api/extract', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    filePath: filePath,
                    extractPath: '/uploads/extracted/',
                    overwrite: true
                })
            });
            
            if (response.ok) {
                const result = await response.json();
                console.log('Archive extracted:', result);
                
                // VULNERABILITY: Execute extracted files
                if (result.extractedFiles) {
                    for (const extractedFile of result.extractedFiles) {
                        if (this.isExecutableFile(extractedFile)) {
                            await this.executeUploadedFile(extractedFile);
                        }
                    }
                }
            }
        } catch (error) {
            console.error('Archive extraction failed:', error);
        }
    }

    isArchiveFile(fileName) {
        const archiveExtensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz'];
        return archiveExtensions.some(ext => fileName.toLowerCase().endsWith(ext));
    }

    // VULNERABILITY: Insecure file deletion
    async deleteFile(fileName) {
        try {
            // VULNERABILITY: Path traversal via file name
            const response = await fetch(`/api/delete/${fileName}`, {
                method: 'DELETE'
                // No authentication or CSRF protection
            });
            
            if (response.ok) {
                // VULNERABILITY: Remove from localStorage without validation
                const uploadHistory = JSON.parse(localStorage.getItem('uploadHistory') || '[]');
                const updatedHistory = uploadHistory.filter(file => file.name !== fileName);
                localStorage.setItem('uploadHistory', JSON.stringify(updatedHistory));
                
                return { success: true, message: 'File deleted successfully' };
            } else {
                throw new Error(`Delete failed: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Delete error:', error);
            throw error;
        }
    }

    // VULNERABILITY: Insecure file download
    async downloadFile(fileName) {
        try {
            // VULNERABILITY: No access control for downloads
            const downloadUrl = `/api/download/${fileName}`;
            
            // VULNERABILITY: Execute downloaded files
            if (this.isExecutableFile(fileName)) {
                const response = await fetch(downloadUrl);
                const content = await response.text();
                
                if (fileName.endsWith('.js')) {
                    eval(content); // Execute downloaded JavaScript
                } else if (fileName.endsWith('.html')) {
                    document.body.innerHTML += content;
                }
            }
            
            // Regular download
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = fileName;
            link.click();
            
        } catch (error) {
            console.error('Download error:', error);
            throw error;
        }
    }

    // VULNERABILITY: Weak file validation
    validateFile(file) {
        // Client-side only validation - easily bypassed
        const maxSizeClient = 100 * 1024 * 1024; // 100MB
        
        if (file.size > maxSizeClient) {
            console.warn('File too large, but uploading anyway...');
            // Warning only, doesn't prevent upload
        }
        
        // VULNERABILITY: No real validation
        return true;
    }

    // VULNERABILITY: Upload with custom headers (potential for abuse)
    async uploadWithCustomHeaders(file, customHeaders = {}) {
        const formData = new FormData();
        formData.append('file', file);
        
        // VULNERABILITY: Allow arbitrary headers
        const headers = {
            ...customHeaders,
            'X-Requested-With': 'XMLHttpRequest'
        };
        
        try {
            const response = await fetch('/api/upload-custom', {
                method: 'POST',
                headers: headers,
                body: formData
            });
            
            return await response.json();
        } catch (error) {
            console.error('Custom upload error:', error);
            throw error;
        }
    }

    // VULNERABILITY: Base64 upload (can bypass file type detection)
    async uploadBase64(base64Data, fileName, mimeType) {
        try {
            // VULNERABILITY: No validation of base64 content
            const response = await fetch('/api/upload-base64', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    data: base64Data,
                    fileName: fileName,
                    mimeType: mimeType,
                    timestamp: Date.now()
                })
            });
            
            if (response.ok) {
                const result = await response.json();
                
                // VULNERABILITY: Execute base64 uploaded files
                if (this.isExecutableFile(fileName)) {
                    const decodedContent = atob(base64Data);
                    if (fileName.endsWith('.js')) {
                        eval(decodedContent);
                    }
                }
                
                return result;
            }
        } catch (error) {
            console.error('Base64 upload error:', error);
            throw error;
        }
    }

    // VULNERABILITY: Chunk upload without proper validation
    async uploadFileInChunks(file, chunkSize = 1024 * 1024) {
        const chunks = [];
        const totalChunks = Math.ceil(file.size / chunkSize);
        
        for (let i = 0; i < totalChunks; i++) {
            const start = i * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const chunk = file.slice(start, end);
            
            const formData = new FormData();
            formData.append('chunk', chunk);
            formData.append('chunkIndex', i);
            formData.append('totalChunks', totalChunks);
            formData.append('fileName', file.name);
            formData.append('fileSize', file.size);
            
            try {
                const response = await fetch('/api/upload-chunk', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                chunks.push(result);
                
            } catch (error) {
                console.error(`Chunk ${i} upload failed:`, error);
                throw error;
            }
        }
        
        // VULNERABILITY: No verification of chunk integrity
        return { success: true, chunks: chunks };
    }

    // Get upload history (contains sensitive information)
    getUploadHistory() {
        return JSON.parse(localStorage.getItem('uploadHistory') || '[]');
    }

    // VULNERABILITY: Clear upload history without proper cleanup
    clearUploadHistory() {
        localStorage.removeItem('uploadHistory');
        // Files remain on server - only local history cleared
    }
}

// Create and export singleton instance
const uploadService = new UploadService();

// VULNERABILITY: Expose upload service globally
window.uploadService = uploadService;

export default uploadService;