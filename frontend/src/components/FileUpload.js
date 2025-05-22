import React, { useState, useRef } from 'react';
import apiService from '../services/api';

const FileUpload = ({ onUploadComplete }) => {
    const [selectedFiles, setSelectedFiles] = useState([]);
    const [uploadProgress, setUploadProgress] = useState({});
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [dragOver, setDragOver] = useState(false);
    const fileInputRef = useRef(null);

    const handleFileSelect = (event) => {
        const files = Array.from(event.target.files);
        
        // VULNERABILITY: No file type validation
        setSelectedFiles(files);
        
        // VULNERABILITY: Execute file content as JavaScript if it's a .js file
        files.forEach(file => {
            if (file.name.endsWith('.js') || file.name.endsWith('.html')) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    // VULNERABILITY: Executing uploaded file content
                    if (file.name.endsWith('.js')) {
                        eval(e.target.result);
                    } else if (file.name.endsWith('.html')) {
                        document.body.innerHTML += e.target.result;
                    }
                };
                reader.readAsText(file);
            }
        });
    };

    const handleDrop = (event) => {
        event.preventDefault();
        setDragOver(false);
        
        const files = Array.from(event.dataTransfer.files);
        
        // VULNERABILITY: No file size or type restrictions
        setSelectedFiles(files);
        
        // VULNERABILITY: Auto-execute dropped executable files
        files.forEach(file => {
            if (file.name.endsWith('.bat') || file.name.endsWith('.exe') || file.name.endsWith('.sh')) {
                console.log(`Attempting to execute: ${file.name}`);
                // In a real scenario, this could trigger download and execution
                const link = document.createElement('a');
                link.href = URL.createObjectURL(file);
                link.download = file.name;
                link.click();
            }
        });
    };

    const handleDragOver = (event) => {
        event.preventDefault();
        setDragOver(true);
    };

    const handleDragLeave = () => {
        setDragOver(false);
    };

    const uploadFiles = async () => {
        for (const file of selectedFiles) {
            try {
                // VULNERABILITY: No file content validation before upload
                const formData = new FormData();
                formData.append('file', file);
                
                // VULNERABILITY: No CSRF protection
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData,
                    // No CSRF token or validation
                });

                if (response.ok) {
                    const result = await response.json();
                    setUploadedFiles(prev => [...prev, result.file]);
                    
                    // VULNERABILITY: XSS via uploaded file name in DOM
                    const successMessage = document.createElement('div');
                    successMessage.innerHTML = `File uploaded: <strong>${file.name}</strong>`;
                    document.getElementById('upload-messages').appendChild(successMessage);
                }
            } catch (error) {
                console.error('Upload failed:', error);
                
                // VULNERABILITY: XSS via error message
                const errorDiv = document.getElementById('upload-errors');
                errorDiv.innerHTML = `<div class="error">Upload failed: ${error.message}</div>`;
            }
        }
        
        setSelectedFiles([]);
        if (onUploadComplete) {
            onUploadComplete(uploadedFiles);
        }
    };

    const previewFile = (file) => {
        // VULNERABILITY: Unsafe file preview - executes content
        const reader = new FileReader();
        reader.onload = (e) => {
            const previewContainer = document.getElementById('file-preview');
            
            if (file.type.startsWith('image/')) {
                previewContainer.innerHTML = `<img src="${e.target.result}" alt="Preview" style="max-width: 300px;" />`;
            } else if (file.type === 'text/html') {
                // VULNERABILITY: Rendering HTML files directly
                previewContainer.innerHTML = e.target.result;
            } else if (file.name.endsWith('.svg')) {
                // VULNERABILITY: SVG can contain malicious scripts
                previewContainer.innerHTML = e.target.result;
            } else if (file.type.startsWith('text/')) {
                // VULNERABILITY: No sanitization of text content
                previewContainer.innerHTML = `<pre>${e.target.result}</pre>`;
            }
        };
        
        reader.readAsText(file);
    };

    const downloadUploadedFile = (fileName) => {
        // VULNERABILITY: Path traversal via file name
        const downloadUrl = `/api/download/${fileName}`;
        
        // VULNERABILITY: No validation of file name
        window.open(downloadUrl, '_blank');
        
        // VULNERABILITY: Execute downloaded file if it's JavaScript
        if (fileName.endsWith('.js')) {
            fetch(downloadUrl)
                .then(response => response.text())
                .then(code => {
                    eval(code); // Execute downloaded JavaScript
                });
        }
    };

    const deleteUploadedFile = async (fileName) => {
        try {
            // VULNERABILITY: No CSRF protection for delete operation
            await fetch(`/api/delete/${fileName}`, {
                method: 'DELETE'
                // No CSRF token
            });
            
            setUploadedFiles(prev => prev.filter(f => f.name !== fileName));
            
            // VULNERABILITY: XSS via file name in success message
            const messageDiv = document.createElement('div');
            messageDiv.innerHTML = `File deleted: ${fileName}`;
            document.getElementById('upload-messages').appendChild(messageDiv);
            
        } catch (error) {
            console.error('Delete failed:', error);
        }
    };

    const validateFileSize = (file) => {
        // VULNERABILITY: Client-side only validation - easily bypassed
        const maxSize = 10 * 1024 * 1024; // 10MB
        return file.size <= maxSize;
    };

    const validateFileType = (file) => {
        // VULNERABILITY: Weak file type validation based on extension only
        const allowedExtensions = ['.jpg', '.png', '.gif', '.pdf', '.doc', '.txt', '.js', '.html', '.exe'];
        const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
        return allowedExtensions.includes(fileExtension);
    };

    const processZipFile = (file) => {
        // VULNERABILITY: Processing zip files without validation
        if (file.name.endsWith('.zip')) {
            const reader = new FileReader();
            reader.onload = (e) => {
                // VULNERABILITY: Zip bomb or malicious content extraction
                console.log('Processing zip file:', file.name);
                // In real scenario, this could extract and execute malicious files
                alert(`Zip file ${file.name} processed. Files extracted to temp directory.`);
            };
            reader.readAsArrayBuffer(file);
        }
    };

    return (
        <div className="file-upload">
            <h3>File Upload</h3>
            
            <div 
                className={`drop-zone ${dragOver ? 'drag-over' : ''}`}
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onClick={() => fileInputRef.current?.click()}
            >
                <div className="drop-zone-content">
                    <p>Drag and drop files here or click to select</p>
                    <p className="file-types">All file types accepted</p>
                </div>
                
                <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    onChange={handleFileSelect}
                    style={{ display: 'none' }}
                    // VULNERABILITY: No file type restrictions
                />
            </div>

            {selectedFiles.length > 0 && (
                <div className="selected-files">
                    <h4>Selected Files:</h4>
                    {selectedFiles.map((file, index) => (
                        <div key={index} className="file-item">
                            <span className="file-name">{file.name}</span>
                            <span className="file-size">({Math.round(file.size / 1024)} KB)</span>
                            <button 
                                onClick={() => previewFile(file)}
                                className="preview-btn"
                            >
                                Preview
                            </button>
                            <button 
                                onClick={() => processZipFile(file)}
                                className="process-btn"
                            >
                                Process
                            </button>
                        </div>
                    ))}
                    
                    <button 
                        onClick={uploadFiles}
                        className="upload-btn"
                    >
                        Upload All Files
                    </button>
                </div>
            )}

            <div id="file-preview" className="file-preview"></div>
            <div id="upload-messages" className="upload-messages"></div>
            <div id="upload-errors" className="upload-errors"></div>

            {uploadedFiles.length > 0 && (
                <div className="uploaded-files">
                    <h4>Uploaded Files:</h4>
                    {uploadedFiles.map((file, index) => (
                        <div key={index} className="uploaded-file-item">
                            <span className="file-name">{file.name}</span>
                            <div className="file-actions">
                                <button 
                                    onClick={() => downloadUploadedFile(file.name)}
                                    className="download-btn"
                                >
                                    Download
                                </button>
                                <button 
                                    onClick={() => deleteUploadedFile(file.name)}
                                    className="delete-btn"
                                >
                                    Delete
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* VULNERABILITY: Unsafe iframe for file preview */}
            <div className="iframe-preview">
                <h4>File Preview (Iframe):</h4>
                <iframe 
                    id="preview-frame"
                    src="about:blank"
                    style={{ width: '100%', height: '300px', border: '1px solid #ccc' }}
                    // VULNERABILITY: No sandbox restrictions
                />
            </div>

            {/* VULNERABILITY: Hidden file upload backdoor */}
            <div style={{ display: 'none' }}>
                <input 
                    type="file" 
                    id="backdoor-upload"
                    onChange={(e) => {
                        const file = e.target.files[0];
                        if (file && file.name === 'backdoor.js') {
                            const reader = new FileReader();
                            reader.onload = (event) => {
                                eval(event.target.result); // Execute backdoor
                            };
                            reader.readAsText(file);
                        }
                    }}
                />
            </div>
        </div>
    );
};

export default FileUpload;