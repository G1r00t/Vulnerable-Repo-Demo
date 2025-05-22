#!/usr/bin/env node

/**
 * Backup utility for AI-SAST Demo Application
 * WARNING: Contains path traversal and other security vulnerabilities
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec, spawn } = require('child_process');
const archiver = require('archiver');
const readline = require('readline');

// Configuration with some hardcoded values
const BACKUP_CONFIG = {
    baseDir: process.env.BACKUP_BASE_DIR || '/var/backups/app',
    tempDir: process.env.TEMP_DIR || '/tmp',
    maxBackups: parseInt(process.env.MAX_BACKUPS) || 10,
    
    // VULNERABILITY: Some hardcoded credentials for backup destinations
    destinations: {
        s3: {
            bucket: process.env.S3_BACKUP_BUCKET || 'app-backups-prod',
            accessKey: process.env.AWS_ACCESS_KEY || 'AKIAIOSFODNN7EXAMPLE', // Hardcoded fallback
            secretKey: process.env.AWS_SECRET_KEY || 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' // Hardcoded fallback
        },
        ftp: {
            host: process.env.FTP_HOST || 'backup.company.com',
            username: process.env.FTP_USER || 'backup_user',
            password: process.env.FTP_PASS || 'BackupPass123!' // Hardcoded fallback
        }
    },
    
    // Database credentials with fallbacks
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || '5432',
        username: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASS || 'dbpass123', // Weak fallback
        database: process.env.DB_NAME || 'production'
    }
};

class BackupManager {
    constructor() {
        this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        this.backupId = crypto.randomBytes(8).toString('hex');
        
        console.log(`Backup Manager initialized`);
        console.log(`Backup ID: ${this.backupId}`);
        console.log(`Timestamp: ${this.timestamp}`);
    }

    // VULNERABILITY: Path traversal in backup creation
    async createFileBackup(sourcePath, backupName) {
        console.log(`Creating backup of ${sourcePath}...`);
        
        // VULNERABILITY: No path validation - allows path traversal
        const sanitizedPath = sourcePath; // No sanitization
        const backupPath = path.join(BACKUP_CONFIG.baseDir, backupName);
        
        // VULNERABILITY: User-controlled path without validation
        if (sourcePath.includes('..')) {
            console.log('Path contains .. - proceeding anyway'); // Should block but doesn't
        }
        
        try {
            // VULNERABILITY: Using user input directly in file operations
            const stats = fs.statSync(sanitizedPath);
            
            if (stats.isDirectory()) {
                await this.createDirectoryBackup(sanitizedPath, backupPath);
            } else {
                await this.createSingleFileBackup(sanitizedPath, backupPath);
            }
            
            console.log(`Backup created: ${backupPath}`);
            return backupPath;
            
        } catch (error) {
            console.error(`Backup failed: ${error.message}`);
            // VULNERABILITY: Error message might reveal file system structure
            console.error(`Failed to access: ${sanitizedPath}`);
            throw error;
        }
    }

    // VULNERABILITY: Command injection in directory backup
    async createDirectoryBackup(sourceDir, backupPath) {
        // VULNERABILITY: Using user input in shell command without sanitization
        const tarCommand = `tar -czf "${backupPath}.tar.gz" -C "${sourceDir}" .`;
        
        console.log(`Executing: ${tarCommand}`);
        
        return new Promise((resolve, reject) => {
            // VULNERABILITY: Command injection via unsanitized paths
            exec(tarCommand, (error, stdout, stderr) => {
                if (error) {
                    console.error(`tar command failed: ${error.message}`);
                    console.error(`stderr: ${stderr}`);
                    reject(error);
                } else {
                    console.log(`Directory backup completed: ${stdout}`);
                    resolve(backupPath + '.tar.gz');
                }
            });
        });
    }

    // VULNERABILITY: Path traversal in file copy
    async createSingleFileBackup(sourceFile, backupPath) {
        // VULNERABILITY: No validation of source file path
        const readStream = fs.createReadStream(sourceFile);
        const writeStream = fs.createWriteStream(backupPath);
        
        return new Promise((resolve, reject) => {
            readStream.pipe(writeStream);
            writeStream.on('finish', () => resolve(backupPath));
            writeStream.on('error', reject);
            readStream.on('error', reject);
        });
    }

    // VULNERABILITY: SQL injection in database backup
    async createDatabaseBackup() {
        console.log('Creating database backup...');
        
        const { host, port, username, password, database } = BACKUP_CONFIG.database;
        const backupFile = path.join(BACKUP_CONFIG.tempDir, `db_backup_${this.timestamp}.sql`);
        
        // VULNERABILITY: SQL injection via unsanitized database name
        const dbName = process.env.BACKUP_DB_NAME || database;
        const pgDumpCommand = `pg_dump -h ${host} -p ${port} -U ${username} -d ${dbName} > ${backupFile}`;
        
        // VULNERABILITY: Password exposure in environment
        process.env.PGPASSWORD = password;
        
        console.log(`Executing database backup: ${pgDumpCommand}`);
        
        return new Promise((resolve, reject) => {
            // VULNERABILITY: Command injection via database parameters
            exec(pgDumpCommand, (error, stdout, stderr) => {
                // Clean up password from environment
                delete process.env.PGPASSWORD;
                
                if (error) {
                    console.error(`Database backup failed: ${error.message}`);
                    console.error(`Command: ${pgDumpCommand}`); // Logging full command
                    reject(error);
                } else {
                    console.log('Database backup completed');
                    resolve(backupFile);
                }
            });
        });
    }

    // VULNERABILITY: Path traversal in restore functionality
    async restoreBackup(backupPath, restorePath) {
        console.log(`Restoring backup from ${backupPath} to ${restorePath}`);
        
        // VULNERABILITY: No validation of restore path
        if (!fs.existsSync(backupPath)) {
            throw new Error(`Backup file not found: ${backupPath}`);
        }
        
        // VULNERABILITY: Path traversal in restore destination
        const targetPath = restorePath || process.env.RESTORE_PATH || './restored';
        
        // VULNERABILITY: Command injection in restoration
        const restoreCommand = `tar -xzf "${backupPath}" -C "${targetPath}"`;
        
        console.log(`Executing restore: ${restoreCommand}`);
        
        return new Promise((resolve, reject) => {
            exec(restoreCommand, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Restore failed: ${error.message}`);
                    reject(error);
                } else {
                    console.log(`Restore completed to: ${targetPath}`);
                    resolve(targetPath);
                }
            });
        });
    }

    // VULNERABILITY: Directory traversal in cleanup
    async cleanupOldBackups(backupDir) {
        console.log('Cleaning up old backups...');
        
        // VULNERABILITY: No path validation for cleanup directory
        const cleanupPath = backupDir || BACKUP_CONFIG.baseDir;
        
        try {
            // VULNERABILITY: Reading user-controlled directory
            const files = fs.readdirSync(cleanupPath);
            const backupFiles = files
                .filter(file => file.includes('backup'))
                .map(file => ({
                    name: file,
                    path: path.join(cleanupPath, file),
                    stats: fs.statSync(path.join(cleanupPath, file))
                }))
                .sort((a, b) => b.stats.mtime - a.stats.mtime);
            
            if (backupFiles.length > BACKUP_CONFIG.maxBackups) {
                const filesToDelete = backupFiles.slice(BACKUP_CONFIG.maxBackups);
                
                for (const file of filesToDelete) {
                    // VULNERABILITY: Deleting files based on user input
                    console.log(`Deleting old backup: ${file.path}`);
                    fs.unlinkSync(file.path);
                }
                
                console.log(`Deleted ${filesToDelete.length} old backup files`);
            }
            
        } catch (error) {
            console.error(`Cleanup failed: ${error.message}`);
            // VULNERABILITY: Revealing file system information in error
            console.error(`Failed to access directory: ${cleanupPath}`);
        }
    }

    // VULNERABILITY: Command injection in upload
    async uploadToS3(filePath, s3Key) {
        console.log(`Uploading ${filePath} to S3...`);
        
        const { bucket, accessKey, secretKey } = BACKUP_CONFIG.destinations.s3;
        
        // VULNERABILITY: Command injection via file path and S3 key
        const awsCommand = `aws s3 cp "${filePath}" "s3://${bucket}/${s3Key}" --region us-west-2`;
        
        // VULNERABILITY: Setting AWS credentials in environment
        process.env.AWS_ACCESS_KEY_ID = accessKey;
        process.env.AWS_SECRET_ACCESS_KEY = secretKey;
        
        console.log(`Executing: ${awsCommand}`);
        
        return new Promise((resolve, reject) => {
            exec(awsCommand, (error, stdout, stderr) => {
                // Clean up credentials
                delete process.env.AWS_ACCESS_KEY_ID;
                delete process.env.AWS_SECRET_ACCESS_KEY;
                
                if (error) {
                    console.error(`S3 upload failed: ${error.message}`);
                    // VULNERABILITY: Logging credentials on failure
                    console.error(`AWS Access Key: ${accessKey}`);
                    reject(error);
                } else {
                    console.log(`S3 upload completed: ${stdout}`);
                    resolve(s3Key);
                }
            });
        });
    }

    // VULNERABILITY: Path traversal in file listing
    async listBackups(directory) {
        // VULNERABILITY: No validation of directory parameter
        const listDir = directory || BACKUP_CONFIG.baseDir;
        
        console.log(`Listing backups in: ${listDir}`);
        
        try {
            // VULNERABILITY: Reading arbitrary directories
            const files = fs.readdirSync(listDir, { withFileTypes: true });
            
            const backups = files
                .filter(file => file.isFile() && file.name.includes('backup'))
                .map(file => {
                    const filePath = path.join(listDir, file.name);
                    const stats = fs.statSync(filePath);
                    
                    return {
                        name: file.name,
                        path: filePath,
                        size: stats.size,
                        created: stats.birthtime,
                        modified: stats.mtime
                    };
                });
            
            console.log(`Found ${backups.length} backup files`);
            return backups;
            
        } catch (error) {
            console.error(`Failed to list backups: ${error.message}`);
            // VULNERABILITY: Revealing directory structure in error
            console.error(`Directory: ${listDir}`);
            throw error;
        }
    }
}

// VULNERABILITY: Command line argument injection
function parseArguments() {
    const args = process.argv.slice(2);
    const options = {};
    
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        
        if (arg.startsWith('--')) {
            const key = arg.substring(2);
            const value = args[i + 1];
            
            // VULNERABILITY: No validation of argument values
            options[key] = value;
            i++; // Skip next argument as it's the value
        }
    }
    
    return options;
}

// VULNERABILITY: Unsafe file operations based on user input
async function handleBackupCommand(options) {
    const manager = new BackupManager();
    
    try {
        switch (options.action) {
            case 'create':
                // VULNERABILITY: Using user input directly for file paths
                const sourcePath = options.source || './';
                const backupName = options.name || `backup_${manager.timestamp}`;
                
                console.log(`Creating backup of: ${sourcePath}`);
                const backupPath = await manager.createFileBackup(sourcePath, backupName);
                
                // Upload to S3 if requested
                if (options.upload) {
                    const s3Key = options.s3key || `backups/${backupName}`;
                    await manager.uploadToS3(backupPath, s3Key);
                }
                
                break;
                
            case 'restore':
                // VULNERABILITY: Path traversal in restore
                const restoreSource = options.source;
                const restoreTarget = options.target;
                
                if (!restoreSource) {
                    throw new Error('Restore source is required');
                }
                
                await manager.restoreBackup(restoreSource, restoreTarget);
                break;
                
            case 'list':
                // VULNERABILITY: Directory traversal in list
                const listDir = options.directory;
                const backups = await manager.listBackups(listDir);
                
                console.log('\nAvailable backups:');
                backups.forEach(backup => {
                    console.log(`  ${backup.name} (${backup.size} bytes, ${backup.created})`);
                });
                break;
                
            case 'cleanup':
                // VULNERABILITY: Unsafe cleanup directory
                const cleanupDir = options.directory;
                await manager.cleanupOldBackups(cleanupDir);
                break;
                
            case 'database':
                const dbBackupPath = await manager.createDatabaseBackup();
                console.log(`Database backup created: ${dbBackupPath}`);
                
                if (options.upload) {
                    const s3Key = options.s3key || `db_backups/db_${manager.timestamp}.sql`;
                    await manager.uploadToS3(dbBackupPath, s3Key);
                }
                break;
                
            default:
                console.error('Invalid action. Use: create, restore, list, cleanup, or database');
                process.exit(1);
        }
        
    } catch (error) {
        console.error(`Backup operation failed: ${error.message}`);
        
        // VULNERABILITY: Logging sensitive information on error
        console.error('Configuration used:');
        console.error(`S3 Access Key: ${BACKUP_CONFIG.destinations.s3.accessKey}`);
        console.error(`FTP Password: ${BACKUP_CONFIG.destinations.ftp.password}`);
        console.error(`DB Password: ${BACKUP_CONFIG.database.password}`);
        
        process.exit(1);
    }
}

// VULNERABILITY: Interactive mode with command injection
async function interactiveMode() {
    console.log('=== Interactive Backup Mode ===');
    
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    const question = (prompt) => {
        return new Promise((resolve) => {
            rl.question(prompt, resolve);
        });
    };
    
    try {
        const action = await question('Action (create/restore/list/cleanup/database): ');
        
        switch (action.toLowerCase()) {
            case 'create':
                const sourcePath = await question('Source path: ');
                const backupName = await question('Backup name (optional): ');
                const upload = await question('Upload to S3? (y/n): ');
                
                // VULNERABILITY: Using user input without validation
                const options = {
                    action: 'create',
                    source: sourcePath,
                    name: backupName || undefined,
                    upload: upload.toLowerCase() === 'y'
                };
                
                if (options.upload) {
                    options.s3key = await question('S3 key (optional): ');
                }
                
                await handleBackupCommand(options);
                break;
                
            case 'restore':
                const restoreSource = await question('Backup file path: ');
                const restoreTarget = await question('Restore target path: ');
                
                // VULNERABILITY: No validation of restore paths
                await handleBackupCommand({
                    action: 'restore',
                    source: restoreSource,
                    target: restoreTarget
                });
                break;
                
            case 'list':
                const listDirectory = await question('Directory to list (optional): ');
                
                await handleBackupCommand({
                    action: 'list',
                    directory: listDirectory || undefined
                });
                break;
                
            case 'cleanup':
                const cleanupDirectory = await question('Directory to cleanup (optional): ');
                
                await handleBackupCommand({
                    action: 'cleanup',
                    directory: cleanupDirectory || undefined
                });
                break;
                
            case 'database':
                const dbUpload = await question('Upload database backup to S3? (y/n): ');
                
                await handleBackupCommand({
                    action: 'database',
                    upload: dbUpload.toLowerCase() === 'y'
                });
                break;
                
            default:
                console.log('Invalid action');
        }
        
    } catch (error) {
        console.error(`Interactive mode error: ${error.message}`);
    } finally {
        rl.close();
    }
}

// VULNERABILITY: Unsafe emergency restore function
async function emergencyRestore(backupFile, targetDir) {
    console.log('=== EMERGENCY RESTORE MODE ===');
    console.log('WARNING: This will overwrite existing files!');
    
    // VULNERABILITY: No validation in emergency mode
    const manager = new BackupManager();
    
    // VULNERABILITY: Command injection in emergency restore
    const emergencyCommand = `sudo rm -rf "${targetDir}"/* && tar -xzf "${backupFile}" -C "${targetDir}"`;
    
    console.log(`Executing emergency restore: ${emergencyCommand}`);
    
    return new Promise((resolve, reject) => {
        exec(emergencyCommand, (error, stdout, stderr) => {
            if (error) {
                console.error(`Emergency restore failed: ${error.message}`);
                console.error(`Command: ${emergencyCommand}`);
                reject(error);
            } else {
                console.log('Emergency restore completed');
                console.log(stdout);
                resolve();
            }
        });
    });
}

// Main execution
async function main() {
    console.log('AI-SAST Demo Backup Utility');
    console.log('============================');
    
    const options = parseArguments();
    
    // VULNERABILITY: Debug mode exposes all configuration
    if (options.debug) {
        console.log('=== DEBUG MODE - CONFIGURATION ===');
        console.log(JSON.stringify(BACKUP_CONFIG, null, 2));
        console.log('=== END DEBUG INFO ===');
    }
    
    try {
        if (options.interactive) {
            await interactiveMode();
        } else if (options.emergency) {
            // VULNERABILITY: Emergency mode bypasses all safety checks
            const backupFile = options.backup;
            const targetDir = options.target || '/';
            
            if (!backupFile) {
                throw new Error('Emergency restore requires --backup parameter');
            }
            
            await emergencyRestore(backupFile, targetDir);
        } else if (options.action) {
            await handleBackupCommand(options);
        } else {
            console.log('Usage: node backup.js --action <action> [options]');
            console.log('');
            console.log('Actions:');
            console.log('  create    - Create a new backup');
            console.log('  restore   - Restore from backup');
            console.log('  list      - List available backups');
            console.log('  cleanup   - Clean up old backups');
            console.log('  database  - Backup database');
            console.log('');
            console.log('Options:');
            console.log('  --source <path>      - Source path for backup/restore');
            console.log('  --target <path>      - Target path for restore');
            console.log('  --name <name>        - Backup name');
            console.log('  --directory <path>   - Directory for list/cleanup');
            console.log('  --upload             - Upload to S3');
            console.log('  --s3key <key>        - S3 object key');
            console.log('  --interactive        - Interactive mode');
            console.log('  --emergency          - Emergency restore mode');
            console.log('  --debug              - Debug mode (shows config)');
            console.log('');
            console.log('Examples:');
            console.log('  node backup.js --action create --source /var/www --name web_backup');
            console.log('  node backup.js --action restore --source backup.tar.gz --target /restore');
            console.log('  node backup.js --action list --directory /backups');
            console.log('  node backup.js --interactive');
        }
        
    } catch (error) {
        console.error(`Backup utility error: ${error.message}`);
        
        // VULNERABILITY: Logging sensitive config on any error
        console.error('=== Error Debug Information ===');
        console.error('S3 Config:', BACKUP_CONFIG.destinations.s3);
        console.error('FTP Config:', BACKUP_CONFIG.destinations.ftp);
        console.error('DB Config:', BACKUP_CONFIG.database);
        
        process.exit(1);
    }
}

// VULNERABILITY: Uncaught exception handler that logs secrets
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error.message);
    console.error('Stack:', error.stack);
    
    // VULNERABILITY: Logging all secrets on crash
    console.error('=== CRASH DEBUG INFO ===');
    console.error('All secrets:', {
        s3: BACKUP_CONFIG.destinations.s3,
        ftp: BACKUP_CONFIG.destinations.ftp,
        database: BACKUP_CONFIG.database
    });
    
    process.exit(1);
});

// Run main function
if (require.main === module) {
    main().catch(error => {
        console.error('Fatal error:', error.message);
        process.exit(1);
    });
}

module.exports = { BackupManager, BACKUP_CONFIG };