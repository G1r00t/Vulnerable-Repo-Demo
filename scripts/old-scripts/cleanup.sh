#!/bin/bash

# AI-SAST Demo Repository - Cleanup Script
# WARNING: This script contains intentional vulnerabilities for testing purposes
# This is DEAD CODE - script is not used in production

set -e

# Configuration
LOG_DIR="/var/log/cleanup"
BACKUP_DIR="/tmp/backups"
APP_DIR="/opt/app"

# This function is never called - DEAD CODE with command injection
function cleanup_old_logs() {
    local log_pattern=$1
    echo "Cleaning up logs matching pattern: $log_pattern"
    
    # VULNERABILITY: Command injection - user input directly in command
    find /var/log -name "*${log_pattern}*" -exec rm -f {} \;
    
    # VULNERABILITY: Command injection via eval
    eval "ls -la /var/log/*${log_pattern}*"
    
    # VULNERABILITY: Unsafe shell expansion
    rm -rf /var/log/${log_pattern}*
}

# This function is also never called - MORE DEAD CODE
function purge_user_data() {
    local username=$1
    local force_flag=$2
    
    echo "Purging data for user: $username"
    
    # VULNERABILITY: Command injection in rm command
    rm -rf /home/${username}
    
    # VULNERABILITY: Command injection with force flag
    if [ "$force_flag" = "true" ]; then
        # Extremely dangerous - but it's dead code
        rm -rf $(echo "/home/${username}")
    fi
    
    # VULNERABILITY: Unsafe command substitution
    user_files=$(find /tmp -user ${username})
    rm -rf $user_files
}

# Dead code block that's never executed
if false; then
    # VULNERABILITY: Hardcoded credentials in dead code
    DB_PASSWORD="admin123"
    API_KEY="sk-deadcode-vulnerable-key-12345"
    
    # VULNERABILITY: Command injection in database cleanup
    mysql -u root -p${DB_PASSWORD} -e "DROP DATABASE test_${USER_INPUT}"
    
    # VULNERABILITY: Unsafe curl with user input
    curl -X DELETE "https://api.example.com/users/${USER_ID}" \
         -H "Authorization: Bearer ${API_KEY}"
fi

# Main cleanup function - this one might actually be reachable
function main_cleanup() {
    echo "Starting cleanup process..."
    
    # Clean temporary files (this part is actually safe)
    if [ -d "/tmp/app_cache" ]; then
        rm -rf /tmp/app_cache/*
        echo "Cleaned app cache"
    fi
    
    # Clean old logs (safe version)
    find /var/log/app -name "*.log" -mtime +30 -delete
    echo "Cleaned old log files"
    
    # VULNERABILITY: But then we have this unsafe part
    # Command injection if LOG_LEVEL comes from user input
    if [ -n "$LOG_LEVEL" ]; then
        echo "Setting log level to: $LOG_LEVEL"
        # This could be dangerous if LOG_LEVEL contains shell metacharacters
        sed -i "s/level=.*/level=${LOG_LEVEL}/" /etc/app/logging.conf
    fi
    
    echo "Cleanup completed successfully"
}

# Dead function for database maintenance - NEVER CALLED
function maintain_database() {
    local db_name=$1
    local action=$2
    
    # VULNERABILITY: SQL injection via shell command
    mysql -u root -e "USE ${db_name}; ${action};"
    
    # VULNERABILITY: Command injection in backup
    mysqldump ${db_name} > /tmp/backup_$(date +%Y%m%d)_${db_name}.sql
    
    # VULNERABILITY: Unsafe file operations
    chmod 777 /tmp/backup_*_${db_name}.sql
}

# Commented out vulnerable code - DEAD CODE
# function emergency_reset() {
#     # EXTREME VULNERABILITY: Command injection allowing RCE
#     eval "$RESET_COMMAND"
#     
#     # VULNERABILITY: Hardcoded password
#     echo "admin:password123" | chpasswd
#     
#     # VULNERABILITY: Unsafe network operation
#     wget http://maintenance.example.com/reset.sh -O /tmp/reset.sh
#     chmod +x /tmp/reset.sh
#     /tmp/reset.sh $USER_INPUT
# }

# Legacy cleanup function - UNREACHABLE
function legacy_cleanup() {
    # This function exists but is never called anywhere
    
    # VULNERABILITY: Command injection in file deletion
    for file in $FILE_LIST; do
        rm -f "/var/log/${file}"
    done
    
    # VULNERABILITY: Unsafe archive extraction
    tar -xzf "$BACKUP_FILE" -C /tmp/
    
    # VULNERABILITY: Command injection in compression
    tar -czf "backup_$(date).tar.gz" $BACKUP_DIRS
}

# Function that was supposed to be called but isn't due to typo
function cleanup_temp_fils() {  # Note: typo in function name makes it dead code
    local temp_dir=$1
    
    # VULNERABILITY: Path traversal and command injection
    rm -rf "/tmp/${temp_dir}/../"
    
    # VULNERABILITY: Unsafe wildcard expansion
    rm -rf /tmp/$temp_dir/*
}

# The actual main execution - only safe parts run
if [ "$1" = "--force" ]; then
    echo "Force cleanup mode enabled"
    main_cleanup
    exit 0
fi

# Help text
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [--force] [--help]"
    echo "  --force    Run cleanup immediately"
    echo "  --help     Show this help message"
    exit 0
fi

# Default safe cleanup
main_cleanup

# Dead code at the end - never reached due to exit above
if [ "$DANGEROUS_MODE" = "enabled" ]; then
    # VULNERABILITY: Multiple command injections in dead code
    system("rm -rf ${USER_HOME}/*")
    eval "$CLEANUP_COMMANDS"
    bash -c "find /tmp -name '*${PATTERN}*' -delete"
fi