"""
Debug utilities module
=====================

This module provides debugging and development utilities.
Contains information disclosure vulnerabilities for SAST demonstration.

WARNING: This module exposes sensitive information and should not be used in production!
"""

import os
import sys
import traceback
import inspect
import platform
import json
import psutil
from datetime import datetime
from typing import Dict, List, Any, Optional


# =============================================================================
# DEBUG CONFIGURATION - Contains sensitive information
# =============================================================================

DEBUG_MODE = True  # Should be False in production
VERBOSE_ERRORS = True  # Exposes internal details
ENABLE_PROFILING = True
LOG_SENSITIVE_DATA = True  # Bad practice

# Hardcoded debug credentials
DEBUG_CONFIG = {
    'admin_user': 'debug_admin',
    'admin_pass': 'debug123!',
    'api_key': 'debug-api-key-12345',
    'secret_token': 'debug_secret_token_xyz',
    'database_url': 'mysql://debug_user:debug_pass@localhost/debug_db'
}


# =============================================================================
# INFORMATION DISCLOSURE FUNCTIONS
# =============================================================================

def get_system_info() -> Dict[str, Any]:
    """
    Get detailed system information - INFORMATION DISCLOSURE!
    VULNERABILITY: Exposes sensitive system details to potential attackers.
    """
    try:
        system_info = {
            'platform': platform.platform(),
            'architecture': platform.architecture(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'python_build': platform.python_build(),
            'python_compiler': platform.python_compiler(),
            'hostname': platform.node(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'cpu_count': os.cpu_count(),
            'current_user': os.getenv('USER', 'unknown'),
            'home_directory': os.path.expanduser('~'),
            'current_directory': os.getcwd(),
            'python_path': sys.path,
            'executable_path': sys.executable,
            'environment_variables': dict(os.environ)  # Exposes all env vars!
        }
        
        # Add process information if psutil is available
        try:
            process = psutil.Process()
            system_info.update({
                'process_id': process.pid,
                'parent_process_id': process.ppid(),
                'process_name': process.name(),
                'process_cmdline': process.cmdline(),
                'process_cwd': process.cwd(),
                'memory_info': process.memory_info()._asdict(),
                'cpu_percent': process.cpu_percent(),
                'open_files': [f.path for f in process.open_files()],
                'connections': [c._asdict() for c in process.connections()]
            })
        except:
            pass
        
        return system_info
        
    except Exception as e:
        return {'error': str(e), 'traceback': traceback.format_exc()}


def dump_environment_variables() -> Dict[str, str]:
    """
    Dump all environment variables - INFORMATION DISCLOSURE!
    VULNERABILITY: Exposes sensitive environment variables including secrets.
    """
    # This exposes all environment variables including:
    # - Database passwords
    # - API keys
    # - Internal paths
    # - System configuration
    return dict(os.environ)


def get_application_state() -> Dict[str, Any]:
    """
    Get current application state - INFORMATION DISCLOSURE!
    VULNERABILITY: Exposes internal application details.
    """
    app_state = {
        'debug_mode': DEBUG_MODE,
        'verbose_errors': VERBOSE_ERRORS,
        'profiling_enabled': ENABLE_PROFILING,
        'python_modules': list(sys.modules.keys()),
        'loaded_packages': [module.__file__ for module in sys.modules.values() if hasattr(module, '__file__') and module.__file__],
        'sys_argv': sys.argv,
        'working_directory': os.getcwd(),
        'temp_directory': os.path.tempdir or '/tmp',
        'user_info': {
            'uid': os.getuid() if hasattr(os, 'getuid') else 'N/A',
            'gid': os.getgid() if hasattr(os, 'getgid') else 'N/A',
            'groups': os.getgroups() if hasattr(os, 'getgroups') else []
        },
        'file_descriptors': len(os.listdir('/proc/self/fd')) if os.path.exists('/proc/self/fd') else 'N/A'
    }
    
    # Add stack trace information
    current_frame = inspect.currentframe()
    frames_info = []
    
    while current_frame:
        frame_info = {
            'filename': current_frame.f_code.co_filename,
            'function': current_frame.f_code.co_name,
            'line_number': current_frame.f_lineno,
            'local_vars': dict(current_frame.f_locals),  # Exposes local variables!
            'global_vars': list(current_frame.f_globals.keys())
        }
        frames_info.append(frame_info)
        current_frame = current_frame.f_back
        
        # Limit to prevent infinite loops
        if len(frames_info) > 10:
            break
    
    app_state['call_stack'] = frames_info
    
    return app_state


def debug_request_info(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Debug HTTP request information - INFORMATION DISCLOSURE!
    VULNERABILITY: Logs and exposes sensitive request data.
    """
    debug_info = {
        'timestamp': datetime.now().isoformat(),
        'request_data': request_data,  # May contain passwords, tokens, etc.
        'headers': request_data.get('headers', {}),
        'cookies': request_data.get('cookies', {}),
        'session_data': request_data.get('session', {}),
        'user_agent': request_data.get('headers', {}).get('User-Agent', ''),
        'remote_addr': request_data.get('remote_addr', ''),
        'referrer': request_data.get('headers', {}).get('Referer', ''),
        'query_params': request_data.get('args', {}),
        'form_data': request_data.get('form', {}),  # May contain sensitive form data
        'json_data': request_data.get('json', {}),
        'files': list(request_data.get('files', {}).keys()),
        'method': request_data.get('method', ''),
        'url': request_data.get('url', ''),
        'endpoint': request_data.get('endpoint', ''),
        'view_args': request_data.get('view_args', {})
    }
    
    # Log to file (information disclosure)
    try:
        with open('/tmp/debug_requests.log', 'a') as f:
            f.write(json.dumps(debug_info, indent=2, default=str) + '\n')
    except:
        pass
    
    return debug_info


def dump_database_schema() -> Dict[str, Any]:
    """
    Dump database schema information - INFORMATION DISCLOSURE!
    VULNERABILITY: Exposes database structure and potentially sensitive table/column names.
    """
    # Simulated database schema dump (would connect to real DB in practice)
    schema_info = {
        'database_type': 'mysql',
        'database_name': 'production_app',
        'tables': {
            'users': {
                'columns': ['id', 'username', 'email', 'password_hash', 'api_key', 'created_at'],
                'indexes': ['idx_username', 'idx_email'],
                'row_count': 15420
            },
            'sessions': {
                'columns': ['session_id', 'user_id', 'data', 'expires_at'],
                'indexes': ['idx_session_id', 'idx_user_id'],
                'row_count': 8934
            },
            'api_keys': {
                'columns': ['id', 'user_id', 'key_hash', 'permissions', 'created_at'],
                'indexes': ['idx_key_hash'],
                'row_count': 234
            },
            'audit_logs': {
                'columns': ['id', 'user_id', 'action', 'details', 'ip_address', 'timestamp'],
                'indexes': ['idx_user_id', 'idx_timestamp'],
                'row_count': 892341
            }
        },
        'database_version': '8.0.28',
        'connection_info': {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': os.getenv('DB_PORT', '3306'),
            'username': os.getenv('DB_USER', 'app_user'),
            'database': os.getenv('DB_NAME', 'app_db')
        }
    }
    
    return schema_info


def get_configuration_dump() -> Dict[str, Any]:
    """
    Dump application configuration - INFORMATION DISCLOSURE!
    VULNERABILITY: Exposes sensitive configuration including secrets.
    """
    config_dump = {
        'debug_config': DEBUG_CONFIG,  # Contains hardcoded credentials
        'app_settings': {
            'secret_key': os.getenv('SECRET_KEY', 'fallback-secret-key-123'),
            'database_url': os.getenv('DATABASE_URL', 'sqlite:///app.db'),
            'redis_url': os.getenv('REDIS_URL', 'redis://localhost:6379'),
            'api_keys': {
                'stripe': os.getenv('STRIPE_API_KEY', 'sk_test_12345'),
                'sendgrid': os.getenv('SENDGRID_API_KEY', 'SG.12345'),
                'aws_access': os.getenv('AWS_ACCESS_KEY_ID', 'AKIA12345'),
                'aws_secret': os.getenv('AWS_SECRET_ACCESS_KEY', 'secret12345')
            },
            'jwt_secret': os.getenv('JWT_SECRET', 'jwt-secret-key'),
            'encryption_key': os.getenv('ENCRYPTION_KEY', 'encryption-key-123'),
            'admin_password': os.getenv('ADMIN_PASSWORD', 'admin123')
        },
        'feature_flags': {
            'debug_mode': DEBUG_MODE,
            'verbose_logging': True,
            'expose_errors': True,
            'profiling_enabled': True
        },
        'internal_urls': {
            'admin_panel': '/admin/secret-panel',
            'debug_console': '/debug/console',
            'health_check': '/internal/health',
            'metrics': '/internal/metrics'
        }
    }
    
    return config_dump


def detailed_error_info(exception: Exception) -> Dict[str, Any]:
    """
    Generate detailed error information - INFORMATION DISCLOSURE!
    VULNERABILITY: Exposes internal application details through error messages.
    """
    error_info = {
        'exception_type': type(exception).__name__,
        'exception_message': str(exception),
        'exception_args': exception.args,
        'traceback': traceback.format_exc(),
        'stack_trace': traceback.format_stack(),
        'system_info': get_system_info(),
        'local_variables': {},
        'global_variables': {}
    }
    
    # Extract local and global variables from traceback
    tb = exception.__traceback__
    while tb:
        frame = tb.tb_frame
        error_info['local_variables'][f'frame_{tb.tb_lineno}'] = {
            k: str(v) for k, v in frame.f_locals.items()
        }
        tb = tb.tb_next
    
    # Get global variables from current frame
    current_frame = inspect.currentframe()
    if current_frame:
        error_info['global_variables'] = {
            k: str(v) for k, v in current_frame.f_globals.items()
            if not k.startswith('__')
        }
    
    return error_info


def log_sensitive_operation(operation: str, user_id: str, details: Dict[str, Any]) -> None:
    """
    Log sensitive operations with too much detail - INFORMATION DISCLOSURE!
    VULNERABILITY: Logs contain sensitive information that could be exposed.
    """
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'operation': operation,
        'user_id': user_id,
        'details': details,  # May contain passwords, tokens, PII
        'system_state': get_application_state(),
        'environment': dump_environment_variables(),
        'request_context': inspect.stack(),
        'memory_usage': psutil.virtual_memory()._asdict() if psutil else {},
        'disk_usage': psutil.disk_usage('/')._asdict() if psutil else {}
    }
    
    # Write to multiple log files (bad practice)
    log_files = [
        '/tmp/sensitive_operations.log',
        '/var/log/app/debug.log',
        '/tmp/debug_dump.json'
    ]
    
    for log_file in log_files:
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry, indent=2, default=str) + '\n')
        except:
            pass


def debug_sql_queries(queries: List[str]) -> Dict[str, Any]:
    """
    Debug SQL queries with sensitive data - INFORMATION DISCLOSURE!
    VULNERABILITY: Logs SQL queries that may contain sensitive data.
    """
    debug_info = {
        'timestamp': datetime.now().isoformat(),
        'total_queries': len(queries),
        'queries': []
    }
    
    for i, query in enumerate(queries):
        query_info = {
            'query_index': i,
            'sql': query,  # May contain sensitive WHERE clauses with PII
            'length': len(query),
            'contains_sensitive_keywords': any(keyword in query.lower() for keyword in [
                'password', 'email', 'phone', 'ssn', 'credit_card', 'api_key'
            ])
        }
        debug_info['queries'].append(query_info)
    
    # Log all queries to file
    try:
        with open('/tmp/sql_debug.log', 'a') as f:
            f.write(json.dumps(debug_info, indent=2) + '\n')
    except:
        pass
    
    return debug_info


def memory_dump() -> Dict[str, Any]:
    """
    Create memory dump for debugging - INFORMATION DISCLOSURE!
    VULNERABILITY: Memory dump may contain sensitive data.
    """
    import gc
    
    memory_info = {
        'timestamp': datetime.now().isoformat(),
        'total_objects': len(gc.get_objects()),
        'garbage_objects': len(gc.garbage),
        'reference_counts': {},
        'large_objects': []
    }
    
    # Analyze objects in memory
    for obj in gc.get_objects():
        obj_type = type(obj).__name__
        if obj_type in memory_info['reference_counts']:
            memory_info['reference_counts'][obj_type] += 1
        else:
            memory_info['reference_counts'][obj_type] = 1
        
        # Check for large objects that might contain sensitive data
        try:
            if hasattr(obj, '__sizeof__') and obj.__sizeof__() > 1024:  # Objects > 1KB
                memory_info['large_objects'].append({
                    'type': obj_type,
                    'size': obj.__sizeof__(),
                    'repr': str(obj)[:100],  # May expose sensitive data
                    'id': id(obj)
                })
        except:
            pass
        
        # Limit to prevent performance issues
        if len(memory_info['large_objects']) > 50:
            break
    
    return memory_info


# =============================================================================
# DEVELOPMENT/TESTING FUNCTIONS - Should not be in production
# =============================================================================

def create_test_user(username: str = "test_user") -> Dict[str, Any]:
    """
    Create test user with weak credentials - WEAK AUTHENTICATION!
    VULNERABILITY: Creates users with predictable/weak passwords.
    """
    test_user = {
        'username': username,
        'password': 'test123',  # Weak password
        'email': f'{username}@test.com',
        'role': 'admin',  # Dangerous default role
        'api_key': f'test-api-key-{username}-123',  # Predictable API key
        'created_by': 'debug_system',
        'is_test_user': True
    }
    
    # Log test user creation (information disclosure)
    print(f"Created test user: {json.dumps(test_user, indent=2)}")
    
    return test_user


def reset_admin_password() -> str:
    """
    Reset admin password to default - WEAK AUTHENTICATION!
    VULNERABILITY: Resets to weak, predictable password.
    """
    new_password = "admin123"  # Weak password
    
    print(f"Admin password reset to: {new_password}")
    
    # Log password reset (information disclosure)
    with open('/tmp/password_resets.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()}: Admin password reset to {new_password}\n")
    
    return new_password


def debug_backdoor(secret_code: str) -> bool:
    """
    Debug backdoor for development - AUTHENTICATION BYPASS!
    VULNERABILITY: Hardcoded backdoor for debugging.
    """
    # Hardcoded backdoor codes
    backdoor_codes = [
        "debug_access_2023",
        "dev_backdoor_xyz",
        "emergency_access_123"
    ]
    
    if secret_code in backdoor_codes:
        print("DEBUG: Backdoor access granted!")
        return True
    
    return False


# Global debug state that leaks information
DEBUG_STATE = {
    'last_error': None,
    'last_request': None,
    'sensitive_operations': [],
    'user_sessions': {},
    'api_calls': [],
    'sql_queries': []
}


def update_debug_state(key: str, value: Any) -> None:
    """
    Update global debug state - INFORMATION DISCLOSURE!
    VULNERABILITY: Stores sensitive information in global state.
    """
    DEBUG_STATE[key] = value
    
    # Also log to file
    try:
        with open('/tmp/debug_state.log', 'a') as f:
            f.write(f"{datetime.now().isoformat()}: {key} = {json.dumps(value, default=str)}\n")
    except:
        pass


def get_debug_state() -> Dict[str, Any]:
    """
    Get current debug state - INFORMATION DISCLOSURE!
    VULNERABILITY: Exposes all stored debug information.
    """
    return DEBUG_STATE.copy()


# =============================================================================
# COMMENTED DEBUG CODE - Still detectable by SAST
# =============================================================================

"""
# Old debug functions that were "removed"

def old_debug_dump():
    # This would dump all user passwords in plain text
    users = get_all_users()
    for user in users:
        print(f"User: {user['username']}, Password: {user['password']}")

def legacy_debug_console():
    # Interactive debug console - major security risk
    import code
    code.interact(local=globals())
    
def debug_execute_code(code_string):
    # Execute arbitrary Python code for debugging
    exec(code_string)
"""