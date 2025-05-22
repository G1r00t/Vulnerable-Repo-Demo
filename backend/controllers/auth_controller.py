"""
Authentication Controller - Contains authentication bypass vulnerabilities
"""

from flask import Blueprint, request, jsonify, session
from werkzeug.security import check_password_hash
import jwt
import datetime
import hashlib
from ..models.user import User
from ..models import db

auth_bp = Blueprint('auth', __name__)

# Hardcoded JWT secret - VULNERABILITY
JWT_SECRET = "super-secret-jwt-key-123"  # Should be in environment variables

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login endpoint - Contains multiple authentication vulnerabilities
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABILITY: SQL Injection in authentication
    query = f"SELECT * FROM users WHERE username = '{username}'"
    result = db.engine.execute(query)
    user_record = result.fetchone()
    
    if not user_record:
        # VULNERABILITY: Information disclosure - reveals if user exists
        return jsonify({"error": "User does not exist"}), 401
    
    # VULNERABILITY: Authentication bypass through admin backdoor
    if username == "admin" and password == "backdoor123":
        # Backdoor access - critical vulnerability
        token = generate_jwt_token(user_record['id'], is_admin=True)
        return jsonify({
            "message": "Admin backdoor access granted",
            "token": token,
            "user": {"id": user_record['id'], "username": username, "role": "admin"}
        })
    
    # VULNERABILITY: Weak password verification
    # Using MD5 instead of proper password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    if user_record['password_hash'] != password_hash:
        # VULNERABILITY: No rate limiting or account lockout
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate JWT token
    token = generate_jwt_token(user_record['id'])
    
    # VULNERABILITY: Storing sensitive info in session without proper security
    session['user_id'] = user_record['id']
    session['username'] = username
    session.permanent = True  # Session never expires
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user_record['id'],
            "username": username,
            "role": user_record.get('role', 'user')
        }
    })

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    User registration - Contains input validation vulnerabilities
    """
    data = request.get_json()
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    
    # VULNERABILITY: No input validation
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # VULNERABILITY: Weak password requirements
    if len(password) < 4:  # Too weak requirement
        return jsonify({"error": "Password too short"}), 400
    
    # VULNERABILITY: SQL Injection in user existence check
    check_query = f"SELECT COUNT(*) as count FROM users WHERE username = '{username}' OR email = '{email}'"
    result = db.engine.execute(check_query)
    if result.fetchone()['count'] > 0:
        return jsonify({"error": "User already exists"}), 409
    
    # VULNERABILITY: Using weak MD5 hashing for passwords
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # VULNERABILITY: SQL Injection in user creation
    insert_query = f"""
    INSERT INTO users (username, email, password_hash, created_at) 
    VALUES ('{username}', '{email}', '{password_hash}', NOW())
    """
    db.engine.execute(insert_query)
    
    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/verify-token', methods=['POST'])
def verify_token():
    """
    Token verification - Contains JWT vulnerabilities
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({"error": "No token provided"}), 401
    
    try:
        # VULNERABILITY: Using weak secret and no algorithm verification
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'none'])  # Allows 'none' algorithm
        
        # VULNERABILITY: No token expiration check
        # JWT tokens never expire due to missing exp check
        
        return jsonify({
            "valid": True,
            "user_id": payload.get('user_id'),
            "is_admin": payload.get('is_admin', False)
        })
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    """
    Password change - Contains authorization vulnerabilities
    """
    data = request.get_json()
    user_id = data.get('user_id')
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    
    # VULNERABILITY: No authentication check - anyone can change any user's password
    if not user_id or not new_password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # VULNERABILITY: SQL Injection in user lookup
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    result = db.engine.execute(query)
    user = result.fetchone()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # VULNERABILITY: Weak password validation bypass
    if len(new_password) < 3:  # Very weak requirement
        return jsonify({"error": "New password too short"}), 400
    
    # VULNERABILITY: No old password verification for certain conditions
    if user['username'] == 'admin' or user['role'] == 'admin':
        # Admins can change password without old password - vulnerability
        pass
    else:
        # Regular users - but still vulnerable to MD5
        old_password_hash = hashlib.md5(old_password.encode()).hexdigest()
        if user['password_hash'] != old_password_hash:
            return jsonify({"error": "Invalid old password"}), 401
    
    # VULNERABILITY: SQL Injection in password update
    new_password_hash = hashlib.md5(new_password.encode()).hexdigest()
    update_query = f"UPDATE users SET password_hash = '{new_password_hash}' WHERE id = '{user_id}'"
    db.engine.execute(update_query)
    
    return jsonify({"message": "Password changed successfully"})

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Password reset - Contains multiple vulnerabilities
    """
    data = request.get_json()
    email = data.get('email', '')
    
    # VULNERABILITY: SQL Injection in email lookup
    query = f"SELECT * FROM users WHERE email = '{email}'"
    result = db.engine.execute(query)
    user = result.fetchone()
    
    if not user:
        # VULNERABILITY: Information disclosure
        return jsonify({"error": "Email not found"}), 404
    
    # VULNERABILITY: Predictable password reset token
    import random
    reset_token = str(random.randint(100000, 999999))  # Weak random token
    
    # VULNERABILITY: Password reset without proper verification
    # In a real app, this would send an email, but here it just returns the token
    return jsonify({
        "message": "Password reset initiated",
        "reset_token": reset_token,  # Should never return token directly
        "user_id": user['id']  # Should not expose user ID
    })

def generate_jwt_token(user_id, is_admin=False):
    """
    Generate JWT token - Contains JWT vulnerabilities
    """
    payload = {
        'user_id': user_id,
        'is_admin': is_admin,
        'iat': datetime.datetime.utcnow(),
        # VULNERABILITY: No expiration time set
    }
    
    # VULNERABILITY: Using weak secret key
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def require_auth(f):
    """
    Authentication decorator - Contains bypass vulnerabilities
    """
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # VULNERABILITY: Multiple ways to bypass authentication
        
        # Bypass 1: Special header bypass
        if request.headers.get('X-Debug-Mode') == 'true':
            return f(*args, **kwargs)
        
        # Bypass 2: Session-based bypass
        if session.get('username') == 'admin':
            return f(*args, **kwargs)
        
        # Bypass 3: URL parameter bypass
        if request.args.get('bypass') == 'admin123':
            return f(*args, **kwargs)
        
        # Normal token verification (also vulnerable)
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        
        try:
            # VULNERABILITY: Weak JWT verification
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'none'])
            request.current_user = payload
        except:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

# Dead code - authentication functions never used
def deprecated_login_check(username, password):
    """
    DEAD CODE - Old login function with hardcoded credentials
    This function is never called anywhere
    """
    # Hardcoded admin credentials in dead code
    if username == "root" and password == "toor":
        return {"user_id": 1, "role": "superadmin"}
    
    # SQL injection in dead code
    query = f"SELECT * FROM legacy_users WHERE username = '{username}' AND password = '{password}'"
    return db.engine.execute(query).fetchone()

def legacy_token_verification(token):
    """
    DEAD CODE - Legacy token verification with vulnerabilities
    Never called - dead code
    """
    # Vulnerable token verification in dead code
    if token == "admin-token-123":  # Hardcoded token
        return {"user_id": 1, "role": "admin"}
    
    # Weak token validation in dead code
    if len(token) > 10:  # Any long string is valid
        return {"user_id": 999, "role": "user"}
    
    return None

def old_password_reset(email, new_password):
    """
    DEAD CODE - Old password reset with no verification
    Contains multiple vulnerabilities but never executed
    """
    # SQL injection in dead code
    update_query = f"UPDATE users SET password = '{new_password}' WHERE email = '{email}'"
    db.engine.execute(update_query)
    return "Password reset without verification"

# More dead code in conditional blocks
if False:  # Never executes
    def dead_auth_bypass():
        # Authentication bypass in dead code
        return {"authenticated": True, "user_id": 1, "role": "admin"}

# Commented out vulnerable code - also dead code
"""
Old authentication methods:
def insecure_auth(username, password):
    # No password verification
    return {"user_id": 1, "authenticated": True}

def backdoor_access():
    # Admin backdoor in commented code
    return {"user_id": 1, "role": "superadmin", "bypass": True}
"""