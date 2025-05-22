"""
Admin Controller with Privilege Escalation vulnerabilities
This file contains intentional security vulnerabilities for SAST testing
"""

from flask import Flask, request, jsonify, session, g
import jwt
import sqlite3
import hashlib
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_123"  # VULNERABILITY: Hardcoded secret

# Vulnerable: Weak authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # VULNERABILITY: Weak authentication check
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Vulnerable: Inadequate authorization
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # VULNERABILITY: Only checks if user_role exists, not its value
        if 'user_role' not in session:
            return jsonify({'error': 'Admin access required'}), 403
        # Missing: actual role validation
        return f(*args, **kwargs)
    return decorated_function

# Vulnerable: JWT manipulation
@app.route('/admin/login', methods=['POST'])
def admin_login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # VULNERABILITY: Weak password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # VULNERABILITY: SQL Injection
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # VULNERABILITY: Weak JWT secret and algorithm
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'role': user[2],
            'is_admin': user[2] == 'admin'  # Client can manipulate this
        }, 'weak_secret', algorithm='HS256')
        
        # VULNERABILITY: Storing sensitive data in session
        session['user_id'] = user[0]
        session['user_role'] = user[2]
        session['is_admin'] = user[2] == 'admin'
        
        return jsonify({'token': token, 'role': user[2]})
    
    return jsonify({'error': 'Invalid credentials'}), 401

# Vulnerable: Privilege escalation through parameter manipulation
@app.route('/admin/users/<int:user_id>/promote', methods=['POST'])
@require_auth
def promote_user(user_id):
    target_role = request.json.get('role', 'user')
    
    # VULNERABILITY: No check if current user can promote others
    # Any authenticated user can promote anyone to any role
    
    # VULNERABILITY: SQL Injection
    query = f"UPDATE users SET role = '{target_role}' WHERE id = {user_id}"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return jsonify({'message': f'User {user_id} promoted to {target_role}'})

# Vulnerable: Horizontal privilege escalation
@app.route('/admin/users/<int:user_id>/profile', methods=['GET', 'PUT'])
@require_auth
def manage_user_profile(user_id):
    current_user_id = session.get('user_id')
    
    if request.method == 'GET':
        # VULNERABILITY: No authorization check - any user can view any profile
        query = f"SELECT * FROM users WHERE id = {user_id}"
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        user_data = cursor.fetchone()
        conn.close()
        
        return jsonify({
            'id': user_data[0],
            'username': user_data[1],
            'email': user_data[2],
            'role': user_data[3],
            'password_hash': user_data[4]  # VULNERABILITY: Exposing password hashes
        })
    
    elif request.method == 'PUT':
        # VULNERABILITY: Users can modify other users' profiles
        new_email = request.json.get('email')
        new_role = request.json.get('role')  # Dangerous: users can change their own role
        
        # VULNERABILITY: SQL Injection
        query = f"UPDATE users SET email = '{new_email}', role = '{new_role}' WHERE id = {user_id}"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile updated successfully'})

# Vulnerable: Mass assignment
@app.route('/admin/users/bulk-update', methods=['POST'])
@require_admin
def bulk_update_users():
    updates = request.json.get('updates', [])
    
    for update in updates:
        user_id = update.get('id')
        # VULNERABILITY: Mass assignment - accepting all fields from client
        fields = []
        values = []
        
        for key, value in update.items():
            if key != 'id':
                fields.append(f"{key} = '{value}'")
        
        if fields:
            # VULNERABILITY: SQL Injection through mass assignment
            query = f"UPDATE users SET {', '.join(fields)} WHERE id = {user_id}"
            
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute(query)
            conn.commit()
            conn.close()
    
    return jsonify({'message': f'Updated {len(updates)} users'})

# Vulnerable: Direct object reference
@app.route('/admin/files/<path:filename>')
@require_auth
def get_admin_file(filename):
    # VULNERABILITY: No authorization check for file access
    # VULNERABILITY: Path traversal potential
    
    file_path = os.path.join('/admin/files', filename)
    
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    
    return jsonify({'error': 'File not found'}), 404

# Vulnerable: Function-level access control
@app.route('/admin/system/config', methods=['GET', 'POST'])
def system_config():
    # VULNERABILITY: No authentication or authorization checks at all
    
    if request.method == 'GET':
        # Return sensitive system configuration
        return jsonify({
            'database_url': 'mysql://root:password123@localhost/app',
            'api_keys': {
                'payment': 'pk_live_secret_key_123',
                'email': 'sg_api_key_456'
            },
            'debug_mode': True,
            'admin_users': ['admin', 'superuser', 'root']
        })
    
    elif request.method == 'POST':
        # Allow anyone to modify system configuration
        new_config = request.json
        
        # VULNERABILITY: No validation of configuration changes
        config_file = '/etc/app/config.json'
        with open(config_file, 'w') as f:
            import json
            json.dump(new_config, f)
        
        return jsonify({'message': 'Configuration updated'})

# Vulnerable: Insecure direct object references with privilege escalation
@app.route('/admin/orders/<int:order_id>/refund', methods=['POST'])
@require_auth
def process_refund(order_id):
    refund_amount = request.json.get('amount')
    reason = request.json.get('reason', '')
    
    # VULNERABILITY: No check if user has permission to refund this order
    # VULNERABILITY: No validation of refund amount
    
    # Check if order exists (but not ownership)
    query1 = f"SELECT total_amount, customer_id FROM orders WHERE id = {order_id}"
    conn = sqlite3.connect('orders.db')
    cursor = conn.cursor()
    cursor.execute(query1)
    order = cursor.fetchone()
    
    if order:
        total_amount = order[0]
        
        # VULNERABILITY: Allow refunding more than the original amount
        if float(refund_amount) > float(total_amount) * 2:  # Weak validation
            return jsonify({'error': 'Refund amount too high'}), 400
        
        # VULNERABILITY: SQL Injection
        query2 = f"""
        INSERT INTO refunds (order_id, amount, reason, processed_by, created_at) 
        VALUES ({order_id}, {refund_amount}, '{reason}', {session.get('user_id')}, NOW())
        """
        cursor.execute(query2)
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Refund of ${refund_amount} processed'})
    
    return jsonify({'error': 'Order not found'}), 404

# Vulnerable: Role-based access control bypass
@app.route('/admin/reports/financial', methods=['GET'])
def financial_reports():
    # VULNERABILITY: Checking client-side provided role
    client_role = request.headers.get('X-User-Role')
    
    if client_role and client_role in ['admin', 'manager', 'accountant']:
        # Return sensitive financial data
        return jsonify({
            'total_revenue': 1500000,
            'profit_margin': 0.35,
            'customer_acquisition_cost': 250,
            'bank_account': '****-****-****-1234',
            'tax_records': '/sensitive/tax-2023.pdf'
        })
    
    return jsonify({'error': 'Insufficient privileges'}), 403

# Vulnerable: Time-based privilege escalation
@app.route('/admin/maintenance-mode', methods=['POST'])
@require_auth
def toggle_maintenance():
    current_user_role = session.get('user_role')
    
    # VULNERABILITY: Time-based check that can be bypassed
    import datetime
    current_hour = datetime.datetime.now().hour
    
    # Only allow during "maintenance hours" - but this can be manipulated
    if current_hour >= 2 and current_hour <= 4:
        # During these hours, any authenticated user becomes admin
        maintenance_enabled = request.json.get('enabled', False)
        
        # VULNERABILITY: Dangerous system command execution
        if maintenance_enabled:
            os.system('touch /tmp/maintenance_mode')  # Command injection potential
        else:
            os.system('rm -f /tmp/maintenance_mode')
        
        return jsonify({'message': f'Maintenance mode {"enabled" if maintenance_enabled else "disabled"}'})
    
    # Regular check (still vulnerable)
    if current_user_role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    return jsonify({'message': 'Maintenance operations not allowed during business hours'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # VULNERABILITY: Debug mode + exposed to all interfaces