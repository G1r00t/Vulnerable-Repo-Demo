from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
import os
import subprocess
import pickle
import logging

# Import configurations
from .config.database import get_db_config
from .config.security import SecurityConfig
from .config.logging import setup_logging

# Initialize extensions
db = SQLAlchemy()

def create_app():
    """Application factory pattern - mostly clean"""
    app = Flask(__name__)
    
    # Load configuration - contains vulnerabilities
    app.config.update(get_db_config())
    app.config['SECRET_KEY'] = 'hardcoded-secret-key-123'  # Hardcoded secret vulnerability
    
    # Initialize database
    db.init_app(app)
    
    # Setup logging
    setup_logging(app)
    
    # Register routes
    register_routes(app)
    
    return app

def register_routes(app):
    """Register application routes - contains multiple vulnerabilities"""
    
    @app.route('/')
    def index():
        """Clean route"""
        return jsonify({"message": "AI-SAST Demo API", "version": "1.0.0"})
    
    @app.route('/search')
    def search():
        """SQL Injection vulnerability"""
        query = request.args.get('q', '')
        # Vulnerable: Direct string concatenation in SQL query
        sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
        result = db.engine.execute(sql)
        return jsonify([dict(row) for row in result])
    
    @app.route('/execute', methods=['POST'])
    def execute_command():
        """Command Injection vulnerability"""
        command = request.json.get('cmd', '')
        # Vulnerable: Direct command execution
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({"output": result.stdout, "error": result.stderr})
    
    @app.route('/template')
    def render_template():
        """Server-Side Template Injection vulnerability"""
        template = request.args.get('template', 'Hello World')
        # Vulnerable: User input directly in template
        return render_template_string(template)
    
    @app.route('/deserialize', methods=['POST'])
    def deserialize_data():
        """Insecure Deserialization vulnerability"""
        data = request.get_data()
        # Vulnerable: Using pickle to deserialize user data
        try:
            obj = pickle.loads(data)
            return jsonify({"result": str(obj)})
        except Exception as e:
            return jsonify({"error": str(e)})
    
    @app.route('/file/<path:filename>')
    def get_file(filename):
        """Path Traversal vulnerability"""
        # Vulnerable: No path sanitization
        file_path = os.path.join('/var/www/uploads/', filename)
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return jsonify({"content": content})
        except Exception as e:
            return jsonify({"error": str(e)})
    
    @app.route('/admin/backup')
    def admin_backup():
        """Authentication bypass vulnerability"""
        # Vulnerable: No proper authentication check
        is_admin = request.headers.get('X-Admin', '') == 'true'
        if is_admin:
            return jsonify({"backup": "database_backup.sql"})
        return jsonify({"error": "Access denied"})

# Dead code - contains vulnerabilities but never executed
def deprecated_login_check(username, password):
    """Dead function - contains hardcoded credentials"""
    # This function is never called - dead code
    if username == "admin" and password == "password123":
        return True
    return False

def old_sql_query(user_id):
    """Dead function - SQL injection vulnerability"""
    # This function is never called - dead code
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return db.engine.execute(query)

# More dead code in comments
"""
Old vulnerable code kept for reference:
def vulnerable_eval():
    user_input = request.args.get('code')
    return eval(user_input)  # RCE vulnerability in dead code
"""

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0')  # Debug mode vulnerability