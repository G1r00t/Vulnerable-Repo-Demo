"""
Controllers package for AI-SAST Demo Application
Clean controller package initialization
"""

from flask import Blueprint

# Import all controllers
from .auth_controller import auth_bp
from .user_controller import user_bp
from .product_controller import product_bp
from .admin_controller import admin_bp
from .file_controller import file_bp

def register_blueprints(app):
    """
    Register all controller blueprints with the Flask app
    Clean registration function
    """
    # Register all blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(user_bp, url_prefix='/api/users')
    app.register_blueprint(product_bp, url_prefix='/api/products')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(file_bp, url_prefix='/api/files')
    
    return app

# Clean exports
__all__ = [
    'register_blueprints',
    'auth_bp',
    'user_bp', 
    'product_bp',
    'admin_bp',
    'file_bp'
]