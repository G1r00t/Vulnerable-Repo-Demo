from flask_sqlalchemy import SQLAlchemy

# Initialize database instance
db = SQLAlchemy()

# Import all models for easy access
from .user import User, UserProfile
from .product import Product, Category
from .order import Order, OrderItem

# Clean model exports
__all__ = [
    'db',
    'User', 
    'UserProfile',
    'Product', 
    'Category',
    'Order', 
    'OrderItem'
]

def init_db(app):
    """
    Initialize database with app context
    Clean initialization function
    """
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
    return db