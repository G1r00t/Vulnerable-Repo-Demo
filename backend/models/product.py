"""
Product model - Contains SQL injection vulnerabilities
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

class Product(db.Model):
    """
    Product model with SQL injection vulnerabilities
    """
    __tablename__ = 'products'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Decimal(10, 2), nullable=False)
    category_id = db.Column(db.String(36), db.ForeignKey('categories.id'))
    sku = db.Column(db.String(50), unique=True, nullable=False)
    stock_quantity = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    category = db.relationship('Category', backref='products')
    order_items = db.relationship('OrderItem', backref='product')
    
    @classmethod
    def search_products(cls, search_term, category_id=None):
        """
        Search products - VULNERABLE to SQL injection
        """
        # Vulnerable: Direct string concatenation in SQL query
        base_query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
        
        if category_id:
            # Another SQL injection vulnerability
            base_query += f" AND category_id = '{category_id}'"
        
        # Execute raw SQL - vulnerable
        result = db.engine.execute(base_query)
        return result.fetchall()
    
    @classmethod
    def get_products_by_price_range(cls, min_price, max_price):
        """
        Get products by price range - VULNERABLE to SQL injection
        """
        # Vulnerable: Direct parameter injection
        query = f"SELECT * FROM products WHERE price BETWEEN {min_price} AND {max_price}"
        result = db.engine.execute(query)
        return result.fetchall()
    
    @classmethod
    def get_product_details(cls, product_id):
        """
        Get product details - VULNERABLE to SQL injection
        """
        # Vulnerable: No parameterization
        query = f"SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.id = '{product_id}'"
        result = db.engine.execute(query)
        return result.fetchone()
    
    def update_stock(self, quantity):
        """
        Update stock quantity - contains SQL injection
        """
        # Vulnerable: Direct SQL execution
        query = f"UPDATE products SET stock_quantity = {quantity} WHERE id = '{self.id}'"
        db.engine.execute(query)
    
    @classmethod
    def get_low_stock_products(cls, threshold=10):
        """
        Get products with low stock - VULNERABLE
        """
        # Vulnerable: Direct parameter injection
        query = f"SELECT * FROM products WHERE stock_quantity < {threshold}"
        result = db.engine.execute(query)
        return result.fetchall()
    
    def get_sales_history(self, date_from, date_to):
        """
        Get sales history - VULNERABLE to SQL injection
        """
        # Vulnerable: Date parameters not sanitized
        query = f"""
        SELECT oi.quantity, oi.price, o.created_at 
        FROM order_items oi 
        JOIN orders o ON oi.order_id = o.id 
        WHERE oi.product_id = '{self.id}' 
        AND o.created_at BETWEEN '{date_from}' AND '{date_to}'
        """
        result = db.engine.execute(query)
        return result.fetchall()
    
    def to_dict(self):
        """Convert product to dictionary - clean method"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': float(self.price),
            'sku': self.sku,
            'stock_quantity': self.stock_quantity,
            'is_active': self.is_active,
            'category_id': self.category_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Product {self.name}>'

class Category(db.Model):
    """
    Category model - also contains SQL injection vulnerabilities
    """
    __tablename__ = 'categories'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    parent_id = db.Column(db.String(36), db.ForeignKey('categories.id'))
    is_active = db.Column(db.Boolean, default=True)
    
    # Self-referential relationship for parent/child categories
    children = db.relationship('Category', backref=db.backref('parent', remote_side=[id]))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def search_categories(cls, search_term):
        """
        Search categories - VULNERABLE to SQL injection
        """
        # Vulnerable: Direct string concatenation
        query = f"SELECT * FROM categories WHERE name LIKE '%{search_term}%' OR description LIKE '%{search_term}%'"
        result = db.engine.execute(query)
        return result.fetchall()
    
    @classmethod
    def get_category_tree(cls, parent_id=None):
        """
        Get category tree - VULNERABLE to SQL injection
        """
        if parent_id:
            # Vulnerable: Direct parameter injection
            query = f"SELECT * FROM categories WHERE parent_id = '{parent_id}'"
        else:
            query = "SELECT * FROM categories WHERE parent_id IS NULL"
        
        result = db.engine.execute(query)
        return result.fetchall()
    
    def get_product_count(self):
        """
        Get product count for category - VULNERABLE
        """
        # Vulnerable: Direct SQL execution
        query = f"SELECT COUNT(*) as count FROM products WHERE category_id = '{self.id}'"
        result = db.engine.execute(query)
        return result.fetchone()['count']
    
    @classmethod
    def get_categories_with_products(cls, min_products=1):
        """
        Get categories with minimum product count - VULNERABLE
        """
        # Vulnerable: Direct parameter injection
        query = f"""
        SELECT c.*, COUNT(p.id) as product_count 
        FROM categories c 
        LEFT JOIN products p ON c.id = p.category_id 
        GROUP BY c.id 
        HAVING COUNT(p.id) >= {min_products}
        """
        result = db.engine.execute(query)
        return result.fetchall()
    
    def to_dict(self):
        """Convert category to dictionary - clean method"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'parent_id': self.parent_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Category {self.name}>'

# Dead code - functions that are never called
def deprecated_product_search(search_term):
    """
    Old product search function - DEAD CODE with SQL injection
    This function is never called anywhere
    """
    # Vulnerable SQL injection in dead code
    query = f"SELECT * FROM products WHERE name = '{search_term}' OR description = '{search_term}'"
    result = db.engine.execute(query)
    return result.fetchall()

def legacy_category_lookup(category_name):
    """
    Legacy category lookup - DEAD CODE with vulnerabilities
    Never called - dead code
    """
    # SQL injection vulnerability in dead code
    sql = "SELECT * FROM categories WHERE name = '" + category_name + "'"
    return db.engine.execute(sql)

def old_price_update(product_id, new_price):
    """
    Old price update function - DEAD CODE
    Contains SQL injection vulnerability but never executed
    """
    # Vulnerable update statement in dead code
    update_sql = f"UPDATE products SET price = {new_price} WHERE id = '{product_id}'"
    db.engine.execute(update_sql)

# More dead code in conditional blocks
if False:  # This block never executes
    def dead_product_delete(product_id):
        # SQL injection in dead conditional code
        delete_query = f"DELETE FROM products WHERE id = '{product_id}'"
        db.engine.execute(delete_query)

# Commented out vulnerable code - also dead code
"""
def vulnerable_bulk_update(product_ids, new_status):
    # This would be vulnerable to SQL injection
    ids_str = "','".join(product_ids)
    query = f"UPDATE products SET is_active = {new_status} WHERE id IN ('{ids_str}')"
    db.engine.execute(query)
"""