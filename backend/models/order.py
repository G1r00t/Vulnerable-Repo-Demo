"""
Order model - Mixed vulnerabilities and clean code
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import json
import pickle  # Vulnerable import

db = SQLAlchemy()

class Order(db.Model):
    """
    Order model with mixed security practices
    Contains some vulnerabilities and some clean code
    """
    __tablename__ = 'orders'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    order_number = db.Column(db.String(20), unique=True, nullable=False)
    
    # Order details
    total_amount = db.Column(db.Decimal(10, 2), nullable=False)
    tax_amount = db.Column(db.Decimal(10, 2), default=0)
    shipping_amount = db.Column(db.Decimal(10, 2), default=0)
    discount_amount = db.Column(db.Decimal(10, 2), default=0)
    
    # Order status
    status = db.Column(db.String(20), default='pending')
    payment_status = db.Column(db.String(20), default='unpaid')
    
    # Shipping information
    shipping_address = db.Column(db.Text)
    billing_address = db.Column(db.Text)
    
    # Metadata - VULNERABLE: Using pickle for serialization
    order_metadata = db.Column(db.LargeBinary)  # Stores pickled data
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    shipped_at = db.Column(db.DateTime)
    delivered_at = db.Column(db.DateTime)
    
    # Relationships
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')
    
    def __init__(self, user_id, items_data=None):
        """Initialize order - clean constructor"""
        self.user_id = user_id
        self.order_number = self.generate_order_number()
        if items_data:
            self.calculate_totals(items_data)
    
    def generate_order_number(self):
        """Generate unique order number - clean method"""
        import random
        import string
        
        timestamp = datetime.now().strftime('%Y%m%d')
        random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"ORD-{timestamp}-{random_part}"
    
    def set_metadata(self, metadata_dict):
        """
        Set order metadata - VULNERABLE: Uses pickle serialization
        """
        # Vulnerable: Using pickle to serialize user-controlled data
        self.order_metadata = pickle.dumps(metadata_dict)
    
    def get_metadata(self):
        """
        Get order metadata - VULNERABLE: Uses pickle deserialization
        """
        if self.order_metadata:
            # Vulnerable: Deserializing potentially malicious data
            return pickle.loads(self.order_metadata)
        return {}
    
    @classmethod
    def search_orders(cls, search_term, user_id=None):
        """
        Search orders - VULNERABLE to SQL injection
        """
        # Vulnerable: Direct string concatenation
        base_query = f"SELECT * FROM orders WHERE order_number LIKE '%{search_term}%'"
        
        if user_id:
            # Another SQL injection point
            base_query += f" AND user_id = '{user_id}'"
        
        result = db.engine.execute(base_query)
        return result.fetchall()
    
    def update_status(self, new_status, user_id=None):
        """
        Update order status - contains SQL injection vulnerability
        """
        # Vulnerable: Direct SQL execution
        if user_id:
            # Check if user owns the order - vulnerable query
            query = f"SELECT COUNT(*) as count FROM orders WHERE id = '{self.id}' AND user_id = '{user_id}'"
            result = db.engine.execute(query)
            if result.fetchone()['count'] == 0:
                raise PermissionError("User does not own this order")
        
        # Vulnerable status update
        update_query = f"UPDATE orders SET status = '{new_status}', updated_at = NOW() WHERE id = '{self.id}'"
        db.engine.execute(update_query)
        self.status = new_status
    
    def calculate_totals(self, items_data):
        """
        Calculate order totals - clean implementation
        """
        subtotal = sum(item['price'] * item['quantity'] for item in items_data)
        self.tax_amount = subtotal * 0.08  # 8% tax
        self.shipping_amount = 10.00 if subtotal < 100 else 0  # Free shipping over $100
        self.total_amount = subtotal + self.tax_amount + self.shipping_amount - self.discount_amount
    
    @classmethod
    def get_orders_by_date_range(cls, start_date, end_date, user_id=None):
        """
        Get orders by date range - VULNERABLE to SQL injection
        """
        # Vulnerable: Date parameters not properly sanitized
        query = f"SELECT * FROM orders WHERE created_at BETWEEN '{start_date}' AND '{end_date}'"
        
        if user_id:
            query += f" AND user_id = '{user_id}'"
        
        result = db.engine.execute(query)
        return result.fetchall()
    
    def add_tracking_info(self, tracking_data):
        """
        Add tracking information - mixed security
        """
        # Clean: Proper JSON serialization for tracking
        current_metadata = self.get_metadata()  # Still vulnerable due to pickle
        current_metadata['tracking'] = tracking_data
        self.set_metadata(current_metadata)  # Still vulnerable
    
    def to_dict(self, include_items=False):
        """Convert order to dictionary - clean method"""
        order_dict = {
            'id': self.id,
            'order_number': self.order_number,
            'user_id': self.user_id,
            'total_amount': float(self.total_amount),
            'tax_amount': float(self.tax_amount),
            'shipping_amount': float(self.shipping_amount),
            'discount_amount': float(self.discount_amount),
            'status': self.status,
            'payment_status': self.payment_status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'shipped_at': self.shipped_at.isoformat() if self.shipped_at else None,
            'delivered_at': self.delivered_at.isoformat() if self.delivered_at else None
        }
        
        if include_items:
            order_dict['items'] = [item.to_dict() for item in self.items]
        
        return order_dict
    
    def __repr__(self):
        return f'<Order {self.order_number}>'

class OrderItem(db.Model):
    """
    Order item model - contains some vulnerabilities
    """
    __tablename__ = 'order_items'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    order_id = db.Column(db.String(36), db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.String(36), db.ForeignKey('products.id'), nullable=False)
    
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Decimal(10, 2), nullable=False)
    total_price = db.Column(db.Decimal(10, 2), nullable=False)
    
    # Product snapshot (in case product details change)
    product_name = db.Column(db.String(200))
    product_sku = db.Column(db.String(50))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @classmethod
    def get_items_by_product(cls, product_id, date_from=None, date_to=None):
        """
        Get order items by product - VULNERABLE to SQL injection
        """
        # Vulnerable: Direct parameter injection
        base_query = f"SELECT * FROM order_items WHERE product_id = '{product_id}'"
        
        if date_from and date_to:
            # Vulnerable: Date parameters not sanitized
            base_query += f" AND created_at BETWEEN '{date_from}' AND '{date_to}'"
        
        result = db.engine.execute(base_query)
        return result.fetchall()
    
    def calculate_total(self):
        """Calculate total price - clean method"""
        self.total_price = self.quantity * self.unit_price
    
    @classmethod
    def get_top_selling_products(cls, limit=10):
        """
        Get top selling products - contains SQL injection
        """
        # Vulnerable: Direct parameter injection
        query = f"""
        SELECT product_id, product_name, SUM(quantity) as total_sold
        FROM order_items 
        GROUP BY product_id, product_name 
        ORDER BY total_sold DESC 
        LIMIT {limit}
        """
        result = db.engine.execute(query)
        return result.fetchall()
    
    def to_dict(self):
        """Convert order item to dictionary - clean method"""
        return {
            'id': self.id,
            'order_id': self.order_id,
            'product_id': self.product_id,
            'quantity': self.quantity,
            'unit_price': float(self.unit_price),
            'total_price': float(self.total_price),
            'product_name': self.product_name,
            'product_sku': self.product_sku,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<OrderItem {self.product_name} x{self.quantity}>'

# Dead code - functions never called
def deprecated_order_search(search_criteria):
    """
    Old order search function - DEAD CODE with SQL injection
    This function is never called anywhere
    """
    # Vulnerable SQL injection in dead code
    query = f"SELECT * FROM orders WHERE status = '{search_criteria['status']}' AND user_id = '{search_criteria['user_id']}'"
    result = db.engine.execute(query)
    return result.fetchall()

def legacy_order_update(order_id, update_data):
    """
    Legacy order update - DEAD CODE with multiple vulnerabilities
    Never called - dead code
    """
    # SQL injection vulnerability in dead code
    for field, value in update_data.items():
        update_sql = f"UPDATE orders SET {field} = '{value}' WHERE id = '{order_id}'"
        db.engine.execute(update_sql)

def old_order_serialization(order_data):
    """
    Old order serialization - DEAD CODE with insecure deserialization
    Contains pickle vulnerability but never executed
    """
    # Vulnerable: Using pickle in dead code
    serialized = pickle.dumps(order_data)
    # This would be vulnerable if called
    deserialized = pickle.loads(serialized)
    return deserialized

# More dead code in conditional blocks
if False:  # This block never executes
    def dead_order_process(order_id, payment_data):
        # SQL injection and insecure deserialization in dead code
        query = f"SELECT * FROM orders WHERE id = '{order_id}'"
        order = db.engine.execute(query).fetchone()
        
        # Vulnerable pickle usage in dead code
        payment_obj = pickle.loads(payment_data)
        return order, payment_obj

# Commented out vulnerable code - also dead code
"""
def vulnerable_order_export(user_input):
    # This would be vulnerable to SQL injection and command injection
    query = f"SELECT * FROM orders WHERE user_id = '{user_input}'"
    import subprocess
    subprocess.run(f"mysqldump orders > /tmp/{user_input}_orders.sql", shell=True)
    return query
"""