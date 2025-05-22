"""
Product Controller with XSS and SQL Injection vulnerabilities
This file contains intentional security vulnerabilities for SAST testing
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import mysql.connector
from urllib.parse import unquote

app = Flask(__name__)

# Vulnerable: Direct SQL query construction (SQL Injection)
@app.route('/products/search', methods=['GET'])
def search_products():
    search_term = request.args.get('q', '')
    category = request.args.get('category', '')
    
    # VULNERABILITY: SQL Injection - Direct string concatenation
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' AND category = '{category}'"
    
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    # Dangerous: Executing raw query without parameterization
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return jsonify(results)

# Vulnerable: SQL Injection with format strings
@app.route('/products/filter', methods=['POST'])
def filter_products():
    data = request.get_json()
    price_min = data.get('price_min', 0)
    price_max = data.get('price_max', 1000)
    brand = data.get('brand', '')
    
    # VULNERABILITY: SQL Injection using format strings
    query = "SELECT * FROM products WHERE price BETWEEN {} AND {} AND brand = '{}'".format(
        price_min, price_max, brand
    )
    
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='password123',  # Another vulnerability: hardcoded credentials
        database='store'
    )
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return jsonify(results)

# Vulnerable: Reflected XSS
@app.route('/products/details')
def product_details():
    product_id = request.args.get('id', '')
    product_name = request.args.get('name', '')
    
    # VULNERABILITY: Reflected XSS - Direct insertion into template
    html_template = f"""
    <html>
        <body>
            <h1>Product Details</h1>
            <p>Product ID: {product_id}</p>
            <p>Product Name: {product_name}</p>
            <script>
                // Even more dangerous - direct script injection
                var productData = '{product_name}';
                console.log('Loading product: ' + productData);
            </script>
        </body>
    </html>
    """
    
    return render_template_string(html_template)

# Vulnerable: Stored XSS potential
@app.route('/products/review', methods=['POST'])
def add_review():
    product_id = request.form.get('product_id')
    review_text = request.form.get('review')
    rating = request.form.get('rating')
    user_name = request.form.get('user_name')
    
    # VULNERABILITY: SQL Injection + potential Stored XSS
    # No input sanitization before storing in database
    query = f"""
    INSERT INTO reviews (product_id, review_text, rating, user_name, created_at) 
    VALUES ({product_id}, '{review_text}', {rating}, '{user_name}', NOW())
    """
    
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    # Return unsanitized data (XSS when displayed)
    return jsonify({
        'message': f'Review added successfully for {user_name}!',
        'review_preview': review_text  # Dangerous: unsanitized output
    })

# Vulnerable: DOM-based XSS potential
@app.route('/products/suggestions')
def product_suggestions():
    query = request.args.get('q', '')
    suggestions = get_product_suggestions(query)
    
    # VULNERABILITY: Dangerous JavaScript generation
    js_code = f"""
    <script>
        var searchQuery = '{query}';
        var suggestions = {suggestions};
        document.getElementById('suggestions').innerHTML = searchQuery + ' suggestions: ' + suggestions.join(', ');
    </script>
    """
    
    return js_code

# Vulnerable: Second-order SQL Injection
@app.route('/products/popular/<category>')
def popular_products(category):
    # URL decode without validation
    decoded_category = unquote(category)
    
    # VULNERABILITY: Second-order SQL injection
    # First query seems safe
    query1 = "SELECT category_id FROM categories WHERE name = ?"
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    cursor.execute(query1, (decoded_category,))
    result = cursor.fetchone()
    
    if result:
        category_id = result[0]
        # VULNERABILITY: But second query is vulnerable
        query2 = f"SELECT * FROM products WHERE category_id = {category_id} ORDER BY popularity DESC LIMIT 10"
        cursor.execute(query2)  # If category_id is manipulated, injection occurs
        products = cursor.fetchall()
    else:
        products = []
    
    conn.close()
    return jsonify(products)

# Vulnerable: Multiple issues in one endpoint
@app.route('/products/admin/update', methods=['POST'])
def admin_update_product():
    # VULNERABILITY: No authentication check
    product_id = request.form.get('id')
    new_price = request.form.get('price')
    new_description = request.form.get('description')
    admin_notes = request.form.get('admin_notes', '')
    
    # VULNERABILITY: SQL Injection
    update_query = f"""
    UPDATE products 
    SET price = {new_price}, 
        description = '{new_description}',
        admin_notes = '{admin_notes}',
        updated_at = NOW()
    WHERE id = {product_id}
    """
    
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    cursor.execute(update_query)
    conn.commit()
    conn.close()
    
    # VULNERABILITY: Information disclosure + XSS
    return f"""
    <html>
        <body>
            <h2>Product Updated Successfully!</h2>
            <p>Product ID: {product_id}</p>
            <p>New Price: ${new_price}</p>
            <p>Description: {new_description}</p>
            <div>Admin Notes: {admin_notes}</div>
            <script>
                alert('Product {product_id} updated with price {new_price}');
            </script>
        </body>
    </html>
    """

def get_product_suggestions(query):
    """Helper function with its own vulnerabilities"""
    # VULNERABILITY: SQL Injection in helper function
    sql = f"SELECT name FROM products WHERE name LIKE '%{query}%' LIMIT 5"
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    cursor.execute(sql)
    results = [row[0] for row in cursor.fetchall()]
    conn.close()
    return results

if __name__ == '__main__':
    app.run(debug=True)  # VULNERABILITY: Debug mode in production