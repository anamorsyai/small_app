import os
import sqlite3
import subprocess
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database initialization
def init_db():
    conn = sqlite3.connect('nexus.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT DEFAULT 'user',
        api_key TEXT
    )''')
    
    # Products table
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        price REAL,
        category TEXT,
        stock INTEGER
    )''')
    
    # Logs table (for command injection scenario)
    c.execute('''CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT
    )''')
    
    # Insert default data
    try:
        c.execute("INSERT INTO users (username, password, email, role, api_key) VALUES (?, ?, ?, ?, ?)",
                  ('admin', 'admin123', 'admin@nexus.com', 'admin', 'ak_admin_9x8y7z'))
        c.execute("INSERT INTO users (username, password, email, role, api_key) VALUES (?, ?, ?, ?, ?)",
                  ('john_doe', 'password123', 'john@example.com', 'user', 'ak_user_1a2b3c'))
        c.execute("INSERT INTO users (username, password, email, role, api_key) VALUES (?, ?, ?, ?, ?)",
                  ('jane_smith', 'securepass', 'jane@example.com', 'user', 'ak_user_4d5e6f'))
        
        products = [
            ('Laptop Pro X1', 'High performance laptop for professionals', 1299.99, 'electronics', 15),
            ('Wireless Mouse', 'Ergonomic wireless mouse', 29.99, 'electronics', 50),
            ('Office Chair', 'Comfortable office chair with lumbar support', 199.99, 'furniture', 8),
            ('Desk Lamp', 'LED desk lamp with adjustable brightness', 45.99, 'furniture', 25),
            ('Coffee Maker', 'Automatic coffee maker with timer', 79.99, 'appliances', 12),
            ('Bluetooth Speaker', 'Portable bluetooth speaker with bass boost', 59.99, 'electronics', 30),
        ]
        c.executemany("INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)", products)
        
        c.execute("INSERT INTO system_logs (action, status) VALUES (?, ?)", ('System initialized', 'success'))
        
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Data already exists
    
    conn.close()

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('nexus.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user['role'] != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if not username or not password or not email:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        try:
            # VULNERABILITY 1: SQL Injection in registration (blind SQLi)
            query = f"INSERT INTO users (username, password, email, role, api_key) VALUES ('{username}', '{password}', '{email}', 'user', 'ak_{username[:3]}123')"
            conn.execute(query)
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        # Secure login (no SQL injection here to force users to find other paths)
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                          (username, password)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template('dashboard.html', products=products)

@app.route('/product/<int:product_id>')
@login_required
def product_detail(product_id):
    conn = get_db_connection()
    # VULNERABILITY 2: SQL Injection in product search (error-based SQLi)
    # The vulnerability is hidden in a complex query builder function
    query = f"SELECT * FROM products WHERE id = {product_id}"
    product = conn.execute(query).fetchone()
    conn.close()
    
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('product.html', product=product)

@app.route('/search')
@login_required
def search():
    query_param = request.args.get('q', '')
    category = request.args.get('category', '')
    
    conn = get_db_connection()
    
    # Complex query building logic to hide the vulnerability
    base_query = "SELECT * FROM products WHERE 1=1"
    
    if query_param:
        # VULNERABILITY 3: XSS in search results (stored XSS via product reviews)
        base_query += f" AND (name LIKE '%{query_param}%' OR description LIKE '%{query_param}%')"
    
    if category:
        base_query += f" AND category = '{category}'"
    
    products = conn.execute(base_query).fetchall()
    conn.close()
    
    return render_template('search.html', products=products, query=query_param, category=category)

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, role, api_key FROM users').fetchall()
    logs = conn.execute('SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT 20').fetchall()
    conn.close()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/admin/diagnostics', methods=['GET', 'POST'])
@admin_required
def diagnostics():
    result = None
    error = None
    
    if request.method == 'POST':
        action = request.form.get('action', '')
        
        if action == 'ping':
            host = request.form.get('host', '')
            if host:
                try:
                    # VULNERABILITY 4: Command Injection
                    # Hidden within a "safe" looking function with multiple validations
                    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
                        error = "Invalid hostname format"
                    else:
                        # The vulnerability: using shell=True with user input
                        cmd = f"ping -c 2 {host}"
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                        result = result.stdout + result.stderr
                        
                        # Log the action
                        conn = get_db_connection()
                        conn.execute('INSERT INTO system_logs (action, status) VALUES (?, ?)',
                                   (f'Ping diagnostic on {host}', 'success' if result else 'failed'))
                        conn.commit()
                        conn.close()
                except subprocess.TimeoutExpired:
                    error = "Command timed out"
                except Exception as e:
                    error = f"Execution failed: {str(e)}"
        
        elif action == 'disk_usage':
            try:
                cmd = "df -h /"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                result = result.stdout
            except Exception as e:
                error = f"Execution failed: {str(e)}"
        
        elif action == 'process_list':
            try:
                cmd = "ps aux | head -10"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                result = result.stdout
            except Exception as e:
                error = f"Execution failed: {str(e)}"
    
    return render_template('diagnostics.html', result=result, error=error)

@app.route('/api/user-data')
@login_required
def api_user_data():
    """API endpoint that might leak information through improper access control"""
    user_id = request.args.get('user_id')
    
    conn = get_db_connection()
    
    # VULNERABILITY 5: Broken Access Control (IDOR)
    # Users can access other users' data by changing the user_id parameter
    if user_id:
        user = conn.execute('SELECT id, username, email, role, api_key FROM users WHERE id = ?', 
                          (user_id,)).fetchone()
    else:
        user = conn.execute('SELECT id, username, email, role, api_key FROM users WHERE id = ?', 
                          (session['user_id'],)).fetchone()
    
    conn.close()
    
    if user:
        return {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'api_key': user['api_key']
        }
    else:
        return {'error': 'User not found'}, 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, debug=True)