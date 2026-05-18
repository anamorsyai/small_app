from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import sqlite3
import os
import subprocess
import hashlib
import re
from functools import wraps

app = Flask(__name__)
app.secret_key = 'super_secret_cloudnexus_key_2024'
DB_PATH = 'cloudnexus.db'

# Database initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )''')
    
    # Projects table
    c.execute('''CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Analytics table
    c.execute('''CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        event_data TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id)
    )''')
    
    # Audit logs
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Create default admin user
    admin_hash = hashlib.sha256('CloudNexus2024!'.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                  ('admin', 'admin@cloudnexus.io', admin_hash, 'admin'))
    except sqlite3.IntegrityError:
        pass
    
    # Create sample user
    user_hash = hashlib.sha256('User123!'.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                  ('demo_user', 'demo@cloudnexus.io', user_hash, 'user'))
    except sqlite3.IntegrityError:
        pass
    
    # Add sample projects
    c.execute("SELECT COUNT(*) FROM projects")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO projects (user_id, name, description, status) VALUES (1, 'Production API', 'Main production API monitoring', 'active')")
        c.execute("INSERT INTO projects (user_id, name, description, status) VALUES (1, 'Staging Environment', 'Staging server analytics', 'active')")
        c.execute("INSERT INTO projects (user_id, name, description, status) VALUES (2, 'Demo Project', 'Sample project for testing', 'active')")
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db()
        c = conn.cursor()
        
        # VULNERABILITY 1: SQL Injection in registration (f-string usage)
        query = f"INSERT INTO users (username, email, password_hash) VALUES ('{username}', '{email}', '{password_hash}')"
        try:
            c.executescript(query)
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            flash('Username or email already exists.', 'danger')
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
            c.execute("INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
                      (user['id'], 'LOGIN', f'User {user["username"]} logged in', request.remote_addr))
            conn.commit()
            conn.close()
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)",
                  (session['user_id'], 'LOGOUT', f'User {session["username"]} logged out'))
        conn.commit()
        conn.close()
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT * FROM projects WHERE user_id = ? OR (SELECT role FROM users WHERE id = ?) = 'admin'", 
              (session['user_id'], session['user_id']))
    projects = c.fetchall()
    
    c.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = c.fetchone()['total_users']
    
    c.execute("SELECT COUNT(*) as total_projects FROM projects")
    total_projects = c.fetchone()['total_projects']
    
    c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10")
    recent_logs = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', projects=projects, total_users=total_users, 
                         total_projects=total_projects, recent_logs=recent_logs)

@app.route('/project/<int:project_id>')
@login_required
def view_project(project_id):
    conn = get_db()
    c = conn.cursor()
    
    # VULNERABILITY 2: SQL Injection in project view (integer bypass possible with type conversion issues)
    query = f"SELECT * FROM projects WHERE id = {project_id}"
    c.execute(query)
    project = c.fetchone()
    
    if not project:
        conn.close()
        flash('Project not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check access control
    if project['user_id'] != session['user_id'] and session.get('role') != 'admin':
        conn.close()
        flash('Access denied to this project.', 'danger')
        return redirect(url_for('dashboard'))
    
    c.execute("SELECT * FROM analytics WHERE project_id = ? ORDER BY timestamp DESC LIMIT 50", (project_id,))
    analytics = c.fetchall()
    conn.close()
    
    return render_template('project.html', project=project, analytics=analytics)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    results = []
    
    if query:
        conn = get_db()
        c = conn.cursor()
        
        # VULNERABILITY 3: XSS - Search term reflected without proper escaping in template
        c.execute("SELECT * FROM projects WHERE name LIKE ? OR description LIKE ?", 
                  (f'%{query}%', f'%{query}%'))
        results = c.fetchall()
        conn.close()
    
    return render_template('search.html', query=query, results=results)

@app.route('/api/user-data')
@login_required
def api_user_data():
    user_id = request.args.get('user_id', session['user_id'])
    
    # VULNERABILITY 4: Broken Access Control (IDOR) - No check if user can access other user's data
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return jsonify(dict(user_data))
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    
    c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100")
    audit_logs = c.fetchall()
    
    conn.close()
    
    return render_template('admin.html', users=users, audit_logs=audit_logs)

@app.route('/admin/diagnostics', methods=['GET', 'POST'])
@admin_required
def diagnostics():
    result = None
    command_output = None
    
    if request.method == 'POST':
        action = request.form.get('action', '')
        target = request.form.get('target', '')
        
        if action == 'ping':
            # VULNERABILITY 5: Command Injection in diagnostics
            try:
                cmd = f"ping -c 2 {target}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                command_output = result.stdout if result.returncode == 0 else result.stderr
            except subprocess.TimeoutExpired:
                command_output = "Command timed out"
            except Exception as e:
                command_output = f"Error: {str(e)}"
        elif action == 'dns':
            try:
                cmd = f"nslookup {target}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                command_output = result.stdout if result.returncode == 0 else result.stderr
            except subprocess.TimeoutExpired:
                command_output = "Command timed out"
            except Exception as e:
                command_output = f"Error: {str(e)}"
    
    return render_template('diagnostics.html', command_output=command_output)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        email = request.form.get('email', '')
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        
        if email:
            try:
                c.execute("UPDATE users SET email = ? WHERE id = ?", (email, session['user_id']))
                conn.commit()
                flash('Email updated successfully.', 'success')
            except sqlite3.IntegrityError:
                flash('Email already in use.', 'danger')
        
        if current_password and new_password:
            current_hash = hashlib.sha256(current_password.encode()).hexdigest()
            c.execute("SELECT password_hash FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            
            if user and user['password_hash'] == current_hash:
                new_hash = hashlib.sha256(new_password.encode()).hexdigest()
                c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, session['user_id']))
                conn.commit()
                flash('Password updated successfully.', 'success')
            else:
                flash('Current password is incorrect.', 'danger')
        
        conn.close()
        return redirect(url_for('profile'))
    
    c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    init_db()
    print("🚀 CloudNexus SaaS Platform starting...")
    print("📍 Access the application at: http://localhost:8080")
    print("👤 Admin credentials: admin / CloudNexus2024!")
    print("👤 Demo user: demo_user / User123!")
    app.run(host='0.0.0.0', port=8080, debug=False)
