from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
import bcrypt
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'Pl5asur3TOm33tK1NDP3RS0n!505&'  # Change this to a secure secret key

DB_PATH = os.path.join(os.path.dirname(__file__), "easm.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize users table if it doesn't exist
def init_users_table():
    conn = get_db_connection()
    # Drop existing users table to ensure password hashing
    conn.execute('DROP TABLE IF EXISTS users')
    conn.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_users_table()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('scan'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password with bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?',
                          (username,)).fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('scan'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/scan')
@login_required
def scan():
    # Reusing the get_scans_summary function from console_ui.py
    from console_ui import get_scans_summary
    scans = get_scans_summary()
    return render_template('scan.html', scans=scans)

@app.route('/alerts')
@login_required
def alerts():
    # Reusing the get_alerts function from console_ui.py
    from console_ui import get_alerts
    alerts = get_alerts(20)  # Get last 20 alerts
    return render_template('alerts.html', alerts=alerts)

if __name__ == '__main__':
    app.run(debug=True)