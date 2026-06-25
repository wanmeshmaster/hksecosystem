from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__, static_folder='source', static_url_path='/source')
app.secret_key = os.urandom(32)
DATABASE = "users.db"

def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    
    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            balance REAL NOT NULL DEFAULT 0.0
        )
    """)
    
    # Transactions table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    try:
        cur.execute("ALTER TABLE users ADD COLUMN balance REAL NOT NULL DEFAULT 0.0")
    except sqlite3.OperationalError:
        pass
        
    conn.commit()
    conn.close()

@app.route('/')
def home():
    apps = [
        {'id': 'hks-bank', 'title': 'HKS Bank', 'url': '/hks-bank.html'},
        {'id': 'coming-soon', 'title': 'Coming soon...', 'url': '/coming-soon.html'}
    ]
    for a in apps:
        image_filename = f"{a['id']}.jpg"
        image_path = os.path.join(app.root_path, 'source', image_filename)
        a['bg_image'] = image_filename if os.path.exists(image_path) else None
    return render_template('index.html', apps=apps)

@app.route('/coming-soon.html')
def coming_soon():
    return render_template('coming-soon.html')

@app.route('/hks-bank.html')
def bank():
    return render_template('hks-bank.html')

@app.route('/hks-bank-dashboard.html')
def bank_dashboard():
    return render_template('hks-bank-dashboard.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required."}), 400

    password_hash = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        is_admin = 1 if user_count == 0 else 0

        cur.execute("""
            INSERT INTO users (username, password_hash, is_admin, balance)
            VALUES (?, ?, ?, 0.0)
        """, (username, password_hash, is_admin))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Account created."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username already exists."}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, is_admin FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        session["username"] = username
        session["is_admin"] = bool(row[1])
        return jsonify({
            "success": True,
            "username": username,
            "isAdmin": bool(row[1])
        })
    return jsonify({"success": False, "message": "Invalid username or password."}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/api/current-user')
def current_user():
    if "username" in session:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT is_admin, balance FROM users WHERE username=?", (session["username"],))
        row = cur.fetchone()
        conn.close()
        if row:
            return jsonify({
                "loggedIn": True,
                "username": session["username"],
                "isAdmin": bool(row[0]),
                "balance": row[1]
            })
    return jsonify({"loggedIn": False})

@app.route('/api/transactions')
def get_transactions():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
        
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("SELECT title, amount, timestamp FROM transactions WHERE username=? ORDER BY timestamp DESC", (session["username"],))
    
    # Format the data into a list of dictionaries
    transactions = [{"title": row[0], "amount": row[1], "date": row[2]} for row in cur.fetchall()]
    conn.close()
    
    return jsonify({"success": True, "transactions": transactions})

def is_admin():
    return session.get("is_admin", False)

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403
    
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("SELECT id, username, balance, is_admin FROM users")
    users = [{"id": row[0], "username": row[1], "balance": row[2], "is_admin": bool(row[3])} for row in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "users": users})

@app.route('/api/admin/add_funds', methods=['POST'])
def admin_add_funds():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403
    
    data = request.get_json()
    username = data.get("username")
    amount = float(data.get("amount", 0))

    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount."}), 400

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    
    # Update balance
    cur.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
    
    # Insert a transaction record titled "Interest"
    cur.execute("""
        INSERT INTO transactions (username, title, amount)
        VALUES (?, ?, ?)
    """, (username, "Interest", amount))
    
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"Successfully added funds to {username}."})

@app.route('/api/admin/subtract_funds', methods=['POST'])
def admin_subtract_funds():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data = request.get_json()
    username = data.get("username")
    amount = float(data.get("amount", 0))

    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount."}), 400

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.execute("SELECT balance FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404

    if row[0] < amount:
        conn.close()
        return jsonify({"success": False, "message": "Insufficient balance."}), 400

    cur.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, username))

    cur.execute("""
        INSERT INTO transactions (username, title, amount)
        VALUES (?, ?, ?)
    """, (username, "Deduction", -amount))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"Successfully subtracted funds from {username}."})

@app.route('/api/admin/promote_user', methods=['POST'])
def admin_promote_user():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400

    # Prevent self-demotion
    if username == session.get("username"):
        return jsonify({"success": False, "message": "You cannot change your own role."}), 400

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404

    new_role = 0 if row[0] else 1
    cur.execute("UPDATE users SET is_admin = ? WHERE username = ?", (new_role, username))
    conn.commit()
    conn.close()

    action = "promoted to Admin" if new_role else "demoted to User"
    return jsonify({"success": True, "message": f"{username} has been {action}.", "isAdmin": bool(new_role)})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)