from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__, static_folder='source', static_url_path='/source')

app.secret_key = os.urandom(32)

DATABASE = "users.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

@app.route('/')
def home():
    # We added the HKS Bank app here with the ID 'hks-bank'
    apps = [
        {
            'id': 'coming-soon', 
            'title': 'Coming soon...', 
            'url': '/coming-soon.html'
        },
        {
            'id': 'hks-bank', 
            'title': 'HKS Bank', 
            'url': '/hks-bank.html'
        }
    ]
    
    # Check if a background image exists for each app
    for a in apps:
        image_filename = f"{a['id']}.jpg"
        image_path = os.path.join(app.root_path, 'source', image_filename)
        
        if os.path.exists(image_path):
            a['bg_image'] = image_filename
        else:
            a['bg_image'] = None

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
        return jsonify({
            "success": False,
            "message": "Username and password required."
        }), 400

    password_hash = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()

        # Count existing users
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]

        # First user becomes admin
        is_admin = 1 if user_count == 0 else 0

        cur.execute(
            """
            INSERT INTO users
            (username, password_hash, is_admin)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, is_admin)
        )

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Account created."
        })

    except sqlite3.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Username already exists."
        }), 400


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT password_hash, is_admin
        FROM users
        WHERE username=?
        """,
        (username,)
    )

    row = cur.fetchone()

    if row and check_password_hash(row[0], password):

        session["username"] = username
        session["is_admin"] = bool(row[1])

        return jsonify({
            "success": True,
            "username": username,
            "isAdmin": bool(row[1])
        })
    conn.close()

    if row and check_password_hash(row[0], password):
        session["username"] = username

        return jsonify({
            "success": True,
            "username": username
        })

    return jsonify({
        "success": False,
        "message": "Invalid username or password."
    }), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()

    return jsonify({
        "success": True
    })

@app.route('/api/current-user')
def current_user():

    if "username" in session:
        return jsonify({
            "loggedIn": True,
            "username": session["username"],
            "isAdmin": session.get("is_admin", False)
        })

    return jsonify({
        "loggedIn": False
    })

def is_admin():
    return session.get("is_admin", False)

@app.route('/api/admin/users')
def admin_users():

    if not is_admin():
        return jsonify({
            "success": False,
            "message": "Administrator access required."
        }), 403

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)