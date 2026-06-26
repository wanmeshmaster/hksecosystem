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
            balance REAL NOT NULL DEFAULT 0.0,
            full_name TEXT NOT NULL DEFAULT ''
        )
    """)

    # Transactions table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            amount REAL NOT NULL,
            account_label TEXT NOT NULL DEFAULT 'Current Account',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Additional bank accounts per user (beyond the primary balance)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0.0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Per-account transaction history
    cur.execute("""
        CREATE TABLE IF NOT EXISTS account_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        )
    """)

    # Safe migrations for existing databases
    for stmt in [
        "ALTER TABLE users ADD COLUMN balance REAL NOT NULL DEFAULT 0.0",
        "ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE transactions ADD COLUMN account_label TEXT NOT NULL DEFAULT 'Current Account'",
    ]:
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()


# ── Page routes ────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    apps = [
        {'id': 'hks-bank',    'title': 'HKS Bank',       'url': '/hks-bank.html'},
        {'id': 'coming-soon', 'title': 'Coming soon...', 'url': '/coming-soon.html'},
    ]
    for a in apps:
        img = f"{a['id']}.jpg"
        a['bg_image'] = img if os.path.exists(os.path.join(app.root_path, 'source', img)) else None
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

@app.route('/hks-bank-checkout.html')
def bank_checkout():
    return render_template('hks-bank-checkout.html')


# ── Auth ───────────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username   = data.get("username", "").strip()
    password   = data.get("password", "").strip()
    first_name = data.get("first_name", "").strip()
    last_name  = data.get("last_name", "").strip()
    full_name  = f"{first_name} {last_name}".strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required."}), 400
    if not first_name or not last_name:
        return jsonify({"success": False, "message": "First and last name required."}), 400

    password_hash = generate_password_hash(password)
    try:
        conn = sqlite3.connect(DATABASE)
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        is_admin = 1 if cur.fetchone()[0] == 0 else 0
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin, balance, full_name) VALUES (?, ?, ?, 0.0, ?)",
            (username, password_hash, is_admin, full_name)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Account created."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username already exists."}), 400


@app.route('/api/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT password_hash, is_admin FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        session["username"] = username
        session["is_admin"] = bool(row[1])
        return jsonify({"success": True, "username": username, "isAdmin": bool(row[1])})
    return jsonify({"success": False, "message": "Invalid username or password."}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route('/api/current-user')
def current_user():
    if "username" in session:
        conn = sqlite3.connect(DATABASE)
        cur  = conn.cursor()
        cur.execute("SELECT is_admin, balance, full_name FROM users WHERE username=?", (session["username"],))
        row = cur.fetchone()
        conn.close()
        if row:
            return jsonify({
                "loggedIn":  True,
                "username":  session["username"],
                "isAdmin":   bool(row[0]),
                "balance":   row[1],
                "fullName":  row[2] if row[2] else session["username"],
            })
    return jsonify({"loggedIn": False})


# ── Transactions ───────────────────────────────────────────────────────────────

@app.route('/api/transactions')
def get_transactions():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute(
        "SELECT title, amount, timestamp, account_label FROM transactions WHERE username=? ORDER BY timestamp DESC",
        (session["username"],)
    )
    transactions = [{"title": r[0], "amount": r[1], "date": r[2], "account_label": r[3]} for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "transactions": transactions})


# ── User: own additional accounts ─────────────────────────────────────────────

@app.route('/api/my-accounts')
def my_accounts():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, account_type, balance, created_at FROM accounts WHERE username = ? ORDER BY created_at ASC",
        (session["username"],)
    )
    accounts = [
        {"id": r[0], "account_type": r[1], "balance": r[2], "created_at": r[3]}
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify({"success": True, "accounts": accounts})


@app.route('/api/account-transactions/<int:account_id>')
def get_account_transactions(account_id):
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    # Verify the account belongs to this user (or user is admin)
    cur.execute("SELECT username FROM accounts WHERE id = ?", (account_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Account not found."}), 404
    if row[0] != session["username"] and not session.get("is_admin"):
        conn.close()
        return jsonify({"success": False, "message": "Access denied."}), 403
    cur.execute(
        "SELECT title, amount, timestamp FROM account_transactions WHERE account_id = ? ORDER BY timestamp DESC",
        (account_id,)
    )
    transactions = [{"title": r[0], "amount": r[1], "date": r[2]} for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "transactions": transactions})


# ── Admin helpers ──────────────────────────────────────────────────────────────

def is_admin():
    return session.get("is_admin", False)


# ── Admin: users ───────────────────────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id, username, full_name, balance, is_admin FROM users")
    users = [
        {"id": r[0], "username": r[1], "full_name": r[2], "balance": r[3], "is_admin": bool(r[4])}
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify({"success": True, "users": users})


# ── Admin: funds ───────────────────────────────────────────────────────────────

@app.route('/api/admin/add_funds', methods=['POST'])
def admin_add_funds():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403
    data       = request.get_json()
    username   = data.get("username")
    amount     = float(data.get("amount", 0))
    reason     = data.get("reason", "Interest").strip() or "Interest"
    account_id = data.get("account_id")  # None means primary account

    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    if account_id:
        cur.execute("SELECT id, username, account_type FROM accounts WHERE id = ? AND username = ?", (account_id, username))
        acc = cur.fetchone()
        if not acc:
            conn.close()
            return jsonify({"success": False, "message": "Account not found."}), 404
        account_label = acc[2]
        cur.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, account_id))
        cur.execute(
            "INSERT INTO account_transactions (account_id, username, title, amount) VALUES (?, ?, ?, ?)",
            (account_id, username, reason, amount)
        )
    else:
        account_label = "Current Account"
        cur.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))

    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (username, reason, amount, account_label)
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Successfully added funds to {username}."})


@app.route('/api/admin/subtract_funds', methods=['POST'])
def admin_subtract_funds():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403
    data       = request.get_json()
    username   = data.get("username")
    amount     = float(data.get("amount", 0))
    reason     = data.get("reason", "Deduction").strip() or "Deduction"
    account_id = data.get("account_id")  # None means primary account

    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    if account_id:
        cur.execute("SELECT balance, account_type FROM accounts WHERE id = ? AND username = ?", (account_id, username))
        acc = cur.fetchone()
        if not acc:
            conn.close()
            return jsonify({"success": False, "message": "Account not found."}), 404
        if acc[0] < amount:
            conn.close()
            return jsonify({"success": False, "message": "Insufficient balance in that account."}), 400
        account_label = acc[1]
        cur.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, account_id))
        cur.execute(
            "INSERT INTO account_transactions (account_id, username, title, amount) VALUES (?, ?, ?, ?)",
            (account_id, username, reason, -amount)
        )
    else:
        account_label = "Current Account"
        cur.execute("SELECT balance FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"success": False, "message": "User not found."}), 404
        if row[0] < amount:
            conn.close()
            return jsonify({"success": False, "message": "Insufficient balance."}), 400
        cur.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, username))

    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (username, reason, -amount, account_label)
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Successfully subtracted funds from {username}."})


# ── Admin: roles ───────────────────────────────────────────────────────────────

@app.route('/api/admin/promote_user', methods=['POST'])
def admin_promote_user():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403
    data     = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400
    if username == session.get("username"):
        return jsonify({"success": False, "message": "You cannot change your own role."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
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


# ── Admin: additional accounts ────────────────────────────────────────────────

@app.route('/api/admin/accounts/<username>', methods=['GET'])
def admin_get_accounts(username):
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, account_type, balance, created_at FROM accounts WHERE username = ? ORDER BY created_at ASC",
        (username,)
    )
    accounts = [
        {"id": r[0], "account_type": r[1], "balance": r[2], "created_at": r[3]}
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify({"success": True, "accounts": accounts})


@app.route('/api/admin/create_account', methods=['POST'])
def admin_create_account():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data            = request.get_json()
    username        = data.get("username", "").strip()
    account_type    = data.get("account_type", "").strip()
    opening_balance = float(data.get("opening_balance", 0))

    if not username or not account_type:
        return jsonify({"success": False, "message": "Username and account type are required."}), 400
    if opening_balance < 0:
        return jsonify({"success": False, "message": "Opening balance cannot be negative."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404

    # Prevent duplicate account type for the same user
    cur.execute("SELECT id FROM accounts WHERE username = ? AND account_type = ?", (username, account_type))
    if cur.fetchone():
        conn.close()
        return jsonify({"success": False, "message": f"This user already has a {account_type}."}), 400

    cur.execute(
        "INSERT INTO accounts (username, account_type, balance) VALUES (?, ?, ?)",
        (username, account_type, opening_balance)
    )
    new_account_id = cur.lastrowid

    # Log opening deposit into both global transactions and account_transactions
    if opening_balance > 0:
        cur.execute(
            "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
            (username, f"Opening deposit — {account_type}", opening_balance, account_type)
        )
        cur.execute(
            "INSERT INTO account_transactions (account_id, username, title, amount) VALUES (?, ?, ?, ?)",
            (new_account_id, username, "Opening deposit", opening_balance)
        )

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"{account_type} created successfully."})


# ── Checkout ───────────────────────────────────────────────────────────────────

@app.route('/api/checkout/process', methods=['POST'])
def process_checkout():
    if "username" not in session:
        return jsonify({"success": False, "message": "You must log in to approve this transaction."}), 401

    data = request.get_json()
    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount format."}), 400

    description = data.get("description", "External Payment").strip()
    if amount <= 0:
        return jsonify({"success": False, "message": "Checkout amount must be greater than zero."}), 400

    username = session["username"]
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT balance FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User account not found."}), 404
    if row[0] < amount:
        conn.close()
        return jsonify({"success": False, "message": "Insufficient funds to complete this payment."}), 400

    cur.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, username))
    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (username, description, -amount, "Current Account")
    )
    conn.commit()
    conn.close()
    session.clear()
    return jsonify({"success": True, "message": "Payment approved securely and session closed."})


# ── Contribution status ────────────────────────────────────────────────────────

@app.route('/api/contribution-status', methods=['GET'])
def contribution_status():
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT SUM(ABS(amount)) FROM transactions WHERE title = 'HKS Coming Soon Contribution'")
    total = cur.fetchone()[0] or 0.0
    conn.close()
    return jsonify({"success": True, "total": total, "goal": 5000.0})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
