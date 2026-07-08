from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import random
import string
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
            is_employee INTEGER NOT NULL DEFAULT 0,
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
        "ALTER TABLE users ADD COLUMN is_employee INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''",
    ]:
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()


# ── HKS Bank ↔ HKMail integration ───────────────────────────────────────────────
# HKS Bank requires every new customer to have an HKMail address on file. Signup
# confirmation codes are delivered as regular emails from a dedicated system
# account (hksbank@hkmail.cn) inside HKMail — no separate email infrastructure.

SYSTEM_MAIL_SENDER = "hksbank@hkmail.cn"


def generate_signup_code(length=8):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(random.choices(alphabet, k=length))


def normalize_mail_address(email):
    email = (email or "").strip().lower()
    if email and "@" not in email:
        email = email + "@hkmail.cn"
    return email


def hkmail_account_lookup(email):
    """Return True if an HKMail account exists for the given address."""
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id FROM mail_users WHERE username=?", (email,))
    row = cur.fetchone()
    conn.close()
    return row is not None


def send_system_mail(recipient, subject, body):
    """Deliver an email into HKMail from the HKS Bank system account.
    Returns True if delivered, False if the recipient has no HKMail account."""
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id FROM mail_users WHERE username=?", (recipient,))
    if not cur.fetchone():
        conn.close()
        return False
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (SYSTEM_MAIL_SENDER, recipient, subject, body)
    )
    conn.commit()
    conn.close()
    return True


# ── Page routes ────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    apps = [
        {'id': 'hks-bank',    'title': 'HKS Bank',       'url': '/hks-bank.html'},
        {'id': 'hkmail',      'title': 'HKMail',          'url': '/hkmail.html'},
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
    email      = normalize_mail_address(data.get("email", ""))
    full_name  = f"{first_name} {last_name}".strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required."}), 400
    if not first_name or not last_name:
        return jsonify({"success": False, "message": "First and last name required."}), 400
    if not email:
        return jsonify({"success": False, "message": "An HKMail email address is required to sign up."}), 400

    # HKS Bank accounts must be tied to an existing HKMail address.
    if not hkmail_account_lookup(email):
        return jsonify({
            "success": False,
            "message": f"We couldn't find an HKMail account for {email}. Please create one first.",
            "needsHkmail": True,
            "email": email
        }), 400

    # Check the username isn't already taken before we bother sending a code.
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    already_taken = cur.fetchone() is not None
    conn.close()
    if already_taken:
        return jsonify({"success": False, "message": "Username already exists."}), 400

    # Registration isn't finalized yet — stash the pending details in the
    # session and email a confirmation code. The account is only created
    # once that code is verified via /api/register/confirm.
    signup_code = generate_signup_code()
    session["pending_bank_signup"] = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "first_name": first_name,
        "last_name": last_name,
        "full_name": full_name,
        "email": email,
        "code": signup_code,
        "attempts": 0,
    }

    delivered = send_system_mail(
        email,
        "Your HKS Bank Sign-Up Code",
        f"Hi {first_name},\n\n"
        f"Use the code below to finish creating your HKS Bank account (username: {username}):\n\n"
        f"    {signup_code}\n\n"
        f"This code is required to complete registration. If you didn't request this, you can ignore this email.\n\n"
        f"— HKS Bank"
    )
    if not delivered:
        session.pop("pending_bank_signup", None)
        return jsonify({"success": False, "message": "Couldn't deliver the confirmation email. Please try again."}), 400

    return jsonify({
        "success": True,
        "pendingVerification": True,
        "email": email,
        "message": f"We've sent a confirmation code to {email}."
    })


@app.route('/api/register/confirm', methods=['POST'])
def register_confirm():
    pending = session.get("pending_bank_signup")
    if not pending:
        return jsonify({"success": False, "message": "No pending registration found. Please start over."}), 400

    data = request.get_json()
    code = (data.get("code", "") or "").strip().upper()

    if not code:
        return jsonify({"success": False, "message": "Confirmation code is required."}), 400

    pending["attempts"] = pending.get("attempts", 0) + 1
    session["pending_bank_signup"] = pending

    if pending["attempts"] > 5:
        session.pop("pending_bank_signup", None)
        return jsonify({"success": False, "message": "Too many incorrect attempts. Please start registration again."}), 400

    if code != pending["code"]:
        remaining = 5 - pending["attempts"]
        return jsonify({"success": False, "message": f"Incorrect code. {remaining} attempt(s) remaining."}), 400

    # Code confirmed — actually create the account now.
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    is_admin = 1 if cur.fetchone()[0] == 0 else 0
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin, balance, full_name, email) VALUES (?, ?, ?, 0.0, ?, ?)",
            (pending["username"], pending["password_hash"], is_admin, pending["full_name"], pending["email"])
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        session.pop("pending_bank_signup", None)
        return jsonify({"success": False, "message": "Username already exists."}), 400
    conn.close()

    session.pop("pending_bank_signup", None)
    return jsonify({"success": True, "username": pending["username"], "message": "Account created successfully."})


@app.route('/api/register/resend', methods=['POST'])
def register_resend():
    pending = session.get("pending_bank_signup")
    if not pending:
        return jsonify({"success": False, "message": "No pending registration found. Please start over."}), 400

    new_code = generate_signup_code()
    pending["code"] = new_code
    pending["attempts"] = 0
    session["pending_bank_signup"] = pending

    send_system_mail(
        pending["email"],
        "Your HKS Bank Sign-Up Code (Resent)",
        f"Hi {pending['first_name']},\n\nHere is your new confirmation code:\n\n    {new_code}\n\n— HKS Bank"
    )
    return jsonify({"success": True, "message": f"A new code was sent to {pending['email']}."})


@app.route('/api/register/cancel', methods=['POST'])
def register_cancel():
    session.pop("pending_bank_signup", None)
    return jsonify({"success": True})


@app.route('/api/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT password_hash, is_admin, is_employee FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        session["username"] = username
        session["is_admin"] = bool(row[1])
        session["is_employee"] = bool(row[2])
        return jsonify({"success": True, "username": username, "isAdmin": bool(row[1]), "isEmployee": bool(row[2])})
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
        cur.execute("SELECT is_admin, balance, full_name, is_employee FROM users WHERE username=?", (session["username"],))
        row = cur.fetchone()
        conn.close()
        if row:
            return jsonify({
                "loggedIn":  True,
                "username":  session["username"],
                "isAdmin":   bool(row[0]),
                "balance":   row[1],
                "fullName":  row[2] if row[2] else session["username"],
                "isEmployee": bool(row[3]),
            })
    return jsonify({"loggedIn": False})


# ── Transactions ───────────────────────────────────────────────────────────────

@app.route('/api/transactions')
def get_transactions():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    primary_only = request.args.get('account') == 'primary'
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    if primary_only:
        cur.execute(
            "SELECT title, amount, timestamp, account_label FROM transactions WHERE username=? AND account_label='Current Account' ORDER BY timestamp DESC",
            (session["username"],)
        )
    else:
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

def is_employee_or_admin():
    return session.get("is_admin", False) or session.get("is_employee", False)


# ── Admin: users ───────────────────────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id, username, full_name, balance, is_admin, is_employee FROM users")
    users = [
        {"id": r[0], "username": r[1], "full_name": r[2], "balance": r[3], "is_admin": bool(r[4]), "is_employee": bool(r[5])}
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify({"success": True, "users": users})


# ── Admin: funds ───────────────────────────────────────────────────────────────

@app.route('/api/admin/add_funds', methods=['POST'])
def admin_add_funds():
    if not is_employee_or_admin():
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
    if not is_employee_or_admin():
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


@app.route('/api/admin/set_employee', methods=['POST'])
def admin_set_employee():
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
    cur.execute("SELECT is_employee, is_admin FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404
    if row[1]:
        conn.close()
        return jsonify({"success": False, "message": "Cannot set employee status on an Admin user."}), 400

    new_val = 0 if row[0] else 1
    cur.execute("UPDATE users SET is_employee = ? WHERE username = ?", (new_val, username))
    conn.commit()
    conn.close()

    action = "promoted to Employee" if new_val else "demoted to User"
    return jsonify({"success": True, "message": f"{username} has been {action}.", "isEmployee": bool(new_val)})


# ── Admin: additional accounts ────────────────────────────────────────────────

@app.route('/api/admin/accounts/<username>', methods=['GET'])
def admin_get_accounts(username):
    if not is_employee_or_admin():
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
    if not is_employee_or_admin():
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


@app.route('/api/admin/close_account', methods=['POST'])
def admin_close_account():
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data       = request.get_json()
    account_id = data.get("account_id")
    username   = data.get("username", "").strip()

    if not account_id:
        return jsonify({"success": False, "message": "Account ID required."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    cur.execute("SELECT account_type, balance, username FROM accounts WHERE id = ?", (account_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Account not found."}), 404

    account_type, balance, owner = row
    # Safety: username must match
    if username and owner != username:
        conn.close()
        return jsonify({"success": False, "message": "Account does not belong to this user."}), 403

    cur.execute("DELETE FROM account_transactions WHERE account_id = ?", (account_id,))
    cur.execute("DELETE FROM accounts WHERE id = ?", (account_id,))

    # Transfer any remaining balance to the user's primary account
    if balance > 0:
        cur.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (balance, owner))
        cur.execute(
            "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
            (owner, f"Transfer from closed {account_type}", balance, "Current Account")
        )

    conn.commit()
    conn.close()
    transferred = f" ${balance:.2f} transferred to Current Account." if balance > 0 else ""
    return jsonify({"success": True, "message": f"{account_type} closed.{transferred}", "balance": balance})


@app.route('/api/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if not is_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data     = request.get_json()
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400
    if username == session.get("username"):
        return jsonify({"success": False, "message": "You cannot delete your own account."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404

    # Delete all associated data
    cur.execute("SELECT id FROM accounts WHERE username = ?", (username,))
    account_ids = [r[0] for r in cur.fetchall()]
    for aid in account_ids:
        cur.execute("DELETE FROM account_transactions WHERE account_id = ?", (aid,))
    cur.execute("DELETE FROM accounts WHERE username = ?", (username,))
    cur.execute("DELETE FROM transactions WHERE username = ?", (username,))
    cur.execute("DELETE FROM users WHERE username = ?", (username,))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"User '{username}' and all associated data deleted."})


# ── User-to-user transfer ──────────────────────────────────────────────────────

@app.route('/api/transfer', methods=['POST'])
def transfer():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data      = request.get_json()
    recipient = data.get("recipient", "").strip()
    reference = data.get("reference", "").strip() or "Transfer"
    try:
        amount = round(float(data.get("amount", 0)), 2)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount."}), 400

    sender = session["username"]

    if not recipient:
        return jsonify({"success": False, "message": "Recipient username is required."}), 400
    if recipient == sender:
        return jsonify({"success": False, "message": "You cannot transfer money to yourself."}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be greater than zero."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    # Verify recipient exists
    cur.execute("SELECT username, full_name FROM users WHERE username = ?", (recipient,))
    rec_row = cur.fetchone()
    if not rec_row:
        conn.close()
        return jsonify({"success": False, "message": "Recipient not found. Check the username and try again."}), 404

    # Check sender balance
    cur.execute("SELECT balance FROM users WHERE username = ?", (sender,))
    sender_row = cur.fetchone()
    if not sender_row or sender_row[0] < amount:
        conn.close()
        return jsonify({"success": False, "message": "Insufficient funds."}), 400

    recipient_full = rec_row[1] or recipient

    # Debit sender
    cur.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, sender))
    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (sender, f"Transfer to {recipient} — {reference}", -amount, "Current Account")
    )

    # Credit recipient
    cur.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, recipient))
    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (recipient, f"Transfer from {sender} — {reference}", amount, "Current Account")
    )

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"${amount:.2f} sent to {recipient_full} successfully.", "recipient_full": recipient_full})


# ── Internal account-to-account move ──────────────────────────────────────────

@app.route('/api/move-funds', methods=['POST'])
def move_funds():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data            = request.get_json()
    from_account_id = data.get("from_account_id")   # None = primary Current Account
    to_account_id   = data.get("to_account_id")     # None = primary Current Account
    try:
        amount = round(float(data.get("amount", 0)), 2)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount."}), 400

    username = session["username"]

    if from_account_id == to_account_id:
        return jsonify({"success": False, "message": "Source and destination must be different."}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be greater than zero."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    # ── Resolve & validate source ──────────────────────────
    if from_account_id is None:
        cur.execute("SELECT balance FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"success": False, "message": "User not found."}), 404
        from_balance = row[0]
        from_label   = "Current Account"
    else:
        cur.execute("SELECT balance, account_type, username FROM accounts WHERE id = ?", (from_account_id,))
        row = cur.fetchone()
        if not row or row[2] != username:
            conn.close()
            return jsonify({"success": False, "message": "Source account not found."}), 404
        from_balance = row[0]
        from_label   = row[1]

    if from_balance < amount:
        conn.close()
        return jsonify({"success": False, "message": f"Insufficient balance in {from_label}."}), 400

    # ── Resolve & validate destination ─────────────────────
    if to_account_id is None:
        to_label = "Current Account"
    else:
        cur.execute("SELECT account_type, username FROM accounts WHERE id = ?", (to_account_id,))
        row = cur.fetchone()
        if not row or row[1] != username:
            conn.close()
            return jsonify({"success": False, "message": "Destination account not found."}), 404
        to_label = row[0]

    # ── Debit source ───────────────────────────────────────
    if from_account_id is None:
        cur.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, username))
    else:
        cur.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, from_account_id))
        cur.execute(
            "INSERT INTO account_transactions (account_id, username, title, amount) VALUES (?, ?, ?, ?)",
            (from_account_id, username, f"Internal transfer to {to_label}", -amount)
        )
    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (username, f"Internal transfer to {to_label}", -amount, from_label)
    )

    # ── Credit destination ─────────────────────────────────
    if to_account_id is None:
        cur.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
    else:
        cur.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, to_account_id))
        cur.execute(
            "INSERT INTO account_transactions (account_id, username, title, amount) VALUES (?, ?, ?, ?)",
            (to_account_id, username, f"Internal transfer from {from_label}", amount)
        )
    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (username, f"Internal transfer from {from_label}", amount, to_label)
    )

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"${amount:.2f} moved from {from_label} to {to_label}."})


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

# ══════════════════════════════════════════════════════════════════════════════
# HKMail — separate database & session namespace
# ══════════════════════════════════════════════════════════════════════════════

MAIL_DATABASE = "mail.db"


def init_mail_db():
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()

    # Users table (completely separate from HKS Bank)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mail_users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT UNIQUE NOT NULL,   -- stored as full address e.g. jane@hkmail.cn
            password_hash TEXT NOT NULL,
            full_name    TEXT NOT NULL DEFAULT '',
            is_admin     INTEGER NOT NULL DEFAULT 0,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Emails table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sender      TEXT NOT NULL,
            recipient   TEXT NOT NULL,
            subject     TEXT NOT NULL DEFAULT '(No subject)',
            body        TEXT NOT NULL DEFAULT '',
            sent_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            read        INTEGER NOT NULL DEFAULT 0,
            deleted_by_sender    INTEGER NOT NULL DEFAULT 0,
            deleted_by_recipient INTEGER NOT NULL DEFAULT 0,
            folder_sender        TEXT NOT NULL DEFAULT 'sent',
            folder_recipient     TEXT NOT NULL DEFAULT 'inbox'
        )
    """)

    # Ensure the HKS Bank system mailbox exists so it can send signup codes.
    # It gets a random, never-shared password since no one logs into it directly.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (SYSTEM_MAIL_SENDER,))
    if not cur.fetchone():
        locked_password_hash = generate_password_hash(os.urandom(32).hex())
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin) VALUES (?, ?, ?, 0)",
            (SYSTEM_MAIL_SENDER, locked_password_hash, "HKS Bank")
        )

    conn.commit()
    conn.close()


def mail_current_user():
    """Return the HKMail username from session, or None."""
    return session.get("mail_username")


# ── HKMail page routes ─────────────────────────────────────────────────────────

@app.route('/hkmail.html')
def hkmail_login():
    return render_template('hkmail.html')

@app.route('/hkmail-inbox.html')
def hkmail_inbox():
    return render_template('hkmail-inbox.html')


# ── HKMail Auth API ────────────────────────────────────────────────────────────

@app.route('/api/hkmail/account-exists')
def hkmail_account_exists():
    """Public lookup used by other apps (e.g. HKS Bank signup) to verify an
    HKMail address exists before allowing registration."""
    email = normalize_mail_address(request.args.get("email", ""))
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400
    return jsonify({"success": True, "email": email, "exists": hkmail_account_lookup(email)})


@app.route('/api/hkmail/register', methods=['POST'])
def hkmail_register():
    data       = request.get_json()
    username   = data.get("username", "").strip().lower()   # full address
    password   = data.get("password", "").strip()
    first_name = data.get("first_name", "").strip()
    last_name  = data.get("last_name", "").strip()
    full_name  = f"{first_name} {last_name}".strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400
    if not first_name or not last_name:
        return jsonify({"success": False, "message": "First and last name are required."}), 400
    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters."}), 400

    password_hash = generate_password_hash(password)
    try:
        conn = sqlite3.connect(MAIL_DATABASE)
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM mail_users")
        is_admin = 1 if cur.fetchone()[0] == 0 else 0
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin) VALUES (?, ?, ?, ?)",
            (username, password_hash, full_name, is_admin)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Account created."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "That email address is already taken."}), 400


@app.route('/api/hkmail/login', methods=['POST'])
def hkmail_login_api():
    data     = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT password_hash, full_name, is_admin FROM mail_users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        session["mail_username"] = username
        session["mail_full_name"] = row[1]
        session["mail_is_admin"]  = bool(row[2])
        return jsonify({"success": True, "username": username, "fullName": row[1], "isAdmin": bool(row[2])})
    return jsonify({"success": False, "message": "Incorrect email or password."}), 401


@app.route('/api/hkmail/logout', methods=['POST'])
def hkmail_logout():
    session.pop("mail_username", None)
    session.pop("mail_full_name", None)
    session.pop("mail_is_admin", None)
    return jsonify({"success": True})


@app.route('/api/hkmail/current-user')
def hkmail_current_user():
    u = mail_current_user()
    if u:
        conn = sqlite3.connect(MAIL_DATABASE)
        cur  = conn.cursor()
        cur.execute("SELECT full_name, is_admin FROM mail_users WHERE username=?", (u,))
        row = cur.fetchone()
        conn.close()
        if row:
            return jsonify({"loggedIn": True, "username": u,
                            "fullName": row[0], "isAdmin": bool(row[1])})
    return jsonify({"loggedIn": False})


# ── HKMail: compose / send ─────────────────────────────────────────────────────

@app.route('/api/hkmail/send', methods=['POST'])
def hkmail_send():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data      = request.get_json()
    recipient = data.get("recipient", "").strip().lower()
    subject   = data.get("subject",   "").strip() or "(No subject)"
    body      = data.get("body",       "").strip()

    if not recipient:
        return jsonify({"success": False, "message": "Recipient is required."}), 400

    # Auto-append @hkmail.cn if no domain given
    if "@" not in recipient:
        recipient = recipient + "@hkmail.cn"

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()

    # Verify recipient exists
    cur.execute("SELECT id FROM mail_users WHERE username=?", (recipient,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"success": False, "message": f"No HKMail account found for {recipient}."}), 404

    # Self-send: one row, shows in both sent & inbox
    if recipient == u:
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body, folder_sender, folder_recipient) VALUES (?,?,?,?,?,?)",
            (u, recipient, subject, body, 'sent', 'inbox')
        )
    else:
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?,?,?,?)",
            (u, recipient, subject, body)
        )

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Message sent to {recipient}."})


# ── HKMail: list folders ───────────────────────────────────────────────────────

@app.route('/api/hkmail/inbox')
def hkmail_inbox_api():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, sender, subject, sent_at, read
        FROM emails
        WHERE recipient=? AND deleted_by_recipient=0
        ORDER BY sent_at DESC
    """, (u,))
    emails = [{"id": r[0], "from": r[1], "subject": r[2], "date": r[3], "read": bool(r[4])}
              for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "emails": emails})


@app.route('/api/hkmail/sent')
def hkmail_sent_api():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, recipient, subject, sent_at
        FROM emails
        WHERE sender=? AND deleted_by_sender=0 AND recipient != sender
        ORDER BY sent_at DESC
    """, (u,))
    emails = [{"id": r[0], "to": r[1], "subject": r[2], "date": r[3]}
              for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "emails": emails})


@app.route('/api/hkmail/trash')
def hkmail_trash_api():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    # Show emails deleted by this user (either as sender or recipient)
    cur.execute("""
        SELECT id, sender, recipient, subject, sent_at,
               deleted_by_sender, deleted_by_recipient
        FROM emails
        WHERE (sender=? AND deleted_by_sender=1)
           OR (recipient=? AND deleted_by_recipient=1)
        ORDER BY sent_at DESC
    """, (u, u))
    emails = []
    for r in cur.fetchall():
        emails.append({
            "id": r[0], "from": r[1], "to": r[2],
            "subject": r[3], "date": r[4]
        })
    conn.close()
    return jsonify({"success": True, "emails": emails})


# ── HKMail: read a single email ────────────────────────────────────────────────

@app.route('/api/hkmail/email/<int:email_id>')
def hkmail_read_email(email_id):
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, sender, recipient, subject, body, sent_at, read
        FROM emails WHERE id=?
    """, (email_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Email not found."}), 404

    sender, recipient = row[1], row[2]
    if u not in (sender, recipient):
        conn.close()
        return jsonify({"success": False, "message": "Access denied."}), 403

    # Mark as read if recipient
    if u == recipient and not row[6]:
        cur.execute("UPDATE emails SET read=1 WHERE id=?", (email_id,))
        conn.commit()

    conn.close()
    return jsonify({
        "success": True,
        "email": {
            "id": row[0], "from": row[1], "to": row[2],
            "subject": row[3], "body": row[4], "date": row[5], "read": True
        }
    })


# ── HKMail: mark as read/unread ────────────────────────────────────────────────

@app.route('/api/hkmail/email/<int:email_id>/mark-read', methods=['POST'])
def hkmail_mark_read(email_id):
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json()
    read_val = 1 if data.get("read", True) else 0
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT recipient FROM emails WHERE id=?", (email_id,))
    row = cur.fetchone()
    if not row or row[0] != u:
        conn.close()
        return jsonify({"success": False, "message": "Not found."}), 404
    cur.execute("UPDATE emails SET read=? WHERE id=?", (read_val, email_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ── HKMail: delete (soft) ──────────────────────────────────────────────────────

@app.route('/api/hkmail/email/<int:email_id>/delete', methods=['POST'])
def hkmail_delete_email(email_id):
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT sender, recipient FROM emails WHERE id=?", (email_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Email not found."}), 404

    sender, recipient = row
    if u == sender:
        cur.execute("UPDATE emails SET deleted_by_sender=1 WHERE id=?", (email_id,))
    if u == recipient:
        cur.execute("UPDATE emails SET deleted_by_recipient=1 WHERE id=?", (email_id,))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Moved to Trash."})


# ── HKMail: restore from trash ────────────────────────────────────────────────

@app.route('/api/hkmail/email/<int:email_id>/restore', methods=['POST'])
def hkmail_restore_email(email_id):
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT sender, recipient FROM emails WHERE id=?", (email_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Email not found."}), 404

    sender, recipient = row
    if u == sender:
        cur.execute("UPDATE emails SET deleted_by_sender=0 WHERE id=?", (email_id,))
    if u == recipient:
        cur.execute("UPDATE emails SET deleted_by_recipient=0 WHERE id=?", (email_id,))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Email restored."})


# ── HKMail: permanent delete ───────────────────────────────────────────────────

@app.route('/api/hkmail/email/<int:email_id>/delete-permanent', methods=['POST'])
def hkmail_delete_permanent(email_id):
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT sender, recipient, deleted_by_sender, deleted_by_recipient FROM emails WHERE id=?", (email_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Email not found."}), 404

    sender, recipient, del_sender, del_recipient = row
    if u not in (sender, recipient):
        conn.close()
        return jsonify({"success": False, "message": "Access denied."}), 403

    # Only truly delete if both parties have deleted it (or it's a self-send)
    both_deleted = (
        (sender == u and del_sender) or (sender != u)
    ) and (
        (recipient == u and del_recipient) or (recipient != u)
    )

    if both_deleted or sender == recipient:
        cur.execute("DELETE FROM emails WHERE id=?", (email_id,))
    else:
        # Just mark this side as deleted
        if u == sender:
            cur.execute("UPDATE emails SET deleted_by_sender=1 WHERE id=?", (email_id,))
        if u == recipient:
            cur.execute("UPDATE emails SET deleted_by_recipient=1 WHERE id=?", (email_id,))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Email permanently deleted."})


# ── HKMail: unread count ───────────────────────────────────────────────────────

@app.route('/api/hkmail/unread-count')
def hkmail_unread_count():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM emails WHERE recipient=? AND read=0 AND deleted_by_recipient=0", (u,)
    )
    count = cur.fetchone()[0]
    conn.close()
    return jsonify({"success": True, "count": count})


# ── HKMail: admin — list all users ────────────────────────────────────────────

@app.route('/api/hkmail/admin/users')
def hkmail_admin_users():
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id, username, full_name, is_admin, created_at FROM mail_users ORDER BY created_at")
    users = [{"id": r[0], "username": r[1], "full_name": r[2],
              "is_admin": bool(r[3]), "created_at": r[4]} for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "users": users})

if __name__ == '__main__':
    init_db()
    init_mail_db()
    app.run(host='0.0.0.0', port=5001, debug=True)