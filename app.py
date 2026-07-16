from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import random
import string
from datetime import datetime, date

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

    # Bank cards — issued by an admin/employee, tied to a user and (optionally)
    # a specific account. Not every account has a card; cards are opt-in.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cards (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT NOT NULL,
            account_id      INTEGER,                 -- NULL = draws from primary Current Account
            account_label   TEXT NOT NULL DEFAULT 'Current Account',
            card_number     TEXT UNIQUE NOT NULL,
            cvv             TEXT NOT NULL,
            expiry_month    INTEGER NOT NULL,
            expiry_year     INTEGER NOT NULL,
            cardholder_name TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'active',   -- active | frozen | cancelled
            card_type       TEXT NOT NULL DEFAULT 'regular',  -- regular | hkmail
            issued_by       TEXT NOT NULL DEFAULT '',
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
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
        "ALTER TABLE cards ADD COLUMN card_type TEXT NOT NULL DEFAULT 'regular'",
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

# The HKMail administrator account. This is seeded as the very first row in
# mail_users (ahead of the bank's system mailbox) so it is unambiguously the
# "first user" of the HKMail service. It's the only account that can manage
# other HKMail users, mark accounts as verified/official, etc.
ADMIN_MAIL_USERNAME = "admin@hkmail.cn"
ADMIN_MAIL_DEFAULT_PASSWORD = "AdminPass123!"  # demo credential, change in a real deployment

# Automated, no-reply mailbox used as the sender for system-generated notices
# (welcome emails, Premium subscription confirmations/renewals/cancellations)
# that were previously sent from the admin account. Logs in with the same
# password as the admin account so it's easy to check what it's sending.
NOREPLY_MAIL_USERNAME = "noreply@hkmail.cn"

# Fixed demo credential for the HKS Bank system mailbox (SYSTEM_MAIL_SENDER),
# same pattern as ADMIN_MAIL_DEFAULT_PASSWORD — change in a real deployment.
HKSBANK_MAIL_DEFAULT_PASSWORD = "HksBankSys456!"


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


# ── HKS Bank cards ───────────────────────────────────────────────────────────────
# Fictitious 6-digit issuer prefix (IIN) for HKS Bank cards. It's fine for this
# to be public/hardcoded — real banks' BINs are public too — so the checkout
# page can instantly recognize an HKS Bank card as the customer types.
CARD_BIN = "457124"


def _luhn_checksum(number_str):
    digits = [int(d) for d in number_str]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10


def generate_card_number():
    """Generate a unique 16-digit, Luhn-valid card number starting with CARD_BIN."""
    remaining = 16 - len(CARD_BIN) - 1
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    try:
        while True:
            body = CARD_BIN + ''.join(random.choices(string.digits, k=remaining))
            check_digit = (10 - _luhn_checksum(body + '0')) % 10
            candidate = body + str(check_digit)
            cur.execute("SELECT 1 FROM cards WHERE card_number=?", (candidate,))
            if not cur.fetchone():
                return candidate
    finally:
        conn.close()


def generate_cvv():
    return f"{random.randint(0, 999):03d}"


def compute_expiry(from_date=None):
    """Card expires exactly 3 years from the date it was opened."""
    d = from_date or date.today()
    try:
        expiry = d.replace(year=d.year + 3)
    except ValueError:
        # Feb 29 on a non-leap target year
        expiry = d.replace(year=d.year + 3, day=28)
    return expiry.month, expiry.year


def mask_card_number(card_number):
    return "•••• •••• •••• " + card_number[-4:]


def is_hks_bank_card_number(card_number):
    digits = ''.join(ch for ch in (card_number or '') if ch.isdigit())
    return digits.startswith(CARD_BIN)


def is_card_expired(expiry_month, expiry_year):
    """A card is expired once we're past the end of its expiry month."""
    today = date.today()
    if today.year > expiry_year:
        return True
    if today.year == expiry_year and today.month > expiry_month:
        return True
    return False


def card_to_dict(row, reveal_number=False, reveal_cvv=False):
    """row columns: id, username, account_id, account_label, card_number, cvv,
    expiry_month, expiry_year, cardholder_name, status, issued_by, created_at, card_type"""
    expired = is_card_expired(row[6], row[7])
    raw_status = row[9]
    # cancelled stays cancelled even past expiry; otherwise expired takes
    # display priority over active/frozen since it can no longer be used.
    display_status = raw_status if raw_status == 'cancelled' else ('expired' if expired else raw_status)
    card_type = row[12] if len(row) > 12 else 'regular'

    d = {
        "id": row[0],
        "username": row[1],
        "account_id": row[2],
        "account_label": row[3],
        "last4": row[4][-4:],
        "masked_number": mask_card_number(row[4]),
        "expiry": f"{row[6]:02d}/{str(row[7])[-2:]}",
        "cardholder_name": row[8],
        "status": display_status,
        "raw_status": raw_status,
        "expired": expired,
        "issued_by": row[10],
        "created_at": row[11],
        "card_type": card_type,
    }
    if reveal_number:
        d["card_number"] = row[4]
    if reveal_cvv:
        d["cvv"] = row[5]
    return d


def get_hkmail_card(cur):
    """Return the raw row for the ecosystem's current usable HKMail merchant
    card (card_type='hkmail', not cancelled, not expired), or None. There can
    only ever be one such card system-wide. Uses the caller's cursor so this
    can be included in an existing transaction."""
    cur.execute("""
        SELECT id, username, account_id, account_label, card_number, cvv,
               expiry_month, expiry_year, cardholder_name, status, issued_by, created_at, card_type
        FROM cards WHERE card_type = 'hkmail'
        ORDER BY created_at DESC
    """)
    for row in cur.fetchall():
        status, expiry_month, expiry_year = row[9], row[6], row[7]
        if status != 'cancelled' and not is_card_expired(expiry_month, expiry_year):
            return row
    return None


def credit_hkmail_revenue(cur, amount, description):
    """Route HKMail subscription revenue into the account backing the
    ecosystem's HKMail merchant card, if one currently exists and is usable.
    Returns True if credited, False if there's currently no valid HKMail
    card — the payer's card is still charged either way; the revenue just
    has nowhere to land until an admin opens one."""
    card = get_hkmail_card(cur)
    if not card:
        return False

    username, account_id, account_label = card[1], card[2], card[3]
    if account_id:
        cur.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, account_id))
        cur.execute(
            "INSERT INTO account_transactions (account_id, username, title, amount) VALUES (?, ?, ?, ?)",
            (account_id, username, description, amount)
        )
    else:
        cur.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))

    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (username, description, amount, account_label)
    )
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

    # Cards tied to this account can no longer draw funds — cancel them.
    cur.execute("UPDATE cards SET status = 'cancelled' WHERE account_id = ?", (account_id,))

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
    cur.execute("DELETE FROM cards WHERE username = ?", (username,))
    cur.execute("DELETE FROM users WHERE username = ?", (username,))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"User '{username}' and all associated data deleted."})


# ── Admin: cards ───────────────────────────────────────────────────────────────

@app.route('/api/admin/cards/<username>', methods=['GET'])
def admin_get_cards(username):
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, username, account_id, account_label, card_number, cvv,
               expiry_month, expiry_year, cardholder_name, status, issued_by, created_at, card_type
        FROM cards WHERE username = ? ORDER BY created_at DESC
    """, (username,))
    cards = [card_to_dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "cards": cards})


@app.route('/api/admin/create_card', methods=['POST'])
def admin_create_card():
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data       = request.get_json()
    username   = data.get("username", "").strip()
    account_id = data.get("account_id")  # None/omitted = primary Current Account
    card_type  = (data.get("card_type") or "regular").strip().lower()

    if not username:
        return jsonify({"success": False, "message": "Username is required."}), 400
    if card_type not in ("regular", "hkmail"):
        return jsonify({"success": False, "message": "Invalid card type."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()

    cur.execute("SELECT full_name, email FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404
    full_name, email = user_row
    cardholder_name = (full_name or username).strip().upper()

    if card_type == "hkmail":
        existing = get_hkmail_card(cur)
        if existing:
            conn.close()
            return jsonify({
                "success": False,
                "message": f"An HKMail card already exists (held by {existing[1]}). "
                           f"Cancel it or wait for it to expire before opening another."
            }), 400

    if account_id:
        cur.execute("SELECT account_type FROM accounts WHERE id = ? AND username = ?", (account_id, username))
        acc_row = cur.fetchone()
        if not acc_row:
            conn.close()
            return jsonify({"success": False, "message": "Account not found for this user."}), 404
        account_label = acc_row[0]
    else:
        account_id = None
        account_label = "Current Account"

    card_number = generate_card_number()
    cvv = generate_cvv()
    expiry_month, expiry_year = compute_expiry()
    issued_by = session.get("username", "")

    cur.execute("""
        INSERT INTO cards (username, account_id, account_label, card_number, cvv,
                            expiry_month, expiry_year, cardholder_name, status, card_type, issued_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    """, (username, account_id, account_label, card_number, cvv, expiry_month, expiry_year, cardholder_name, card_type, issued_by))
    new_card_id = cur.lastrowid
    conn.commit()

    cur.execute("""
        SELECT id, username, account_id, account_label, card_number, cvv,
               expiry_month, expiry_year, cardholder_name, status, issued_by, created_at, card_type
        FROM cards WHERE id = ?
    """, (new_card_id,))
    card = card_to_dict(cur.fetchone(), reveal_number=True, reveal_cvv=True)
    conn.close()

    # Let the customer know via HKMail, if they have an address on file.
    if email:
        type_note = (
            "This is the ecosystem's HKMail merchant card — HKMail Premium subscription "
            "revenue will be deposited onto it automatically.\n\n"
            if card_type == "hkmail" else ""
        )
        send_system_mail(
            email,
            "Your New HKMail Merchant Card" if card_type == "hkmail" else "Your New HKS Bank Card",
            f"Hi {full_name or username},\n\n"
            f"A new HKS Bank card has been opened for your {account_label} (username: {username}).\n\n"
            f"{type_note}"
            f"    Card number: {card_number}\n"
            f"    CVV:         {cvv}\n"
            f"    Expires:     {expiry_month:02d}/{str(expiry_year)[-2:]}\n"
            f"    Name on card: {cardholder_name}\n\n"
            f"Keep these details safe — anyone with them can use this card. If you didn't request this, "
            f"please contact HKS Bank support immediately.\n\n"
            f"— HKS Bank"
        )

    return jsonify({"success": True, "message": f"Card issued for {username}.", "card": card})


@app.route('/api/admin/card/freeze', methods=['POST'])
def admin_freeze_card():
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data    = request.get_json()
    card_id = data.get("card_id")
    if not card_id:
        return jsonify({"success": False, "message": "Card ID required."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT status FROM cards WHERE id = ?", (card_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Card not found."}), 404
    if row[0] == 'cancelled':
        conn.close()
        return jsonify({"success": False, "message": "Cancelled cards cannot be frozen or unfrozen."}), 400

    new_status = 'active' if row[0] == 'frozen' else 'frozen'
    cur.execute("UPDATE cards SET status = ? WHERE id = ?", (new_status, card_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "status": new_status, "message": f"Card is now {new_status}."})


@app.route('/api/admin/card/cancel', methods=['POST'])
def admin_cancel_card():
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data    = request.get_json()
    card_id = data.get("card_id")
    if not card_id:
        return jsonify({"success": False, "message": "Card ID required."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT status FROM cards WHERE id = ?", (card_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Card not found."}), 404

    cur.execute("UPDATE cards SET status = 'cancelled' WHERE id = ?", (card_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Card cancelled."})


@app.route('/api/admin/card/delete', methods=['POST'])
def admin_delete_card():
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data    = request.get_json()
    card_id = data.get("card_id")
    if not card_id:
        return jsonify({"success": False, "message": "Card ID required."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT status, expiry_month, expiry_year FROM cards WHERE id = ?", (card_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Card not found."}), 404

    status, expiry_month, expiry_year = row
    if status != 'cancelled' and not is_card_expired(expiry_month, expiry_year):
        conn.close()
        return jsonify({"success": False, "message": "Only cancelled or expired cards can be deleted."}), 400

    cur.execute("DELETE FROM cards WHERE id = ?", (card_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Card deleted."})


# ── User: own cards ────────────────────────────────────────────────────────────

@app.route('/api/my-cards')
def my_cards():
    if "username" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    # ?full=1 reveals the complete card number and CVV (used on the user's own
    # profile page, where the owner legitimately needs both to make a payment).
    # Without it, cards stay masked — this is what the checkout flow requests.
    reveal = request.args.get("full") in ("1", "true", "yes")
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, username, account_id, account_label, card_number, cvv,
               expiry_month, expiry_year, cardholder_name, status, issued_by, created_at, card_type
        FROM cards WHERE username = ? ORDER BY created_at DESC
    """, (session["username"],))
    cards = [card_to_dict(r, reveal_number=reveal, reveal_cvv=reveal) for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "cards": cards})


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


def _debit_for_card_payment(cur, card_row, amount, description):
    """Shared debit logic for a card payment. card_row is a full cards row tuple.
    Returns (ok, message).

    Writes to the `transactions` table exactly like a balance payment does
    (same title, same shape) so anything that matches on transaction title —
    e.g. the coming-soon contribution progress bar — behaves identically
    regardless of whether the customer paid by balance or by card. The
    card-specific detail (last 4 digits) is still recorded in the per-account
    `account_transactions` history for the customer's own reference."""
    card_id, username, account_id, account_label = card_row[0], card_row[1], card_row[2], card_row[3]

    if account_id:
        cur.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,))
        bal_row = cur.fetchone()
        if not bal_row:
            return False, "The account linked to this card no longer exists."
        if bal_row[0] < amount:
            return False, "Card declined — insufficient funds."
        cur.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, account_id))
        cur.execute(
            "INSERT INTO account_transactions (account_id, username, title, amount) VALUES (?, ?, ?, ?)",
            (account_id, username, f"{description} (Card •••• {card_row[4][-4:]})", -amount)
        )
    else:
        cur.execute("SELECT balance FROM users WHERE username = ?", (username,))
        bal_row = cur.fetchone()
        if not bal_row:
            return False, "The account linked to this card no longer exists."
        if bal_row[0] < amount:
            return False, "Card declined — insufficient funds."
        cur.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, username))

    cur.execute(
        "INSERT INTO transactions (username, title, amount, account_label) VALUES (?, ?, ?, ?)",
        (username, description, -amount, account_label)
    )
    return True, "Payment approved."


@app.route('/api/checkout/pay-with-card', methods=['POST'])
def checkout_pay_with_card():
    """Manual card entry payment — no HKS Bank login required."""
    data = request.get_json()
    raw_number   = data.get("card_number", "")
    card_number  = ''.join(ch for ch in raw_number if ch.isdigit())
    cvv          = (data.get("cvv", "") or "").strip()
    exp_month    = data.get("expiry_month")
    exp_year     = data.get("expiry_year")
    description  = (data.get("description", "") or "External Payment").strip()
    meta         = (data.get("meta", "") or "").strip()

    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount format."}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Checkout amount must be greater than zero."}), 400

    if not card_number or not cvv or not exp_month or not exp_year:
        return jsonify({"success": False, "message": "Please fill in all card details."}), 400

    try:
        exp_month = int(exp_month)
        exp_year  = int(exp_year)
        if exp_year < 100:  # accept 2-digit year input
            exp_year += 2000
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid expiry date."}), 400

    if not is_hks_bank_card_number(card_number):
        return jsonify({"success": False, "message": "This does not appear to be a valid HKS Bank card number."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, username, account_id, account_label, card_number, cvv,
               expiry_month, expiry_year, cardholder_name, status, card_type
        FROM cards WHERE card_number = ?
    """, (card_number,))
    card = cur.fetchone()

    if not card:
        conn.close()
        return jsonify({"success": False, "message": "Card not found. Please check the card number."}), 404
    if card[5] != cvv:
        conn.close()
        return jsonify({"success": False, "message": "Incorrect CVV."}), 400
    if (card[6], card[7]) != (exp_month, exp_year):
        conn.close()
        return jsonify({"success": False, "message": "Incorrect expiry date."}), 400
    if card[9] == 'cancelled':
        conn.close()
        return jsonify({"success": False, "message": "This card has been cancelled."}), 400
    if is_card_expired(card[6], card[7]):
        conn.close()
        return jsonify({"success": False, "message": "This card has expired."}), 400
    if card[9] == 'frozen':
        conn.close()
        return jsonify({"success": False, "message": "This card is frozen. Contact HKS Bank to unfreeze it."}), 400

    ok, message = _debit_for_card_payment(cur, card, amount, description)
    if not ok:
        conn.close()
        return jsonify({"success": False, "message": message}), 400

    if meta.startswith("hkmail_premium:"):
        credit_hkmail_revenue(cur, amount, description)

    conn.commit()
    conn.close()

    if meta.startswith("hkmail_premium:"):
        _activate_mail_premium(session.get("mail_username"), meta.split(":", 1)[1], card[0])

    return jsonify({"success": True, "message": message})


@app.route('/api/checkout/pay-with-session-card', methods=['POST'])
def checkout_pay_with_session_card():
    """Card payment where the card details are pulled automatically from the
    logged-in HKS Bank session — the browser never sees the full card number/CVV."""
    if "username" not in session:
        return jsonify({"success": False, "message": "You must log in to approve this transaction."}), 401

    data    = request.get_json()
    card_id = data.get("card_id")
    description = (data.get("description", "") or "External Payment").strip()
    meta        = (data.get("meta", "") or "").strip()

    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount format."}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Checkout amount must be greater than zero."}), 400
    if not card_id:
        return jsonify({"success": False, "message": "Please choose a card."}), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, username, account_id, account_label, card_number, cvv,
               expiry_month, expiry_year, cardholder_name, status, card_type
        FROM cards WHERE id = ?
    """, (card_id,))
    card = cur.fetchone()

    if not card or card[1] != session["username"]:
        conn.close()
        return jsonify({"success": False, "message": "Card not found."}), 404
    if card[9] == 'cancelled':
        conn.close()
        return jsonify({"success": False, "message": "This card has been cancelled."}), 400
    if is_card_expired(card[6], card[7]):
        conn.close()
        return jsonify({"success": False, "message": "This card has expired."}), 400
    if card[9] == 'frozen':
        conn.close()
        return jsonify({"success": False, "message": "This card is frozen. Contact HKS Bank to unfreeze it."}), 400

    ok, message = _debit_for_card_payment(cur, card, amount, description)
    if not ok:
        conn.close()
        return jsonify({"success": False, "message": message}), 400

    if meta.startswith("hkmail_premium:"):
        credit_hkmail_revenue(cur, amount, description)

    conn.commit()
    conn.close()

    # Finalize before clearing the session — session.clear() below wipes the
    # shared cookie, including the HKMail login state read here.
    if meta.startswith("hkmail_premium:"):
        _activate_mail_premium(session.get("mail_username"), meta.split(":", 1)[1], card[0])

    session.clear()
    return jsonify({"success": True, "message": message})


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

# ── HKMail storage plans ────────────────────────────────────────────────────────
# Every mailbox starts on the Free plan. Users can subscribe to one paid tier at
# a time; paid tiers add storage and a "Premium" badge shown next to their name
# wherever they appear as a sender. Billing runs monthly through HKS Bank.
FREE_STORAGE_MB = 1024  # 1GB for free users

MAIL_PLANS = {
    "5gb":   {"id": "5gb",   "label": "Premium 5GB",   "storage_mb": 5   * 1024, "price": 1.99,  "badge": True},
    "25gb":  {"id": "25gb",  "label": "Premium 25GB",  "storage_mb": 25  * 1024, "price": 4.99,  "badge": True},
    "50gb":  {"id": "50gb",  "label": "Premium 50GB",  "storage_mb": 50  * 1024, "price": 9.99,  "badge": True},
    "100gb": {"id": "100gb", "label": "Premium 100GB", "storage_mb": 100 * 1024, "price": 19.99, "badge": True},
}


def add_one_month(d):
    """Return the date one calendar month after d (clamped to a valid day)."""
    month = d.month + 1
    year  = d.year + (month - 1) // 12
    month = ((month - 1) % 12) + 1
    is_leap = (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0))
    days_in_month = [31, 29 if is_leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    day = min(d.day, days_in_month[month - 1])
    return date(year, month, day)


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
            is_verified  INTEGER NOT NULL DEFAULT 0,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Safe migration for existing databases created before is_verified existed
    try:
        cur.execute("ALTER TABLE mail_users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # Premium subscriptions — one row per plan a mailbox has purchased. Plans
    # stack: a mailbox can hold several rows at once (e.g. both 50gb and
    # 100gb), and its total storage is Free + the sum of all rows here that
    # are still in effect ('active' or 'cancelled'-but-not-yet-expired).
    # UNIQUE(username, plan_id) means re-subscribing to a plan you already
    # have (even one you'd cancelled) reactivates the same row rather than
    # creating a duplicate.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mail_subscriptions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL,
            plan_id      TEXT NOT NULL,              -- '5gb' | '25gb' | '50gb' | '100gb'
            price        REAL NOT NULL,
            status       TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'cancelled'
            card_id      INTEGER,                    -- HKS Bank cards.id used for billing
            next_billing TEXT,                        -- ISO date of next charge, or of grace-period end
            started_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username, plan_id)
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

    # mail_storage_used_bytes() and every folder listing filter/scan by
    # sender and by recipient on every request, so index both columns
    # rather than falling back to a full table scan of `emails` as mail
    # volume grows.
    cur.execute("CREATE INDEX IF NOT EXISTS idx_emails_sender ON emails(sender)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_emails_recipient ON emails(recipient)")

    # Ensure the HKMail administrator account exists. It's inserted first so
    # it is literally the first user of the HKMail service, and it is both
    # an admin and a verified/official account from the start.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (ADMIN_MAIL_USERNAME,))
    if not cur.fetchone():
        admin_password_hash = generate_password_hash(ADMIN_MAIL_DEFAULT_PASSWORD)
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified) VALUES (?, ?, ?, 1, 1)",
            (ADMIN_MAIL_USERNAME, admin_password_hash, "HKMail Administrator")
        )

    # Ensure the no-reply account exists. It sends HKMail's own automated
    # notices (welcome emails, Premium confirmations/renewals/cancellations)
    # that used to come from the admin account. It shares the admin account's
    # password so admins can log in as noreply@hkmail.cn to check its outbox.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (NOREPLY_MAIL_USERNAME,))
    if not cur.fetchone():
        noreply_password_hash = generate_password_hash(ADMIN_MAIL_DEFAULT_PASSWORD)
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified) VALUES (?, ?, ?, 0, 1)",
            (NOREPLY_MAIL_USERNAME, noreply_password_hash, "HKMail (No-Reply)")
        )

    # Ensure the HKS Bank system mailbox exists so it can send signup codes.
    # It uses the same fixed demo-credential pattern as admin/noreply so it
    # can genuinely be signed into if needed.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (SYSTEM_MAIL_SENDER,))
    if not cur.fetchone():
        system_password_hash = generate_password_hash(HKSBANK_MAIL_DEFAULT_PASSWORD)
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified) VALUES (?, ?, ?, 0, 1)",
            (SYSTEM_MAIL_SENDER, system_password_hash, "HKS Bank")
        )

    conn.commit()
    conn.close()


def mail_current_user():
    """Return the HKMail username from session, or None."""
    return session.get("mail_username")


# ── HKMail: storage & premium subscription helpers ─────────────────────────────

def mail_get_subscriptions(username):
    """All subscription rows for a mailbox: (id, plan_id, price, status, card_id, next_billing)."""
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, plan_id, price, status, card_id, next_billing
        FROM mail_subscriptions WHERE username=? ORDER BY price DESC
    """, (username,))
    rows = cur.fetchall()
    conn.close()
    return rows


def mail_storage_limit_mb(username):
    """Free 1GB plus every plan the mailbox currently holds — plans stack."""
    total = FREE_STORAGE_MB
    for _id, plan_id, _price, status, _card_id, _next in mail_get_subscriptions(username):
        if status in ("active", "cancelled"):
            plan = MAIL_PLANS.get(plan_id)
            if plan:
                total += plan["storage_mb"]
    return total


def mail_storage_used_bytes(username, cur=None):
    """Bytes of mail currently stored for this mailbox (sent copies plus
    received copies). Each email row is counted once even for self-sends,
    since it's a single stored row.

    Byte counting: uses SQL's LENGTH() cast to BLOB rather than plain
    LENGTH(subject)/LENGTH(body). SQLite's LENGTH() on a TEXT value returns
    the character count, not the byte count — for any non-ASCII text that
    silently undercounts and drifts from the byte-based check applied at
    send time (len(subject.encode("utf-8")) + len(body.encode("utf-8"))).
    Casting to BLOB first makes LENGTH() measure UTF-8 bytes, so this query
    matches the send-time check exactly.

    Trash counts toward quota: a soft-deleted email (deleted_by_sender=1 or
    deleted_by_recipient=1) still occupies a row in `emails` — the content
    isn't actually freed until it's permanently deleted (DELETE FROM emails,
    see /email/<id>/delete-permanent). So trashed mail is intentionally
    still counted here; only a permanent delete reduces used_bytes. Emptying
    Trash is therefore how a user actually frees up space, not just
    dragging mail there.
    """
    query = """
        SELECT COALESCE(SUM(LENGTH(CAST(subject AS BLOB)) + LENGTH(CAST(body AS BLOB))), 0)
        FROM emails
        WHERE sender=? OR recipient=?
    """
    if cur is not None:
        # Reuse the caller's cursor/connection so this read happens inside
        # whatever transaction the caller already holds (see hkmail_send,
        # where this must be read atomically with the INSERT that follows).
        cur.execute(query, (username, username))
        return cur.fetchone()[0] or 0

    conn = sqlite3.connect(MAIL_DATABASE)
    c = conn.cursor()
    c.execute(query, (username, username))
    total = c.fetchone()[0] or 0
    conn.close()
    return total


def mail_get_premium_summary(username):
    """(is_premium, badge_label) for wherever this mailbox appears as a sender.
    is_premium is True if any plan is still in effect (active, or cancelled
    but not yet past its grace-period end); badge_label names the largest
    such plan, since that's the one worth bragging about in the badge."""
    best_label = None
    best_price = -1
    for _id, plan_id, price, status, _card_id, _next in mail_get_subscriptions(username):
        if status in ("active", "cancelled") and price > best_price:
            plan = MAIL_PLANS.get(plan_id)
            if plan:
                best_price = price
                best_label = plan["label"]
    return (best_label is not None), best_label


def _activate_mail_premium(mail_username, plan_id, card_id):
    """Called right after a successful HKS Bank payment for an HKMail Premium
    plan. Creates (or reactivates, if this exact plan was previously
    cancelled and expired) a subscription row and schedules the first
    renewal one month out. Plans stack — this never touches the mailbox's
    other subscriptions."""
    plan = MAIL_PLANS.get(plan_id)
    if not plan or not mail_username:
        return False

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id FROM mail_users WHERE username=?", (mail_username,))
    if not cur.fetchone():
        conn.close()
        return False

    next_billing = add_one_month(date.today())
    cur.execute("""
        INSERT INTO mail_subscriptions (username, plan_id, price, status, card_id, next_billing)
        VALUES (?, ?, ?, 'active', ?, ?)
        ON CONFLICT(username, plan_id) DO UPDATE SET
            price=excluded.price, status='active', card_id=excluded.card_id,
            next_billing=excluded.next_billing
    """, (mail_username, plan_id, plan["price"], card_id, next_billing.isoformat()))

    total_mb = FREE_STORAGE_MB
    cur.execute("""
        SELECT plan_id FROM mail_subscriptions WHERE username=? AND status IN ('active','cancelled')
    """, (mail_username,))
    for (pid,) in cur.fetchall():
        p = MAIL_PLANS.get(pid)
        if p:
            total_mb += p["storage_mb"]

    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (
            NOREPLY_MAIL_USERNAME, mail_username, "Welcome to HKMail Premium!",
            f"Hi,\n\nYou're now subscribed to HKMail {plan['label']} — "
            f"{plan['storage_mb'] // 1024}GB of storage for ${plan['price']:.2f}/month.\n\n"
            f"Your total storage is now {total_mb // 1024}GB (Free plan plus every Premium tier you "
            "hold — plans stack instead of replacing each other).\n\n"
            "Your Premium badge will now appear next to your name whenever you send or "
            f"receive mail. Its next billing date is {next_billing.isoformat()}.\n\n"
            "You can cancel any plan anytime from the Storage page — you'll keep that plan's "
            "storage until the end of the period you've already paid for.\n\n"
            "— HKMail"
        )
    )

    conn.commit()
    conn.close()
    return True


def _mail_subscription_due(username, sub_id, plan_id, price, status, card_id, next_billing):
    """Handle one subscription row whose next_billing date has arrived."""
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    plan = MAIL_PLANS.get(plan_id, {})
    plan_label = plan.get("label", "HKMail Premium")

    if status == "cancelled":
        # Grace period the user already paid for has ended — this plan goes away.
        cur.execute("DELETE FROM mail_subscriptions WHERE id=?", (sub_id,))
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, f"Your HKMail {plan_label} plan has ended",
             f"Your {plan_label} subscription was cancelled and its final billing period has now "
             "ended. That plan's storage and badge have been removed — your remaining storage is "
             "the Free 1GB plus any other Premium plans you still hold.")
        )
        conn.commit()
        conn.close()
        return

    # status == 'active' and a renewal charge is due
    if not card_id:
        cur.execute("UPDATE mail_subscriptions SET status='cancelled' WHERE id=?", (sub_id,))
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, f"HKMail {plan_label} renewal needed",
             f"We couldn't automatically renew your {plan_label} subscription because no HKS Bank "
             "card is saved for it. Resubscribe from the Storage page before your current period "
             "ends, or it will be removed.")
        )
        conn.commit()
        conn.close()
        return

    bank_conn = sqlite3.connect(DATABASE)
    bank_cur  = bank_conn.cursor()
    bank_cur.execute("""
        SELECT id, username, account_id, account_label, card_number, cvv,
               expiry_month, expiry_year, cardholder_name, status, card_type
        FROM cards WHERE id=?
    """, (card_id,))
    card = bank_cur.fetchone()

    charge_ok = False
    if card and card[9] == "active" and not is_card_expired(card[6], card[7]):
        charge_ok, _msg = _debit_for_card_payment(
            bank_cur, card, price, f"HKMail {plan_label} (monthly renewal)"
        )
        if charge_ok:
            credit_hkmail_revenue(bank_cur, price, f"HKMail {plan_label} (monthly renewal)")

    if charge_ok:
        bank_conn.commit()
        new_next = add_one_month(next_billing)
        cur.execute("UPDATE mail_subscriptions SET next_billing=? WHERE id=?",
                    (new_next.isoformat(), sub_id))
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, f"HKMail {plan_label} renewed",
             f"Your {plan_label} subscription renewed for ${price:.2f}. "
             f"Next billing date: {new_next.isoformat()}.")
        )
    else:
        bank_conn.rollback()
        cur.execute("DELETE FROM mail_subscriptions WHERE id=?", (sub_id,))
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, f"HKMail {plan_label} renewal failed",
             f"We couldn't renew your {plan_label} subscription — the card on file was declined "
             "or is no longer available. That plan has been removed — your remaining storage is "
             "the Free 1GB plus any other Premium plans you still hold.")
        )
    bank_conn.close()
    conn.commit()
    conn.close()


def mail_run_billing_cycle(username):
    """Check every subscription this mailbox holds and, for any whose next
    billing date has arrived, either renew it (charging its saved HKS Bank
    card) or let a cancellation take effect. Safe to call on every page
    load — a no-op unless a charge or expiry is actually due."""
    for sub_id, plan_id, price, status, card_id, next_billing_str in mail_get_subscriptions(username):
        if not next_billing_str:
            continue
        try:
            next_billing = date.fromisoformat(next_billing_str)
        except (TypeError, ValueError):
            continue
        if date.today() < next_billing:
            continue
        _mail_subscription_due(username, sub_id, plan_id, price, status, card_id, next_billing)


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
        # Self-registered accounts are always plain, unverified users. The
        # only admin account is the dedicated one seeded at startup; official
        # accounts are created and verified explicitly by that admin.
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified) VALUES (?, ?, ?, 0, 0)",
            (username, password_hash, full_name)
        )

        # Drop a welcome email from the no-reply system account into the new
        # inbox so every user's very first message shows what an official
        # HKMail sender looks like (and explains the badges they'll see).
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (
                NOREPLY_MAIL_USERNAME,
                username,
                "Welcome to HKMail!",
                f"Hi {first_name or 'there'},\n\n"
                f"Welcome to HKMail — your new address is {username}.\n\n"
                "A couple of things worth knowing as you get started:\n\n"
                "  • This message comes from noreply@hkmail.cn — HKMail's automated system "
                "account. Don't reply to it; nobody reads that inbox.\n"
                "  • Messages from admin@hkmail.cn carry an \"Admin\" badge, so you can always "
                "tell when HKMail's administrators are contacting you.\n"
                "  • Some senders — like official service accounts and Premium subscribers — "
                "carry a \"Verified\" or \"Premium\" badge. If a message claims to be from an "
                "official service but has no badge, be cautious.\n\n"
                "That's it — enjoy your inbox!\n\n"
                "— HKMail"
            )
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

    # Auto-append @hkmail.cn if no domain given (e.g. "noreply" -> "noreply@hkmail.cn")
    if username and "@" not in username:
        username = username + "@hkmail.cn"

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT password_hash, full_name, is_admin, is_verified FROM mail_users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        session["mail_username"] = username
        session["mail_full_name"] = row[1]
        session["mail_is_admin"]  = bool(row[2])
        return jsonify({"success": True, "username": username, "fullName": row[1],
                         "isAdmin": bool(row[2]), "isVerified": bool(row[3])})
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
        mail_run_billing_cycle(u)
        conn = sqlite3.connect(MAIL_DATABASE)
        cur  = conn.cursor()
        cur.execute("""
            SELECT full_name, is_admin, is_verified
            FROM mail_users WHERE username=?
        """, (u,))
        row = cur.fetchone()
        conn.close()
        if row:
            is_premium, badge_label = mail_get_premium_summary(u)
            return jsonify({"loggedIn": True, "username": u, "fullName": row[0],
                            "isAdmin": bool(row[1]), "isVerified": bool(row[2]),
                            "isPremium": is_premium,
                            "premiumLabel": badge_label})
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

    # Renewals/downgrades may have just changed either mailbox's limit
    mail_run_billing_cycle(u)
    mail_run_billing_cycle(recipient)

    message_size = len(subject.encode("utf-8")) + len(body.encode("utf-8"))

    # The quota check-then-insert below has to be atomic: read used_bytes,
    # compare to the limit, then INSERT. Done as three separate statements
    # on separate connections, two concurrent sends near the limit could
    # both read a used_bytes that's still under quota, both pass the check,
    # and both insert — pushing the mailbox over quota.
    #
    # BEGIN IMMEDIATE grabs SQLite's write lock up front (rather than only
    # at the first write), so a second concurrent request blocks here until
    # the first one has committed or rolled back. By the time it re-reads
    # used_bytes, it sees the first send's row already counted, closing the
    # race. isolation_level=None puts the connection in autocommit mode so
    # "BEGIN IMMEDIATE" is issued exactly as written instead of sqlite3's
    # default implicit-transaction handling getting in the way.
    conn = sqlite3.connect(MAIL_DATABASE, isolation_level=None)
    cur  = conn.cursor()
    try:
        cur.execute("BEGIN IMMEDIATE")

        # Verify recipient exists
        cur.execute("SELECT id FROM mail_users WHERE username=?", (recipient,))
        if not cur.fetchone():
            conn.rollback()
            return jsonify({"success": False, "message": f"No HKMail account found for {recipient}."}), 404

        sender_limit_bytes = mail_storage_limit_mb(u) * 1024 * 1024
        if mail_storage_used_bytes(u, cur=cur) + message_size > sender_limit_bytes:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Your mailbox is full. Delete some mail or upgrade to Premium for more storage."
            }), 400

        if recipient != u:
            recipient_limit_bytes = mail_storage_limit_mb(recipient) * 1024 * 1024
            if mail_storage_used_bytes(recipient, cur=cur) + message_size > recipient_limit_bytes:
                conn.rollback()
                return jsonify({
                    "success": False,
                    "message": f"{recipient}'s mailbox is full and can't accept this message right now."
                }), 400

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
    finally:
        conn.close()

    return jsonify({"success": True, "message": f"Message sent to {recipient}."})


# ── HKMail: storage & premium subscription ─────────────────────────────────────

def _mail_plans_payload():
    return [
        {"id": p["id"], "label": p["label"], "storage_mb": p["storage_mb"],
         "storage_gb": p["storage_mb"] // 1024, "price": p["price"], "badge": p["badge"]}
        for p in MAIL_PLANS.values()
    ]


@app.route('/api/hkmail/premium/plans')
def hkmail_premium_plans():
    return jsonify({"success": True, "free_storage_mb": FREE_STORAGE_MB, "plans": _mail_plans_payload()})


@app.route('/api/hkmail/storage')
def hkmail_storage():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    mail_run_billing_cycle(u)

    # A mailbox can hold several plans at once (they stack), so report every
    # plan's individual status rather than assuming a single active plan.
    subs_by_plan = {plan_id: (status, price, card_id, next_billing)
                     for _id, plan_id, price, status, card_id, next_billing in mail_get_subscriptions(u)}

    is_premium, badge_label = mail_get_premium_summary(u)
    used_bytes = mail_storage_used_bytes(u)
    limit_mb   = mail_storage_limit_mb(u)

    plans_payload = []
    for p in MAIL_PLANS.values():
        sub = subs_by_plan.get(p["id"])
        if sub:
            status, price, card_id, next_billing = sub
            plans_payload.append({
                "id": p["id"], "label": p["label"], "storage_mb": p["storage_mb"],
                "storage_gb": p["storage_mb"] // 1024, "price": price,
                "status": status, "next_billing": next_billing,
                "auto_renews": bool(status == "active" and card_id),
            })
        else:
            plans_payload.append({
                "id": p["id"], "label": p["label"], "storage_mb": p["storage_mb"],
                "storage_gb": p["storage_mb"] // 1024, "price": p["price"],
                "status": None, "next_billing": None, "auto_renews": False,
            })

    return jsonify({
        "success": True,
        "used_bytes": used_bytes,
        "used_mb": round(used_bytes / (1024 * 1024), 3),
        "limit_mb": limit_mb,
        "is_premium": is_premium,
        "badge_label": badge_label,
        "plans": plans_payload,
        "free_storage_mb": FREE_STORAGE_MB,
    })


@app.route('/api/hkmail/premium/start', methods=['POST'])
def hkmail_premium_start():
    """Kick off a subscription purchase. Returns a URL to HKS Bank's checkout —
    the frontend redirects the browser there to complete payment."""
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data    = request.get_json() or {}
    plan_id = (data.get("plan", "") or "").strip().lower()
    plan    = MAIL_PLANS.get(plan_id)
    if not plan:
        return jsonify({"success": False, "message": "Unknown plan."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT status FROM mail_subscriptions WHERE username=? AND plan_id=?", (u, plan_id))
    row = cur.fetchone()
    conn.close()

    if row and row[0] == 'active':
        return jsonify({"success": False, "message": f"You're already subscribed to {plan['label']}."}), 400
    if row and row[0] == 'cancelled':
        return jsonify({
            "success": False,
            "canResume": True,
            "message": f"You already have {plan['label']} — it's cancelled but still active. "
                       "Turn recurring billing back on instead of paying again."
        }), 400

    from urllib.parse import quote
    desc      = f"HKMail {plan['label']} Subscription"
    meta      = f"hkmail_premium:{plan_id}"
    return_url = "/hkmail-inbox.html?upgraded=1"
    checkout_url = (
        f"/hks-bank-checkout.html?amount={plan['price']}"
        f"&desc={quote(desc)}&return_url={quote(return_url)}&meta={quote(meta)}"
    )
    return jsonify({"success": True, "checkout_url": checkout_url})


@app.route('/api/hkmail/premium/cancel', methods=['POST'])
def hkmail_premium_cancel():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data    = request.get_json() or {}
    plan_id = (data.get("plan", "") or "").strip().lower()
    plan    = MAIL_PLANS.get(plan_id)
    if not plan:
        return jsonify({"success": False, "message": "Unknown plan."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id, status, next_billing FROM mail_subscriptions WHERE username=? AND plan_id=?",
                (u, plan_id))
    row = cur.fetchone()
    if not row or row[1] != 'active':
        conn.close()
        return jsonify({"success": False, "message": f"You don't have an active {plan['label']} plan."}), 400

    sub_id, _status, next_billing = row
    cur.execute("UPDATE mail_subscriptions SET status='cancelled' WHERE id=?", (sub_id,))
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (NOREPLY_MAIL_USERNAME, u, f"Your HKMail {plan['label']} subscription was cancelled",
         f"Hi,\n\nYour {plan['label']} subscription has been cancelled and won't renew or be "
         f"charged again. You'll keep that plan's storage and Premium badge until {next_billing}, "
         "after which that plan's storage will be removed (any other Premium plans you hold are "
         "unaffected).\n\n"
         "Changed your mind? You can turn recurring billing back on for this exact plan any time "
         "before then from the Storage page, at no extra charge.\n\n"
         "— HKMail")
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Your {plan['label']} subscription has been cancelled. "
                    f"You'll keep that plan's storage and badge until {next_billing}, and won't be charged again."
    })


@app.route('/api/hkmail/premium/resume', methods=['POST'])
def hkmail_premium_resume():
    """Turn recurring billing back on for a plan that's cancelled but still
    within its paid-for grace period — no new payment, reuses the card that
    was on file when the plan was cancelled. Only affects that one plan;
    any other plans the mailbox holds are untouched."""
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data    = request.get_json() or {}
    plan_id = (data.get("plan", "") or "").strip().lower()
    plan    = MAIL_PLANS.get(plan_id)
    if not plan:
        return jsonify({"success": False, "message": "Unknown plan."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT id, status, card_id, next_billing FROM mail_subscriptions WHERE username=? AND plan_id=?",
                (u, plan_id))
    row = cur.fetchone()
    if not row or row[1] != 'cancelled':
        conn.close()
        return jsonify({"success": False, "message": f"You don't have a cancelled {plan['label']} plan to resume."}), 400

    sub_id, _status, card_id, next_billing = row
    cur.execute("UPDATE mail_subscriptions SET status='active' WHERE id=?", (sub_id,))
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (NOREPLY_MAIL_USERNAME, u, f"HKMail {plan['label']} billing resumed",
         f"Recurring billing for your {plan['label']} subscription is back on. "
         f"You won't be charged again until {next_billing}, and your storage and badge for this "
         "plan were never interrupted.")
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Recurring billing for {plan['label']} is back on. "
                    f"Next charge: {next_billing}." + ("" if card_id else
                    " Note: no card is on file for it, so add one before that date or it will lapse again.")
    })


# ── HKMail: account deletion ────────────────────────────────────────────────────

@app.route('/api/hkmail/account/delete', methods=['POST'])
def hkmail_delete_account():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if u in (ADMIN_MAIL_USERNAME, SYSTEM_MAIL_SENDER, NOREPLY_MAIL_USERNAME):
        return jsonify({"success": False, "message": "This account can't be deleted."}), 400

    data     = request.get_json() or {}
    password = (data.get("password", "") or "").strip()

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT password_hash FROM mail_users WHERE username=?", (u,))
    row = cur.fetchone()
    if not row or not check_password_hash(row[0], password):
        conn.close()
        return jsonify({"success": False, "message": "Incorrect password."}), 401

    # Cancelling immediately (rather than at period end) since the mailbox
    # and its billing record are about to be removed entirely.
    cur.execute("DELETE FROM mail_subscriptions WHERE username=?", (u,))
    cur.execute("DELETE FROM mail_users WHERE username=?", (u,))
    conn.commit()
    conn.close()

    session.pop("mail_username", None)
    session.pop("mail_full_name", None)
    session.pop("mail_is_admin", None)
    return jsonify({"success": True, "message": "Your HKMail account has been deleted."})


# ── HKMail: list folders ───────────────────────────────────────────────────────

@app.route('/api/hkmail/inbox')
def hkmail_inbox_api():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    mail_run_billing_cycle(u)
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT e.id, e.sender, e.subject, e.sent_at, e.read, mu.is_admin, mu.is_verified
        FROM emails e
        LEFT JOIN mail_users mu ON mu.username = e.sender
        WHERE e.recipient=? AND e.deleted_by_recipient=0
        ORDER BY e.sent_at DESC
    """, (u,))
    rows = cur.fetchall()
    conn.close()
    emails = []
    for r in rows:
        is_premium, badge_label = mail_get_premium_summary(r[1])
        emails.append({"id": r[0], "from": r[1], "subject": r[2], "date": r[3], "read": bool(r[4]),
                        "from_is_admin": bool(r[5]), "from_is_verified": bool(r[6]),
                        "from_is_premium": is_premium,
                        "from_premium_label": badge_label})
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
        SELECT e.id, e.sender, e.recipient, e.subject, e.sent_at,
               e.deleted_by_sender, e.deleted_by_recipient, mu.is_admin, mu.is_verified
        FROM emails e
        LEFT JOIN mail_users mu ON mu.username = e.sender
        WHERE (e.sender=? AND e.deleted_by_sender=1)
           OR (e.recipient=? AND e.deleted_by_recipient=1)
        ORDER BY e.sent_at DESC
    """, (u, u))
    rows = cur.fetchall()
    conn.close()
    emails = []
    for r in rows:
        is_premium, badge_label = mail_get_premium_summary(r[1])
        emails.append({
            "id": r[0], "from": r[1], "to": r[2],
            "subject": r[3], "date": r[4],
            "from_is_admin": bool(r[7]), "from_is_verified": bool(r[8]),
            "from_is_premium": is_premium,
            "from_premium_label": badge_label
        })
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
        SELECT e.id, e.sender, e.recipient, e.subject, e.body, e.sent_at, e.read,
               mu.is_admin, mu.is_verified
        FROM emails e
        LEFT JOIN mail_users mu ON mu.username = e.sender
        WHERE e.id=?
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
    is_premium, badge_label = mail_get_premium_summary(row[1])
    return jsonify({
        "success": True,
        "email": {
            "id": row[0], "from": row[1], "to": row[2],
            "subject": row[3], "body": row[4], "date": row[5], "read": True,
            "from_is_admin": bool(row[7]), "from_is_verified": bool(row[8]),
            "from_is_premium": is_premium,
            "from_premium_label": badge_label
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
    cur.execute("SELECT id, username, full_name, is_admin, is_verified, created_at FROM mail_users ORDER BY created_at")
    users = [{"id": r[0], "username": r[1], "full_name": r[2],
              "is_admin": bool(r[3]), "is_verified": bool(r[4]), "created_at": r[5]}
             for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "users": users})


# ── HKMail: admin — promote / demote admin role ───────────────────────────────

@app.route('/api/hkmail/admin/promote', methods=['POST'])
def hkmail_admin_promote():
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403
    data     = request.get_json()
    username = (data.get("username", "") or "").strip().lower()

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400
    if username == mail_current_user():
        return jsonify({"success": False, "message": "You cannot change your own role."}), 400
    if username == SYSTEM_MAIL_SENDER:
        return jsonify({"success": False, "message": "The bank system mailbox's role can't be changed."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT is_admin FROM mail_users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404

    new_role = 0 if row[0] else 1
    cur.execute("UPDATE mail_users SET is_admin=? WHERE username=?", (new_role, username))
    conn.commit()
    conn.close()

    action = "promoted to Admin" if new_role else "demoted to User"
    return jsonify({"success": True, "message": f"{username} has been {action}.", "isAdmin": bool(new_role)})


# ── HKMail: admin — verify / unverify an account ──────────────────────────────

@app.route('/api/hkmail/admin/verify', methods=['POST'])
def hkmail_admin_verify():
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403
    data     = request.get_json()
    username = (data.get("username", "") or "").strip().lower()

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT is_verified FROM mail_users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404

    new_val = 0 if row[0] else 1
    cur.execute("UPDATE mail_users SET is_verified=? WHERE username=?", (new_val, username))
    conn.commit()
    conn.close()

    action = "marked as a verified official account" if new_val else "unmarked as verified"
    return jsonify({"success": True, "message": f"{username} has been {action}.", "isVerified": bool(new_val)})


# ── HKMail: admin — create an official account ────────────────────────────────

@app.route('/api/hkmail/admin/create-account', methods=['POST'])
def hkmail_admin_create_account():
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403
    data       = request.get_json()
    username   = (data.get("username", "") or "").strip().lower()
    password   = (data.get("password", "") or "").strip()
    full_name  = (data.get("full_name", "") or "").strip()
    is_verified = 1 if data.get("is_verified", True) else 0

    if "@" not in username and username:
        username = username + "@hkmail.cn"

    if not username or not password:
        return jsonify({"success": False, "message": "Address and password are required."}), 400
    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters."}), 400
    if not full_name:
        full_name = username.split("@")[0].replace(".", " ").title()

    password_hash = generate_password_hash(password)
    try:
        conn = sqlite3.connect(MAIL_DATABASE)
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified) VALUES (?, ?, ?, 0, ?)",
            (username, password_hash, full_name, is_verified)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"Official account {username} created.", "username": username})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "That email address is already taken."}), 400

def check_hkmail_card_on_startup():
    """Warn on the console if there's no usable HKMail merchant card — until
    one exists, HKMail Premium subscription revenue has nowhere to land."""
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    card = get_hkmail_card(cur)
    conn.close()
    if not card:
        print("=" * 78)
        print("    WARNING: No active HKMail merchant card exists.")
        print("    HKMail Premium subscription payments will be charged to the customer")
        print("    but the revenue will NOT be deposited anywhere until an admin opens")
        print("    an HKMail-type card for some account (HKS Bank dashboard → edit user →")
        print("    Issue New Card → Card Type: HKMail).")
        print("=" * 78)


if __name__ == '__main__':
    init_db()
    init_mail_db()
    check_hkmail_card_on_startup()
    app.run(host='0.0.0.0', port=5001, debug=True)