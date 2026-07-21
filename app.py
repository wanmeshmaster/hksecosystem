from flask import Flask, render_template, request, jsonify, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import random
import string
import base64
from datetime import datetime, date, timedelta

app = Flask(__name__, static_folder='source', static_url_path='/source')
app.secret_key = os.urandom(32)
DATABASE = "users.db"

# Safety net around HKMail's per-attachment 15MB limit: up to 15 attachments
# per email, base64-encoded (~33% larger than raw), plus headroom for the
# rest of the JSON payload.
app.config['MAX_CONTENT_LENGTH'] = 320 * 1024 * 1024


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
            full_name TEXT NOT NULL DEFAULT '',
            customer_type TEXT NOT NULL DEFAULT 'personal',   -- personal | business
            company_name TEXT NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

    # HKS Bank support tickets. Deliberately its OWN table, separate from
    # HKMail's `emails` table (which lives in a different database file
    # entirely) — the case number here is a random 12-character code, not
    # derived from any email row id, per spec.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bank_support_cases (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number  TEXT UNIQUE NOT NULL,
            username     TEXT NOT NULL,
            message      TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'open',   -- open | in_progress | resolved | closed
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Audit trail for HKS Bank support case management — every status change
    # (and, in future, assignment/note/etc. actions) made by an Administrator
    # or Employee is recorded here so the lifecycle of a case is fully
    # traceable. Kept as its own table (rather than emails, like HKMail's
    # admin audit trail) since this is bank-side staff activity, not mail.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bank_support_case_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         INTEGER NOT NULL,
            action          TEXT NOT NULL,               -- e.g. status_change
            old_status      TEXT,
            new_status      TEXT,
            note            TEXT NOT NULL DEFAULT '',
            actor_username  TEXT NOT NULL,
            actor_role      TEXT NOT NULL,                -- admin | employee
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES bank_support_cases(id)
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
        "ALTER TABLE users ADD COLUMN customer_type TEXT NOT NULL DEFAULT 'personal'",
        "ALTER TABLE users ADD COLUMN company_name TEXT NOT NULL DEFAULT ''",
        # SQLite's ALTER TABLE won't accept CURRENT_TIMESTAMP as a column
        # default (only constant defaults are allowed there), so the column
        # is added nullable and backfilled just below.
        "ALTER TABLE users ADD COLUMN created_at DATETIME",
    ]:
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # Backfill: any account created before this column existed has no real
    # creation timestamp on record, so it's stamped with "now" the first time
    # this migration runs — the best available approximation, not the true
    # original signup time.
    cur.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

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

# Address used as the "From" on automatic non-delivery (bounce) notices.
# Deliberately not a real, loggable-into HKMail mailbox — just a from-address
# string stored on the email row, the same way a real mail server's
# mailer-daemon isn't an account anyone signs into.
MAILER_DAEMON_SENDER = "mailer-daemon@hkmail.cn"

# Local-parts that mark a mailbox as automated/no-reply. Users can't send
# mail to any address matching one of these, since a real mail provider
# wouldn't be able to connect to an address that never accepts incoming mail.
NOREPLY_LOCAL_PARTS = {"noreply", "no-reply"}

# Fixed demo credential for the HKS Bank system mailbox (SYSTEM_MAIL_SENDER),
# same pattern as ADMIN_MAIL_DEFAULT_PASSWORD — change in a real deployment.
HKSBANK_MAIL_DEFAULT_PASSWORD = "HksBankSys456!"

# Mailbox that receives support requests submitted from the "Support" button
# in the HKMail sidebar. A real account (rather than a plain constant string)
# so support staff can actually log in and read the queue like any other
# HKMail inbox. Fixed demo credential, same pattern as the accounts above.
SUPPORT_MAIL_USERNAME = "support@hkmail.cn"
SUPPORT_MAIL_DEFAULT_PASSWORD = "SupportQueue321!"

# Mailbox that receives support requests from the "Support" button on the
# HKS Bank dashboard. Separate from HKMail's own support@hkmail.cn — this one
# is specifically for banking issues. A real HKMail account, same pattern as
# the accounts above, with its own fixed demo credential.
BANK_SUPPORT_MAIL_USERNAME = "hksbank.support@hkmail.cn"
BANK_SUPPORT_MAIL_DEFAULT_PASSWORD = "HksBankSupport852!"

# General-inquiries mailbox, listed publicly as HKMail's contact address.
# Carries the same Support-staff tier as support@hkmail.cn (is_employee=1)
# so whoever mans it can be recognised as staff, and is seeded as an
# official/verified account like the other service mailboxes.
CONTACT_MAIL_USERNAME = "contact@hkmail.cn"
CONTACT_MAIL_DEFAULT_PASSWORD = "ContactDesk742!"

# Legal/compliance mailbox (takedown notices, terms questions, regulatory
# correspondence). Seeded as a verified/official account like the other
# service mailboxes, but not Support-staff — it doesn't work the support
# request queue.
LEGAL_MAIL_USERNAME = "legal@hkmail.cn"
LEGAL_MAIL_DEFAULT_PASSWORD = "LegalDept963!"


# ── HKMail: account-service support requests (password reset / deletion) ──────

# How long a disabled (pending-deletion) account can be reinstated before it's
# eligible for permanent deletion.
ACCOUNT_DELETION_GRACE_DAYS = 30

MAIL_SUPPORT_REQUEST_TYPES = ("password_reset", "account_deletion", "business_account")
MAIL_SUPPORT_REQUEST_STATUSES = ("pending", "approved", "rejected", "completed", "cancelled")
MAIL_SUPPORT_REQUEST_STATUS_LABELS = {
    "pending": "Pending Review",
    "approved": "Approved",
    "rejected": "Rejected",
    "completed": "Completed",
    "cancelled": "Cancelled",
}
MAIL_SUPPORT_REQUEST_TYPE_LABELS = {
    "password_reset": "Password Reset",
    "account_deletion": "Account Deletion",
    "business_account": "Business Account Verification",
}


def generate_signup_code(length=8):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(random.choices(alphabet, k=length))


def generate_case_number(length=12):
    """Random alphanumeric case number for bank support tickets — 12
    characters, uppercase letters and digits. Deliberately unrelated to any
    other row id in the system (unlike HKMail's own support case numbers,
    which are derived from the email row)."""
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


def hkmail_account_details(email):
    """Return {"exists", "account_type", "company_name", "is_verified_business"}
    for the given HKMail address, or None if no such account exists. Used by
    HKS Bank to decide whether a signup email qualifies for a business
    account (must be a business-type HKMail address) and, if so, to pull the
    company name across rather than asking for it twice."""
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute(
        "SELECT account_type, company_name, is_verified_business FROM mail_users WHERE username=?",
        (email,)
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "account_type": row[0] or "personal",
        "company_name": row[1] or "",
        "is_verified_business": bool(row[2]),
    }


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
# 6-digit issuer prefix (IIN) for HKS Bank cards. It's fine for this
# to be public/hardcoded so the checkout
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


def bank_account_snapshot_text(cur, username):
    """Plain-text snapshot of a customer's HKS Bank account for support
    tickets: profile info, every account, every card (masked). Deliberately
    excludes transaction history — that needs a separate HKMail attachment/
    embed update to include safely, which hasn't been built yet."""
    cur.execute(
        "SELECT full_name, email, balance, is_admin, is_employee FROM users WHERE username = ?",
        (username,)
    )
    row = cur.fetchone()
    if not row:
        return "Account record not found."
    full_name, email, balance, is_admin, is_employee = row
    role = "Admin" if is_admin else ("Employee" if is_employee else "Customer")

    lines = [
        f"Username: {username}",
        f"Full name: {full_name or '(none)'}",
        f"Linked HKMail address: {email or '(none)'}",
        f"Role: {role}",
        f"Current Account balance: ${balance:.2f}",
        "",
    ]

    cur.execute(
        "SELECT account_type, balance, created_at FROM accounts WHERE username = ? ORDER BY created_at",
        (username,)
    )
    accounts = cur.fetchall()
    lines.append("Additional accounts:" if accounts else "Additional accounts: none")
    for acc_type, acc_balance, created_at in accounts:
        lines.append(f"  - {acc_type}: ${acc_balance:.2f} (opened {created_at})")
    lines.append("")

    cur.execute("""
        SELECT card_number, card_type, status, expiry_month, expiry_year, account_label
        FROM cards WHERE username = ? ORDER BY created_at
    """, (username,))
    cards = cur.fetchall()
    lines.append("Cards:" if cards else "Cards: none")
    for card_number, card_type, status, exp_m, exp_y, acct_label in cards:
        disp_status = 'expired' if (status != 'cancelled' and is_card_expired(exp_m, exp_y)) else status
        type_note = " [HKMail merchant card]" if card_type == 'hkmail' else ""
        lines.append(
            f"  - {mask_card_number(card_number)} ({acct_label}) — {disp_status}{type_note}, "
            f"exp {exp_m:02d}/{str(exp_y)[-2:]}"
        )
    lines.append("")

    lines.append(
        "Note: transaction history is not included in support tickets yet."
    )
    return "\n".join(lines)


# ── Page routes ────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    apps = [
        {'id': 'hks-bank',    'title': '',       'url': '/hks-bank.html'},
        {'id': 'hkmail',      'title': '',          'url': '/hkmail.html'},
        {'id': 'coming-soon', 'title': '', 'url': '/coming-soon.html'},
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

@app.route('/hks-bank-support.html')
def bank_support_page():
    return render_template('hks-bank-support.html')

@app.route('/about-us.html')
def about_us():
    return render_template('about-us.html')

@app.route('/terms.html')
def os_terms():
    return render_template('terms.html')


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

    customer_type = (data.get("customer_type", "personal") or "personal").strip().lower()
    if customer_type not in ("personal", "business"):
        customer_type = "personal"

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required."}), 400
    if not first_name or not last_name:
        return jsonify({"success": False, "message": "First and last name required."}), 400
    if not email:
        return jsonify({"success": False, "message": "An HKMail email address is required to sign up."}), 400

    # HKS Bank accounts must be tied to an existing HKMail address.
    hkmail_details = hkmail_account_details(email)
    if not hkmail_details:
        return jsonify({
            "success": False,
            "message": f"We couldn't find an HKMail account for {email}. Please create one first.",
            "needsHkmail": True,
            "email": email
        }), 400

    # Business HKS Bank accounts must be backed by a business-type HKMail
    # address — a personal @hkmail.cn mailbox doesn't qualify.
    company_name = ""
    if customer_type == "business":
        if hkmail_details["account_type"] != "business":
            return jsonify({
                "success": False,
                "message": f"{email} is a personal HKMail account. Business customers need a business HKMail address.",
                "needsBusinessHkmail": True,
                "email": email
            }), 400
        company_name = hkmail_details["company_name"]

    # Check both username and email
    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    
    # 1. Check if username exists
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    username_taken = cur.fetchone() is not None
    
    # 2. Check if email exists
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    email_taken = cur.fetchone() is not None
    
    conn.close()
    
    # 3. Return respective errors to the frontend
    if username_taken:
        return jsonify({"success": False, "message": "Username already exists."}), 400
        
    if email_taken:
        return jsonify({
            "success": False, 
            "message": "An HKS Bank account is already registered with this email address."
        }), 400
    # =====================================================================

    # Registration isn't finalized yet - stash the pending details in the
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
        "customer_type": customer_type,
        "company_name": company_name,
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
            "INSERT INTO users (username, password_hash, is_admin, balance, full_name, email, "
            "customer_type, company_name, created_at) "
            "VALUES (?, ?, ?, 0.0, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (pending["username"], pending["password_hash"], is_admin, pending["full_name"], pending["email"],
             pending.get("customer_type", "personal"), pending.get("company_name", ""))
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
    # The bank and HKMail share one session cookie. session.clear() would
    # wipe HKMail's mail_username/mail_full_name/mail_is_admin too, logging
    # the user out of mail whenever they log out of the bank (bug). Pop only
    # the bank-owned keys so an HKMail session, if any, is left untouched —
    # matching how /api/hkmail/logout already scopes itself to mail-only keys.
    session.pop("username", None)
    session.pop("is_admin", None)
    session.pop("is_employee", None)
    session.pop("pending_bank_signup", None)
    return jsonify({"success": True})


@app.route('/api/current-user')
def current_user():
    if "username" in session:
        conn = sqlite3.connect(DATABASE)
        cur  = conn.cursor()
        cur.execute(
            "SELECT is_admin, balance, full_name, is_employee, customer_type, company_name "
            "FROM users WHERE username=?", (session["username"],)
        )
        row = cur.fetchone()
        conn.close()
        if row:
            customer_type = row[4] or "personal"
            return jsonify({
                "loggedIn":  True,
                "username":  session["username"],
                "isAdmin":   bool(row[0]),
                "balance":   row[1],
                "fullName":  row[2] if row[2] else session["username"],
                "isEmployee": bool(row[3]),
                "customerType": customer_type,
                "isBusiness": customer_type == "business",
                "companyName": row[5] or "",
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
    cur.execute(
        "SELECT id, username, full_name, balance, is_admin, is_employee, created_at, "
        "customer_type, company_name FROM users"
    )
    users = [
        {"id": r[0], "username": r[1], "full_name": r[2], "balance": r[3], "is_admin": bool(r[4]),
         "is_employee": bool(r[5]), "created_at": r[6],
         "customer_type": r[7] or "personal", "is_business": (r[7] or "personal") == "business",
         "company_name": r[8] or ""}
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


# ── HKS Bank: support requests ───────────────────────────────────────────────

@app.route('/api/bank/support', methods=['POST'])
def bank_support():
    """File a support request from the "Support" button on the HKS Bank
    dashboard.

    Unlike HKMail's own support system (whose case numbers are derived from
    the email row id), this case number is a random 12-character code kept
    in its own `bank_support_cases` table in the bank's database — entirely
    independent of the `emails` table, which lives in a different database
    file. The ticket itself is still delivered as a normal HKMail message to
    hksbank.support@hkmail.cn, and a confirmation with the case number is
    sent to whatever HKMail address is linked to the customer's bank account.
    """
    if "username" not in session:
        return jsonify({"success": False, "message": "You must be logged in to contact support."}), 401

    data    = request.get_json() or {}
    message = (data.get("message", "") or "").strip()
    if not message:
        return jsonify({"success": False, "message": "Please describe your issue before sending."}), 400

    username = session["username"]

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT email FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Account not found."}), 404
    email = row[0]

    account_snapshot = bank_account_snapshot_text(cur, username)

    case_number = generate_case_number()
    cur.execute("SELECT 1 FROM bank_support_cases WHERE case_number = ?", (case_number,))
    while cur.fetchone():
        case_number = generate_case_number()
        cur.execute("SELECT 1 FROM bank_support_cases WHERE case_number = ?", (case_number,))

    cur.execute(
        "INSERT INTO bank_support_cases (case_number, username, message, status) VALUES (?, ?, ?, 'open')",
        (case_number, username, message)
    )
    conn.commit()
    conn.close()

    # File the ticket with HKS Bank support, then confirm to the customer.
    # Both are ordinary HKMail messages — only the case number itself is
    # tracked outside the emails table.
    mail_conn = sqlite3.connect(MAIL_DATABASE)
    mail_cur  = mail_conn.cursor()

    ticket_sender = email if email else SYSTEM_MAIL_SENDER
    mail_cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (
            ticket_sender, BANK_SUPPORT_MAIL_USERNAME,
            f"[{case_number}] Support request from {username}",
            f"{account_snapshot}\n\n――――――――――――――――――\nCustomer's message:\n{message}"
        )
    )

    confirmed = False
    if email:
        mail_cur.execute("SELECT id FROM mail_users WHERE username = ?", (email,))
        if mail_cur.fetchone():
            mail_cur.execute(
                "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
                (
                    SYSTEM_MAIL_SENDER, email,
                    f"We've received your support request ({case_number})",
                    "Thanks for reaching out to HKS Bank Support.\n\n"
                    f"Your case number is {case_number}. Please reference it in any "
                    "follow-up correspondence about this issue.\n\n"
                    "Our support team will get back to you as soon as possible.\n\n"
                    "— HKS Bank Support\n\n"
                    "――――――――――――――――――\n"
                    "Your original message:\n" + message
                )
            )
            confirmed = True

    mail_conn.commit()
    mail_conn.close()

    if confirmed:
        return jsonify({
            "success": True,
            "message": "Your support request has been sent. Check your HKMail inbox for a confirmation with your case number."
        })
    return jsonify({
        "success": True,
        "message": "Your support request has been filed, but we couldn't email a confirmation since no HKMail address is on file."
    })


# ── HKS Bank: support case management (Administrators & Employees) ─────────────
# Dedicated interface for authorised staff to review, triage, and resolve the
# support requests customers file via /api/bank/support. Deliberately kept
# separate from the customer-facing submission route above: staff work off
# case id (internal, sequential) while customers only ever see/reference the
# opaque case_number.

BANK_SUPPORT_STATUSES = ("open", "in_progress", "resolved", "closed")
BANK_SUPPORT_STATUS_LABELS = {
    "open": "Open",
    "in_progress": "In Progress",
    "resolved": "Resolved",
    "closed": "Closed",
}


def bank_support_case_to_dict(row, full_name=None):
    (case_id, case_number, username, message, status, created_at) = row
    return {
        "id": case_id,
        "case_number": case_number,
        "username": username,
        "full_name": full_name or username,
        "message": message,
        "status": status,
        "status_label": BANK_SUPPORT_STATUS_LABELS.get(status, status),
        "created_at": created_at,
    }


@app.route('/api/bank/admin/support-cases', methods=['GET'])
def bank_admin_list_support_cases():
    """List every support request for the staff management interface.
    Administrators and Employees only — standard users have no route to
    other customers' support requests."""
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    status_filter = (request.args.get("status", "") or "").strip().lower()

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    if status_filter and status_filter in BANK_SUPPORT_STATUSES:
        cur.execute("""
            SELECT c.id, c.case_number, c.username, c.message, c.status, c.created_at
            FROM bank_support_cases c
            WHERE c.status = ?
            ORDER BY c.created_at DESC
        """, (status_filter,))
    else:
        cur.execute("""
            SELECT c.id, c.case_number, c.username, c.message, c.status, c.created_at
            FROM bank_support_cases c
            ORDER BY c.created_at DESC
        """)
    rows = cur.fetchall()

    # Attach requester full names in one extra pass (small dataset; keeps the
    # main query simple and avoids assumptions about NULL full_name values).
    full_names = {}
    if rows:
        cur.execute("SELECT username, full_name FROM users")
        full_names = {u: (fn if fn else u) for u, fn in cur.fetchall()}
    conn.close()

    cases = [bank_support_case_to_dict(r, full_names.get(r[2])) for r in rows]
    return jsonify({"success": True, "cases": cases})


@app.route('/api/bank/admin/support-cases/<int:case_id>', methods=['GET'])
def bank_admin_get_support_case(case_id):
    """Full detail for one case, including its audit trail — the basis for a
    future response-history / internal-notes view."""
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, case_number, username, message, status, created_at
        FROM bank_support_cases WHERE id = ?
    """, (case_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Support case not found."}), 404

    cur.execute("SELECT full_name FROM users WHERE username = ?", (row[2],))
    fn_row = cur.fetchone()
    full_name = (fn_row[0] if fn_row and fn_row[0] else row[2])

    cur.execute("""
        SELECT action, old_status, new_status, note, actor_username, actor_role, created_at
        FROM bank_support_case_events
        WHERE case_id = ?
        ORDER BY created_at ASC, id ASC
    """, (case_id,))
    events = [
        {
            "action": r[0], "old_status": r[1], "new_status": r[2], "note": r[3],
            "actor_username": r[4], "actor_role": r[5], "created_at": r[6],
        }
        for r in cur.fetchall()
    ]
    conn.close()

    case = bank_support_case_to_dict(row, full_name)
    case["events"] = events
    return jsonify({"success": True, "case": case})


@app.route('/api/bank/admin/support-cases/<int:case_id>/status', methods=['POST'])
def bank_admin_update_support_case_status(case_id):
    """Update a support case's status (Open / In Progress / Resolved /
    Closed). Every change — old status, new status, optional note, and which
    staff member made it — is written to bank_support_case_events for the
    audit log."""
    if not is_employee_or_admin():
        return jsonify({"success": False, "message": "Administrator access required."}), 403

    data       = request.get_json() or {}
    new_status = (data.get("status", "") or "").strip().lower()
    note       = (data.get("note", "") or "").strip()

    if new_status not in BANK_SUPPORT_STATUSES:
        return jsonify({
            "success": False,
            "message": f"Invalid status. Must be one of: {', '.join(BANK_SUPPORT_STATUS_LABELS.values())}."
        }), 400

    conn = sqlite3.connect(DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT status FROM bank_support_cases WHERE id = ?", (case_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Support case not found."}), 404

    old_status = row[0]
    actor_username = session["username"]
    actor_role = "admin" if is_admin() else "employee"

    if old_status == new_status:
        conn.close()
        return jsonify({
            "success": True,
            "message": f"Case is already {BANK_SUPPORT_STATUS_LABELS[new_status]}.",
            "status": new_status,
            "status_label": BANK_SUPPORT_STATUS_LABELS[new_status],
        })

    cur.execute("UPDATE bank_support_cases SET status = ? WHERE id = ?", (new_status, case_id))
    cur.execute("""
        INSERT INTO bank_support_case_events
            (case_id, action, old_status, new_status, note, actor_username, actor_role)
        VALUES (?, 'status_change', ?, ?, ?, ?, ?)
    """, (case_id, old_status, new_status, note, actor_username, actor_role))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Case status updated to {BANK_SUPPORT_STATUS_LABELS[new_status]}.",
        "status": new_status,
        "status_label": BANK_SUPPORT_STATUS_LABELS[new_status],
    })


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
    # Same shared-cookie hazard as /api/logout: clear only the bank-owned
    # session keys so an HKMail login in the same browser session survives.
    session.pop("username", None)
    session.pop("is_admin", None)
    session.pop("is_employee", None)
    session.pop("pending_bank_signup", None)
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

    if meta.startswith("hkmail_premium:"):
        _activate_mail_premium(session.get("mail_username"), meta.split(":", 1)[1], card[0])

    # Same shared-cookie hazard as /api/logout: clear only the bank-owned
    # session keys so an HKMail login in the same browser session survives.
    session.pop("username", None)
    session.pop("is_admin", None)
    session.pop("is_employee", None)
    session.pop("pending_bank_signup", None)
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
    "5gb":   {"id": "5gb",   "label": "Premium 5GB",   "storage_mb": 5   * 1024, "price": 1.99,  "badge": True, "tier": "silver",  "tier_label": "Silver"},
    "25gb":  {"id": "25gb",  "label": "Premium 25GB",  "storage_mb": 25  * 1024, "price": 4.99,  "badge": True, "tier": "gold",    "tier_label": "Gold"},
    "50gb":  {"id": "50gb",  "label": "Premium 50GB",  "storage_mb": 50  * 1024, "price": 9.99,  "badge": True, "tier": "emerald", "tier_label": "Emerald"},
    "100gb": {"id": "100gb", "label": "Premium 100GB", "storage_mb": 100 * 1024, "price": 19.99, "badge": True, "tier": "diamond", "tier_label": "Diamond"},
}

# ── HKMail attachments ──────────────────────────────────────────────────────────
# Per-file cap, enforced both when decoding the upload and again defensively at
# the DB layer. Attachment bytes count toward the sender's AND recipient's
# storage quota, same as the subject/body bytes already did.
MAX_ATTACHMENT_SIZE_MB    = 15
MAX_ATTACHMENT_SIZE_BYTES = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024

# Sanity cap on how many files one email can carry — not a spec requirement,
# just guards against someone scripting a single request with thousands of
# tiny attachments.
MAX_ATTACHMENTS_PER_EMAIL = 15


def format_bytes(n):
    """Human-readable size, e.g. 15728640 -> '15.0 MB'."""
    n = float(n)
    if n < 1024:
        return f"{int(n)} bytes"
    n /= 1024
    if n < 1024:
        return f"{n:.1f} KB"
    n /= 1024
    if n < 1024:
        return f"{n:.1f} MB"
    n /= 1024
    return f"{n:.1f} GB"


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

    # Safe migrations for existing databases
    for stmt in [
        "ALTER TABLE mail_users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0",
        # Support-staff tier, distinct from full Admins — mirrors HKS Bank's
        # is_employee/is_admin split. Support personnel can review/process
        # support requests but can't manage roles, verified status, etc.
        "ALTER TABLE mail_users ADD COLUMN is_employee INTEGER NOT NULL DEFAULT 0",
        # Account-deletion disablement state. A disabled account is not
        # deleted yet — it's in the 30-day recovery window that starts once
        # an account-deletion support request is approved. `disabled_at` is
        # when that window started; `scheduled_deletion_at` is the date the
        # account becomes eligible for permanent deletion.
        "ALTER TABLE mail_users ADD COLUMN is_disabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE mail_users ADD COLUMN disabled_at DATETIME",
        "ALTER TABLE mail_users ADD COLUMN scheduled_deletion_at DATETIME",
        # Business accounts: a distinct registration path (separate window on
        # the register screen) for companies. account_type separates these
        # from ordinary personal mailboxes; business_status tracks the
        # underlying business_account support-case lifecycle
        # (''|pending|approved|rejected) independently of is_verified_business
        # so a previously-approved business can be re-reviewed without losing
        # its badge mid-review. is_verified_business drives the "Verified
        # Business" badge shown on the account and on its outgoing mail —
        # deliberately separate from is_verified (HKMail's "official account"
        # badge for HKMail/HKS Bank's own service mailboxes) since the two
        # mean different things and are granted through different flows.
        "ALTER TABLE mail_users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'personal'",
        "ALTER TABLE mail_users ADD COLUMN business_status TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mail_users ADD COLUMN is_verified_business INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE mail_users ADD COLUMN company_name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mail_users ADD COLUMN company_address TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mail_users ADD COLUMN company_phone TEXT NOT NULL DEFAULT ''",
        # Custom email domain a business account registered with (e.g.
        # "acme.com"), so their address is jane@acme.com instead of
        # jane@hkmail.cn. Blank for personal accounts and for businesses
        # that chose to stay on @hkmail.cn. Domain ownership isn't verified
        # yet (HKMail isn't live), so any domain is accepted for now.
        "ALTER TABLE mail_users ADD COLUMN custom_domain TEXT NOT NULL DEFAULT ''",
    ]:
        try:
            cur.execute(stmt)
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

    # File attachments. One row per file, linked to the email it was sent
    # with. `data` holds the raw file bytes (BLOB) — stored inline rather than
    # on disk so a permanent-delete of the email cleanly frees the space, and
    # so mail_storage_used_bytes() can account for it with a plain SQL SUM
    # alongside the subject/body bytes it already counts.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS email_attachments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id    INTEGER NOT NULL,
            filename    TEXT NOT NULL,
            mime_type   TEXT NOT NULL DEFAULT 'application/octet-stream',
            size_bytes  INTEGER NOT NULL,
            data        BLOB NOT NULL,
            FOREIGN KEY (email_id) REFERENCES emails(id)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attachments_email ON email_attachments(email_id)")

    # Account-service support requests: password resets and account-deletion
    # requests filed through HKMail Support, reviewed and processed by
    # authorised support staff (Employees/Admins). Deliberately its own
    # table (rather than free-text emails to support@hkmail.cn, like the
    # general "Contact Support" button) since these two request types carry
    # their own state machine, verification step, and audit trail.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mail_support_requests (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            request_number      TEXT UNIQUE NOT NULL,
            username            TEXT NOT NULL,
            request_type        TEXT NOT NULL,               -- password_reset | account_deletion
            status              TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected | completed | cancelled
            message             TEXT NOT NULL DEFAULT '',
            -- Password-reset identity verification (a one-time code emailed
            -- to the requester's own inbox; staff can't approve a reset
            -- until the requester has proven they still control the inbox).
            verification_code   TEXT,
            verified            INTEGER NOT NULL DEFAULT 0,
            verified_at         DATETIME,
            -- Handled-by / decision bookkeeping, duplicated from the events
            -- table onto the row itself purely for fast list/filter queries.
            decided_by          TEXT,
            decided_at          DATETIME,
            -- Set when the account owner clicks "Request reinstatement" on the
            -- recovery banner; cleared from the badge count once support opens
            -- the request detail (reinstatement_seen_at).
            reinstatement_requested_at DATETIME,
            reinstatement_seen_at    DATETIME,
            created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_support_requests_username ON mail_support_requests(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_support_requests_status ON mail_support_requests(status)")

    for stmt in [
        "ALTER TABLE mail_support_requests ADD COLUMN reinstatement_requested_at DATETIME",
        "ALTER TABLE mail_support_requests ADD COLUMN reinstatement_seen_at DATETIME",
        # Company details captured at business registration, carried onto
        # the request row so support staff can review them without a second
        # lookup. Blank for password_reset/account_deletion requests.
        "ALTER TABLE mail_support_requests ADD COLUMN company_name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mail_support_requests ADD COLUMN company_address TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mail_support_requests ADD COLUMN company_phone TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mail_support_requests ADD COLUMN custom_domain TEXT NOT NULL DEFAULT ''",
    ]:
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # Full audit trail for the above — every submission, verification,
    # approval, rejection, and completion, plus who (user or staff) did it.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mail_support_request_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id      INTEGER NOT NULL,
            action          TEXT NOT NULL,           -- submitted | verified | status_change | note
            old_status      TEXT,
            new_status      TEXT,
            note            TEXT NOT NULL DEFAULT '',
            actor_username  TEXT NOT NULL,
            actor_role      TEXT NOT NULL,            -- user | employee | admin
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES mail_support_requests(id)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_support_events_request ON mail_support_request_events(request_id)")

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

    # Ensure the support@hkmail.cn mailbox exists so it can receive support
    # requests submitted from the "Support" button in the sidebar.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (SUPPORT_MAIL_USERNAME,))
    if not cur.fetchone():
        support_password_hash = generate_password_hash(SUPPORT_MAIL_DEFAULT_PASSWORD)
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified, is_employee) VALUES (?, ?, ?, 0, 1, 1)",
            (SUPPORT_MAIL_USERNAME, support_password_hash, "HKMail Support")
        )
    # Existing deployments: ensure the support mailbox can manage account requests.
    cur.execute("UPDATE mail_users SET is_employee=1 WHERE username=?", (SUPPORT_MAIL_USERNAME,))

    # Ensure the hksbank.support@hkmail.cn mailbox exists so it can receive
    # support requests submitted from the "Support" button on the HKS Bank
    # dashboard. This is separate from HKMail's own support@hkmail.cn.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (BANK_SUPPORT_MAIL_USERNAME,))
    if not cur.fetchone():
        bank_support_password_hash = generate_password_hash(BANK_SUPPORT_MAIL_DEFAULT_PASSWORD)
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified) VALUES (?, ?, ?, 0, 1)",
            (BANK_SUPPORT_MAIL_USERNAME, bank_support_password_hash, "HKS Bank Support")
        )

    # Ensure the contact@hkmail.cn mailbox exists — HKMail's general public
    # inquiries address. Verified/official like the other service mailboxes,
    # and carries the Support-staff tier (is_employee=1) so it's tagged the
    # same way support@hkmail.cn is.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (CONTACT_MAIL_USERNAME,))
    if not cur.fetchone():
        contact_password_hash = generate_password_hash(CONTACT_MAIL_DEFAULT_PASSWORD)
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified, is_employee) VALUES (?, ?, ?, 0, 1, 1)",
            (CONTACT_MAIL_USERNAME, contact_password_hash, "HKMail Contact")
        )

    # Ensure the legal@hkmail.cn mailbox exists — HKMail's legal/compliance
    # address. Verified/official from the start, same as the other service
    # mailboxes, but not tagged as Support staff.
    cur.execute("SELECT id FROM mail_users WHERE username=?", (LEGAL_MAIL_USERNAME,))
    if not cur.fetchone():
        legal_password_hash = generate_password_hash(LEGAL_MAIL_DEFAULT_PASSWORD)
        cur.execute(
            "INSERT INTO mail_users (username, password_hash, full_name, is_admin, is_verified) VALUES (?, ?, ?, 0, 1)",
            (LEGAL_MAIL_USERNAME, legal_password_hash, "HKMail Legal")
        )

    conn.commit()
    conn.close()


def mail_current_user():
    """Return the HKMail username from session, or None."""
    return session.get("mail_username")


def mail_is_support_staff():
    """True if the logged-in HKMail user is an Admin or Support-staff
    (Employee) account — the only roles allowed to review/process support
    requests."""
    return bool(session.get("mail_is_admin")) or bool(session.get("mail_is_employee"))


def generate_support_request_number(cur, length=10):
    """Deprecated — account-service cases now use CASE-{email_id} numbering
    shared with the general support inbox. Kept only so old migrations/rows
    with SR-* numbers don't break lookups."""
    alphabet = string.ascii_uppercase + string.digits
    while True:
        number = "SR-" + ''.join(random.choices(alphabet, k=length))
        cur.execute("SELECT 1 FROM mail_support_requests WHERE request_number = ?", (number,))
        if not cur.fetchone():
            return number


def mail_insert_support_case(cur, sender, subject_stub, body):
    """Deliver a support case to support@hkmail.cn as a normal inbox email.
    Returns (case_email_id, case_number) where case_number is CASE-{id:06d}."""
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (sender, SUPPORT_MAIL_USERNAME, subject_stub, body)
    )
    case_id = cur.lastrowid
    case_number = f"CASE-{case_id:06d}"
    cur.execute(
        "UPDATE emails SET subject=? WHERE id=?",
        (f"[{case_number}] {subject_stub} from {sender}", case_id)
    )
    return case_id, case_number


def mail_send_support_case_confirmation(cur, recipient, case_number, request_label, extra_body=""):
    """Drop the standard case-number confirmation into the user's inbox."""
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (
            NOREPLY_MAIL_USERNAME, recipient,
            f"We've received your {request_label} ({case_number})",
            "Thanks for contacting HKMail Support.\n\n"
            f"Your case number is {case_number}. Please reference it in any "
            "follow-up correspondence about this issue.\n\n"
            + (extra_body + "\n\n" if extra_body else "")
            + "— HKMail Support"
        )
    )


def mail_log_support_event(cur, request_id, action, actor_username, actor_role,
                            old_status=None, new_status=None, note=""):
    cur.execute("""
        INSERT INTO mail_support_request_events
            (request_id, action, old_status, new_status, note, actor_username, actor_role)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (request_id, action, old_status, new_status, note, actor_username, actor_role))


def mail_reinstatement_is_pending(reinstatement_requested_at, reinstatement_seen_at):
    """True while a recovery-banner reinstatement click is waiting for support
    to open the linked account-deletion request."""
    if not reinstatement_requested_at:
        return False
    if not reinstatement_seen_at:
        return True
    return reinstatement_requested_at > reinstatement_seen_at


def mail_support_requests_notification_count(cur):
    """How many account-service items still need support attention."""
    cur.execute("""
        SELECT COUNT(*) FROM mail_support_requests
        WHERE (request_type='account_deletion' AND status='pending')
           OR (request_type='business_account' AND status='pending')
           OR (
               request_type='account_deletion'
               AND status='approved'
               AND reinstatement_requested_at IS NOT NULL
               AND (reinstatement_seen_at IS NULL
                    OR reinstatement_requested_at > reinstatement_seen_at)
           )
    """)
    return cur.fetchone()[0]


def mail_support_request_to_dict(row):
    (req_id, req_number, username, req_type, status, message, verified,
     verified_at, decided_by, decided_at, created_at,
     reinstatement_requested_at, reinstatement_seen_at,
     company_name, company_address, company_phone, custom_domain) = row
    return {
        "id": req_id,
        "request_number": req_number,
        "username": username,
        "request_type": req_type,
        "request_type_label": MAIL_SUPPORT_REQUEST_TYPE_LABELS.get(req_type, req_type),
        "status": status,
        "status_label": MAIL_SUPPORT_REQUEST_STATUS_LABELS.get(status, status),
        "message": message,
        "verified": bool(verified),
        "verified_at": verified_at,
        "decided_by": decided_by,
        "decided_at": decided_at,
        "created_at": created_at,
        "reinstatement_pending": mail_reinstatement_is_pending(
            reinstatement_requested_at, reinstatement_seen_at),
        "company_name": company_name,
        "company_address": company_address,
        "company_phone": company_phone,
        "custom_domain": custom_domain,
    }


def _mail_days_remaining(scheduled_deletion_at):
    """Whole days left until scheduled_deletion_at, floored at 0 — used to
    drive the recovery-banner countdown."""
    if not scheduled_deletion_at:
        return 0
    try:
        deadline = datetime.strptime(scheduled_deletion_at, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return 0
    remaining = deadline - datetime.now()
    return max(0, remaining.days + (1 if remaining.seconds > 0 else 0))


def mail_finalize_pending_deletions():
    """Lazy sweep: permanently delete any HKMail account whose 30-day
    disablement/recovery window has elapsed. Safe to call on every request
    that touches login or the support-request queue — a no-op unless a
    deletion is actually due, same pattern as mail_run_billing_cycle()."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT username FROM mail_users
        WHERE is_disabled = 1 AND scheduled_deletion_at IS NOT NULL AND scheduled_deletion_at <= ?
    """, (now,))
    due = [r[0] for r in cur.fetchall()]

    for username in due:
        cur.execute("DELETE FROM mail_subscriptions WHERE username=?", (username,))
        cur.execute("DELETE FROM mail_users WHERE username=?", (username,))
        # Audit trail: log permanent deletion against any of that user's
        # still-open support requests (there should be exactly one approved
        # account_deletion request driving this).
        cur.execute("""
            SELECT id, status FROM mail_support_requests
            WHERE username=? AND request_type='account_deletion' AND status='approved'
        """, (username,))
        for req_id, old_status in cur.fetchall():
            cur.execute("UPDATE mail_support_requests SET status='completed' WHERE id=?", (req_id,))
            mail_log_support_event(cur, req_id, "status_change", "system", "system",
                                    old_status=old_status, new_status="completed",
                                    note=f"30-day recovery period elapsed; account {username} permanently deleted.")
        # Audit log to admin@hkmail.cn as well, for visibility outside the
        # request itself.
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, ADMIN_MAIL_USERNAME, f"[Account permanently deleted] {username}",
             f"The 30-day recovery period for {username}'s account deletion has elapsed. "
             "The account has been permanently deleted.")
        )

    if due:
        conn.commit()
    conn.close()


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

    Attachments: their raw byte size (size_bytes, computed once at send time
    from the decoded file) is added on top of the subject/body total, joined
    through the parent email so the same sender/recipient/trash rules apply
    to them automatically.
    """
    query = """
        SELECT
            COALESCE((SELECT SUM(LENGTH(CAST(subject AS BLOB)) + LENGTH(CAST(body AS BLOB)))
                       FROM emails WHERE sender=? OR recipient=?), 0)
            +
            COALESCE((SELECT SUM(a.size_bytes)
                       FROM email_attachments a
                       JOIN emails e ON e.id = a.email_id
                       WHERE e.sender=? OR e.recipient=?), 0)
    """
    params = (username, username, username, username)
    if cur is not None:
        # Reuse the caller's cursor/connection so this read happens inside
        # whatever transaction the caller already holds (see hkmail_send,
        # where this must be read atomically with the INSERT that follows).
        cur.execute(query, params)
        return cur.fetchone()[0] or 0

    conn = sqlite3.connect(MAIL_DATABASE)
    c = conn.cursor()
    c.execute(query, params)
    total = c.fetchone()[0] or 0
    conn.close()
    return total


def mail_get_premium_summary(username):
    """(is_premium, badge_label, tier) for wherever this mailbox appears as a
    sender. is_premium is True if any plan is still in effect (active, or
    cancelled but not yet past its grace-period end); badge_label/tier name
    the largest such plan, since that's the one worth bragging about in the
    badge — tier is one of 'silver'/'gold'/'emerald'/'diamond', matching the
    plan's storage size (5/25/50/100GB), for coloring the badge."""
    best_label = None
    best_tier  = None
    best_price = -1
    for _id, plan_id, price, status, _card_id, _next in mail_get_subscriptions(username):
        if status in ("active", "cancelled") and price > best_price:
            plan = MAIL_PLANS.get(plan_id)
            if plan:
                best_price = price
                best_label = plan["label"]
                best_tier  = plan["tier"]
    return (best_label is not None), best_label, best_tier


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

@app.route('/hkmail-terms.html')
def hkmail_terms():
    return render_template('hkmail-terms.html')


# ── HKMail Auth API ────────────────────────────────────────────────────────────

@app.route('/api/hkmail/account-exists')
def hkmail_account_exists():
    """Public lookup used by other apps (e.g. HKS Bank signup) to verify an
    HKMail address exists before allowing registration."""
    email = normalize_mail_address(request.args.get("email", ""))
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400
    details = hkmail_account_details(email)
    return jsonify({
        "success": True,
        "email": email,
        "exists": details is not None,
        "accountType": details["account_type"] if details else None,
    })


@app.route('/api/hkmail/register', methods=['POST'])
def hkmail_register():
    data         = request.get_json()
    username     = data.get("username", "").strip().lower()   # full address
    password     = data.get("password", "").strip()
    first_name   = data.get("first_name", "").strip()
    last_name    = data.get("last_name", "").strip()
    full_name    = f"{first_name} {last_name}".strip()

    account_type = (data.get("account_type", "personal") or "personal").strip().lower()
    if account_type not in ("personal", "business"):
        account_type = "personal"

    company_name    = (data.get("company_name", "") or "").strip()
    company_address = (data.get("company_address", "") or "").strip()
    company_phone    = (data.get("company_phone", "") or "").strip()
    custom_domain    = (data.get("custom_domain", "") or "").strip().lower()
    # Strip a leading "@" if someone pastes "@acme.com" into the field.
    if custom_domain.startswith("@"):
        custom_domain = custom_domain[1:]

    if not username or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400
    if not first_name or not last_name:
        return jsonify({"success": False, "message": "First and last name are required."}), 400
    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters."}), 400

    if account_type == "business":
        if not company_name:
            return jsonify({"success": False, "message": "Company name is required for a business account."}), 400
        if not company_address:
            return jsonify({"success": False, "message": "Company address is required for a business account."}), 400
        if not company_phone:
            return jsonify({"success": False, "message": "A contact phone number is required for a business account."}), 400
        # Domain ownership isn't verified yet (HKMail isn't live), so any
        # domain is accepted for now — but the chosen address must actually
        # use it, so the mailbox and the domain being registered agree.
        if custom_domain and not username.endswith("@" + custom_domain):
            return jsonify({"success": False, "message": f"Your address must end in @{custom_domain} to use that custom domain."}), 400
    else:
        # Personal accounts don't carry business fields even if the client sent some.
        company_name = company_address = company_phone = custom_domain = ""

    password_hash = generate_password_hash(password)
    try:
        conn = sqlite3.connect(MAIL_DATABASE)
        cur  = conn.cursor()
        # Self-registered accounts are always plain, unverified users. The
        # only admin account is the dedicated one seeded at startup; official
        # accounts are created and verified explicitly by that admin. Business
        # accounts additionally start with business_status='pending' until a
        # support member reviews the case filed just below.
        cur.execute("""
            INSERT INTO mail_users
                (username, password_hash, full_name, is_admin, is_verified,
                 account_type, business_status, company_name, company_address,
                 company_phone, custom_domain)
            VALUES (?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)
        """, (
            username, password_hash, full_name, account_type,
            "pending" if account_type == "business" else "",
            company_name, company_address, company_phone, custom_domain
        ))

        # Drop a welcome email from the no-reply system account into the new
        # inbox so every user's very first message shows what an official
        # HKMail sender looks like (and explains the badges they'll see).
        welcome_body = (
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
        )
        if account_type == "business":
            welcome_body += (
                "  • Your business account is pending verification. We've opened a case "
                "for our support team to review your company details — you'll get an email "
                "here once it's decided, and a \"Verified Business\" badge will appear on your "
                "account once approved.\n\n"
            )
        welcome_body += "That's it — enjoy your inbox!\n\n— HKMail"

        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, "Welcome to HKMail!", welcome_body)
        )

        # Business accounts open a review case in the same Account Requests
        # queue support staff already work (password resets / deletions),
        # so it shows up for a support member to approve or reject.
        if account_type == "business":
            case_body = (
                "New business account registration\n\n"
                f"User: {username}\n"
                f"Company name: {company_name}\n"
                f"Company address: {company_address}\n"
                f"Phone: {company_phone}\n"
                f"Custom domain: {custom_domain or '(none — using @hkmail.cn)'}\n\n"
                "Please review and approve or reject from the Account Requests tab."
            )
            _case_id, case_number = mail_insert_support_case(cur, username, "Business account registration", case_body)
            cur.execute("""
                INSERT INTO mail_support_requests
                    (request_number, username, request_type, status,
                     company_name, company_address, company_phone, custom_domain)
                VALUES (?, ?, 'business_account', 'pending', ?, ?, ?, ?)
            """, (case_number, username, company_name, company_address, company_phone, custom_domain))
            request_id = cur.lastrowid
            mail_log_support_event(cur, request_id, "submitted", username, "user",
                                    new_status="pending", note="Business account registration submitted.")
            mail_send_support_case_confirmation(
                cur, username, case_number, "business account registration",
                extra_body="Our support team will review your company details shortly. "
                           "You'll receive an email here once your business account is approved "
                           "or if we need more information."
            )

        conn.commit()
        conn.close()
        if account_type == "business":
            return jsonify({"success": True, "message": "Account created. Your business account is pending verification — check your inbox for a case confirmation."})
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

    # Sweep first so a login attempt right at the end of the recovery window
    # sees the account as already (permanently) gone rather than stale.
    mail_finalize_pending_deletions()

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT password_hash, full_name, is_admin, is_verified, is_employee,
               is_disabled, scheduled_deletion_at, account_type, business_status,
               is_verified_business
        FROM mail_users WHERE username=?
    """, (username,))
    row = cur.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        session["mail_username"] = username
        session["mail_full_name"] = row[1]
        session["mail_is_admin"]  = bool(row[2])
        session["mail_is_employee"] = bool(row[4])
        payload = {"success": True, "username": username, "fullName": row[1],
                   "isAdmin": bool(row[2]), "isVerified": bool(row[3]),
                   "accountType": row[7], "businessStatus": row[8],
                   "isVerifiedBusiness": bool(row[9])}
        # A disabled account can still sign in — it's in its recovery window,
        # not gone yet — but the inbox flags it so the UI can show the
        # recovery banner instead of pretending everything's normal.
        if row[5]:
            payload["disabled"] = True
            payload["scheduledDeletionAt"] = row[6]
            payload["daysRemaining"] = _mail_days_remaining(row[6])
            conn_rein = sqlite3.connect(MAIL_DATABASE)
            cur_rein  = conn_rein.cursor()
            cur_rein.execute("""
                SELECT reinstatement_requested_at, reinstatement_seen_at
                FROM mail_support_requests
                WHERE username=? AND request_type='account_deletion' AND status='approved'
                ORDER BY id DESC LIMIT 1
            """, (username,))
            rein_row = cur_rein.fetchone()
            conn_rein.close()
            if rein_row:
                payload["reinstatementPending"] = mail_reinstatement_is_pending(rein_row[0], rein_row[1])
        return jsonify(payload)
    return jsonify({"success": False, "message": "Incorrect email or password."}), 401


@app.route('/api/hkmail/logout', methods=['POST'])
def hkmail_logout():
    session.pop("mail_username", None)
    session.pop("mail_full_name", None)
    session.pop("mail_is_admin", None)
    session.pop("mail_is_employee", None)
    return jsonify({"success": True})


@app.route('/api/hkmail/current-user')
def hkmail_current_user():
    u = mail_current_user()
    if u:
        mail_finalize_pending_deletions()
        mail_run_billing_cycle(u)
        conn = sqlite3.connect(MAIL_DATABASE)
        cur  = conn.cursor()
        cur.execute("""
            SELECT full_name, is_admin, is_verified, is_employee, is_disabled, scheduled_deletion_at,
                   account_type, business_status, is_verified_business, company_name, custom_domain
            FROM mail_users WHERE username=?
        """, (u,))
        row = cur.fetchone()
        if row:
            is_premium, badge_label, badge_tier = mail_get_premium_summary(u)
            payload = {"loggedIn": True, "username": u, "fullName": row[0],
                       "isAdmin": bool(row[1]), "isVerified": bool(row[2]),
                       "isSupportStaff": bool(row[1]) or bool(row[3]),
                       "isPremium": is_premium,
                       "premiumLabel": badge_label,
                       "premiumTier": badge_tier,
                       "accountType": row[6], "businessStatus": row[7],
                       "isVerifiedBusiness": bool(row[8]),
                       "companyName": row[9], "customDomain": row[10]}
            if row[4]:
                payload["disabled"] = True
                payload["scheduledDeletionAt"] = row[5]
                payload["daysRemaining"] = _mail_days_remaining(row[5])
                cur.execute("""
                    SELECT reinstatement_requested_at, reinstatement_seen_at
                    FROM mail_support_requests
                    WHERE username=? AND request_type='account_deletion' AND status='approved'
                    ORDER BY id DESC LIMIT 1
                """, (u,))
                rein_row = cur.fetchone()
                if rein_row:
                    payload["reinstatementPending"] = mail_reinstatement_is_pending(
                        rein_row[0], rein_row[1])
            conn.close()
            return jsonify(payload)
        conn.close()
    return jsonify({"loggedIn": False})


# ── HKMail: compose / send ─────────────────────────────────────────────────────

def mail_deliver_bounce(sender_username, recipient, subject, reason_text):
    """Insert an automatic non-delivery notice into sender_username's inbox,
    the way a real mail server's mailer-daemon reports a failed delivery."""
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?,?,?,?)",
        (
            MAILER_DAEMON_SENDER,
            sender_username,
            f"Undeliverable: {subject}",
            "This is an automated message from the HKMail delivery system.\n\n"
            f"Your message could not be delivered to {recipient}.\n"
            f"{reason_text}\n\n"
            "--- Original message ---\n"
            f"To: {recipient}\n"
            f"Subject: {subject}"
        )
    )
    conn.commit()
    conn.close()


@app.route('/api/hkmail/send', methods=['POST'])
def hkmail_send():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn_check = sqlite3.connect(MAIL_DATABASE)
    cur_check  = conn_check.cursor()
    cur_check.execute("SELECT is_disabled FROM mail_users WHERE username=?", (u,))
    disabled_row = cur_check.fetchone()
    conn_check.close()
    if disabled_row and disabled_row[0]:
        return jsonify({"success": False, "message": "Your account is disabled pending deletion. Request reinstatement to resume sending mail."}), 403

    data      = request.get_json()
    recipient = data.get("recipient", "").strip().lower()
    subject   = data.get("subject",   "").strip() or "(No subject)"
    body      = data.get("body",       "").strip()
    attachments_in = data.get("attachments") or []

    if not recipient:
        return jsonify({"success": False, "message": "Recipient is required."}), 400

    if not isinstance(attachments_in, list):
        return jsonify({"success": False, "message": "Invalid attachments."}), 400
    if len(attachments_in) > MAX_ATTACHMENTS_PER_EMAIL:
        return jsonify({"success": False, "message": f"You can attach at most {MAX_ATTACHMENTS_PER_EMAIL} files."}), 400

    # Decode and validate every attachment up front — each file must be
    # 15MB or smaller. Decoding here (rather than trusting the base64
    # string's length) means the check is against the actual file size,
    # not the ~33% larger base64 encoding of it.
    parsed_attachments = []  # list of (filename, mime_type, size_bytes, raw_bytes)
    total_attachment_bytes = 0
    for att in attachments_in:
        if not isinstance(att, dict):
            return jsonify({"success": False, "message": "Invalid attachment."}), 400
        filename  = (att.get("filename") or "").strip()
        mime_type = (att.get("mime_type") or "").strip() or "application/octet-stream"
        b64data   = att.get("data") or ""

        if not filename:
            return jsonify({"success": False, "message": "Each attachment needs a filename."}), 400

        try:
            raw = base64.b64decode(b64data, validate=True)
        except Exception:
            return jsonify({"success": False, "message": f'"{filename}" could not be read — please re-attach it.'}), 400

        size = len(raw)
        if size == 0:
            return jsonify({"success": False, "message": f'"{filename}" is empty.'}), 400
        if size > MAX_ATTACHMENT_SIZE_BYTES:
            return jsonify({
                "success": False,
                "message": f'"{filename}" is {format_bytes(size)} — attachments must be {MAX_ATTACHMENT_SIZE_MB}MB or smaller.'
            }), 400

        total_attachment_bytes += size
        parsed_attachments.append((filename, mime_type, size, raw))

    # Auto-append @hkmail.cn if no domain given
    if "@" not in recipient:
        recipient = recipient + "@hkmail.cn"

    # No-reply mailboxes never accept incoming mail — a real mail provider
    # couldn't connect to them either. As far as the sender is concerned the
    # message goes out normally; the failure only shows up moments later as
    # a bounce notice in their inbox, same as real email.
    recipient_local_part = recipient.split("@", 1)[0]
    if recipient_local_part in NOREPLY_LOCAL_PARTS:
        mail_deliver_bounce(
            u, recipient, subject,
            "This address does not accept incoming mail (no-reply mailbox)."
        )
        return jsonify({"success": True, "message": f"Message sent to {recipient}."})

    # Renewals/downgrades may have just changed either mailbox's limit
    mail_run_billing_cycle(u)
    mail_run_billing_cycle(recipient)

    message_size = len(subject.encode("utf-8")) + len(body.encode("utf-8")) + total_attachment_bytes

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
            conn.close()
            mail_deliver_bounce(
                u, recipient, subject,
                "The HKMail delivery system couldn't connect to this address — it doesn't exist."
            )
            return jsonify({"success": True, "message": f"Message sent to {recipient}."})

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

        email_id = cur.lastrowid
        for filename, mime_type, size, raw in parsed_attachments:
            cur.execute(
                "INSERT INTO email_attachments (email_id, filename, mime_type, size_bytes, data) VALUES (?,?,?,?,?)",
                (email_id, filename, mime_type, size, raw)
            )

        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": f"Message sent to {recipient}."})


# ── HKMail: support requests ─────────────────────────────────────────────────

@app.route('/api/hkmail/support', methods=['POST'])
def hkmail_support():
    """File a support request from the sidebar "Support" button.

    The request itself is delivered as a normal email to support@hkmail.cn so
    the support team can work their queue like any other inbox. The case
    number is derived from that email's row id at the moment it's created —
    there's no separate case table, the email row *is* the case record. The
    case number isn't returned to the caller here (per spec, it should only
    reach the user via the confirmation email); a confirmation email quoting
    it is dropped into the user's own inbox from the no-reply account
    immediately afterward.
    """
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data    = request.get_json() or {}
    message = (data.get("message", "") or "").strip()
    if not message:
        return jsonify({"success": False, "message": "Please describe your issue before sending."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        _case_id, case_number = mail_insert_support_case(cur, u, "Support request", message)
        mail_send_support_case_confirmation(
            cur, u, case_number, "support request",
            extra_body="Our support team will get back to you as soon as possible.\n\n"
                       "――――――――――――――――――\nYour original message:\n" + message
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "Your support request has been sent. Check your inbox for a confirmation."})


# ── HKMail: account-service support requests (password reset / deletion) ──────

@app.route('/api/hkmail/support/password-reset/check', methods=['POST'])
def hkmail_password_reset_check():
    """Validate the user's current password before the new-password step."""
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json() or {}
    current = (data.get("current_password", "") or "").strip()
    if not current:
        return jsonify({"success": False, "message": "Please enter your current password."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT password_hash FROM mail_users WHERE username=?", (u,))
    row = cur.fetchone()
    conn.close()

    if not row or not check_password_hash(row[0], current):
        return jsonify({"success": False, "message": "That password is incorrect."}), 400

    return jsonify({"success": True})


@app.route('/api/hkmail/support/password-reset', methods=['POST'])
def hkmail_password_reset():
    """Self-service password change: verify current password, set a new one,
    file a CASE-numbered support ticket for the audit trail, then sign out."""
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data    = request.get_json() or {}
    current = (data.get("current_password", "") or "").strip()
    new_pw  = (data.get("new_password", "") or "").strip()
    confirm = (data.get("confirm_password", "") or "").strip()

    if not current:
        return jsonify({"success": False, "message": "Please enter your current password."}), 400
    if not new_pw or not confirm:
        return jsonify({"success": False, "message": "Please enter and confirm your new password."}), 400
    if new_pw != confirm:
        return jsonify({"success": False, "message": "New passwords don't match."}), 400
    if len(new_pw) < 8:
        return jsonify({"success": False, "message": "New password must be at least 8 characters."}), 400
    if current == new_pw:
        return jsonify({"success": False, "message": "New password must be different from your current password."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("SELECT password_hash FROM mail_users WHERE username=?", (u,))
        row = cur.fetchone()
        if not row or not check_password_hash(row[0], current):
            return jsonify({"success": False, "message": "That password is incorrect."}), 400

        cur.execute("UPDATE mail_users SET password_hash=? WHERE username=?",
                    (generate_password_hash(new_pw), u))

        support_body = (
            f"Password reset (self-service)\n\n"
            f"User: {u}\n"
            "The account holder verified their current password and set a new "
            "password through HKMail Support. No staff action is required."
        )
        _case_id, case_number = mail_insert_support_case(cur, u, "Password reset", support_body)

        cur.execute("""
            INSERT INTO mail_support_requests
                (request_number, username, request_type, status, verified, verified_at)
            VALUES (?, ?, 'password_reset', 'completed', 1, CURRENT_TIMESTAMP)
        """, (case_number, u))
        request_id = cur.lastrowid
        mail_log_support_event(cur, request_id, "submitted", u, "user",
                                new_status="completed", note="Self-service password reset.")
        mail_log_support_event(cur, request_id, "status_change", u, "user",
                                old_status="pending", new_status="completed",
                                note="Password changed by account holder.")

        mail_send_support_case_confirmation(
            cur, u, case_number, "password reset",
            extra_body="Your password has been changed. Please sign in again with your new password."
        )

        conn.commit()
    finally:
        conn.close()

    session.pop("mail_username", None)
    session.pop("mail_full_name", None)
    session.pop("mail_is_admin", None)
    session.pop("mail_is_employee", None)

    return jsonify({
        "success": True,
        "logout": True,
        "message": "Password updated. Please sign in again with your new password."
    })


@app.route('/api/hkmail/support/account-deletion', methods=['POST'])
def hkmail_request_account_deletion():
    """File a support-mediated account-deletion request. Distinct from the
    instant, password-confirmed self-delete in the Danger Zone: this path
    goes through staff review, and once approved the account is disabled
    for a 30-day recovery window rather than deleted immediately."""
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if u in (ADMIN_MAIL_USERNAME, SYSTEM_MAIL_SENDER, NOREPLY_MAIL_USERNAME, SUPPORT_MAIL_USERNAME, BANK_SUPPORT_MAIL_USERNAME):
        return jsonify({"success": False, "message": "This account can't be deleted."}), 400

    data    = request.get_json() or {}
    message = (data.get("message", "") or "").strip()

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT id FROM mail_support_requests
            WHERE username=? AND request_type='account_deletion' AND status='pending'
        """, (u,))
        if cur.fetchone():
            return jsonify({"success": False, "message": "You already have an account deletion request pending review."}), 400

        support_body = f"Account deletion request\n\nUser: {u}\n"
        if message:
            support_body += f"\nNote from user:\n{message}"
        else:
            support_body += "\n(No additional message from user.)"

        _case_id, case_number = mail_insert_support_case(cur, u, "Account deletion request", support_body)

        cur.execute("""
            INSERT INTO mail_support_requests
                (request_number, username, request_type, status, message)
            VALUES (?, ?, 'account_deletion', 'pending', ?)
        """, (case_number, u, message))
        request_id = cur.lastrowid
        mail_log_support_event(cur, request_id, "submitted", u, "user",
                                new_status="pending", note="Account deletion requested.")

        mail_send_support_case_confirmation(
            cur, u, case_number, "account deletion request",
            extra_body="Our support team will review your request shortly.\n\n"
                       "If approved, your account will be disabled and enter a "
                       f"{ACCOUNT_DELETION_GRACE_DAYS}-day recovery window before it's permanently "
                       "deleted — you'll be able to request reinstatement at any point during that "
                       "window."
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "Your account deletion request has been sent. Check your inbox for a confirmation."})


@app.route('/api/hkmail/account/request-reinstatement', methods=['POST'])
def hkmail_request_reinstatement():
    """Called from the recovery banner shown to a disabled account. Reopens
    the original account-deletion support case for staff review. Only one
    pending reinstatement click is allowed until support opens the request."""
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("SELECT is_disabled FROM mail_users WHERE username=?", (u,))
        row = cur.fetchone()
        if not row or not row[0]:
            return jsonify({"success": False, "message": "Your account isn't disabled."}), 400

        cur.execute("""
            SELECT id, request_number, reinstatement_requested_at, reinstatement_seen_at
            FROM mail_support_requests
            WHERE username=? AND request_type='account_deletion' AND status='approved'
            ORDER BY id DESC LIMIT 1
        """, (u,))
        req = cur.fetchone()
        if not req:
            return jsonify({"success": False, "message": "No approved account deletion request found."}), 400

        req_id, case_number, rein_requested_at, rein_seen_at = req
        if mail_reinstatement_is_pending(rein_requested_at, rein_seen_at):
            return jsonify({
                "success": False,
                "message": "You already have a reinstatement request pending review.",
                "alreadyPending": True,
            }), 400

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        support_body = (
            f"Reinstatement requested\n\n"
            f"User: {u}\n"
            f"Original case: {case_number}\n\n"
            "The account owner has requested reinstatement from the recovery banner. "
            "Please review and reinstate from the Account Requests tab if appropriate."
        )
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (u, SUPPORT_MAIL_USERNAME, f"[{case_number}] Reinstatement requested", support_body)
        )
        cur.execute(
            "UPDATE mail_support_requests SET reinstatement_requested_at=? WHERE id=?",
            (now, req_id),
        )
        mail_log_support_event(cur, req_id, "note", u, "user",
                                note="Account owner requested reinstatement from the recovery banner.")
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "Reinstatement requested. Our support team will review it shortly."})


@app.route('/api/hkmail/support/my-requests', methods=['GET'])
def hkmail_my_support_requests():
    """Open account-service requests for the logged-in user (no staff-only fields)."""
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, request_number, username, request_type, status, message, verified,
               verified_at, decided_by, decided_at, created_at,
               reinstatement_requested_at, reinstatement_seen_at,
               company_name, company_address, company_phone, custom_domain
        FROM mail_support_requests WHERE username=? ORDER BY created_at DESC LIMIT 20
    """, (u,))
    rows = cur.fetchall()
    conn.close()

    requests_out = []
    for row in rows:
        requests_out.append(mail_support_request_to_dict(row))
    return jsonify({"success": True, "requests": requests_out})


# ── HKMail: admin — account-service support requests ───────────────────────────

@app.route('/api/hkmail/admin/support-requests/notification-count', methods=['GET'])
def hkmail_admin_support_requests_notification_count():
    if not mail_is_support_staff():
        return jsonify({"success": False, "message": "Support staff access required."}), 403

    mail_finalize_pending_deletions()
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    count = mail_support_requests_notification_count(cur)
    conn.close()
    return jsonify({"success": True, "count": count})

@app.route('/api/hkmail/admin/support-requests', methods=['GET'])
def hkmail_admin_list_support_requests():
    if not mail_is_support_staff():
        return jsonify({"success": False, "message": "Support staff access required."}), 403

    mail_finalize_pending_deletions()

    req_type = (request.args.get("type") or "").strip()
    status   = (request.args.get("status") or "").strip()

    query  = """
        SELECT id, request_number, username, request_type, status, message, verified,
               verified_at, decided_by, decided_at, created_at,
               reinstatement_requested_at, reinstatement_seen_at,
               company_name, company_address, company_phone, custom_domain
        FROM mail_support_requests
    """
    clauses, params = [], []
    if req_type in MAIL_SUPPORT_REQUEST_TYPES:
        clauses.append("request_type=?")
        params.append(req_type)
    if status in MAIL_SUPPORT_REQUEST_STATUSES:
        clauses.append("status=?")
        params.append(status)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC"

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()

    requests_out = []
    for row in rows:
        d = mail_support_request_to_dict(row)
        if d["request_type"] == "account_deletion":
            cur.execute("SELECT is_disabled, scheduled_deletion_at FROM mail_users WHERE username=?", (d["username"],))
            u_row = cur.fetchone()
            d["account_is_disabled"] = bool(u_row[0]) if u_row else False
            d["scheduled_deletion_at"] = u_row[1] if u_row else None
        requests_out.append(d)
    conn.close()

    return jsonify({"success": True, "requests": requests_out})


@app.route('/api/hkmail/admin/support-requests/<int:request_id>', methods=['GET'])
def hkmail_admin_get_support_request(request_id):
    """Full detail for one account-service request, including its audit trail."""
    if not mail_is_support_staff():
        return jsonify({"success": False, "message": "Support staff access required."}), 403

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, request_number, username, request_type, status, message, verified,
               verified_at, decided_by, decided_at, created_at,
               reinstatement_requested_at, reinstatement_seen_at,
               company_name, company_address, company_phone, custom_domain
        FROM mail_support_requests WHERE id=?
    """, (request_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Request not found."}), 404

    req = mail_support_request_to_dict(row)
    if req["request_type"] == "account_deletion":
        cur.execute("SELECT is_disabled, scheduled_deletion_at FROM mail_users WHERE username=?", (req["username"],))
        u_row = cur.fetchone()
        req["account_is_disabled"] = bool(u_row[0]) if u_row else False
        req["scheduled_deletion_at"] = u_row[1] if u_row else None

    if req.get("reinstatement_pending"):
        cur.execute("""
            UPDATE mail_support_requests SET reinstatement_seen_at=CURRENT_TIMESTAMP
            WHERE id=? AND reinstatement_requested_at IS NOT NULL
        """, (request_id,))
        req["reinstatement_pending"] = False
        conn.commit()

    cur.execute("""
        SELECT action, old_status, new_status, note, actor_username, actor_role, created_at
        FROM mail_support_request_events WHERE request_id=? ORDER BY created_at ASC, id ASC
    """, (request_id,))
    events = [
        {"action": e[0], "old_status": e[1], "new_status": e[2], "note": e[3],
         "actor_username": e[4], "actor_role": e[5], "created_at": e[6]}
        for e in cur.fetchall()
    ]
    conn.close()
    return jsonify({"success": True, "request": req, "events": events})


@app.route('/api/hkmail/admin/support-requests/<int:request_id>/approve', methods=['POST'])
def hkmail_admin_approve_support_request(request_id):
    """Approve a pending account-deletion request — disables the account and
    starts its 30-day recovery window. Password resets are self-service and
    never reach this endpoint."""
    if not mail_is_support_staff():
        return jsonify({"success": False, "message": "Support staff access required."}), 403

    actor_username = mail_current_user()
    actor_role = "admin" if session.get("mail_is_admin") else "employee"

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT username, request_type, status FROM mail_support_requests WHERE id=?
        """, (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "message": "Request not found."}), 404
        username, req_type, status = row

        if req_type == "password_reset":
            return jsonify({"success": False, "message": "Password resets are self-service — no staff approval is needed."}), 400

        if status != "pending":
            return jsonify({"success": False, "message": "This request has already been decided."}), 400

        if req_type == "account_deletion":
            now = datetime.now()
            scheduled_deletion_at = (now + timedelta(days=ACCOUNT_DELETION_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")

            cur.execute("""
                UPDATE mail_users SET is_disabled=1, disabled_at=?, scheduled_deletion_at=?
                WHERE username=?
            """, (now.strftime("%Y-%m-%d %H:%M:%S"), scheduled_deletion_at, username))
            cur.execute("""
                UPDATE mail_support_requests
                SET status='approved', decided_by=?, decided_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (actor_username, request_id))
            mail_log_support_event(cur, request_id, "status_change", actor_username, actor_role,
                                    old_status="pending", new_status="approved",
                                    note=f"Account deletion approved. Disabled with a {ACCOUNT_DELETION_GRACE_DAYS}-day recovery window ending {scheduled_deletion_at}.")

            cur.execute(
                "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
                (NOREPLY_MAIL_USERNAME, username, "Your HKMail account has been disabled",
                 "Your account deletion request has been approved.\n\n"
                 "Your account is now disabled. You have "
                 f"{ACCOUNT_DELETION_GRACE_DAYS} days (until {scheduled_deletion_at}) to request "
                 "reinstatement before it's permanently deleted. Sign in at any point during "
                 "this window to request reinstatement.\n\n"
                 "— HKMail Support")
            )
            conn.commit()
            return jsonify({"success": True, "message": f"{username}'s account has been disabled and scheduled for deletion on {scheduled_deletion_at}."})

        elif req_type == "business_account":
            cur.execute("""
                UPDATE mail_users SET is_verified_business=1, business_status='approved'
                WHERE username=?
            """, (username,))
            cur.execute("""
                UPDATE mail_support_requests
                SET status='approved', decided_by=?, decided_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (actor_username, request_id))
            mail_log_support_event(cur, request_id, "status_change", actor_username, actor_role,
                                    old_status="pending", new_status="approved",
                                    note="Business account approved. \"Verified Business\" badge granted.")

            cur.execute(
                "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
                (NOREPLY_MAIL_USERNAME, username, "Your business account has been verified",
                 "Good news — your business account has been reviewed and approved.\n\n"
                 "Your account now carries a \"Verified Business\" badge, visible to anyone "
                 "you email.\n\n— HKMail Support")
            )
            conn.commit()
            return jsonify({"success": True, "message": f"{username}'s business account has been verified."})

        else:
            return jsonify({"success": False, "message": "Unknown request type."}), 400
    finally:
        conn.close()


@app.route('/api/hkmail/admin/support-requests/<int:request_id>/reject', methods=['POST'])
def hkmail_admin_reject_support_request(request_id):
    if not mail_is_support_staff():
        return jsonify({"success": False, "message": "Support staff access required."}), 403

    actor_username = mail_current_user()
    actor_role = "admin" if session.get("mail_is_admin") else "employee"
    data = request.get_json() or {}
    note = (data.get("note", "") or "").strip()

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("SELECT username, request_type, status FROM mail_support_requests WHERE id=?", (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "message": "Request not found."}), 404
        username, req_type, status = row
        if status != "pending":
            return jsonify({"success": False, "message": "This request has already been decided."}), 400

        cur.execute("""
            UPDATE mail_support_requests
            SET status='rejected', decided_by=?, decided_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (actor_username, request_id))
        mail_log_support_event(cur, request_id, "status_change", actor_username, actor_role,
                                old_status="pending", new_status="rejected", note=note)

        if req_type == "business_account":
            cur.execute("UPDATE mail_users SET business_status='rejected' WHERE username=?", (username,))

        type_label = MAIL_SUPPORT_REQUEST_TYPE_LABELS.get(req_type, req_type)
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, f"Your {type_label} request was not approved",
             f"Your {type_label.lower()} request has been reviewed and was not approved.\n\n"
             + (f"Reason given: {note}\n\n" if note else "")
             + "If you believe this was a mistake, please contact HKMail Support.\n\n— HKMail Support")
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": f"{MAIL_SUPPORT_REQUEST_TYPE_LABELS.get(req_type, req_type)} request rejected."})


@app.route('/api/hkmail/admin/support-requests/<int:request_id>/reinstate', methods=['POST'])
def hkmail_admin_reinstate_account(request_id):
    """Reverse an approved account-deletion request during its recovery
    window: re-enable the account and mark the request cancelled."""
    if not mail_is_support_staff():
        return jsonify({"success": False, "message": "Support staff access required."}), 403

    actor_username = mail_current_user()
    actor_role = "admin" if session.get("mail_is_admin") else "employee"

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT username, request_type, status FROM mail_support_requests WHERE id=?
        """, (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "message": "Request not found."}), 404
        username, req_type, status = row
        if req_type != "account_deletion" or status != "approved":
            return jsonify({"success": False, "message": "Only an approved, still-pending account deletion can be reinstated."}), 400

        cur.execute("""
            UPDATE mail_users SET is_disabled=0, disabled_at=NULL, scheduled_deletion_at=NULL
            WHERE username=?
        """, (username,))
        cur.execute("""
            UPDATE mail_support_requests
            SET status='cancelled', decided_by=?, decided_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (actor_username, request_id))
        mail_log_support_event(cur, request_id, "status_change", actor_username, actor_role,
                                old_status="approved", new_status="cancelled",
                                note="Account reinstated within the recovery window.")

        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, "Your HKMail account has been reinstated",
             "Good news — your account deletion has been reversed and your account is fully "
             "active again.\n\nIf you didn't request this, please contact HKMail Support "
             "immediately.\n\n— HKMail Support")
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": f"{username}'s account has been reinstated."})


# ── HKMail: storage & premium subscription ─────────────────────────────────────

def _mail_plans_payload():
    return [
        {"id": p["id"], "label": p["label"], "storage_mb": p["storage_mb"],
         "storage_gb": p["storage_mb"] // 1024, "price": p["price"], "badge": p["badge"],
         "tier": p["tier"], "tier_label": p["tier_label"]}
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

    is_premium, badge_label, badge_tier = mail_get_premium_summary(u)
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
                "tier": p["tier"], "tier_label": p["tier_label"],
            })
        else:
            plans_payload.append({
                "id": p["id"], "label": p["label"], "storage_mb": p["storage_mb"],
                "storage_gb": p["storage_mb"] // 1024, "price": p["price"],
                "status": None, "next_billing": None, "auto_renews": False,
                "tier": p["tier"], "tier_label": p["tier_label"],
            })

    return jsonify({
        "success": True,
        "used_bytes": used_bytes,
        "used_mb": round(used_bytes / (1024 * 1024), 3),
        "limit_mb": limit_mb,
        "is_premium": is_premium,
        "badge_label": badge_label,
        "badge_tier": badge_tier,
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
    if u in (ADMIN_MAIL_USERNAME, SYSTEM_MAIL_SENDER, NOREPLY_MAIL_USERNAME, SUPPORT_MAIL_USERNAME, BANK_SUPPORT_MAIL_USERNAME):
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
        SELECT e.id, e.sender, e.subject, e.sent_at, e.read, mu.is_admin, mu.is_verified,
               (SELECT COUNT(*) FROM email_attachments a WHERE a.email_id = e.id),
               mu.is_verified_business
        FROM emails e
        LEFT JOIN mail_users mu ON mu.username = e.sender
        WHERE e.recipient=? AND e.deleted_by_recipient=0
        ORDER BY e.sent_at DESC
    """, (u,))
    rows = cur.fetchall()
    conn.close()
    emails = []
    for r in rows:
        is_premium, badge_label, badge_tier = mail_get_premium_summary(r[1])
        emails.append({"id": r[0], "from": r[1], "subject": r[2], "date": r[3], "read": bool(r[4]),
                        "from_is_admin": bool(r[5]), "from_is_verified": bool(r[6]),
                        "from_is_premium": is_premium,
                        "from_premium_label": badge_label,
                        "from_premium_tier": badge_tier,
                        "attachment_count": r[7],
                        "from_is_verified_business": bool(r[8])})
    return jsonify({"success": True, "emails": emails})


@app.route('/api/hkmail/sent')
def hkmail_sent_api():
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, recipient, subject, sent_at,
               (SELECT COUNT(*) FROM email_attachments a WHERE a.email_id = emails.id)
        FROM emails
        WHERE sender=? AND deleted_by_sender=0 AND recipient != sender
        ORDER BY sent_at DESC
    """, (u,))
    emails = [{"id": r[0], "to": r[1], "subject": r[2], "date": r[3], "attachment_count": r[4]}
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
               e.deleted_by_sender, e.deleted_by_recipient, mu.is_admin, mu.is_verified,
               (SELECT COUNT(*) FROM email_attachments a WHERE a.email_id = e.id),
               mu.is_verified_business
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
        is_premium, badge_label, badge_tier = mail_get_premium_summary(r[1])
        emails.append({
            "id": r[0], "from": r[1], "to": r[2],
            "subject": r[3], "date": r[4],
            "from_is_admin": bool(r[7]), "from_is_verified": bool(r[8]),
            "from_is_premium": is_premium,
            "from_premium_label": badge_label,
            "from_premium_tier": badge_tier,
            "attachment_count": r[9],
            "from_is_verified_business": bool(r[10])
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
               mu.is_admin, mu.is_verified, mu.is_verified_business
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

    cur.execute(
        "SELECT id, filename, mime_type, size_bytes FROM email_attachments WHERE email_id=? ORDER BY id",
        (email_id,)
    )
    attachments = [
        {"id": a[0], "filename": a[1], "mime_type": a[2], "size_bytes": a[3]}
        for a in cur.fetchall()
    ]

    conn.close()
    is_premium, badge_label, badge_tier = mail_get_premium_summary(row[1])
    return jsonify({
        "success": True,
        "email": {
            "id": row[0], "from": row[1], "to": row[2],
            "subject": row[3], "body": row[4], "date": row[5], "read": True,
            "from_is_admin": bool(row[7]), "from_is_verified": bool(row[8]),
            "from_is_premium": is_premium,
            "from_premium_label": badge_label,
            "from_premium_tier": badge_tier,
            "from_is_verified_business": bool(row[9]),
            "attachments": attachments
        }
    })


# ── HKMail: download an attachment ─────────────────────────────────────────────

@app.route('/api/hkmail/attachment/<int:attachment_id>/download')
def hkmail_download_attachment(attachment_id):
    u = mail_current_user()
    if not u:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("""
        SELECT a.filename, a.mime_type, a.data, e.sender, e.recipient
        FROM email_attachments a
        JOIN emails e ON e.id = a.email_id
        WHERE a.id=?
    """, (attachment_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "Attachment not found."}), 404

    filename, mime_type, data, sender, recipient = row
    # Only the sender or recipient of the parent email may download it —
    # same access rule as reading the email itself.
    if u not in (sender, recipient):
        return jsonify({"success": False, "message": "Access denied."}), 403

    # Strip anything that could break out of the Content-Disposition header
    # value (quotes, newlines) rather than trusting the stored filename.
    safe_filename = filename.replace('"', "'").replace("\r", " ").replace("\n", " ")

    return Response(
        data,
        mimetype=mime_type or 'application/octet-stream',
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
    )


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
        cur.execute("DELETE FROM email_attachments WHERE email_id=?", (email_id,))
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
    cur.execute("""
        SELECT id, username, full_name, is_admin, is_verified, is_employee, created_at,
               is_disabled, disabled_at, scheduled_deletion_at,
               account_type, business_status, is_verified_business, company_name, custom_domain
        FROM mail_users ORDER BY created_at
    """)
    rows = cur.fetchall()
    conn.close()

    users = []
    for r in rows:
        username = r[1]
        subs = []
        for sub_id, plan_id, price, status, _card_id, next_billing in mail_get_subscriptions(username):
            if status not in ("active", "cancelled"):
                continue
            plan = MAIL_PLANS.get(plan_id)
            subs.append({
                "id": sub_id, "plan_id": plan_id,
                "label": plan["label"] if plan else plan_id,
                "tier": plan["tier"] if plan else None,
                "tier_label": plan["tier_label"] if plan else None,
                "price": price, "status": status, "next_billing": next_billing,
            })
        users.append({"id": r[0], "username": username, "full_name": r[2],
                       "is_admin": bool(r[3]), "is_verified": bool(r[4]),
                       "is_employee": bool(r[5]), "created_at": r[6],
                       "is_disabled": bool(r[7]), "disabled_at": r[8],
                       "scheduled_deletion_at": r[9],
                       "account_type": r[10], "business_status": r[11],
                       "is_verified_business": bool(r[12]),
                       "company_name": r[13], "custom_domain": r[14],
                       "subscriptions": subs})
    return jsonify({"success": True, "users": users})


# ── HKMail: admin — disable / reinstate / delete user accounts ────────────────

MAIL_PROTECTED_ACCOUNTS = (
    ADMIN_MAIL_USERNAME, SYSTEM_MAIL_SENDER, NOREPLY_MAIL_USERNAME,
    SUPPORT_MAIL_USERNAME, BANK_SUPPORT_MAIL_USERNAME,
)


@app.route('/api/hkmail/admin/users/disable', methods=['POST'])
def hkmail_admin_disable_user():
    """Admin-initiated account disable — same 30-day recovery window as
    approving an account-deletion support request."""
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403

    data     = request.get_json() or {}
    username = (data.get("username", "") or "").strip().lower()
    admin_username = mail_current_user()

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400
    if username == admin_username:
        return jsonify({"success": False, "message": "You cannot disable your own account."}), 400
    if username in MAIL_PROTECTED_ACCOUNTS:
        return jsonify({"success": False, "message": "This system account can't be disabled."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("SELECT is_disabled FROM mail_users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "message": "User not found."}), 404
        if row[0]:
            return jsonify({"success": False, "message": "This account is already disabled."}), 400

        now = datetime.now()
        disabled_at = now.strftime("%Y-%m-%d %H:%M:%S")
        scheduled_deletion_at = (now + timedelta(days=ACCOUNT_DELETION_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")

        cur.execute("""
            UPDATE mail_users SET is_disabled=1, disabled_at=?, scheduled_deletion_at=?
            WHERE username=?
        """, (disabled_at, scheduled_deletion_at, username))

        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, "Your HKMail account has been disabled",
             "Your account has been disabled by an HKMail administrator.\n\n"
             "Your account is now disabled. You have "
             f"{ACCOUNT_DELETION_GRACE_DAYS} days (until {scheduled_deletion_at}) to request "
             "reinstatement before it's permanently deleted. Sign in at any point during "
             "this window to request reinstatement.\n\n"
             "— HKMail Support")
        )
        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, ADMIN_MAIL_USERNAME, f"[Account disabled] {username}",
             f"Administrator {admin_username} disabled {username}'s account. "
             f"Scheduled for permanent deletion on {scheduled_deletion_at}.")
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "success": True,
        "message": f"{username}'s account has been disabled and scheduled for deletion on {scheduled_deletion_at}."
    })


@app.route('/api/hkmail/admin/users/reinstate', methods=['POST'])
def hkmail_admin_reinstate_user():
    """Re-enable a disabled account and cancel any pending deletion."""
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403

    data     = request.get_json() or {}
    username = (data.get("username", "") or "").strip().lower()
    admin_username = mail_current_user()
    admin_role = "admin"

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("SELECT is_disabled FROM mail_users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "message": "User not found."}), 404
        if not row[0]:
            return jsonify({"success": False, "message": "This account is not disabled."}), 400

        cur.execute("""
            UPDATE mail_users SET is_disabled=0, disabled_at=NULL, scheduled_deletion_at=NULL
            WHERE username=?
        """, (username,))

        cur.execute("""
            SELECT id FROM mail_support_requests
            WHERE username=? AND request_type='account_deletion' AND status='approved'
        """, (username,))
        for (req_id,) in cur.fetchall():
            cur.execute("""
                UPDATE mail_support_requests
                SET status='cancelled', decided_by=?, decided_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (admin_username, req_id))
            mail_log_support_event(cur, req_id, "status_change", admin_username, admin_role,
                                    old_status="approved", new_status="cancelled",
                                    note="Account reinstated by administrator.")

        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, username, "Your HKMail account has been reinstated",
             "Good news — your account has been reinstated by an HKMail administrator and is "
             "fully active again.\n\nIf you didn't expect this, please contact HKMail Support "
             "immediately.\n\n— HKMail Support")
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": f"{username}'s account has been reinstated."})


@app.route('/api/hkmail/admin/users/delete', methods=['POST'])
def hkmail_admin_delete_user():
    """Immediately and permanently delete a user account (admin action)."""
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403

    data     = request.get_json() or {}
    username = (data.get("username", "") or "").strip().lower()
    admin_username = mail_current_user()

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400
    if username == admin_username:
        return jsonify({"success": False, "message": "You cannot delete your own account."}), 400
    if username in MAIL_PROTECTED_ACCOUNTS:
        return jsonify({"success": False, "message": "This system account can't be deleted."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    try:
        cur.execute("SELECT id FROM mail_users WHERE username=?", (username,))
        if not cur.fetchone():
            return jsonify({"success": False, "message": "User not found."}), 404

        cur.execute("DELETE FROM mail_subscriptions WHERE username=?", (username,))
        cur.execute("DELETE FROM mail_users WHERE username=?", (username,))

        cur.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            (NOREPLY_MAIL_USERNAME, ADMIN_MAIL_USERNAME, f"[Account permanently deleted] {username}",
             f"Administrator {admin_username} permanently deleted the account {username}.")
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": f"{username}'s account has been permanently deleted."})


# ── HKMail: admin — immediately revoke a subscription ─────────────────────────

@app.route('/api/hkmail/admin/subscriptions/<int:sub_id>/revoke', methods=['POST'])
def hkmail_admin_revoke_subscription(sub_id):
    """Immediately end a subscription — unlike a user-initiated cancel (which
    keeps the plan's storage/badge until the paid-for period runs out), this
    removes the row outright so mail_storage_limit_mb() drops that plan's
    storage right away. The affected user is emailed, and a record — with a
    timestamp, the reason given, and which admin did it — is logged as an
    email to admin@hkmail.cn for an audit trail."""
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403

    data   = request.get_json() or {}
    reason = (data.get("reason", "") or "").strip()
    if not reason:
        return jsonify({"success": False, "message": "Please provide a reason for revoking this subscription."}), 400

    admin_username  = mail_current_user()
    admin_full_name = session.get("mail_full_name") or admin_username

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT username, plan_id, status FROM mail_subscriptions WHERE id=?", (sub_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Subscription not found."}), 404

    username, plan_id, status = row
    if status not in ("active", "cancelled"):
        conn.close()
        return jsonify({"success": False, "message": "That subscription is no longer in effect."}), 400

    plan = MAIL_PLANS.get(plan_id)
    plan_label = plan["label"] if plan else plan_id

    cur.execute("DELETE FROM mail_subscriptions WHERE id=?", (sub_id,))

    revoked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Notify the affected user.
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (NOREPLY_MAIL_USERNAME, username, f"Your HKMail {plan_label} subscription has been revoked",
         f"Hi,\n\nAn HKMail administrator has revoked your {plan_label} subscription, effective "
         "immediately. That plan's storage and Premium badge have already been removed — your "
         "storage limit is now the Free 1GB plus any other Premium plans you still hold.\n\n"
         f"Reason given: {reason}\n\n"
         "If you believe this was a mistake, please contact HKMail Support.\n\n"
         "— HKMail")
    )

    # Audit log: a record of who revoked what, when, and why, kept as an
    # email to admin@hkmail.cn alongside HKMail's other administrative mail.
    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
        (NOREPLY_MAIL_USERNAME, ADMIN_MAIL_USERNAME, f"[Subscription revoked] {username} — {plan_label}",
         "A Premium subscription was revoked by an administrator.\n\n"
         f"Timestamp: {revoked_at}\n"
         f"User: {username}\n"
         f"Plan: {plan_label}\n"
         f"Reason: {reason}\n"
         f"Revoked by: {admin_full_name} ({admin_username})")
    )

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"{plan_label} subscription revoked for {username}."})


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


@app.route('/api/hkmail/admin/employee', methods=['POST'])
def hkmail_admin_toggle_employee():
    """Grant or revoke support-staff (Employee) access for account-request management."""
    if not session.get("mail_is_admin"):
        return jsonify({"success": False, "message": "Admin access required."}), 403
    data     = request.get_json() or {}
    username = (data.get("username", "") or "").strip().lower()

    if not username:
        return jsonify({"success": False, "message": "Username required."}), 400
    if username == mail_current_user():
        return jsonify({"success": False, "message": "You cannot change your own role."}), 400
    if username in (ADMIN_MAIL_USERNAME, SYSTEM_MAIL_SENDER, NOREPLY_MAIL_USERNAME,
                    SUPPORT_MAIL_USERNAME, BANK_SUPPORT_MAIL_USERNAME):
        return jsonify({"success": False, "message": "This system account's role can't be changed."}), 400

    conn = sqlite3.connect(MAIL_DATABASE)
    cur  = conn.cursor()
    cur.execute("SELECT is_employee, is_admin FROM mail_users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found."}), 404
    if row[1]:
        conn.close()
        return jsonify({"success": False, "message": "Admins already have support access."}), 400

    new_val = 0 if row[0] else 1
    cur.execute("UPDATE mail_users SET is_employee=? WHERE username=?", (new_val, username))
    conn.commit()
    conn.close()

    action = "granted support staff access" if new_val else "revoked support staff access"
    return jsonify({"success": True, "message": f"{username} has been {action}.", "isEmployee": bool(new_val)})


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