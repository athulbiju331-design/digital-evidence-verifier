import os, re, sqlite3, hashlib, random, smtplib
from datetime import datetime
from functools import wraps
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort

# ---------------- CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "evidence.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

EMAIL_ADDRESS = "your_email@gmail.com"          # 🔴 change
EMAIL_PASSWORD = "your_gmail_app_password"     # 🔴 change

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "super_secret_key"

# ---------------- DB ----------------
def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        position TEXT,
        station TEXT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        approved INTEGER DEFAULT 0,
        reset_otp TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        filename TEXT,
        storage_name TEXT,
        officer TEXT,
        md5 TEXT,
        sha256 TEXT,
        timestamp TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS custody_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        filename TEXT,
        officer TEXT,
        action TEXT,
        status TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

def create_sample_admin():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username='admin'")
    if not cur.fetchone():
        pwd = generate_password_hash("admin123")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
        INSERT INTO users
        (full_name,email,phone,position,station,username,password_hash,role,approved,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """, ("Administrator","admin@example.com","","Admin","HQ","admin",pwd,"admin",1,ts))
        conn.commit()
    conn.close()

# ---------------- UTILS ----------------
EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
PHONE_RE = re.compile(r"^\d{10}$")

def calculate_hashes(path):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk); sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()

def generate_case_id():
    return "CE-" + datetime.now().strftime("%y%m%d") + "-" + str(random.randint(100,999))

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'role' not in session:
                return redirect(url_for('login'))
            if session['role'] not in roles:
                return abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def make_unique_username(full_name, station):
    base = full_name.split()[0].lower()
    st = "".join([c for c in station.lower() if c.isalpha()])[:4] or "stn"
    conn = get_conn(); cur = conn.cursor()
    while True:
        uname = f"{base}.{st}.{random.randint(100,999)}"
        cur.execute("SELECT id FROM users WHERE username=?", (uname,))
        if not cur.fetchone():
            conn.close(); return uname

def send_otp_email(to_email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Password Reset OTP"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    server.send_message(msg)
    server.quit()

# ---------------- AUTH ----------------

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        full_name = request.form["full_name"]
        email = request.form["email"].lower()
        phone = request.form["phone"]
        position = request.form["position"]
        station = request.form["station"]
        password = request.form["password"]

        if not EMAIL_RE.match(email):
            return render_template("signup.html", message="Invalid Email")

        if not PHONE_RE.match(phone):
            return render_template("signup.html", message="Phone must be 10 digits")

        username = make_unique_username(full_name, station)
        pwd_hash = generate_password_hash(password)

        conn = get_conn(); cur = conn.cursor()
        try:
            cur.execute("""
            INSERT INTO users
            (full_name,email,phone,position,station,username,password_hash,role,approved,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (full_name,email,phone,position,station,username,pwd_hash,"officer",0,
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        except:
            conn.close()
            return render_template("signup.html", message="Email Already Exists")

        conn.close()
        return render_template("signup.html", success=True, username=username, email=email)

    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user_input = request.form["username"].lower()
        password = request.form["password"]

        conn = get_conn(); cur = conn.cursor()
        cur.execute("""
        SELECT username,password_hash,role,approved FROM users
        WHERE lower(username)=? OR lower(email)=?
        """, (user_input,user_input))
        u = cur.fetchone()
        conn.close()

        if not u or not check_password_hash(u["password_hash"], password):
            return render_template("login.html", message="Invalid Login")

        if u["role"] != "admin" and u["approved"] != 1:
            return render_template("login.html", message="Waiting for Admin Approval")

        session["username"] = u["username"]
        session["role"] = u["role"]

        return redirect(url_for("dashboard" if u["role"]=="admin" else "index"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- FORGOT PASSWORD ----------------

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        otp = request.form.get("otp")
        new_password = request.form.get("new_password")

        conn = get_conn(); cur = conn.cursor()

        if email and not otp:
            cur.execute("SELECT id FROM users WHERE email=?", (email,))
            if not cur.fetchone():
                return render_template("forgot_password.html", step="email", message="Email Not Found")

            otp_code = str(random.randint(100000,999999))
            cur.execute("UPDATE users SET reset_otp=? WHERE email=?", (otp_code,email))
            conn.commit()
            send_otp_email(email, otp_code)
            return render_template("forgot_password.html", step="otp", email=email)

        if email and otp and new_password:
            cur.execute("SELECT reset_otp FROM users WHERE email=?", (email,))
            row = cur.fetchone()

            if not row or row["reset_otp"] != otp:
                return render_template("forgot_password.html", step="otp", message="Invalid OTP")

            cur.execute("UPDATE users SET password_hash=?, reset_otp=NULL WHERE email=?",
                        (generate_password_hash(new_password),email))
            conn.commit()
            return redirect(url_for("login"))

    return render_template("forgot_password.html", step="email")

# ---------------- OFFICER ----------------

@app.route("/")
@role_required("officer")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
@role_required("officer")
def upload():
    file = request.files["file"]
    filename = secure_filename(file.filename)
    storage = datetime.now().strftime("%Y%m%d%H%M%S_") + filename
    path = os.path.join(UPLOAD_FOLDER, storage)
    file.save(path)

    md5, sha = calculate_hashes(path)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
    INSERT INTO evidence
    (case_id,filename,storage_name,officer,md5,sha256,timestamp)
    VALUES (?,?,?,?,?,?,?)
    """, (generate_case_id(),filename,storage,session["username"],md5,sha,
          datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit(); conn.close()

    flash("Evidence Uploaded Successfully")
    return redirect(url_for("index"))

@app.route("/view")
@role_required("officer","admin")
def view():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM evidence ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    return render_template("view.html", evidence=rows)

# ✅✅✅ VERIFY ROUTE — THIS FIXES YOUR ERROR ✅✅✅
@app.route("/verify/<int:evidence_id>", methods=["GET","POST"])
@role_required("officer","admin")
def verify(evidence_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        abort(404)

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected")
            return redirect(request.url)

        file = request.files["file"]
        tmp_path = os.path.join(UPLOAD_FOLDER, "tmp_" + file.filename)
        file.save(tmp_path)

        _, current_sha = calculate_hashes(tmp_path)
        os.remove(tmp_path)

        if current_sha == row["sha256"]:
            flash("✅ File Verified — No Tampering", "success")
        else:
            flash("🚨 Tampering Detected", "danger")

    return render_template("verify.html", row=row)

# ---------------- ADMIN ----------------

@app.route("/dashboard")
@role_required("admin")
def dashboard():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    conn.close()
    return render_template("dashboard.html", users=users)

@app.route("/approve_user/<int:user_id>", methods=["POST"])
@role_required("admin")
def approve_user(user_id):
    action = request.form["action"]
    conn = get_conn(); cur = conn.cursor()

    if action == "approve":
        cur.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))

    conn.commit(); conn.close()
    return redirect(url_for("dashboard"))

# ---------------- START ----------------
if __name__ == "__main__":
    init_db()
    create_sample_admin()
    app.run(debug=True)
