from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import psycopg2
import psycopg2.extras
import os
import jwt
import bcrypt
import datetime
import smtplib
import imaplib
import poplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from functools import wraps
import time

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey123")
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

SECRET_KEY     = os.environ.get("SECRET_KEY", "supersecretkey123")
GMAIL_USER     = os.environ.get("GMAIL_USER", "")
GMAIL_PASSWORD = os.environ.get("GMAIL_PASSWORD", "")

# ─── DB ───────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "postgres"),
        database=os.environ.get("DB_NAME", "tododb"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD", "postgres")
    )

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(100) UNIQUE NOT NULL,
            email         VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS categories (
            id      SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name    VARCHAR(100) NOT NULL,
            color   VARCHAR(20) DEFAULT '#6366f1'
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
            category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
            title       VARCHAR(255) NOT NULL,
            description TEXT,
            priority    VARCHAR(20) DEFAULT 'medium',
            deadline    DATE,
            done        BOOLEAN DEFAULT FALSE,
            created_at  TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS notes (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title      VARCHAR(255) NOT NULL,
            content    TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

# ─── AUTH ─────────────────────────────────────────────────────────

def make_token(user_id):
    return jwt.encode(
        {"user_id": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)},
        SECRET_KEY, algorithm="HS256"
    )

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth  = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data    = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = data["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(user_id, *args, **kwargs)
    return decorated

@app.route("/auth/register", methods=["POST"])
def register():
    data     = request.json or {}
    username = data.get("username", "").strip()
    email_   = data.get("email", "").strip()
    password = data.get("password", "")
    if not username or not email_ or not password:
        return jsonify({"error": "All fields required"}), 400
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (username, email_, pw_hash)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Email or username already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"token": make_token(user_id), "username": username}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    data     = request.json or {}
    email_   = data.get("email", "").strip()
    password = data.get("password", "")
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT id, username, password_hash FROM users WHERE email=%s", (email_,))
        row = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    if row is None or not bcrypt.checkpw(password.encode(), row[2].encode()):
        return jsonify({"error": "Invalid email or password"}), 401
    return jsonify({"token": make_token(row[0]), "username": row[1]}), 200

# ─── CATEGORIES ───────────────────────────────────────────────────

@app.route("/categories", methods=["GET"])
@token_required
def get_categories(user_id):
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM categories WHERE user_id=%s ORDER BY id", (user_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route("/categories", methods=["POST"])
@token_required
def create_category(user_id):
    data = request.json or {}
    if not data.get("name"):
        return jsonify({"error": "Name required"}), 400
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "INSERT INTO categories (user_id, name, color) VALUES (%s, %s, %s) RETURNING *",
        (user_id, data["name"], data.get("color", "#6366f1"))
    )
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(row)), 201

@app.route("/categories/<int:cat_id>", methods=["DELETE"])
@token_required
def delete_category(user_id, cat_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM categories WHERE id=%s AND user_id=%s", (cat_id, user_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Deleted"}), 200

# ─── TASKS ────────────────────────────────────────────────────────

def serialize_task(r):
    d = dict(r)
    if d.get("deadline"):   d["deadline"]   = d["deadline"].isoformat()
    if d.get("created_at"): d["created_at"] = d["created_at"].isoformat()
    return d

@app.route("/tasks", methods=["GET"])
@token_required
def get_tasks(user_id):
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT t.*, c.name as category_name, c.color as category_color
        FROM tasks t LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = %s ORDER BY t.created_at DESC
    """, (user_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([serialize_task(r) for r in rows]), 200

@app.route("/tasks/<int:task_id>", methods=["GET"])
@token_required
def get_task(user_id, task_id):
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM tasks WHERE id=%s AND user_id=%s", (task_id, user_id))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(serialize_task(row)), 200

@app.route("/tasks", methods=["POST"])
@token_required
def create_task(user_id):
    data = request.json or {}
    if not data.get("title"):
        return jsonify({"error": "Title required"}), 400
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO tasks (user_id, category_id, title, description, priority, deadline)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING *
    """, (
        user_id,
        data.get("category_id") or None,
        data["title"],
        data.get("description", ""),
        data.get("priority", "medium"),
        data.get("deadline") or None
    ))
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    task = serialize_task(row)
    # WebSocket — уведомляем всех подключённых клиентов
    socketio.emit("task_created", task)
    return jsonify(task), 201

@app.route("/tasks/<int:task_id>", methods=["PUT"])
@token_required
def update_task(user_id, task_id):
    data = request.json or {}
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        UPDATE tasks SET title=%s, description=%s, priority=%s,
        deadline=%s, category_id=%s, done=%s
        WHERE id=%s AND user_id=%s
    """, (
        data.get("title", ""),
        data.get("description", ""),
        data.get("priority", "medium"),
        data.get("deadline") or None,
        data.get("category_id") or None,
        data.get("done", False),
        task_id, user_id
    ))
    conn.commit()
    cur.close()
    conn.close()
    # WebSocket — уведомляем всех
    socketio.emit("task_updated", {"id": task_id, "done": data.get("done", False), "title": data.get("title", "")})
    return jsonify({"message": "Updated"}), 200

@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@token_required
def delete_task(user_id, task_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM tasks WHERE id=%s AND user_id=%s", (task_id, user_id))
    conn.commit()
    cur.close()
    conn.close()
    # WebSocket — уведомляем всех
    socketio.emit("task_deleted", {"id": task_id})
    return jsonify({"message": "Deleted"}), 200

@app.route("/tasks/<int:task_id>/complete", methods=["POST"])
@token_required
def complete_task(user_id, task_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "UPDATE tasks SET done=TRUE WHERE id=%s AND user_id=%s RETURNING title",
        (task_id, user_id)
    )
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if row is None:
        return jsonify({"error": "Not found"}), 404
    # WebSocket — уведомляем всех
    socketio.emit("task_updated", {"id": task_id, "done": True, "title": row[0]})
    if GMAIL_USER and GMAIL_PASSWORD:
        try:
            send_email(GMAIL_USER, f"Задача выполнена: {row[0]}",
                       f"Задача '{row[0]}' отмечена как выполненная.")
        except Exception:
            pass
    return jsonify({"message": "Task completed"}), 200

# ─── NOTES ────────────────────────────────────────────────────────

def serialize_note(r):
    d = dict(r)
    if d.get("created_at"): d["created_at"] = d["created_at"].isoformat()
    if d.get("updated_at"): d["updated_at"] = d["updated_at"].isoformat()
    return d

@app.route("/notes", methods=["GET"])
@token_required
def get_notes(user_id):
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM notes WHERE user_id=%s ORDER BY updated_at DESC", (user_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([serialize_note(r) for r in rows]), 200

@app.route("/notes", methods=["POST"])
@token_required
def create_note(user_id):
    data = request.json or {}
    if not data.get("title"):
        return jsonify({"error": "Title required"}), 400
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (%s, %s, %s) RETURNING *",
        (user_id, data["title"], data.get("content", ""))
    )
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(serialize_note(row)), 201

@app.route("/notes/<int:note_id>", methods=["PUT"])
@token_required
def update_note(user_id, note_id):
    data = request.json or {}
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "UPDATE notes SET title=%s, content=%s, updated_at=NOW() WHERE id=%s AND user_id=%s",
        (data.get("title", ""), data.get("content", ""), note_id, user_id)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Updated"}), 200

@app.route("/notes/<int:note_id>", methods=["DELETE"])
@token_required
def delete_note(user_id, note_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM notes WHERE id=%s AND user_id=%s", (note_id, user_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Deleted"}), 200

# ─── EMAIL ────────────────────────────────────────────────────────

def send_email(to, subject, body):
    msg = MIMEMultipart()
    msg["From"]    = GMAIL_USER
    msg["To"]      = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))
    with smtplib.SMTP_SSL("smtp.mail.me.com", 465) as s:
        s.login(GMAIL_USER, GMAIL_PASSWORD)
        s.sendmail(GMAIL_USER, to, msg.as_string())

@app.route("/email/send", methods=["POST"])
@token_required
def email_send(user_id):
    data = request.json or {}
    if not GMAIL_USER or not GMAIL_PASSWORD:
        return jsonify({"error": "Email not configured"}), 500
    try:
        send_email(data["to"], data["subject"], data["body"])
        return jsonify({"message": "Email sent"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/email/imap", methods=["GET"])
@token_required
def email_imap(user_id):
    if not GMAIL_USER or not GMAIL_PASSWORD:
        return jsonify({"error": "Email not configured"}), 500
    try:
        mail = imaplib.IMAP4_SSL("imap.mail.me.com", 993)
        mail.login(GMAIL_USER, GMAIL_PASSWORD)
        mail.select("inbox")
        _, data = mail.search(None, "ALL")
        ids   = data[0].split()
        last5 = ids[-5:] if len(ids) >= 5 else ids
        messages = []
        for uid in reversed(last5):
            _, msg_data = mail.fetch(uid, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            subject, enc = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(enc or "utf-8")
            messages.append({"subject": subject, "from": msg.get("From", ""), "date": msg.get("Date", "")})
        mail.logout()
        return jsonify(messages), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/email/pop3", methods=["GET"])
@token_required
def email_pop3(user_id):
    if not GMAIL_USER or not GMAIL_PASSWORD:
        return jsonify({"error": "Email not configured"}), 500
    try:
        mail  = poplib.POP3_SSL("mail.me.com", 995)
        mail.user(GMAIL_USER)
        mail.pass_(GMAIL_PASSWORD)
        count = len(mail.list()[1])
        messages = []
        start = max(1, count - 4)
        for i in range(count, start - 1, -1):
            raw = b"\n".join(mail.retr(i)[1])
            msg = email.message_from_bytes(raw)
            subject, enc = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(enc or "utf-8")
            messages.append({"subject": subject, "from": msg.get("From", ""), "date": msg.get("Date", "")})
        mail.quit()
        return jsonify(messages), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── WEBSOCKET EVENTS ─────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    print(f"Client connected: {request.sid}")
    emit("connected", {"message": "WebSocket connected"})

@socketio.on("disconnect")
def on_disconnect():
    print(f"Client disconnected: {request.sid}")

@socketio.on("ping")
def on_ping():
    emit("pong", {"message": "pong"})

# ─── START ────────────────────────────────────────────────────────

if __name__ == "__main__":
    for i in range(10):
        try:
            init_db()
            print("DB initialized successfully")
            break
        except Exception as e:
            print(f"Waiting for DB... ({i+1}/10): {e}")
            time.sleep(3)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)