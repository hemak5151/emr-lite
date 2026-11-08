#!/usr/bin/env python3
"""EMR Lite: dependency-free local demonstration application.

Uses only Python's standard library. Not for real patient data or production use.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from pathlib import Path
from contextlib import contextmanager
from datetime import date
import hashlib, hmac, html, secrets, sqlite3, time

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "data" / "emr.sqlite3"
HOST, PORT = "127.0.0.1", 8000
SESSION_SECONDS = 8 *  60 * 60
SEXES = {"Not specified", "Female", "Male", "Other"}
MAX_FAILS, LOCK_SECONDS = 5, 300
FAILS = {}  # (ip, username) -> recent failure timestamps (in memory only)


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


@contextmanager
def conn():
    """Open, commit and always close a connection (sqlite3's own `with` does not close)."""
    con = db()
    try:
        with con:
            yield con
    finally:
        con.close()


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + ":" + digest.hex()


DUMMY_HASH = None


def password_ok(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def init_db():
    with conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL, full_name TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('doctor','nurse','hospital_admin','system_admin')),
          active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS patients (
          id INTEGER PRIMARY KEY, global_id TEXT UNIQUE NOT NULL,
          local_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
          dob TEXT NOT NULL, sex TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS records (
          id INTEGER PRIMARY KEY, patient_id INTEGER NOT NULL REFERENCES patients(id),
          category TEXT NOT NULL, content TEXT NOT NULL, author_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'Draft'
        );
        CREATE TABLE IF NOT EXISTS record_versions (
          id INTEGER PRIMARY KEY, record_id INTEGER NOT NULL REFERENCES records(id),
          version INTEGER NOT NULL, category TEXT NOT NULL, content TEXT NOT NULL,
          changed_by INTEGER NOT NULL REFERENCES users(id), changed_at TEXT NOT NULL,
          reason TEXT NOT NULL, UNIQUE(record_id, version)
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL,
          resource TEXT NOT NULL, outcome TEXT NOT NULL, detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
        );
        """)
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            demo = [
              ("doctor", "Doctor Demo", "doctor"),
              ("nurse", "Nurse Demo", "nurse"),
              ("admin", "Hospital Admin", "hospital_admin"),
              ("sysadmin", "System Admin", "system_admin"),
            ]
            for username, full_name, role in demo:
                con.execute("INSERT INTO users(username,password,full_name,role) VALUES(?,?,?,?)",
                            (username, password_hash("ChangeMe123!"), full_name, role))
        if con.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 0:
            now = stamp()
            con.execute("INSERT INTO patients(global_id,local_id,name,dob,sex,created_at) VALUES(?,?,?,?,?,?)",
                        ("G-PAT-0001", "HOSP-0001", "Aarav Demo", "1998-04-12", "Not specified", now))


def stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def page(title, body, user=None):
    nav = ""
    if user:
        nav = f'''<div class="nav"><span>Signed in as <b>{esc(user['full_name'])}</b> · {esc(user['role'].replace('_',' ').title())}</span>
        <form method="post" action="/logout"><input type="hidden" name="csrf" value="{esc(user['csrf'])}"><button class="secondary">Log out</button></form></div>'''
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{esc(title)} · EMR Lite</title><link rel="stylesheet" href="/static/style.css"></head><body><header><div class="brand">EMR <span>Lite</span></div>{nav}</header>
    <main><h1>{esc(title)}</h1>{body}</main><footer>EMR Lite · Local demonstration · Use synthetic data only</footer></body></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "EMRLite/1.0"

    def log_message(self, fmt, *args):
        # Avoid writing request details (which may contain identifiers) to console.
        pass

    def send_html(self, body, status=200, cookie=None):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, path, cookie=None):
        self.send_response(303)
        self.send_header("Location", path)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def form(self):
        try:
            length = max(0, min(int(self.headers.get("Content-Length", "0") or 0), 100_000))
        except ValueError:
            length = 0
        data = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(data, keep_blank_values=True).items()}

    def session_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == "emr_session": return value
        return None

    def current_user(self):
        token = self.session_token()
        if not token: return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with conn() as con:
            row = con.execute("SELECT s.csrf,s.expires_at,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (token_hash,)).fetchone()
            if not row or row["expires_at"] < int(time.time()) or not row["active"]:
                con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                return None
            return {"id": row["id"], "username": row["username"], "full_name": row["full_name"], "role": row["role"], "csrf": row["csrf"]}

    def audit(self, user, action, resource, outcome="success", detail=""):
        with conn() as con:
            con.execute("INSERT INTO audit(user_id,action,resource,outcome,detail,created_at) VALUES(?,?,?,?,?,?)",
                        (user["id"] if user else None, action, resource, outcome, detail[:500], stamp()))

    def require_csrf(self, user, data):
        return bool(user and data.get("csrf") and hmac.compare_digest(data["csrf"], user["csrf"]))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/static/style.css":
            raw = (BASE / "static" / "style.css").read_bytes()
            self.send_response(200); self.send_header("Content-Type", "text/css; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(raw); return
        user = self.current_user()
        if path == "/" or path == "/login":
            if user: return self.redirect("/dashboard")
            body = '''<section class="panel narrow"><p class="muted">Secure local EMR demonstration</p><form method="post" action="/login">
            <label>Username<input name="username" autocomplete="username" required maxlength="60"></label>
            <label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="200"></label>
            <button>Sign in</button></form><p class="hint">Demo accounts and setup instructions are in README.md.</p></section>'''
            return self.send_html(page("Sign in", body))
        if not user:
            return self.redirect("/login")
        if path == "/dashboard":
            body = '<section class="grid">'
            if user["role"] in ("hospital_admin", "system_admin"):
                body += '<a class="tile" href="/patients">Patient registration and directory</a>'
            if user["role"] in ("doctor", "nurse"):
                body += '<a class="tile" href="/patients">Find patient records</a>'
            if user["role"] == "system_admin": body += '<a class="tile" href="/audit">Audit history</a>'
            body += '</section><p class="notice">Access is enforced on the server. A hidden button is not treated as a security boundary.</p>'
            return self.send_html(page("Dashboard", body, user))
        if path == "/patients":
            with conn() as con: rows = con.execute("SELECT id,global_id,local_id,name,dob FROM patients ORDER BY name").fetchall()
            items = ''.join(f'<tr><td>{esc(r["global_id"])}</td><td>{esc(r["local_id"])}</td><td>{esc(r["name"])}</td><td>{esc(r["dob"])}</td><td><a href="/patient?id={r["id"]}">Open</a></td></tr>' for r in rows)
            create = ''
            if user["role"] in ("hospital_admin", "system_admin"):
                create = f'''<section class="panel"><h2>Register patient</h2><form method="post" action="/patients/create"><input type="hidden" name="csrf" value="{esc(user['csrf'])}">
                <div class="formgrid"><label>Patient name<input name="name" required maxlength="120"></label><label>Date of birth<input type="date" name="dob" required></label><label>Sex / not specified<select name="sex"><option>Not specified</option><option>Female</option><option>Male</option><option>Other</option></select></label></div><button>Register patient</button></form></section>'''
            body = create + f'<section class="panel"><h2>Patient directory</h2><div class="tablewrap"><table><thead><tr><th>Global ID</th><th>Local ID</th><th>Name</th><th>Date of birth</th><th></th></tr></thead><tbody>{items or "<tr><td colspan=5>No patients registered.</td></tr>"}</tbody></table></div></section>'
            return self.send_html(page("Patients", body, user))
        if path == "/patient":
            try: pid = int(parse_qs(urlparse(self.path).query).get("id", [""])[0])
            except ValueError: return self.send_html(page("Not found", "<p>Invalid patient.</p>", user), 404)
            with conn() as con:
                patient = con.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
                records = con.execute("SELECT r.*,u.full_name FROM records r JOIN users u ON u.id=r.author_id WHERE patient_id=? ORDER BY r.id DESC", (pid,)).fetchall() if user["role"] in ("doctor", "nurse") else []
            if not patient: return self.send_html(page("Not found", "<p>Patient not found.</p>", user), 404)
            self.audit(user, "PATIENT_VIEW", f"patient:{pid}")
            add = ''
            if user["role"] in ("doctor", "nurse"):
                cats = ['Consultation note','Diagnosis','Laboratory report','Prescription','Allergy','Nursing observation','Discharge summary']
                opts = ''.join(f'<option>{esc(c)}</option>' for c in cats)
                add = f'''<section class="panel"><h2>Add clinical record</h2><form method="post" action="/records/create"><input type="hidden" name="csrf" value="{esc(user['csrf'])}"><input type="hidden" name="patient_id" value="{pid}">
                <label>Category<select name="category">{opts}</select></label><label>Record details<textarea name="content" required maxlength="10000" rows="5"></textarea></label><button>Save draft</button></form></section>'''
            record_html = ''
            if user["role"] in ("doctor", "nurse"):
                for r in records:
                    amend = ''
                    if user["role"] == "doctor" and r["status"] != "Entered in error":
                        amend = f'''<details><summary>Amend record</summary><form method="post" action="/records/amend"><input type="hidden" name="csrf" value="{esc(user['csrf'])}"><input type="hidden" name="record_id" value="{r['id']}"><input type="hidden" name="version" value="{r['version']}"><label>Reason for amendment<input name="reason" required maxlength="300"></label><label>Updated content<textarea name="content" required maxlength="10000">{esc(r['content'])}</textarea></label><button>Save new version</button></form></details>'''
                    record_html += f'<article class="record"><div class="recordhead"><b>{esc(r["category"])}</b><span>v{r["version"]} · {esc(r["status"])}</span></div><p>{esc(r["content"])}</p><small>By {esc(r["full_name"])} · {esc(r["created_at"])}</small>{amend}</article>'
            else:
                record_html = '<p class="notice">Clinical records are restricted to authorised clinical roles. Administrative access does not grant clinical access.</p>'
            body = f'''<section class="panel"><div class="recordhead"><h2>{esc(patient['name'])}</h2><span>{esc(patient['global_id'])}</span></div><p>Local ID: {esc(patient['local_id'])} · DOB: {esc(patient['dob'])} · Sex: {esc(patient['sex'])}</p></section>{add}<section class="panel"><h2>Clinical history</h2>{record_html or '<p class="muted">No clinical records available.</p>'}</section><p><a href="/patients">← Back to patients</a></p>'''
            return self.send_html(page("Patient record", body, user))
        if path == "/audit":
            if user["role"] != "system_admin": return self.forbidden(user, "audit_view")
            with conn() as con: rows = con.execute("SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200").fetchall()
            table = ''.join(f'<tr><td>{esc(r["created_at"])}</td><td>{esc(r["username"] or "system")}</td><td>{esc(r["action"])}</td><td>{esc(r["resource"])}</td><td>{esc(r["outcome"])}</td></tr>' for r in rows)
            return self.send_html(page("Audit history", f'<section class="panel tablewrap"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>Outcome</th></tr></thead><tbody>{table}</tbody></table></section>', user))
        return self.send_html(page("Not found", "<p>The requested page does not exist.</p>", user), 404)

    def forbidden(self, user, resource):
        self.audit(user, "ACCESS_DENIED", resource, "denied")
        return self.send_html(page("Access denied", '<p class="notice">Your role is not authorised to perform this action.</p><p><a href="/dashboard">Return to dashboard</a></p>', user), 403)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.form()
        if path == "/login":
            username, password = data.get("username", "").strip()[:60], data.get("password", "")[:200]
            key, now_t = (self.client_address[0], username.lower()), time.time()
            recent = [t for t in FAILS.get(key, []) if now_t - t < LOCK_SECONDS]
            if len(recent) >= MAX_FAILS:
                self.audit(None, "LOGIN", "account", "denied", "Locked out: too many attempts")
                return self.send_html(page("Sign in", '<p class="error">Too many failed attempts. Try again in a few minutes.</p>'), 429)
            with conn() as con: user = con.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
            ok = password_ok(password, user["password"] if user else DUMMY_HASH)  # same work either way
            if not user or not ok:
                FAILS[key] = recent + [now_t]
                self.audit(None, "LOGIN", "account", "denied", "Invalid credentials")
                return self.send_html(page("Sign in", '<p class="error">Invalid username or password.</p><p><a href="/login">Try again</a></p>'), 401)
            FAILS.pop(key, None)
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            with conn() as con:
                con.execute("DELETE FROM sessions WHERE expires_at<?", (int(time.time()),))
                con.execute("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)",
                            (hashlib.sha256(token.encode()).hexdigest(), user["id"], csrf, int(time.time()) + SESSION_SECONDS))
            self.audit({"id": user["id"]}, "LOGIN", "account")
            return self.redirect("/dashboard", f"emr_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}")
        user = self.current_user()
        if not user: return self.redirect("/login")
        if path == "/logout":
            if not self.require_csrf(user, data): return self.send_html(page("Request rejected", "<p>Invalid security token.</p>", user), 403)
            token = self.session_token() or ""
            with conn() as con: con.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
            self.audit(user, "LOGOUT", "account")
            return self.redirect("/login", "emr_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        if not self.require_csrf(user, data):
            self.audit(user, "CSRF_REJECTED", path, "denied")
            return self.send_html(page("Request rejected", "<p>Invalid security token. Reload and try again.</p>", user), 403)
        if path == "/patients/create":
            if user["role"] not in ("hospital_admin", "system_admin"): return self.forbidden(user, "patient_create")
            name, dob, sex = data.get("name", "").strip(), data.get("dob", ""), data.get("sex", "Not specified")
            try: dob_ok = date(1900, 1, 1) <= date.fromisoformat(dob) <= date.today()
            except ValueError: dob_ok = False
            if not name or len(name) > 120 or not dob_ok or sex not in SEXES:
                return self.send_html(page("Invalid input", "<p>Please provide a valid name and date of birth.</p>", user), 400)
            with conn() as con:
                tmp = secrets.token_hex(8)  # unique placeholder, replaced by id-based IDs below
                pid = con.execute("INSERT INTO patients(global_id,local_id,name,dob,sex,created_at) VALUES(?,?,?,?,?,?)",
                                  (tmp, tmp, name, dob, sex, stamp())).lastrowid
                con.execute("UPDATE patients SET global_id=?, local_id=? WHERE id=?",
                            (f"G-PAT-{pid:04d}", f"HOSP-{pid:04d}", pid))
            self.audit(user, "PATIENT_CREATE", f"patient:{pid}")
            return self.redirect(f"/patient?id={pid}")
        if path == "/records/create":
            if user["role"] not in ("doctor", "nurse"): return self.forbidden(user, "record_create")
            try: pid = int(data.get("patient_id", ""))
            except ValueError: return self.send_html(page("Invalid input", "<p>Invalid patient.</p>", user), 400)
            category, content = data.get("category", ""), data.get("content", "").strip()
            allowed = {'Consultation note','Diagnosis','Laboratory report','Prescription','Allergy','Nursing observation','Discharge summary'}
            if category not in allowed or not content or len(content) > 10000:
                return self.send_html(page("Invalid input", "<p>Check the category and record content.</p>", user), 400)
            if user["role"] == "nurse" and category != "Nursing observation": return self.forbidden(user, "record_category")
            with conn() as con:
                if not con.execute("SELECT 1 FROM patients WHERE id=?", (pid,)).fetchone(): return self.send_html(page("Not found", "<p>Patient not found.</p>", user), 404)
                now = stamp()
                cur = con.execute("INSERT INTO records(patient_id,category,content,author_id,created_at,updated_at) VALUES(?,?,?,?,?,?)", (pid,category,content,user["id"],now,now))
                rid = cur.lastrowid
                con.execute("INSERT INTO record_versions(record_id,version,category,content,changed_by,changed_at,reason) VALUES(?,?,?,?,?,?,?)", (rid,1,category,content,user["id"],now,"Initial entry"))
            self.audit(user, "RECORD_CREATE", f"record:{rid}")
            return self.redirect(f"/patient?id={pid}")
        if path == "/records/amend":
            if user["role"] != "doctor": return self.forbidden(user, "record_amend")
            try: rid, expected = int(data.get("record_id", "")), int(data.get("version", ""))
            except ValueError: return self.send_html(page("Invalid input", "<p>Invalid record/version.</p>", user), 400)
            content, reason = data.get("content", "").strip(), data.get("reason", "").strip()
            if not content or len(content)>10000 or not reason or len(reason)>300: return self.send_html(page("Invalid input", "<p>Provide updated content and a reason.</p>", user), 400)
            with conn() as con:
                row = con.execute("SELECT * FROM records WHERE id=?", (rid,)).fetchone()
                if not row: return self.send_html(page("Not found", "<p>Record not found.</p>", user), 404)
                if row["status"] == "Entered in error": return self.send_html(page("Not allowed", '<p class="notice">This record is closed and cannot be amended.</p>', user), 409)
                if row["version"] != expected:
                    self.audit(user, "RECORD_AMEND_CONFLICT", f"record:{rid}", "conflict", f"Expected {expected}; current {row['version']}")
                    return self.send_html(page("Version conflict", '<p class="notice">Another update has been saved. Reload the latest record before trying again.</p><p><a href="/patient?id='+str(row['patient_id'])+'">Return to record</a></p>', user), 409)
                new_version, now = expected+1, stamp()
                if con.execute("UPDATE records SET content=?,version=?,updated_at=?,status='Amended' WHERE id=? AND version=?", (content,new_version,now,rid,expected)).rowcount != 1:
                    return self.send_html(page("Version conflict", '<p class="notice">Another update has been saved. Reload and try again.</p>', user), 409)
                con.execute("INSERT INTO record_versions(record_id,version,category,content,changed_by,changed_at,reason) VALUES(?,?,?,?,?,?,?)", (rid,new_version,row['category'],content,user['id'],now,reason))
                pid = row["patient_id"]
            self.audit(user, "RECORD_AMEND", f"record:{rid}", "success", f"Version {new_version}; reason: {reason}")
            return self.redirect(f"/patient?id={pid}")
        return self.send_html(page("Not found", "<p>The requested action does not exist.</p>", user), 404)


def main():
    global DUMMY_HASH
    DUMMY_HASH = password_hash("not-a-real-password")
    init_db()
    print(f"EMR Lite running at http://{HOST}:{PORT}")
    print("Use synthetic data only. Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()
