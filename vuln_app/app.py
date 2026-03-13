"""
vuln_app/app.py
---------------
A deliberately vulnerable Flask application used as WATCHDOG's scanning target.
DO NOT deploy this in production — it contains intentional security flaws
that serve as demonstration targets for the WATCHDOG agent pipeline.

Vulnerabilities present (for educational purposes only):
  1. SQL Injection  — /login  (line ~60)
  2. IDOR           — /delete_note/<note_id>  (line ~100)
  3. Hardcoded secret key — app.secret_key  (line ~30)
"""

from flask import Flask, request, session, redirect, url_for, jsonify, render_template_string
import sqlite3, os

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY #3 — Hardcoded secret key.
# Any attacker who reads this source file can forge session cookies.
# Fix: use os.environ.get("SECRET_KEY") or secrets.token_hex(32)
# ─────────────────────────────────────────────────────────────────────────────
app.secret_key = "super_secret_watchdog_demo_key_1234"  # VULN-003: hardcoded secret

# ── In-memory data stores ─────────────────────────────────────────────────────
# Users: {username: password}  (plaintext — also intentional for demo simplicity)
USERS: dict[str, str] = {
    "alice": "password123",
    "bob": "letmein",
}

# Notes: list of dicts {id, owner, content}
NOTES: list[dict] = [
    {"id": 1, "owner": "alice", "content": "Alice's private note"},
    {"id": 2, "owner": "alice", "content": "Alice's bank PIN is 4242"},
    {"id": 3, "owner": "bob",   "content": "Bob's todo list"},
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_db():
    """Return an in-memory SQLite connection pre-populated with the USERS dict."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    for u, p in USERS.items():
        conn.execute("INSERT INTO users VALUES (?, ?)", (u, p))
    conn.commit()
    return conn

# ── Routes ────────────────────────────────────────────────────────────────────

LOGIN_HTML = """
<h2>WATCHDOG Demo Login</h2>
<form method="POST">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login endpoint.

    VULNERABILITY #1 — SQL Injection.
    The username is embedded directly into the SQL query string using
    Python string concatenation.  An attacker can supply:
        username: ' OR '1'='1
    to bypass authentication entirely.

    Fix: use parameterised queries → cursor.execute("SELECT … WHERE username=?", (username,))
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = _get_db()
        # ── VULN-001: SQL injection via string concatenation ──────────────────
        query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
        # Fix would be: cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        try:
            cursor = conn.execute(query)  # VULN-001
            user = cursor.fetchone()
        except sqlite3.OperationalError as exc:
            error = f"DB error: {exc}"
            user = None
        finally:
            conn.close()

        if user:
            session["username"] = user[0]
            return redirect(url_for("notes"))
        else:
            error = "Invalid credentials."

    return render_template_string(LOGIN_HTML, error=error)


@app.route("/notes")
def notes():
    """Return notes belonging to the currently logged-in user."""
    if "username" not in session:
        return redirect(url_for("login"))
    user_notes = [n for n in NOTES if n["owner"] == session["username"]]
    return jsonify({"user": session["username"], "notes": user_notes})


@app.route("/delete_note/<int:note_id>", methods=["POST"])
def delete_note(note_id: int):
    """
    Delete a note by ID.

    VULNERABILITY #2 — Insecure Direct Object Reference (IDOR).
    The endpoint does NOT verify that the note with `note_id` belongs
    to the currently logged-in user.  Any authenticated user can delete
    any other user's note by simply changing the ID in the URL.

    Fix: verify  note["owner"] == session["username"]  before deleting.
    """
    if "username" not in session:
        return jsonify({"error": "Unauthorised"}), 401

    # ── VULN-002: IDOR — no ownership check ───────────────────────────────────
    for i, note in enumerate(NOTES):
        if note["id"] == note_id:
            # Missing check: if note["owner"] != session["username"]: abort(403)
            NOTES.pop(i)  # VULN-002: any user can delete any note
            return jsonify({"deleted": note_id})

    return jsonify({"error": "Note not found"}), 404


@app.route("/logout", methods=["POST", "GET"])
def logout():
    """Clear the session and redirect to login."""
    session.clear()
    return redirect(url_for("login"))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5001)
