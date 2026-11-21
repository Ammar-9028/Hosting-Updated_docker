import csv
import hashlib
import io
import json
import re
import secrets
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, send_file,
                   session)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from . import db as dbm
from . import rdap
from . import sites as S
from .config import Config
from .security import RateLimiter, csrf_ok, csrf_token

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
CSRF_EXEMPT = ("/f/", "/api/v1/")          # form endpoint (public) and bearer-token API
MAX_SUBMISSIONS = 500


def _secret(cfg):
    f = cfg.data_dir / "secret_key"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
        f.chmod(0o600)
    return f.read_text().strip()


def create_app(env=None):
    cfg = Config(env)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    (cfg.data_dir / "sites").mkdir(exist_ok=True)
    db_path = str(cfg.data_dir / "nesthost.db")
    dbm.init(db_path)

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_secret(cfg),
        MAX_CONTENT_LENGTH=(cfg.max_site_mb + 2) * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=cfg.secure,
        # __Host- cookies cannot be set or overwritten by user sites living on sibling subdomains
        SESSION_COOKIE_NAME="__Host-session" if cfg.secure else "session",
        PERMANENT_SESSION_LIFETIME=14 * 24 * 3600)
    if cfg.trust_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    limiter = RateLimiter()
    app.teardown_appcontext(dbm.close)
    app.extensions["cfg"] = cfg

    def db():
        return dbm.get(db_path)

    def today():
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ------------------------------------------------------------------ virtual hosting
    def classify(host):
        base = cfg.base_domain
        if host in (base, "www." + base):
            return "platform", None
        if host.endswith("." + base):
            sub = host[: -len(base) - 1]
            row = db().execute("SELECT * FROM sites WHERE subdomain=?", (sub,)).fetchone() if "." not in sub else None
            return ("site", row) if row else ("missing", sub)
        row = db().execute("SELECT s.* FROM domains d JOIN sites s ON s.id=d.site_id WHERE d.domain=? AND d.verified=1",
                           (host,)).fetchone()
        return ("site", row) if row else ("platform", None)

    def record_hit(sid):
        db().execute("INSERT INTO hits(site_id,day,views) VALUES(?,?,1) "
                     "ON CONFLICT(site_id,day) DO UPDATE SET views=views+1", (sid, today()))
        db().commit()

    @app.before_request
    def vhost():
        if request.endpoint == "healthz":
            return None
        host = request.host.split(":")[0].lower().rstrip(".")
        kind, row = classify(host)
        g.host_kind = kind
        if kind == "platform":
            return None
        if kind == "missing":
            return Response(render_template("unclaimed.html", sub=row), 404)
        if request.method not in ("GET", "HEAD"):
            return Response("Method not allowed", 405)
        if row["status"] != "active":
            return Response(render_template("suspended.html"), 503)
        if row["maintenance"]:
            return Response(render_template("maintenance.html"), 503, headers={"Retry-After": "3600"})
        pub = S.public_dir(cfg, row["id"])
        f = S.resolve_file(pub, request.path)
        if f is None:
            nf = pub / "404.html"
            if nf.is_file():
                return Response(nf.read_bytes(), 404, mimetype="text/html")
            return Response(render_template("site404.html"), 404)
        if request.method == "GET" and f.suffix.lower() in (".html", ".htm") and not S.is_bot(request.headers.get("User-Agent")):
            record_hit(row["id"])
        resp = send_file(f, conditional=True, max_age=300)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return resp

    @app.before_request
    def platform_guard():
        g.user = None
        uid = session.get("uid")
        if uid:
            g.user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if g.user is None:
                session.clear()
        if request.method == "POST" and not request.path.startswith(CSRF_EXEMPT) and not csrf_ok():
            abort(400, "Your session expired. Refresh the page and try again.")

    @app.after_request
    def headers(r):
        r.headers.setdefault("X-Content-Type-Options", "nosniff")
        if getattr(g, "host_kind", "platform") == "platform":
            r.headers.setdefault("X-Frame-Options", "DENY")
            r.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if request.path.startswith("/f/"):
            r.headers["Access-Control-Allow-Origin"] = "*"
            r.headers["Access-Control-Allow-Headers"] = "Content-Type"
            r.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        return r

    @app.context_processor
    def ctx():
        return dict(cfg=cfg, base=cfg.base_domain, brand=cfg.brand, csrf=csrf_token, user=g.get("user"),
                    site_url=cfg.site_url, starters=S.STARTERS)

    def login_required(fn):
        @wraps(fn)
        def w(*a, **k):
            if not g.user:
                return redirect("/login?next=" + request.path)
            return fn(*a, **k)
        return w

    def admin_required(fn):
        @wraps(fn)
        @login_required
        def w(*a, **k):
            if not g.user["is_admin"]:
                abort(403)
            return fn(*a, **k)
        return w

    def own_site(sid):
        row = db().execute("SELECT * FROM sites WHERE id=? AND user_id=?", (sid, g.user["id"])).fetchone()
        if row is None:
            abort(404)
        return row

    def safe_next(n):
        return n if n and n.startswith("/") and not n.startswith("//") else "/dashboard"

    def limited(name, limit, window):
        return not limiter.allow(f"{name}:{request.remote_addr}", limit, window)

    def refresh_stats(sid):
        files, size = S.dir_stats(S.public_dir(cfg, sid))
        db().execute("UPDATE sites SET files=?, bytes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (files, size, sid))
        db().commit()

    def limit_bytes():
        return cfg.max_site_mb * 1048576

    def starter_fields(site_row, **extra):
        f = {"title": site_row["subdomain"].replace("-", " ").title(), "tagline": "My new website is coming soon.",
             "about": "Tell visitors about yourself here. You can change this text from the dashboard.",
             "email": "", "form_action": f"{cfg.home_url}/f/{site_row['form_token']}"}
        f.update(extra)
        return f

    def deploy_zip(sid, stream):
        tmp = Path(tempfile.mkdtemp(prefix="up_", dir=S.site_root(cfg, sid).parent))
        try:
            files, _size, skipped, has_index = S.extract_zip(stream, tmp / "public", limit_bytes(), cfg.max_files)
            S.replace_public(tmp / "public", S.public_dir(cfg, sid))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        refresh_stats(sid)
        return files, skipped, has_index

    # ------------------------------------------------------------------ public pages
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/domains")
    def domains_page():
        return render_template("domains.html")

    @app.get("/docs")
    def docs():
        return render_template("docs.html")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/api/check")
    def api_check():
        if limited("check", 60, 60):
            return jsonify(error="Too many requests. Please try again shortly."), 429
        name = (request.args.get("name") or "").strip().lower()
        ok, why = S.valid_subdomain(name)
        if ok and db().execute("SELECT 1 FROM sites WHERE subdomain=?", (name,)).fetchone():
            ok, why = False, "That name is already taken."
        return jsonify(name=name, available=ok, reason=why, url=cfg.site_url(name) if ok else None,
                       host=f"{name}.{cfg.base_domain}")

    @app.get("/api/domain")
    def api_domain():
        if limited("rdap", 20, 60):
            return jsonify(error="Too many requests. Please try again shortly."), 429
        d = rdap.normalize(request.args.get("d"))
        if not d:
            return jsonify(error="Enter a valid domain, for example example.com"), 400
        return jsonify(domain=d, status=rdap.status(d))

    @app.get("/internal/tls-check")
    def tls_check():
        # Caddy "ask" endpoint: only issue certificates for hostnames that really exist on this platform.
        if request.headers.get("X-Forwarded-For") or request.headers.get("X-Forwarded-Host"):
            abort(404)
        d = (request.args.get("domain") or "").lower().rstrip(".")
        base = cfg.base_domain
        ok = d in (base, "www." + base)
        if not ok and d.endswith("." + base):
            sub = d[: -len(base) - 1]
            ok = "." not in sub and db().execute("SELECT 1 FROM sites WHERE subdomain=? AND status='active'", (sub,)).fetchone() is not None
        if not ok:
            ok = db().execute("SELECT 1 FROM domains WHERE domain=? AND verified=1", (d,)).fetchone() is not None
        return ("ok", 200) if ok else ("no", 404)

    # ------------------------------------------------------------------ auth
    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            if limited("signup", 8, 3600):
                flash("Too many signups from this network. Try again later.", "err")
                return redirect("/signup")
            if not cfg.signup_open:
                flash("New signups are closed right now.", "err")
                return redirect("/signup")
            email = (request.form.get("email") or "").strip().lower()
            pw = request.form.get("password") or ""
            if not EMAIL_RE.match(email) or len(email) > 254:
                flash("Enter a valid email address.", "err")
            elif len(pw) < 8:
                flash("Your password must be at least 8 characters.", "err")
            else:
                first = db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                admin = 1 if (first or email == cfg.admin_email) else 0
                try:
                    cur = db().execute("INSERT INTO users(email,pw_hash,is_admin) VALUES(?,?,?)",
                                       (email, generate_password_hash(pw), admin))
                    db().commit()
                except sqlite3.IntegrityError:
                    flash("An account with this email already exists. Please log in.", "err")
                    return redirect("/login")
                session.clear()
                session["uid"] = cur.lastrowid
                session.permanent = True
                return redirect(safe_next(request.args.get("next")))
        return render_template("auth.html", mode="signup")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if limited("login", 10, 60):
                flash("Too many attempts. Try again in a minute.", "err")
                return redirect("/login")
            email = (request.form.get("email") or "").strip().lower()
            row = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if row and check_password_hash(row["pw_hash"], request.form.get("password") or ""):
                session.clear()
                session["uid"] = row["id"]
                session.permanent = True
                return redirect(safe_next(request.args.get("next")))
            flash("Incorrect email or password.", "err")
        return render_template("auth.html", mode="login")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect("/")

    # ------------------------------------------------------------------ account
    @app.get("/account")
    @login_required
    def account():
        toks = db().execute("SELECT * FROM tokens WHERE user_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
        used = db().execute("SELECT COALESCE(SUM(bytes),0), COUNT(*) FROM sites WHERE user_id=?", (g.user["id"],)).fetchone()
        return render_template("account.html", tokens=toks, used_bytes=used[0], site_count=used[1], new_token=None)

    @app.post("/account/password")
    @login_required
    def change_password():
        if not check_password_hash(g.user["pw_hash"], request.form.get("current") or ""):
            flash("Your current password is incorrect.", "err")
        elif len(request.form.get("new") or "") < 8:
            flash("The new password must be at least 8 characters.", "err")
        else:
            db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(request.form["new"]), g.user["id"]))
            db().commit()
            flash("Password updated.", "ok")
        return redirect("/account")

    @app.post("/account/tokens")
    @login_required
    def create_token():
        name = (request.form.get("name") or "").strip()[:40] or "API token"
        count = db().execute("SELECT COUNT(*) FROM tokens WHERE user_id=?", (g.user["id"],)).fetchone()[0]
        if count >= 10:
            flash("You can have at most 10 API tokens.", "err")
            return redirect("/account")
        raw = "nh_" + secrets.token_urlsafe(24)
        db().execute("INSERT INTO tokens(user_id,name,token_hash) VALUES(?,?,?)",
                     (g.user["id"], name, hashlib.sha256(raw.encode()).hexdigest()))
        db().commit()
        toks = db().execute("SELECT * FROM tokens WHERE user_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
        used = db().execute("SELECT COALESCE(SUM(bytes),0), COUNT(*) FROM sites WHERE user_id=?", (g.user["id"],)).fetchone()
        return render_template("account.html", tokens=toks, used_bytes=used[0], site_count=used[1], new_token=raw)

    @app.post("/account/tokens/<int:tid>/delete")
    @login_required
    def delete_token(tid):
        db().execute("DELETE FROM tokens WHERE id=? AND user_id=?", (tid, g.user["id"]))
        db().commit()
        flash("Token revoked.", "ok")
        return redirect("/account")

    @app.post("/account/delete")
    @login_required
    def delete_account():
        if not check_password_hash(g.user["pw_hash"], request.form.get("password") or ""):
            flash("Password is incorrect. Account not deleted.", "err")
            return redirect("/account")
        if g.user["is_admin"] and db().execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0] == 1:
            flash("You are the only admin. Make another user an admin before deleting this account.", "err")
            return redirect("/account")
        for r in db().execute("SELECT id FROM sites WHERE user_id=?", (g.user["id"],)).fetchall():
            shutil.rmtree(S.site_root(cfg, r["id"]), ignore_errors=True)
        db().execute("DELETE FROM users WHERE id=?", (g.user["id"],))
        db().commit()
        session.clear()
        flash("Your account and all your sites were deleted.", "ok")
        return redirect("/")

    # ------------------------------------------------------------------ dashboard + sites
    @app.get("/dashboard")
    @login_required
    def dashboard():
        rows = db().execute("SELECT * FROM sites WHERE user_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
        return render_template("dashboard.html", sites=rows)

    @app.post("/sites")
    @login_required
    def create_site():
        sub = (request.form.get("subdomain") or "").strip().lower()
        starter = request.form.get("starter") or "coming"
        ok, why = S.valid_subdomain(sub)
        if not ok:
            flash(why, "err")
            return redirect("/dashboard")
        n = db().execute("SELECT COUNT(*) FROM sites WHERE user_id=?", (g.user["id"],)).fetchone()[0]
        if n >= cfg.max_sites:
            flash(f"The free plan allows up to {cfg.max_sites} sites.", "err")
            return redirect("/dashboard")
        try:
            cur = db().execute("INSERT INTO sites(user_id,subdomain,form_token) VALUES(?,?,?)",
                               (g.user["id"], sub, secrets.token_urlsafe(12)))
            db().commit()
        except sqlite3.IntegrityError:
            flash("That name is already taken.", "err")
            return redirect("/dashboard")
        sid = cur.lastrowid
        site = db().execute("SELECT * FROM sites WHERE id=?", (sid,)).fetchone()
        pub = S.public_dir(cfg, sid)
        pub.mkdir(parents=True, exist_ok=True)
        (pub / "index.html").write_text(S.render_starter(starter, starter_fields(site, email=g.user["email"])), encoding="utf-8")
        refresh_stats(sid)
        flash(f"Your site is live: {cfg.site_url(sub)}", "ok")
        return redirect(f"/sites/{sid}")

    @app.get("/sites/<int:sid>")
    @login_required
    def manage(sid):
        site = own_site(sid)
        doms = db().execute("SELECT * FROM domains WHERE site_id=? ORDER BY id", (sid,)).fetchall()
        ip = cfg.server_ip or ", ".join(sorted(S.dns_ips(cfg.base_domain))) or "<server-ip>"
        since = (datetime.now(timezone.utc) - timedelta(days=13)).strftime("%Y-%m-%d")
        got = {r["day"]: r["views"] for r in db().execute("SELECT day, views FROM hits WHERE site_id=? AND day>=?", (sid, since))}
        days = [(datetime.now(timezone.utc) - timedelta(days=13 - i)).strftime("%Y-%m-%d") for i in range(14)]
        series = [(d[5:], got.get(d, 0)) for d in days]
        peak = max([v for _, v in series] + [1])
        subs = db().execute("SELECT COUNT(*) FROM submissions WHERE site_id=?", (sid,)).fetchone()[0]
        return render_template("site.html", site=site, domains=doms, server_ip=ip, max_mb=cfg.max_site_mb, tab="overview",
                               series=series, peak=peak, total_views=sum(v for _, v in series), subs=subs)

    @app.post("/sites/<int:sid>/upload")
    @login_required
    def upload(sid):
        site = own_site(sid)
        f = request.files.get("zip")
        if not f or not f.filename.lower().endswith(".zip"):
            return jsonify(ok=False, message="Choose a .zip file."), 400
        try:
            files, skipped, has_index = deploy_zip(sid, f.stream)
        except S.SiteError as e:
            return jsonify(ok=False, message=str(e)), 400
        msg = f"{files} files uploaded."
        if not has_index:
            msg += " Note: there is no index.html in the root of your ZIP."
        return jsonify(ok=True, message=msg, skipped=skipped[:20], url=cfg.site_url(site["subdomain"]))

    @app.post("/sites/<int:sid>/publish")
    @login_required
    def publish(sid):
        site = own_site(sid)
        fields = {k: (request.form.get(k) or "").strip()[:600] for k in ("title", "tagline", "about", "email")}
        fields["title"] = fields["title"][:80] or "My website"
        pub = S.public_dir(cfg, sid)
        pub.mkdir(parents=True, exist_ok=True)
        (pub / "index.html").write_text(
            S.render_starter(request.form.get("starter", "coming"), starter_fields(site, **fields)), encoding="utf-8")
        refresh_stats(sid)
        flash("Your site was published.", "ok")
        return redirect(f"/sites/{sid}")

    @app.post("/sites/<int:sid>/maintenance")
    @login_required
    def maintenance(sid):
        site = own_site(sid)
        new = 0 if site["maintenance"] else 1
        db().execute("UPDATE sites SET maintenance=? WHERE id=?", (new, sid))
        db().commit()
        flash("Maintenance mode is ON. Visitors see a maintenance page." if new else "Maintenance mode is OFF. Your site is live.", "ok")
        return redirect(f"/sites/{sid}")

    @app.post("/sites/<int:sid>/delete")
    @login_required
    def delete_site(sid):
        own_site(sid)
        db().execute("DELETE FROM sites WHERE id=?", (sid,))
        db().commit()
        shutil.rmtree(S.site_root(cfg, sid), ignore_errors=True)
        flash("Site deleted.", "ok")
        return redirect("/dashboard")

    @app.get("/sites/<int:sid>/download")
    @login_required
    def download(sid):
        site = own_site(sid)
        data = S.zip_site(S.public_dir(cfg, sid))
        return send_file(io.BytesIO(data), mimetype="application/zip", as_attachment=True,
                         download_name=f"{site['subdomain']}-backup.zip")

    # ---- file manager -------------------------------------------------------
    @app.get("/sites/<int:sid>/files")
    @login_required
    def files(sid):
        site = own_site(sid)
        fl = S.list_files(S.public_dir(cfg, sid))
        return render_template("files.html", site=site, files=fl, tab="files", used=sum(f["size"] for f in fl), limit=limit_bytes())

    @app.get("/sites/<int:sid>/files/edit")
    @login_required
    def edit_file(sid):
        site = own_site(sid)
        try:
            rel = S.safe_rel(request.args.get("path"), editable=True)
        except S.SiteError as e:
            flash(str(e), "err")
            return redirect(f"/sites/{sid}/files")
        f = S.public_dir(cfg, sid) / rel
        if not f.is_file() or f.stat().st_size > S.MAX_EDIT_BYTES:
            flash("That file was not found or is too large to edit here.", "err")
            return redirect(f"/sites/{sid}/files")
        return render_template("editor.html", site=site, path=rel, content=f.read_text(encoding="utf-8", errors="replace"), tab="files")

    @app.post("/sites/<int:sid>/files/save")
    @login_required
    def save_file(sid):
        own_site(sid)
        try:
            rel = S.safe_rel(request.form.get("path"), editable=True)
        except S.SiteError as e:
            flash(str(e), "err")
            return redirect(f"/sites/{sid}/files")
        pub = S.public_dir(cfg, sid)
        f = pub / rel
        data = (request.form.get("content") or "").replace("\r\n", "\n").encode("utf-8")
        old = f.stat().st_size if f.is_file() else 0
        if S.dir_stats(pub)[1] - old + len(data) > limit_bytes():
            flash(f"This would exceed your {cfg.max_site_mb} MB limit.", "err")
        else:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
            refresh_stats(sid)
            flash(f"Saved {rel}.", "ok")
        return redirect(f"/sites/{sid}/files/edit?path={rel}")

    @app.post("/sites/<int:sid>/files/new")
    @login_required
    def new_file(sid):
        own_site(sid)
        try:
            rel = S.safe_rel(request.form.get("path"), editable=True)
        except S.SiteError as e:
            flash(str(e), "err")
            return redirect(f"/sites/{sid}/files")
        f = S.public_dir(cfg, sid) / rel
        if f.exists():
            flash("A file with that name already exists.", "err")
            return redirect(f"/sites/{sid}/files")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("<!DOCTYPE html>\n<html>\n<head><meta charset=\"UTF-8\"><title>New page</title></head>\n<body>\n<h1>New page</h1>\n</body>\n</html>\n"
                     if rel.endswith((".html", ".htm")) else "", encoding="utf-8")
        refresh_stats(sid)
        return redirect(f"/sites/{sid}/files/edit?path={rel}")

    @app.post("/sites/<int:sid>/files/delete")
    @login_required
    def delete_file(sid):
        own_site(sid)
        try:
            rel = S.safe_rel(request.form.get("path"))
        except S.SiteError as e:
            flash(str(e), "err")
            return redirect(f"/sites/{sid}/files")
        f = S.public_dir(cfg, sid) / rel
        if f.is_file():
            f.unlink()
            refresh_stats(sid)
            flash(f"Deleted {rel}.", "ok")
        return redirect(f"/sites/{sid}/files")

    @app.post("/sites/<int:sid>/files/upload")
    @login_required
    def upload_files(sid):
        own_site(sid)
        pub = S.public_dir(cfg, sid)
        folder = (request.form.get("folder") or "").strip().strip("/")
        added = 0
        for f in request.files.getlist("files"):
            name = Path((f.filename or "").replace("\\", "/")).name
            try:
                rel = S.safe_rel(f"{folder}/{name}" if folder else name)
            except S.SiteError as e:
                flash(f"{name or 'file'}: {e}", "err")
                continue
            data = f.read()
            target = pub / rel
            old = target.stat().st_size if target.is_file() else 0
            if S.dir_stats(pub)[1] - old + len(data) > limit_bytes():
                flash(f"{name}: this would exceed your {cfg.max_site_mb} MB limit.", "err")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            added += 1
        refresh_stats(sid)
        if added:
            flash(f"{added} file(s) uploaded.", "ok")
        return redirect(f"/sites/{sid}/files")

    # ---- custom domains -----------------------------------------------------
    @app.post("/sites/<int:sid>/domain")
    @login_required
    def add_domain(sid):
        own_site(sid)
        d = rdap.normalize(request.form.get("domain"))
        if not d:
            flash("Enter a valid domain, for example mysite.com", "err")
        elif d == cfg.base_domain or d.endswith("." + cfg.base_domain):
            flash("You cannot use this platform's own domain. You already get a free subdomain.", "err")
        elif db().execute("SELECT COUNT(*) FROM domains WHERE site_id=?", (sid,)).fetchone()[0] >= 2:
            flash("A site can have at most 2 custom domains.", "err")
        else:
            try:
                db().execute("INSERT INTO domains(site_id,domain) VALUES(?,?)", (sid, d))
                db().commit()
                flash("Domain added. Point your DNS to this server, then click Verify.", "ok")
            except sqlite3.IntegrityError:
                flash("That domain is already connected to a site.", "err")
        return redirect(f"/sites/{sid}")

    @app.post("/sites/<int:sid>/domain/<int:did>/verify")
    @login_required
    def verify_domain(sid, did):
        own_site(sid)
        row = db().execute("SELECT * FROM domains WHERE id=? AND site_id=?", (did, sid)).fetchone()
        if row is None:
            abort(404)
        expected = {cfg.server_ip} if cfg.server_ip else S.dns_ips(cfg.base_domain)
        got = S.dns_ips(row["domain"])
        if expected and got & expected:
            db().execute("UPDATE domains SET verified=1 WHERE id=?", (did,))
            db().commit()
            flash(f"{row['domain']} is verified. Its HTTPS certificate is issued on the first visit.", "ok")
        else:
            flash("DNS does not point to this server yet. Wait 5-30 minutes for propagation and try again.", "err")
        return redirect(f"/sites/{sid}")

    @app.post("/sites/<int:sid>/domain/<int:did>/delete")
    @login_required
    def delete_domain(sid, did):
        own_site(sid)
        db().execute("DELETE FROM domains WHERE id=? AND site_id=?", (did, sid))
        db().commit()
        return redirect(f"/sites/{sid}")

    # ---- form inbox -----------------------------------------------------------
    def decode_rows(sid, limit=200):
        out = []
        for r in db().execute("SELECT * FROM submissions WHERE site_id=? ORDER BY id DESC LIMIT ?", (sid, limit)):
            try:
                data = json.loads(r["data"])
            except ValueError:
                data = {}
            out.append({"id": r["id"], "created_at": r["created_at"], "data": data})
        return out

    @app.get("/sites/<int:sid>/forms")
    @login_required
    def forms(sid):
        site = own_site(sid)
        return render_template("forms.html", site=site, rows=decode_rows(sid), tab="forms",
                               endpoint=f"{cfg.home_url}/f/{site['form_token']}")

    @app.post("/sites/<int:sid>/forms/<int:subid>/delete")
    @login_required
    def delete_submission(sid, subid):
        own_site(sid)
        db().execute("DELETE FROM submissions WHERE id=? AND site_id=?", (subid, sid))
        db().commit()
        return redirect(f"/sites/{sid}/forms")

    @app.post("/sites/<int:sid>/forms/clear")
    @login_required
    def clear_submissions(sid):
        own_site(sid)
        db().execute("DELETE FROM submissions WHERE site_id=?", (sid,))
        db().commit()
        flash("Inbox cleared.", "ok")
        return redirect(f"/sites/{sid}/forms")

    @app.get("/sites/<int:sid>/forms.csv")
    @login_required
    def forms_csv(sid):
        site = own_site(sid)
        rows = decode_rows(sid, limit=MAX_SUBMISSIONS)
        keys = sorted({k for r in rows for k in r["data"]})

        def cell(v):                      # neutralise spreadsheet formulas
            s = str(v)
            return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["received_at"] + keys)
        for r in rows:
            w.writerow([r["created_at"]] + [cell(r["data"].get(k, "")) for k in keys])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={site['subdomain']}-submissions.csv"})

    @app.route("/f/<token>", methods=["POST", "OPTIONS"])
    def form_submit(token):
        """Public endpoint that static sites post their contact forms to."""
        if request.method == "OPTIONS":
            return "", 204
        site = db().execute("SELECT * FROM sites WHERE form_token=?", (token,)).fetchone()
        if site is None or site["status"] != "active":
            return jsonify(ok=False, error="Unknown form."), 404
        if not limiter.allow(f"form:{token}:{request.remote_addr}", 5, 60):
            return jsonify(ok=False, error="Too many submissions. Try again in a minute."), 429
        raw = request.get_json(silent=True) if request.is_json else request.form.to_dict(flat=True)
        if not isinstance(raw, dict):
            return jsonify(ok=False, error="Invalid submission."), 400

        def done():
            wants_json = request.is_json or "application/json" in (request.headers.get("Accept") or "")
            if wants_json:
                return jsonify(ok=True)
            allowed = {f"{site['subdomain']}.{cfg.base_domain}"} | {
                r["domain"] for r in db().execute("SELECT domain FROM domains WHERE site_id=? AND verified=1", (site["id"],))}
            for cand in (raw.get("_next"), request.headers.get("Referer")):
                u = urlparse(str(cand or ""))
                if u.scheme in ("http", "https") and (u.hostname or "").lower() in allowed:
                    return redirect(f"{u.scheme}://{u.netloc}{u.path or '/'}?sent=1", 303)
            return render_template("thanks.html", site=site)

        if raw.get("_gotcha"):            # honeypot: pretend success, store nothing
            return done()
        fields = {}
        for k, v in list(raw.items())[:25]:
            k = str(k).strip()[:60]
            if k and not k.startswith("_"):
                fields[k] = str(v)[:2000]
        if not fields:
            return jsonify(ok=False, error="The form is empty."), 400
        if sum(len(k) + len(v) for k, v in fields.items()) > 10000:
            return jsonify(ok=False, error="Submission is too large."), 413
        if db().execute("SELECT COUNT(*) FROM submissions WHERE site_id=?", (site["id"],)).fetchone()[0] >= MAX_SUBMISSIONS:
            return jsonify(ok=False, error="This inbox is full."), 429
        db().execute("INSERT INTO submissions(site_id,data) VALUES(?,?)", (site["id"], json.dumps(fields, ensure_ascii=False)))
        db().commit()
        return done()

    # ------------------------------------------------------------------ deploy API (Bearer token)
    def api_user():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        row = db().execute("SELECT u.*, t.id AS tid FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?",
                           (hashlib.sha256(auth[7:].strip().encode()).hexdigest(),)).fetchone()
        if row:
            db().execute("UPDATE tokens SET last_used=CURRENT_TIMESTAMP WHERE id=?", (row["tid"],))
            db().commit()
        return row

    @app.get("/api/v1/sites")
    def api_sites():
        if limited("api", 60, 60):
            return jsonify(error="Rate limit exceeded."), 429
        u = api_user()
        if not u:
            return jsonify(error="Invalid or missing API token."), 401
        rows = db().execute("SELECT * FROM sites WHERE user_id=?", (u["id"],)).fetchall()
        return jsonify(sites=[{"subdomain": r["subdomain"], "url": cfg.site_url(r["subdomain"]), "status": r["status"],
                               "files": r["files"], "bytes": r["bytes"]} for r in rows])

    @app.post("/api/v1/sites/<sub>/deploy")
    def api_deploy(sub):
        if limited("api", 60, 60):
            return jsonify(error="Rate limit exceeded."), 429
        u = api_user()
        if not u:
            return jsonify(error="Invalid or missing API token."), 401
        site = db().execute("SELECT * FROM sites WHERE subdomain=? AND user_id=?", (sub.lower(), u["id"])).fetchone()
        if not site:
            return jsonify(error="Site not found."), 404
        if site["status"] != "active":
            return jsonify(error="This site is suspended."), 403
        f = request.files.get("zip")
        if not f:
            return jsonify(error="Upload the ZIP as multipart field 'zip'."), 400
        try:
            files, skipped, has_index = deploy_zip(site["id"], f.stream)
        except S.SiteError as e:
            return jsonify(error=str(e)), 400
        return jsonify(ok=True, files=files, skipped=skipped[:20], has_index=has_index, url=cfg.site_url(site["subdomain"]))

    # ------------------------------------------------------------------ admin
    @app.get("/admin")
    @admin_required
    def admin():
        users = db().execute("SELECT u.*, (SELECT COUNT(*) FROM sites s WHERE s.user_id=u.id) AS n FROM users u ORDER BY id").fetchall()
        rows = db().execute("SELECT s.*, u.email FROM sites s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC").fetchall()
        return render_template("admin.html", users=users, sites=rows)

    @app.post("/admin/sites/<int:sid>/<action>")
    @admin_required
    def admin_action(sid, action):
        if action in ("suspend", "unsuspend"):
            db().execute("UPDATE sites SET status=? WHERE id=?", ("suspended" if action == "suspend" else "active", sid))
        elif action == "delete":
            db().execute("DELETE FROM sites WHERE id=?", (sid,))
            shutil.rmtree(S.site_root(cfg, sid), ignore_errors=True)
        else:
            abort(404)
        db().commit()
        return redirect("/admin")

    @app.errorhandler(404)
    def nf(_e):
        return render_template("404.html"), 404

    @app.errorhandler(400)
    def bad(e):
        return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request")), 400

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, msg="You do not have permission to view this page."), 403

    @app.errorhandler(413)
    def big(_e):
        if request.path.endswith("/upload") or request.path.startswith("/api/"):
            return jsonify(ok=False, error=f"File is larger than {cfg.max_site_mb} MB.", message=f"File is larger than {cfg.max_site_mb} MB."), 413
        return render_template("error.html", code=413, msg="That file is too large."), 413

    return app


def wsgi():
    return create_app()
