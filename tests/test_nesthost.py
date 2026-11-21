import io
import re
import tempfile
import unittest
import zipfile
from unittest import mock

from nesthost import rdap
from nesthost.app import create_app


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    buf.seek(0)
    return buf


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"DATA_DIR": self.tmp.name, "BASE_DOMAIN": "localhost", "PUBLIC_PORT": ":8000",
                               "SERVER_IP": "1.2.3.4", "MAX_SITE_MB": "1", "MAX_SITES_PER_USER": "2"})
        self.c = self.app.test_client()
        rdap._cache.clear()

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self):
        html = self.c.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def post(self, path, data=None, **kw):
        d = dict(data or {})
        d["csrf"] = self.csrf()
        return self.c.post(path, data=d, **kw)

    def signup(self, email="a@example.com", pw="password123"):
        return self.post("/signup", {"email": email, "password": pw})

    def make_site(self, sub="mysite", starter="portfolio"):
        self.signup()
        r = self.post("/sites", {"subdomain": sub, "starter": starter})
        self.assertEqual(r.status_code, 302)
        return int(r.headers["Location"].rsplit("/", 1)[-1])

    def upload(self, sid, files, name="site.zip"):
        return self.c.post(f"/sites/{sid}/upload", data={"csrf": self.csrf(), "zip": (make_zip(files), name)},
                           content_type="multipart/form-data")


class PlatformTests(Base):
    def test_pages_render(self):
        for p in ("/", "/domains", "/docs", "/login", "/signup", "/healthz"):
            self.assertEqual(self.c.get(p).status_code, 200, p)
        self.assertIn(b"NestHost", self.c.get("/").data)

    def test_csrf_required(self):
        self.assertEqual(self.c.post("/signup", data={"email": "a@b.co", "password": "password123"}).status_code, 400)

    def test_signup_login_logout(self):
        self.assertEqual(self.signup().headers["Location"], "/dashboard")
        self.assertEqual(self.c.get("/dashboard").status_code, 200)
        self.post("/logout")
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
        r = self.post("/login", {"email": "a@example.com", "password": "wrong"})
        self.assertEqual(r.status_code, 200)          # login page again, with an error message
        self.assertIn(b"Incorrect email or password", r.data)
        self.assertEqual(self.post("/login", {"email": "a@example.com", "password": "password123"}).headers["Location"], "/dashboard")

    def test_weak_password_and_open_redirect(self):
        self.assertEqual(self.post("/signup", {"email": "x@y.co", "password": "short"}).status_code, 200)
        self.signup()
        self.post("/logout")
        r = self.post("/login?next=//evil.com", {"email": "a@example.com", "password": "password123"})
        self.assertEqual(r.headers["Location"], "/dashboard")

    def test_subdomain_rules(self):
        self.signup()
        for bad in ("www", "ab", "-abc", "a--b", "has space", "UPPER_x"):
            self.post("/sites", {"subdomain": bad})
        self.assertEqual(self.c.get("/api/check?name=www").get_json()["available"], False)
        self.assertEqual(self.c.get("/api/check?name=cool-name").get_json()["available"], True)

    def test_site_limit_and_uniqueness(self):
        self.make_site("first")
        self.post("/sites", {"subdomain": "second"})
        self.post("/sites", {"subdomain": "third"})
        self.assertEqual(self.c.get("/api/check?name=first").get_json()["available"], False)
        self.assertEqual(self.c.get("/api/check?name=third").get_json()["available"], True)   # limit is 2

    def test_other_user_cannot_touch_site(self):
        sid = self.make_site()
        self.post("/logout")
        self.signup("b@example.com")
        self.assertEqual(self.c.get(f"/sites/{sid}").status_code, 404)
        self.assertEqual(self.post(f"/sites/{sid}/delete").status_code, 404)

    def test_admin_gate_and_suspend(self):
        sid = self.make_site()                         # first user is admin
        self.assertEqual(self.c.get("/admin").status_code, 200)
        self.post(f"/admin/sites/{sid}/suspend")
        self.assertEqual(self.c.get("/", base_url="http://mysite.localhost").status_code, 503)
        self.post(f"/admin/sites/{sid}/unsuspend")
        self.assertEqual(self.c.get("/", base_url="http://mysite.localhost").status_code, 200)
        self.post("/logout")
        self.signup("b@example.com")
        self.assertEqual(self.c.get("/admin").status_code, 403)


class HostingTests(Base):
    def test_starter_site_is_served_on_subdomain(self):
        self.make_site("rahul")
        r = self.c.get("/", base_url="http://rahul.localhost")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Rahul", r.data)
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_unclaimed_subdomain_and_missing_page(self):
        self.assertEqual(self.c.get("/", base_url="http://nobody.localhost").status_code, 404)
        self.make_site("rahul")
        self.assertEqual(self.c.get("/nope.html", base_url="http://rahul.localhost").status_code, 404)

    def test_user_site_cannot_reach_platform_routes(self):
        self.make_site("rahul")
        r = self.c.get("/dashboard", base_url="http://rahul.localhost")
        self.assertEqual(r.status_code, 404)      # served as a (missing) file of the user's site, not the dashboard
        self.assertEqual(self.c.post("/logout", base_url="http://rahul.localhost").status_code, 405)

    def test_zip_upload_and_clean_urls(self):
        sid = self.make_site("rahul")
        r = self.upload(sid, {"index.html": "<h1>Hello ZIP</h1>", "about.html": "<p>about</p>", "css/a.css": "body{}",
                              "run.php": "<?php ?>", "evil.exe": "MZ"})
        j = r.get_json()
        self.assertTrue(j["ok"], j)
        self.assertEqual(sorted(j["skipped"]), ["evil.exe", "run.php"])
        base = "http://rahul.localhost"
        self.assertIn(b"Hello ZIP", self.c.get("/", base_url=base).data)
        self.assertIn(b"about", self.c.get("/about", base_url=base).data)
        self.assertEqual(self.c.get("/css/a.css", base_url=base).status_code, 200)
        self.assertEqual(self.c.get("/run.php", base_url=base).status_code, 404)

    def test_wrapper_folder_is_flattened(self):
        sid = self.make_site("rahul")
        self.assertTrue(self.upload(sid, {"mysite/index.html": "<b>wrapped</b>"}).get_json()["ok"])
        self.assertIn(b"wrapped", self.c.get("/", base_url="http://rahul.localhost").data)

    def test_zip_slip_and_bad_zip_rejected(self):
        sid = self.make_site("rahul")
        self.assertEqual(self.upload(sid, {"../../evil.html": "x"}).status_code, 400)
        self.assertEqual(self.upload(sid, {"a/../../evil.html": "x"}).status_code, 400)
        r = self.c.post(f"/sites/{sid}/upload", data={"csrf": self.csrf(), "zip": (io.BytesIO(b"not a zip"), "x.zip")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_too_big_site_rejected_and_old_site_kept(self):
        sid = self.make_site("rahul")
        self.upload(sid, {"index.html": "KEEP-ME"})
        r = self.upload(sid, {"index.html": "x", "big.txt": "A" * (2 * 1024 * 1024)})
        self.assertEqual(r.status_code, 400)
        self.assertIn(b"KEEP-ME", self.c.get("/", base_url="http://rahul.localhost").data)

    def test_dotfiles_not_served(self):
        sid = self.make_site("rahul")
        self.upload(sid, {"index.html": "ok", ".env": "SECRET=1"})
        self.assertEqual(self.c.get("/.env", base_url="http://rahul.localhost").status_code, 404)

    def test_builder_escapes_html(self):
        sid = self.make_site("rahul")
        self.post(f"/sites/{sid}/publish", {"starter": "business", "title": "<script>alert(1)</script>", "tagline": "t", "about": "a", "email": "e@x.co"})
        body = self.c.get("/", base_url="http://rahul.localhost").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_all_starters_render(self):
        for i, s in enumerate(("coming", "portfolio", "business", "invite", "linkinbio")):
            self.make_site(f"site{i}x", s) if i == 0 else None
        from nesthost import sites as S
        for s in S.STARTERS:
            out = S.render_starter(s, {"title": "T", "tagline": "tag", "about": "ab", "email": "e@x.co"})
            self.assertNotIn("[[", out, s)

    def test_custom_domain_flow_and_tls_check(self):
        sid = self.make_site("rahul")
        self.post(f"/sites/{sid}/domain", {"domain": "mysite.com"})
        self.assertEqual(self.c.get("/internal/tls-check?domain=mysite.com").status_code, 404)    # not verified yet
        with mock.patch("nesthost.sites.dns_ips", return_value={"9.9.9.9"}):
            self.post(f"/sites/{sid}/domain/1/verify")
        self.assertEqual(self.c.get("/internal/tls-check?domain=mysite.com").status_code, 404)
        with mock.patch("nesthost.sites.dns_ips", return_value={"1.2.3.4"}):
            self.post(f"/sites/{sid}/domain/1/verify")
        self.assertEqual(self.c.get("/internal/tls-check?domain=mysite.com").status_code, 200)
        self.assertEqual(self.c.get("/", base_url="http://mysite.com").status_code, 200)        # served via custom domain
        self.assertEqual(self.c.get("/internal/tls-check?domain=rahul.localhost").status_code, 200)
        self.assertEqual(self.c.get("/internal/tls-check?domain=ghost.localhost").status_code, 404)
        self.assertEqual(self.c.get("/internal/tls-check?domain=mysite.com", headers={"X-Forwarded-For": "8.8.8.8"}).status_code, 404)

    def test_cannot_attach_platform_domain(self):
        sid = self.make_site("rahul")
        self.post(f"/sites/{sid}/domain", {"domain": "x.localhost"})
        self.assertNotIn(b"x.localhost", self.c.get(f"/sites/{sid}").data)


class DomainCheckTests(Base):
    def test_rdap_status_mapping(self):
        for code, expect in ((200, "taken"), (404, "available"), (500, "unknown")):
            rdap._cache.clear()
            with mock.patch("nesthost.rdap._fetch", return_value=code):
                self.assertEqual(self.c.get("/api/domain?d=example.com").get_json()["status"], expect)

    def test_invalid_domains_rejected(self):
        for d in ("", "nodot", "bad domain.com", "a.com/../x", "http://x.com"):
            self.assertEqual(self.c.get("/api/domain", query_string={"d": d}).status_code, 400, d)


class FileManagerTests(Base):
    def test_edit_save_new_delete_and_traversal(self):
        sid = self.make_site("rahul")
        self.assertIn(b"index.html", self.c.get(f"/sites/{sid}/files").data)
        self.assertIn(b"<title>", self.c.get(f"/sites/{sid}/files/edit?path=index.html").data)
        self.post(f"/sites/{sid}/files/save", {"path": "index.html", "content": "<h1>Edited in browser</h1>"})
        self.assertIn(b"Edited in browser", self.c.get("/", base_url="http://rahul.localhost").data)
        self.post(f"/sites/{sid}/files/new", {"path": "css/extra.css"})
        self.assertEqual(self.c.get("/css/extra.css", base_url="http://rahul.localhost").status_code, 200)
        self.post(f"/sites/{sid}/files/delete", {"path": "css/extra.css"})
        self.assertEqual(self.c.get("/css/extra.css", base_url="http://rahul.localhost").status_code, 404)
        for bad in ("../../etc/passwd.html", "a/../../x.html", ".env", "run.php", "photo.png"):
            r = self.post(f"/sites/{sid}/files/save", {"path": bad, "content": "x"})
            self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get("/run.php", base_url="http://rahul.localhost").status_code, 404)

    def test_save_respects_size_limit(self):
        sid = self.make_site("rahul")
        self.post(f"/sites/{sid}/files/save", {"path": "index.html", "content": "A" * (2 * 1024 * 1024)})
        self.assertNotIn(b"AAAA", self.c.get("/", base_url="http://rahul.localhost").data)

    def test_upload_single_files_and_download_backup(self):
        sid = self.make_site("rahul")
        self.c.post(f"/sites/{sid}/files/upload", data={"csrf": self.csrf(), "folder": "img", "files": [(io.BytesIO(b"png-bytes"), "logo.png"), (io.BytesIO(b"x"), "bad.php")]},
                    content_type="multipart/form-data")
        self.assertEqual(self.c.get("/img/logo.png", base_url="http://rahul.localhost").data, b"png-bytes")
        self.assertEqual(self.c.get("/img/bad.php", base_url="http://rahul.localhost").status_code, 404)
        z = zipfile.ZipFile(io.BytesIO(self.c.get(f"/sites/{sid}/download").data))
        self.assertIn("index.html", z.namelist())
        self.assertIn("img/logo.png", z.namelist())

    def test_other_user_cannot_edit(self):
        sid = self.make_site("rahul")
        self.post("/logout")
        self.signup("b@example.com")
        self.assertEqual(self.c.get(f"/sites/{sid}/files").status_code, 404)
        self.assertEqual(self.post(f"/sites/{sid}/files/save", {"path": "index.html", "content": "hacked"}).status_code, 404)


class AnalyticsAndMaintenanceTests(Base):
    def test_counts_page_views_but_not_bots_or_assets(self):
        sid = self.make_site("rahul")
        self.upload(sid, {"index.html": "<p>hi</p>", "a.css": "body{}"})
        base = "http://rahul.localhost"
        for _ in range(3):
            self.c.get("/", base_url=base, headers={"User-Agent": "Mozilla/5.0 Firefox"})
        self.c.get("/", base_url=base, headers={"User-Agent": "Googlebot/2.1"})
        self.c.get("/a.css", base_url=base, headers={"User-Agent": "Mozilla/5.0 Firefox"})
        page = self.c.get(f"/sites/{sid}").get_data(as_text=True)
        self.assertIn("3 page views", page)

    def test_maintenance_mode(self):
        sid = self.make_site("rahul")
        self.post(f"/sites/{sid}/maintenance")
        r = self.c.get("/", base_url="http://rahul.localhost")
        self.assertEqual(r.status_code, 503)
        self.assertIn(b"Under maintenance", r.data)
        self.post(f"/sites/{sid}/maintenance")
        self.assertEqual(self.c.get("/", base_url="http://rahul.localhost").status_code, 200)


class FormInboxTests(Base):
    def setUp(self):
        super().setUp()
        self.sid = self.make_site("rahul", "business")
        self.token = re.search(r"/f/([A-Za-z0-9_-]+)", self.c.get(f"/sites/{self.sid}").get_data(as_text=True)).group(1)

    def test_starter_form_points_at_endpoint(self):
        self.assertIn(f"/f/{self.token}".encode(), self.c.get("/", base_url="http://rahul.localhost").data)

    def test_submission_is_stored_and_listed(self):
        r = self.c.post(f"/f/{self.token}", data={"name": "Asha", "email": "a@b.co", "message": "Hello <b>there</b>"})
        self.assertEqual(r.status_code, 200)                       # thanks page (no safe redirect target)
        inbox = self.c.get(f"/sites/{self.sid}/forms").get_data(as_text=True)
        self.assertIn("Asha", inbox)
        self.assertIn("&lt;b&gt;there&lt;/b&gt;", inbox)           # escaped
        self.assertNotIn("<b>there</b>", inbox)

    def test_json_cors_and_redirect_rules(self):
        r = self.c.post(f"/f/{self.token}", json={"message": "hi"})
        self.assertEqual(r.get_json(), {"ok": True})
        self.assertEqual(r.headers["Access-Control-Allow-Origin"], "*")
        ok = self.c.post(f"/f/{self.token}", data={"message": "x"}, headers={"Referer": "http://rahul.localhost:8000/contact"})
        self.assertEqual(ok.status_code, 303)
        self.assertEqual(ok.headers["Location"], "http://rahul.localhost:8000/contact?sent=1")
        evil = self.c.post(f"/f/{self.token}", data={"message": "x", "_next": "https://evil.com/phish"})
        self.assertEqual(evil.status_code, 200)                    # open redirect refused

    def test_honeypot_unknown_token_empty_and_rate_limit(self):
        self.c.post(f"/f/{self.token}", data={"message": "spam", "_gotcha": "bot"})
        self.assertEqual(self.c.post("/f/nope", data={"a": "b"}).status_code, 404)
        self.assertEqual(self.c.post(f"/f/{self.token}", json={"_x": "only hidden"}).status_code, 400)
        self.assertIn("Form inbox (0)", self.c.get(f"/sites/{self.sid}/forms").get_data(as_text=True))   # honeypot stored nothing
        codes = [self.c.post(f"/f/{self.token}", json={"m": str(i)}).status_code for i in range(7)]
        self.assertIn(429, codes)

    def test_csv_export_neutralises_formulas_and_delete(self):
        self.c.post(f"/f/{self.token}", json={"name": "=HYPERLINK(\"http://x\")", "ok": "fine"})
        csv_text = self.c.get(f"/sites/{self.sid}/forms.csv").get_data(as_text=True)
        self.assertIn("received_at", csv_text)
        self.assertIn("'=HYPERLINK", csv_text)
        self.post(f"/sites/{self.sid}/forms/clear")
        self.assertIn(b"No messages yet", self.c.get(f"/sites/{self.sid}/forms").data)

    def test_suspended_site_rejects_forms(self):
        self.post(f"/admin/sites/{self.sid}/suspend")
        self.assertEqual(self.c.post(f"/f/{self.token}", json={"a": "b"}).status_code, 404)

    def test_inbox_is_private(self):
        self.post("/logout")
        self.signup("b@example.com")
        self.assertEqual(self.c.get(f"/sites/{self.sid}/forms").status_code, 404)
        self.assertEqual(self.c.get(f"/sites/{self.sid}/forms.csv").status_code, 404)


class ApiTokenTests(Base):
    def new_token(self):
        html = self.post("/account/tokens", {"name": "ci"}).get_data(as_text=True)
        return re.search(r"(nh_[A-Za-z0-9_-]+)", html).group(1)

    def test_deploy_with_token(self):
        self.make_site("rahul")
        tok = self.new_token()
        r = self.c.post("/api/v1/sites/rahul/deploy", headers={"Authorization": f"Bearer {tok}"},
                        data={"zip": (make_zip({"index.html": "<h1>From CI</h1>"}), "s.zip")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertTrue(r.get_json()["ok"])
        self.assertIn(b"From CI", self.c.get("/", base_url="http://rahul.localhost").data)
        self.assertEqual(self.c.get("/api/v1/sites", headers={"Authorization": f"Bearer {tok}"}).get_json()["sites"][0]["subdomain"], "rahul")
        self.assertNotIn(tok, self.c.get("/account").get_data(as_text=True))     # token is shown only once

    def test_bad_tokens_and_foreign_sites(self):
        self.make_site("rahul")
        tok = self.new_token()
        self.assertEqual(self.c.post("/api/v1/sites/rahul/deploy", headers={"Authorization": "Bearer nope"}).status_code, 401)
        self.assertEqual(self.c.post("/api/v1/sites/rahul/deploy").status_code, 401)
        self.post("/logout")
        self.signup("b@example.com")
        self.assertEqual(self.c.post("/api/v1/sites/rahul/deploy", headers={"Authorization": "Bearer " + tok.replace("nh_", "nh_x")}).status_code, 401)
        mine = self.c.get("/api/v1/sites", headers={"Authorization": f"Bearer {tok}"}).get_json()["sites"]
        self.assertEqual(len(mine), 1)

    def test_revoked_token_stops_working(self):
        self.make_site("rahul")
        tok = self.new_token()
        self.post("/account/tokens/1/delete")
        self.assertEqual(self.c.get("/api/v1/sites", headers={"Authorization": f"Bearer {tok}"}).status_code, 401)

    def test_deploy_validates_zip(self):
        self.make_site("rahul")
        tok = self.new_token()
        r = self.c.post("/api/v1/sites/rahul/deploy", headers={"Authorization": f"Bearer {tok}"},
                        data={"zip": (make_zip({"../x.html": "x"}), "s.zip")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)


class AccountTests(Base):
    def test_change_password(self):
        self.signup()
        self.post("/account/password", {"current": "wrong", "new": "newpassword1"})
        self.post("/account/password", {"current": "password123", "new": "newpassword1"})
        self.post("/logout")
        self.assertIn(b"Incorrect", self.post("/login", {"email": "a@example.com", "password": "password123"}).data)
        self.assertEqual(self.post("/login", {"email": "a@example.com", "password": "newpassword1"}).status_code, 302)

    def test_delete_account_removes_sites_but_not_last_admin(self):
        self.signup()                                        # first user = admin
        self.post("/account/delete", {"password": "password123"})
        self.assertEqual(self.c.get("/account").status_code, 200)        # refused: only admin
        self.post("/logout")
        self.signup("b@example.com")
        self.post("/sites", {"subdomain": "bsite"})
        self.post("/account/delete", {"password": "password123"})
        self.assertEqual(self.c.get("/", base_url="http://bsite.localhost").status_code, 404)
        self.assertEqual(self.c.get("/account").status_code, 302)


class EnglishOnlyTests(unittest.TestCase):
    """The whole product must be in English: no Hinglish words left in templates, scripts, code or docs."""
    WORDS = re.compile(r"\b(karo|karna|nahi|hai|hain|mein|yahan|dekho|banao|jaise|aapki|aapka|abhi|dobara|toot|hoga|sakte|sakta|kuch|baare|wala|wali|jaldi|shuru)\b", re.I)

    def test_no_hinglish(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        files = [p for pat in ("nesthost/**/*.html", "nesthost/**/*.py", "nesthost/**/*.js", "nesthost/**/*.css", "README.md", ".env.example")
                 for p in root.glob(pat)]
        self.assertGreater(len(files), 20)
        bad = [f"{p.relative_to(root)}: {m.group(0)}" for p in files for m in [self.WORDS.search(p.read_text(encoding="utf-8"))] if m]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
