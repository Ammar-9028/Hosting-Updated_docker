import secrets
import sqlite3

from flask import g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sites(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subdomain TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'active', maintenance INTEGER NOT NULL DEFAULT 0,
  form_token TEXT, files INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS domains(
  id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  domain TEXT UNIQUE NOT NULL, verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS hits(
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE, day TEXT NOT NULL, views INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(site_id, day));
CREATE TABLE IF NOT EXISTS submissions(
  id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  data TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS tokens(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL,
  token_hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used TEXT);
"""


def connect(path):
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


def migrate(con):
    """Upgrades databases created by older versions."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(sites)")}
    if "form_token" not in cols:
        con.execute("ALTER TABLE sites ADD COLUMN form_token TEXT")
    if "maintenance" not in cols:
        con.execute("ALTER TABLE sites ADD COLUMN maintenance INTEGER NOT NULL DEFAULT 0")
    for r in con.execute("SELECT id FROM sites WHERE form_token IS NULL").fetchall():
        con.execute("UPDATE sites SET form_token=? WHERE id=?", (secrets.token_urlsafe(12), r["id"]))
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_form_token ON sites(form_token)")
    con.execute("DELETE FROM hits WHERE day < date('now','-90 day')")


def init(path):
    con = connect(path)
    con.executescript(SCHEMA)
    migrate(con)
    con.commit()
    con.close()


def get(path):
    if "db" not in g:
        g.db = connect(path)
    return g.db


def close(_exc=None):
    con = g.pop("db", None)
    if con is not None:
        con.close()
