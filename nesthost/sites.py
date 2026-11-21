"""Everything about site files: names, safe ZIP extraction, serving, file manager helpers, starter templates."""
import html
import io
import re
import shutil
import socket
import zipfile
from pathlib import Path

from werkzeug.security import safe_join

RESERVED = {"www", "mail", "admin", "api", "app", "ftp", "smtp", "imap", "pop", "ns1", "ns2", "root", "support", "help",
            "billing", "static", "assets", "cdn", "login", "signup", "dashboard", "status", "blog", "docs", "dev",
            "test", "staging", "internal", "secure", "account", "accounts", "webmail", "localhost"}
ALLOWED_EXT = {"html", "htm", "css", "js", "mjs", "json", "txt", "md", "xml", "svg", "png", "jpg", "jpeg", "gif", "webp",
               "avif", "ico", "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "pdf", "map",
               "webmanifest", "csv"}
EDITABLE_EXT = {"html", "htm", "css", "js", "mjs", "json", "txt", "md", "xml", "svg", "csv", "webmanifest"}
MAX_EDIT_BYTES = 512 * 1024
SUB_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$")
REL_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
BOT_RE = re.compile(r"bot|crawl|spider|slurp|preview|monitor|curl|wget|python-requests|headless", re.I)
STARTERS = {"coming": "Coming soon page", "portfolio": "Portfolio", "business": "Business", "invite": "Event invitation",
            "linkinbio": "Link in bio"}


class SiteError(Exception):
    pass


def valid_subdomain(name):
    n = (name or "").strip().lower()
    if not SUB_RE.match(n):
        return False, "Use 3-30 characters: a-z, 0-9 and hyphens (no hyphen at the start or end)."
    if n.startswith("xn--") or "--" in n:
        return False, "Double hyphens and xn-- are not allowed."
    if n in RESERVED:
        return False, "That name is reserved."
    return True, ""


def site_root(cfg, site_id):
    return cfg.data_dir / "sites" / str(site_id)


def public_dir(cfg, site_id):
    return site_root(cfg, site_id) / "public"


def dir_stats(path):
    files = size = 0
    for p in Path(path).rglob("*"):
        if p.is_file():
            files += 1
            size += p.stat().st_size
    return files, size


def ext_of(name):
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def safe_rel(rel, editable=False):
    """Validates a user-supplied relative file path. Returns the cleaned posix path or raises SiteError."""
    rel = (rel or "").strip().replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or ".." in parts or not REL_RE.match("/".join(parts)):
        raise SiteError("Invalid file path. Use letters, numbers, dots, dashes and underscores only.")
    if any(p.startswith(".") for p in parts):
        raise SiteError("Hidden files are not allowed.")
    ext = ext_of(parts[-1])
    if ext not in (EDITABLE_EXT if editable else ALLOWED_EXT):
        raise SiteError("This file type is not allowed." if not editable else "Only text files can be edited here.")
    return "/".join(parts)


def list_files(public, limit=2000):
    public = Path(public)
    out = []
    if not public.is_dir():
        return out
    for p in sorted(public.rglob("*")):
        if p.is_file():
            rel = p.relative_to(public).as_posix()
            out.append({"path": rel, "size": p.stat().st_size,
                        "editable": ext_of(p.name) in EDITABLE_EXT and p.stat().st_size <= MAX_EDIT_BYTES})
            if len(out) >= limit:
                break
    return out


def zip_site(public):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in list_files(public, limit=100000):
            z.write(Path(public) / f["path"], f["path"])
    return buf.getvalue()


def is_bot(ua):
    return not ua or bool(BOT_RE.search(ua))


def extract_zip(stream, dest, max_bytes, max_files):
    """Extracts a ZIP into `dest` safely. Returns (files, bytes, skipped, has_index)."""
    try:
        z = zipfile.ZipFile(stream)
    except zipfile.BadZipFile:
        raise SiteError("This is not a valid ZIP file.")
    infos = [i for i in z.infolist() if not i.is_dir()]
    if not infos:
        raise SiteError("The ZIP is empty.")
    if len(infos) > max_files:
        raise SiteError(f"The ZIP has more than {max_files} files.")
    if sum(i.file_size for i in infos) > max_bytes:
        raise SiteError(f"The site is larger than {max_bytes // 1048576} MB.")

    entries = []
    for i in infos:
        name = i.filename.replace("\\", "/")
        if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
            raise SiteError("The ZIP contains an unsafe path.")
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if ".." in parts:
            raise SiteError("The ZIP contains an unsafe path.")
        entries.append((i, parts))
    if all(len(p) > 1 for _, p in entries) and len({p[0] for _, p in entries}) == 1:
        entries = [(i, p[1:]) for i, p in entries]      # a zipped folder: drop the wrapper folder

    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    skipped, files, total = [], 0, 0
    for info, parts in entries:
        label = "/".join(parts)
        if any(p.startswith(".") or p == "__MACOSX" for p in parts):
            continue
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            skipped.append(label)
            continue
        if ext_of(parts[-1]) not in ALLOWED_EXT:
            skipped.append(label)
            continue
        target = (root.joinpath(*parts)).resolve()
        if root not in target.parents:
            raise SiteError("The ZIP contains an unsafe path.")
        target.parent.mkdir(parents=True, exist_ok=True)
        with z.open(info) as src, open(target, "wb") as out:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise SiteError(f"The site is larger than {max_bytes // 1048576} MB.")
                out.write(chunk)
        files += 1
    if files == 0:
        raise SiteError("No allowed files found in the ZIP (html, css, js, images, fonts...).")
    return files, total, skipped, (root / "index.html").is_file()


def replace_public(new_dir, public):
    """Swap the live folder for the new one (the old one is removed afterwards)."""
    public = Path(public)
    old = public.with_name("public.old")
    shutil.rmtree(old, ignore_errors=True)
    if public.exists():
        public.rename(old)
    Path(new_dir).rename(public)
    shutil.rmtree(old, ignore_errors=True)


def resolve_file(public, rel):
    """Maps a URL path to a file inside `public` (clean URLs supported). Returns Path or None."""
    rel = (rel or "").lstrip("/")
    base = str(public)
    full = safe_join(base, rel) if rel else base
    if full is None:
        return None
    p = Path(full)
    if any(part.startswith(".") for part in Path(rel).parts):
        return None
    if p.is_dir():
        p = p / "index.html"
    elif not p.exists() and "." not in p.name:
        for cand in (p.with_name(p.name + ".html"), p / "index.html"):
            if cand.is_file():
                p = cand
                break
    return p if p.is_file() else None


def render_starter(name, fields):
    if name not in STARTERS:
        name = "coming"
    tpl = (Path(__file__).parent / "starters" / f"{name}.html").read_text(encoding="utf-8")
    fields = dict(fields)
    fields.setdefault("form_action", "#")
    for k, v in fields.items():
        tpl = tpl.replace(f"[[{k}]]", html.escape(str(v), quote=True))
    initial = (fields.get("title") or "N")[:1].upper()
    return tpl.replace("[[initial]]", html.escape(initial))


def dns_ips(host):
    """IPv4 addresses a hostname resolves to (follows CNAMEs). Empty set if it does not resolve."""
    try:
        return {r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET)}
    except OSError:
        return set()
