"""SQLite erişimi. Analiz tabloları koşum / tarama başına sıkıştırılmış JSON olarak saklanır."""
import gzip
import json
import sqlite3
import threading
from collections import OrderedDict
from datetime import datetime, timezone

import pandas as pd

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'izleyici', active INTEGER NOT NULL DEFAULT 1, must_change INTEGER NOT NULL DEFAULT 0,
  created_at TEXT, last_login TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, picus_report TEXT, picus_file TEXT,
  start_utc TEXT, end_utc TEXT, host TEXT, ips TEXT, source TEXT,
  status TEXT, progress INTEGER DEFAULT 0, log TEXT DEFAULT '', error TEXT, warnings TEXT,
  summary TEXT, notes TEXT, created_by TEXT, created_at TEXT, finished_at TEXT, version INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS run_files(
  run_id INTEGER NOT NULL, kind TEXT NOT NULL, data BLOB, rows INTEGER,
  PRIMARY KEY(run_id, kind), FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS changes(
  id INTEGER PRIMARY KEY, tarih TEXT NOT NULL, alan TEXT, aciklama TEXT NOT NULL, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT, username TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS prod_scans(
  id INTEGER PRIMARY KEY, name TEXT, start_utc TEXT, end_utc TEXT, base_run INTEGER, ref_run INTEGER,
  status TEXT, progress INTEGER DEFAULT 0, log TEXT DEFAULT '', error TEXT, warnings TEXT,
  created_by TEXT, created_at TEXT, finished_at TEXT, version INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS prod_files(
  scan_id INTEGER NOT NULL, kind TEXT NOT NULL, data BLOB, rows INTEGER,
  PRIMARY KEY(scan_id, kind), FOREIGN KEY(scan_id) REFERENCES prod_scans(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS rule_decisions(
  rule_id TEXT PRIMARY KEY, karar TEXT, note TEXT, updated_by TEXT, updated_at TEXT,
  durum TEXT, durum_by TEXT, durum_at TEXT);
CREATE TABLE IF NOT EXISTS exceptions(
  id INTEGER PRIMARY KEY, code TEXT, ad TEXT, hosts TEXT, path_eq TEXT, path_prefix TEXT, rules TEXT,
  expression TEXT, note TEXT, active INTEGER DEFAULT 1, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS known_fp(
  rule_id TEXT PRIMARY KEY, kural TEXT, note TEXT, created_by TEXT, created_at TEXT);
"""

# eski kurulumlardan gelen veritabanları için eksik kolonlar
MIGRATIONS = {
    "runs": [("picus_sim_id", "TEXT"), ("picus_run_id", "TEXT"), ("picus_source", "TEXT"), ("origin", "TEXT"),
             ("window_fixed", "INTEGER DEFAULT 0"), ("run_date", "TEXT")],
    "rule_decisions": [("durum", "TEXT"), ("durum_by", "TEXT"), ("durum_at", "TEXT")],
}


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect():
    con = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    con = connect()
    con.executescript(SCHEMA)
    for table, cols in MIGRATIONS.items():
        have = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
        for name, typ in cols:
            if name not in have:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")
    for k, v in config.DEFAULTS.items():
        con.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
    con.commit()
    con.close()


# ---------------------------------------------------------------- ayarlar / denetim
def setting(con, key):
    r = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r and r["value"] is not None else config.DEFAULTS.get(key, "")


def set_setting(con, key, value):
    con.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def audit(con, username, action, detail=""):
    con.execute("INSERT INTO audit(at, username, action, detail) VALUES(?, ?, ?, ?)", (now_utc(), username, action, (detail or "")[:500]))


# ---------------------------------------------------------------- DataFrame saklama
_TABLES = {"run": ("run_files", "run_id", "runs"), "scan": ("prod_files", "scan_id", "prod_scans")}
_cache = OrderedDict()
_lock = threading.Lock()


def _put(con, what, oid, kind, df):
    table, col, _ = _TABLES[what]
    df = df.copy()
    for c in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[c]):
            df[c] = df[c].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = df.to_json(orient="split", index=False, force_ascii=False, default_handler=str)
    blob = gzip.compress(payload.encode("utf-8"), compresslevel=6)
    con.execute(f"INSERT INTO {table}({col}, kind, data, rows) VALUES(?, ?, ?, ?) "
                f"ON CONFLICT({col}, kind) DO UPDATE SET data=excluded.data, rows=excluded.rows", (oid, kind, blob, len(df)))


def _get(con, what, oid, kind):
    table, col, parent = _TABLES[what]
    ver = con.execute(f"SELECT version FROM {parent} WHERE id=?", (oid,)).fetchone()
    key = (what, oid, kind, ver["version"] if ver else None)
    with _lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key].copy()
    r = con.execute(f"SELECT data FROM {table} WHERE {col}=? AND kind=?", (oid, kind)).fetchone()
    if not r or r["data"] is None:
        return pd.DataFrame()
    d = json.loads(gzip.decompress(r["data"]).decode("utf-8"))
    df = pd.DataFrame(d.get("data", []), columns=d.get("columns", []))
    with _lock:
        _cache[key] = df
        while len(_cache) > 32:
            _cache.popitem(last=False)
    return df.copy()


def put_df(con, run_id, kind, df):
    _put(con, "run", run_id, kind, df)


def get_df(con, run_id, kind):
    return _get(con, "run", run_id, kind)


def put_scan_df(con, scan_id, kind, df):
    _put(con, "scan", scan_id, kind, df)


def get_scan_df(con, scan_id, kind):
    return _get(con, "scan", scan_id, kind)


def has_df(con, run_id, kind):
    return con.execute("SELECT 1 FROM run_files WHERE run_id=? AND kind=?", (run_id, kind)).fetchone() is not None


def run_summary(row):
    try:
        return json.loads(row["summary"]) if row and row["summary"] else None
    except ValueError:
        return None


def known_fp(con):
    return {r["rule_id"]: dict(r) for r in con.execute("SELECT * FROM known_fp")}
