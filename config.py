"""Ayarlar. Gizli bilgiler (token'lar) yalnızca uygulama klasöründeki .env dosyasından okunur; kodda hiçbir
kuruma ait değer (zone, host, IP, token) yoktur. Zone / hedef host / Picus IP'leri Ayarlar sayfasından girilir."""
import os
import secrets
from datetime import timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_env():
    f = BASE_DIR / ".env"
    if not f.exists():
        return
    for line in f.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env()

DATA_DIR = Path(os.environ.get("DATA_DIR") or BASE_DIR / "data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "picuscf.db"

HOST = os.environ.get("HOST", "127.0.0.1")          # varsayılan: sadece sunucunun içinden erişim
PORT = int(os.environ.get("PORT", "9999"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "8"))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "200"))
PICUS_URL = os.environ.get("PICUS_API_URL", "https://api.picussecurity.com").rstrip("/")

TR = timezone(timedelta(hours=3))   # Türkiye saati (sabit UTC+3)

# Ayarlar sayfasından değiştirilebilen varsayılanlar. Kuruma özgü değerler boş gelir.
DEFAULTS = {
    "zone_id": os.environ.get("CF_ZONE_ID", ""),
    "picus_ips": os.environ.get("PICUS_IPS", ""),          # Picus saldırı IP'leri / CIDR (virgülle)
    "target_host": os.environ.get("TARGET_HOST", ""),      # Picus'un saldırdığı test host'u
    "margin_before_min": "5",
    "margin_after_min": "15",
    "picus_auto": "0",            # yeni Picus koşumlarını otomatik çek
    "picus_watch": "",            # izlenen simülasyon ID'leri (virgülle)
    "picus_interval_min": "30",
    "picus_wait_min": "20",       # koşum bittikten sonra CF loglarının oturması için bekleme
    "picus_lookback_days": "7",
    "picus_last_check": "",
    "picus_sensitive": "0",       # rapor isteğinde hassas veri (payload) istensin mi
}


def secret_key():
    k = os.environ.get("SECRET_KEY")
    if k:
        return k
    f = DATA_DIR / "secret.key"
    if not f.exists():
        f.write_text(secrets.token_hex(32), encoding="utf-8")
    return f.read_text(encoding="utf-8").strip()


def cf_token():
    return os.environ.get("CF_API_TOKEN", "").strip()


def picus_token():
    return os.environ.get("PICUS_API_TOKEN", "").strip()
