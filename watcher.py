"""İzlenen Picus simülasyonlarının yeni koşumlarını otomatik çeker (Ayarlar > Picus otomatik çekme)."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import config
import db
import jobs
import picusapi

_started = False


def _ts(v):
    try:
        return datetime.strptime(v.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def check_once(con, log=print):
    """Bir kontrol turu. Dönen: oluşturulan koşum sayısı."""
    sims = [x.strip() for x in (db.setting(con, "picus_watch") or "").split(",") if x.strip().isdigit()]
    if not sims or not config.picus_token():
        return 0
    pc = picusapi.PicusClient(config.picus_token(), config.PICUS_URL)
    wait = timedelta(minutes=int(db.setting(con, "picus_wait_min") or 20))
    back = timedelta(days=int(db.setting(con, "picus_lookback_days") or 7))
    now = datetime.now(timezone.utc)
    made = 0
    for sid in sims:
        try:
            name, runs = pc.runs(sid)
        except picusapi.PicusError as e:
            log(f"Picus izleme: simülasyon {sid} okunamadı: {e}")
            continue
        for r in runs:
            done, start = _ts(r["completed_at"]), _ts(r["started_at"])
            if not done or not start or str(r["status"]).lower() not in ("completed", "finished", "done", "success", ""):
                continue
            if now - done < wait or now - start > back:
                continue
            if con.execute("SELECT 1 FROM runs WHERE picus_sim_id=? AND picus_run_id=?", (str(sid), r["id"])).fetchone():
                continue
            ips = db.setting(con, "picus_ips")
            try:
                import cfapi
                ip_list = cfapi.expand_ips(ips)
            except Exception:  # noqa: BLE001
                ip_list = []
            cur = con.execute(
                "INSERT INTO runs(name, picus_sim_id, picus_run_id, picus_source, source, origin, host, ips, start_utc, end_utc, "
                "run_date, status, created_by, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"{name or 'Simülasyon ' + sid} · {start.astimezone(config.TR):%d.%m.%Y}", str(sid), r["id"], "api", "api", "otomatik",
                 db.setting(con, "target_host"), json.dumps(ip_list), start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 done.strftime("%Y-%m-%dT%H:%M:%SZ"), start.strftime("%Y-%m-%dT%H:%M:%SZ"), "kuyrukta", "otomatik", db.now_utc()))
            con.commit()
            jobs.submit(cur.lastrowid, fetch=True, picus=True)
            made += 1
    db.set_setting(con, "picus_last_check", db.now_utc())
    con.commit()
    return made


def _loop():
    while True:
        con = db.connect()
        try:
            if db.setting(con, "picus_auto") == "1":
                check_once(con)
            interval = max(10, int(db.setting(con, "picus_interval_min") or 30))
        except Exception as e:  # noqa: BLE001
            print("Picus izleme hatası:", e)
            interval = 30
        finally:
            con.close()
        time.sleep(interval * 60)


def start():
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, name="picus-izleme", daemon=True).start()
