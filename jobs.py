"""Arka plan işleri: Picus'tan / Cloudflare'den çekme + analiz, Prod FP taramaları. Aynı anda tek iş çalışır."""
import json
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pandas as pd

import analysis
import cfapi
import config
import db
import picusapi
import prodfp

_EXEC = ThreadPoolExecutor(max_workers=1, thread_name_prefix="picuscf-is")
UTC = timezone.utc


def _p(v):
    return datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class Log:
    def __init__(self, con, table, oid):
        self.con, self.table, self.oid = con, table, oid

    def __call__(self, msg, progress=None):
        line = f"[{datetime.now(config.TR):%H:%M:%S}] {msg}\n"
        self.con.execute(f"UPDATE {self.table} SET log = COALESCE(log, '') || ?, progress = COALESCE(?, progress) WHERE id=?",
                         (line, progress, self.oid))
        self.con.commit()


def submit(run_id, fetch, picus=False):
    con = db.connect()
    con.execute("UPDATE runs SET status='kuyrukta', progress=0, error=NULL WHERE id=?", (run_id,))
    con.commit()
    con.close()
    _EXEC.submit(_job, run_id, fetch, picus)


def submit_scan(scan_id):
    con = db.connect()
    con.execute("UPDATE prod_scans SET status='kuyrukta', progress=0, error=NULL WHERE id=?", (scan_id,))
    con.commit()
    con.close()
    _EXEC.submit(_scan_job, scan_id)


def recover_stuck():
    con = db.connect()
    msg = "Uygulama yeniden başladığı için iş yarıda kaldı; tekrar başlatın."
    con.execute("UPDATE runs SET status='hata', error=? WHERE status IN ('kuyrukta', 'calisiyor')", (msg,))
    con.execute("UPDATE prod_scans SET status='hata', error=? WHERE status IN ('kuyrukta', 'calisiyor')", (msg,))
    con.commit()
    con.close()


def window_from(R, con):
    s, e = analysis.picus_window(R)
    mb = int(db.setting(con, "margin_before_min") or 5)
    ma = int(db.setting(con, "margin_after_min") or 15)
    return s - timedelta(minutes=mb), e + timedelta(minutes=ma)


def _iso(d):
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _job(run_id, fetch, picus):
    con = db.connect()
    log = Log(con, "runs", run_id)
    try:
        con.execute("UPDATE runs SET status='calisiyor', log='', progress=1 WHERE id=?", (run_id,))
        con.commit()
        run = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        warnings = [] if (fetch or picus) else json.loads(run["warnings"] or "[]")

        # ---- Picus
        if picus and run["picus_sim_id"] and run["picus_run_id"]:
            pc = picusapi.PicusClient(config.picus_token(), config.PICUS_URL, log)
            log(f"Picus'tan çekiliyor: simülasyon {run['picus_sim_id']}, koşum {run['picus_run_id']}", 2)
            R, w, rep = picusapi.fetch_run(pc, run["picus_sim_id"], run["picus_run_id"],
                                           db.setting(con, "picus_sensitive") == "1",
                                           progress=lambda f, m: log(m, 2 + int(f * 18)), rep_id=run["picus_report"] or None)
            warnings += w
            db.put_df(con, run_id, "picus", R)
            started = ""
            try:
                _, runs = pc.runs(run["picus_sim_id"])
                info = next((x for x in runs if x["id"] == str(run["picus_run_id"])), None)
            except picusapi.PicusError:
                info = None
            s, e = window_from(R, con)
            if info and info["started_at"] and info["completed_at"]:
                ps = pd.Timestamp(info["started_at"].replace(" UTC", ""), tz="UTC").to_pydatetime()
                pe = pd.Timestamp(info["completed_at"].replace(" UTC", ""), tz="UTC").to_pydatetime()
                started = _iso(ps)
                if pe - ps <= timedelta(hours=48):
                    if s < ps - timedelta(hours=1) or e > pe + timedelta(hours=1):
                        warnings.append("Bazı aksiyon zamanları Picus koşum aralığının dışında; CF aralığı koşum aralığına göre alındı.")
                    s = ps - timedelta(minutes=int(db.setting(con, "margin_before_min") or 5))
                    e = pe + timedelta(minutes=int(db.setting(con, "margin_after_min") or 15))
            if not started:
                started = _iso(analysis.picus_window(R)[0])
            upd = {"picus_report": rep or run["picus_report"], "run_date": run["run_date"] or started}
            if not run["window_fixed"]:
                upd.update(start_utc=_iso(s), end_utc=_iso(e))
            con.execute("UPDATE runs SET " + ", ".join(f"{k}=?" for k in upd) + ", version = version + 1 WHERE id=?",
                        (*upd.values(), run_id))
            con.commit()
            run = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            log(f"Picus: {len(R)} test satırı alındı" + (f" (rapor no {rep})" if rep else " (threats/actions)"), 20)

        # ---- Cloudflare
        if fetch:
            start, end = _p(run["start_utc"]), _p(run["end_utc"])
            client = cfapi.CFClient(config.cf_token(), db.setting(con, "zone_id"), log)
            base = {}
            ips = json.loads(run["ips"] or "[]")
            if ips:
                base["clientIP_in"] = ips
            if run["host"]:
                base["clientRequestHTTPHost"] = run["host"]
            log(f"Cloudflare'den çekiliyor: {start.astimezone(config.TR):%d.%m.%Y %H:%M} – "
                f"{end.astimezone(config.TR):%d.%m.%Y %H:%M} (TR), {len(ips)} IP, host: {run['host'] or 'tümü'}", 22)
            h, _, w1 = client.fetch("httpRequestsAdaptive", cfapi.HTTP_FIELDS, base, start, end,
                                    progress=lambda f, m: log(m, 22 + int(f * 38)))
            e, _, w2 = client.fetch("firewallEventsAdaptive", cfapi.EVENT_FIELDS, base, start, end,
                                    progress=lambda f, m: log(m, 60 + int(f * 20)))
            warnings += w1 + w2
            if not h and not e:
                warnings.append("Cloudflare bu aralıkta Picus IP'lerinden hiç istek döndürmedi (tarih, IP ya da veri saklama süresini kontrol edin).")
            db.put_df(con, run_id, "cf_http", pd.DataFrame(h))
            db.put_df(con, run_id, "cf_events", pd.DataFrame(e))
            con.execute("UPDATE runs SET version = version + 1 WHERE id=?", (run_id,))
            con.commit()
            log(f"Çekildi: {len(h)} istek, {len(e)} güvenlik olayı.", 80)

        log("Analiz yapılıyor (Picus ↔ Cloudflare eşleştirme, kritiklik, kurallar)…", 82)
        R = db.get_df(con, run_id, "picus")
        if R.empty:
            raise analysis.PicusFormatError("Koşumda Picus verisi yok.")
        res = analysis.analyze(R, db.get_df(con, run_id, "cf_http"), db.get_df(con, run_id, "cf_events"))
        for k in ("tests", "actions", "categories", "rule_hits", "log_block", "fragile"):
            db.put_df(con, run_id, k, res[k])
        s = res["summary"]
        if s.get("cf_yok"):
            warnings.append("Bu koşumda hiçbir Picus testi Cloudflare verisiyle eşleşmedi: CF kararı, kural ailesi ve kırılgan "
                            "blok hesaplanamadı. CF aralığını / IP'leri kontrol edip 'CF verisini yeniden çek' deneyin.")
        s["uyarilar"] = warnings
        con.execute("UPDATE runs SET status='tamam', progress=100, summary=?, warnings=?, finished_at=?, version = version + 1 WHERE id=?",
                    (json.dumps(s, ensure_ascii=False), json.dumps(warnings, ensure_ascii=False), db.now_utc(), run_id))
        con.commit()
        log(f"Tamamlandı: aksiyon skoru %{s['skor']}, bloklanmayan aksiyon {s['nb_aksiyon']} "
            f"(kritik {s['kritik']}), CF eşleşme {s['eslesen']}/{s['test']}.", 100)
    except Exception as ex:  # noqa: BLE001
        con.rollback()
        con.execute("UPDATE runs SET status='hata', error=? WHERE id=?", (str(ex)[:1000], run_id))
        con.commit()
        log("HATA: " + str(ex))
        if not isinstance(ex, (cfapi.CFError, analysis.PicusFormatError, picusapi.PicusError)):
            log(traceback.format_exc())
    finally:
        con.close()


def _scan_job(scan_id):
    con = db.connect()
    log = Log(con, "prod_scans", scan_id)
    try:
        con.execute("UPDATE prod_scans SET status='calisiyor', log='', progress=1 WHERE id=?", (scan_id,))
        con.commit()
        sc = con.execute("SELECT * FROM prod_scans WHERE id=?", (scan_id,)).fetchone()
        start, end = _p(sc["start_utc"]), _p(sc["end_utc"])
        host = db.setting(con, "target_host")
        client = cfapi.CFClient(config.cf_token(), db.setting(con, "zone_id"), log)
        log(f"Prod olayları çekiliyor: {start.astimezone(config.TR):%d.%m.%Y %H:%M} – {end.astimezone(config.TR):%d.%m.%Y %H:%M} (TR), "
            f"tüm aksiyonlar, test host'u hariç: {host or '-'}", 2)
        data, warns = prodfp.fetch(client, start, end, host, progress=lambda f, m: log(m, 2 + int(f * 88)), log=log)
        for k, df in data.items():
            db.put_scan_df(con, scan_id, k, df)
        log("Kuralların Cloudflare'deki durumu okunuyor (isteğe bağlı)…", 92)
        st = client.rule_states(test_host=host)
        if st.get("ok"):
            rows = [{"rule_id": k, "prod": v.get("prod", ""), "dagitimlar": json.dumps(v.get("dagitimlar", []), ensure_ascii=False),
                     "skip": json.dumps(v.get("skip", []), ensure_ascii=False)} for k, v in st["kurallar"].items()]
            db.put_scan_df(con, scan_id, "states", pd.DataFrame(rows, columns=["rule_id", "prod", "dagitimlar", "skip"]))
            log(f"Kural durumları alındı: {len(rows)} kural.", 96)
        else:
            warns.append("Kuralların prod'daki durumu okunamadı (token'da WAF okuma yetkisi yok olabilir). Prod'da olay görünmeyen "
                         "kurallar 'Ölçülemedi' olarak işaretlenir; kapalı bir kural hiç log üretmez.")
            log("Kural durumları okunamadı: " + st.get("hata", ""), 96)
        con.execute("UPDATE prod_scans SET status='tamam', progress=100, warnings=?, finished_at=?, version = version + 1 WHERE id=?",
                    (json.dumps(warns, ensure_ascii=False), db.now_utc(), scan_id))
        con.commit()
        n = len(data["rules"])
        log(f"Tamamlandı: {n} kural, {int(pd.to_numeric(data['rules'].get('olay', pd.Series(dtype=int)), errors='coerce').fillna(0).sum())} olay.", 100)
    except Exception as ex:  # noqa: BLE001
        con.rollback()
        con.execute("UPDATE prod_scans SET status='hata', error=? WHERE id=?", (str(ex)[:1000], scan_id))
        con.commit()
        log("HATA: " + str(ex))
        if not isinstance(ex, cfapi.CFError):
            log(traceback.format_exc())
    finally:
        con.close()
