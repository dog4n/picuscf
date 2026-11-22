"""Picus × Cloudflare WAF Platformu – Flask uygulaması."""
import io
import json
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import pandas as pd
from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, send_file,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import analysis
import cfapi
import config
import db
import exports
import jobs
import picusapi
import prodfp

ROLES = {"admin": "Yönetici", "izleyici": "İzleyici"}
STATUS = {"kuyrukta": "Kuyrukta", "calisiyor": "Çalışıyor", "tamam": "Tamamlandı", "hata": "Hata"}
ALANLAR = ["CF Managed Ruleset", "OWASP Core Ruleset", "Custom rule", "Bot management", "Exception", "İzleme / Log", "Diğer"]
RID = re.compile(r"\b([0-9a-f]{32})\b")
_fails = {}
_fails_lock = threading.Lock()
_cmp_cache = {}


def create_app(start_watcher=True):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.secret_key(),
        MAX_CONTENT_LENGTH=config.MAX_UPLOAD_MB * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
        SESSION_COOKIE_NAME="picuscf_session", PERMANENT_SESSION_LIFETIME=timedelta(hours=config.SESSION_HOURS),
    )
    db.init_db()
    jobs.recover_stuck()
    _register(app)
    if start_watcher:
        import watcher
        watcher.start()
    return app


# ================================================================ yardımcılar
def con():
    if "con" not in g:
        g.con = db.connect()
    return g.con


def user():
    if "user" not in g:
        uid = session.get("uid")
        g.user = con().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone() if uid else None
    return g.user


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not user():
            return redirect(url_for("login", next=request.path))
        if user()["must_change"] and request.endpoint not in ("password", "logout"):
            flash("Devam etmeden önce şifrenizi değiştirin.", "warn")
            return redirect(url_for("password"))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if user()["role"] != "admin":
            abort(403)
        return f(*a, **k)
    return w


def audit(action, detail=""):
    db.audit(con(), user()["username"] if user() else "-", action, detail)
    con().commit()


def get_run(run_id):
    r = con().execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not r:
        abort(404)
    return r


def rdate(r):
    """Koşum tarihi: Picus koşumunun başlangıcı (yoksa CF aralığının başı)."""
    return r["run_date"] or r["start_utc"] or ""


def okey(r):
    return (rdate(r), r["id"])


def done_runs():
    """Tamamlanmış koşumlar, koşum tarihine göre eskiden yeniye."""
    return sorted(con().execute("SELECT * FROM runs WHERE status='tamam'").fetchall(), key=okey)


def prev_of(run):
    r = [x for x in done_runs() if okey(x) < okey(run)]
    return r[-1] if r else None


def seg_metrics(s, kat):
    if not s:
        return None
    if kat and kat != "Tümü":
        m = s.get("kategori", {}).get(kat)
        return dict(m, kampanya_blocked=None, kampanya_toplam=None) if m else None
    return s


def parse_tr(v):
    """'2026-11-07T23:00' (TR) -> UTC datetime."""
    v = (v or "").strip()
    if not v:
        return None
    for f in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%d.%m.%Y %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(v, f).replace(tzinfo=config.TR).astimezone(timezone.utc)
        except ValueError:
            pass
    raise ValueError(f"Tarih anlaşılamadı: {v}")


def utc_iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tr_date(v):
    """UTC ISO -> TR 'YYYY-MM-DD'."""
    try:
        return pd.Timestamp(v).tz_convert(config.TR).strftime("%Y-%m-%d")
    except Exception:  # noqa: BLE001
        return (v or "")[:10]


def changes_between(a, b):
    """a koşumu (hariç) ile b koşumu (dahil) arasındaki değişiklik kayıtları (TR tarih bazında)."""
    da = tr_date(rdate(a)) if a else None
    dbb = tr_date(rdate(b))
    return [r for r in con().execute("SELECT * FROM changes ORDER BY tarih, id").fetchall()
            if (da is None or r["tarih"] > da) and r["tarih"] <= dbb]


def comparison(a, b):
    key = (a["id"], a["version"], b["id"], b["version"])
    if key not in _cmp_cache:
        c = con()
        res = analysis.compare(db.get_df(c, a["id"], "tests"), db.get_df(c, b["id"], "tests"),
                               db.get_df(c, b["id"], "actions"), db.get_df(c, a["id"], "actions"))
        if len(_cmp_cache) > 8:
            _cmp_cache.clear()
        _cmp_cache[key] = res
    return _cmp_cache[key]


def category_table(sa, sb):
    kats = sorted(set(sa.get("kategori", {})) | set(sb.get("kategori", {})))
    rows = []
    for k in kats:
        ma, mb = sa["kategori"].get(k, {}), sb["kategori"].get(k, {})
        rows.append({"Kategori": k,
                     "Önceki NB aksiyon": ma.get("nb_aksiyon", 0), "Güncel NB aksiyon": mb.get("nb_aksiyon", 0),
                     "Fark": mb.get("nb_aksiyon", 0) - ma.get("nb_aksiyon", 0),
                     "Önceki NB test": ma.get("not_blocked", 0), "Güncel NB test": mb.get("not_blocked", 0),
                     "Önceki skor": ma.get("skor"), "Güncel skor": mb.get("skor"), "Güncel kritik": mb.get("kritik", 0)})
    df = pd.DataFrame(rows)
    return df.sort_values(["Güncel NB aksiyon", "Önceki NB aksiyon"], ascending=False) if len(df) else df


def read_upload(f, name):
    if not f or not f.filename:
        raise ValueError(f"{name} dosyası seçilmedi.")
    return f.read()


def csv_df(raw):
    return pd.read_csv(io.BytesIO(raw), dtype=str, keep_default_na=False, encoding="utf-8-sig", low_memory=False)


def picus_gain(base, ref):
    Tcur = db.get_df(con(), ref["id"], "tests") if ref else None
    Tcmp = comparison(base, ref)["tests"] if base and ref else None
    return prodfp.picus_gain(Tcur, Tcmp)


def scan_or_404(sid):
    r = con().execute("SELECT * FROM prod_scans WHERE id=?", (sid,)).fetchone()
    if not r:
        abort(404)
    return r


def scan_refs(sc):
    """Prod taramasında kullanılacak (önceki, güncel) koşum; URL'den değiştirilebilir. Güncel daha eskiyse yer değiştirir."""
    def pick(v):
        try:
            return con().execute("SELECT * FROM runs WHERE id=? AND status='tamam'", (int(v),)).fetchone() if v else None
        except ValueError:
            return None
    a = pick(request.args.get("a", sc["base_run"]))
    b = pick(request.args.get("b", sc["ref_run"]))
    if a and b and okey(a) > okey(b):
        a, b = b, a
    if a and b and a["id"] == b["id"]:
        a = None
    return a, b


def scan_data(sc):
    prod = {k: db.get_scan_df(con(), sc["id"], k) for k in ("rules", "hp", "src", "samples")}
    st = db.get_scan_df(con(), sc["id"], "states")
    states = dict(zip(st.rule_id, st["prod"])) if len(st) else {}
    return prod, states


def decisions():
    return {r["rule_id"]: dict(r) for r in con().execute("SELECT * FROM rule_decisions")}


def exceptions_list():
    return [dict(r) for r in con().execute("SELECT * FROM exceptions ORDER BY id")]


def build_scan(sc):
    a, b = scan_refs(sc)
    prod, states = scan_data(sc)
    T, E, oz = prodfp.build(prod, picus_gain(a, b), db.setting(con(), "target_host"), decisions(), exceptions_list(),
                            db.known_fp(con()), states)
    return a, b, prod, states, T, E, oz


# ================================================================ rotalar
def _register(app):
    @app.teardown_appcontext
    def _close(exc):
        c = g.pop("con", None)
        if c:
            c.close()

    @app.before_request
    def _csrf():
        session.permanent = True
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        if request.method == "POST":
            tok = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
            if not tok or not secrets.compare_digest(tok, session["csrf"]):
                abort(400, "Oturum doğrulaması başarısız; sayfayı yenileyip tekrar deneyin.")

    @app.after_request
    def _headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = resp.headers.get("Cache-Control", "no-store")
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                   "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
        return resp

    @app.context_processor
    def _ctx():
        return {"me": user(), "csrf": session.get("csrf", ""), "ROLES": ROLES, "STATUS": STATUS, "KARARLAR": prodfp.KARARLAR,
                "DURUMLAR": prodfp.DURUMLAR, "rdate": rdate}

    @app.template_filter("tr")
    def _tr(v, fmt="dt"):
        if not v:
            return "—"
        s = exports.tr_time(v)
        return s[:16] if fmt == "dt" else s[:10] if fmt == "d" else s

    @app.template_filter("trinput")
    def _trinput(v):
        try:
            return pd.Timestamp(v).tz_convert(config.TR).strftime("%Y-%m-%dT%H:%M")
        except Exception:  # noqa: BLE001
            return ""

    @app.template_filter("num")
    def _num(v, dec=0):
        if v is None or v == "" or (isinstance(v, float) and pd.isna(v)):
            return "—"
        try:
            s = f"{float(v):,.{dec}f}"
        except (TypeError, ValueError):
            return str(v)
        return s.replace(",", "X").replace(".", ",").replace("X", ".")

    @app.template_filter("sgn")
    def _sgn(v, dec=0):
        if v is None:
            return "—"
        s = _num(abs(v), dec)
        return ("+" if v > 0 else "-" if v < 0 else "±") + s

    @app.template_filter("pct")
    def _pct(v):
        return "—" if v is None or (isinstance(v, float) and pd.isna(v)) else f"%{round(100 * float(v))}"

    for code, msg in ((403, "Bu işlem için yetkiniz yok."), (404, "Sayfa bulunamadı.")):
        app.register_error_handler(code, (lambda m, c: (lambda e: (render_template("error.html", code=c, msg=m), c)))(msg, code))

    @app.errorhandler(400)
    def _400(e):
        return render_template("error.html", code=400, msg=getattr(e, "description", "Hatalı istek")), 400

    @app.errorhandler(413)
    def _413(e):
        return render_template("error.html", code=413, msg=f"Dosya çok büyük (en fazla {config.MAX_UPLOAD_MB} MB)."), 413

    @app.get("/saglik")
    def health():
        return {"durum": "ok"}

    # ------------------------------------------------------------ giriş
    @app.route("/kurulum", methods=["GET", "POST"])
    def setup():
        if con().execute("SELECT COUNT(*) n FROM users").fetchone()["n"]:
            return redirect(url_for("login"))
        if request.method == "POST":
            u, p = request.form.get("username", "").strip(), request.form.get("password", "")
            if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", u):
                flash("Kullanıcı adı 3-32 karakter olmalı (harf, rakam, . _ -).", "error")
            elif len(p) < 10 or p != request.form.get("password2"):
                flash("Şifre en az 10 karakter olmalı ve iki alan aynı olmalı.", "error")
            else:
                con().execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES(?, ?, 'admin', ?)",
                              (u, generate_password_hash(p), db.now_utc()))
                db.audit(con(), u, "kurulum", "ilk yönetici oluşturuldu")
                con().commit()
                flash("Yönetici oluşturuldu, giriş yapabilirsiniz.", "ok")
                return redirect(url_for("login"))
        return render_template("setup.html")

    @app.route("/giris", methods=["GET", "POST"])
    def login():
        if not con().execute("SELECT COUNT(*) n FROM users").fetchone()["n"]:
            return redirect(url_for("setup"))
        if request.method == "POST":
            u, p = request.form.get("username", "").strip(), request.form.get("password", "")
            key = (u.lower(), request.remote_addr)
            with _fails_lock:
                n, until = _fails.get(key, (0, 0))
            if until > time.time():
                flash("Çok fazla hatalı deneme. Birkaç dakika sonra tekrar deneyin.", "error")
                return render_template("login.html"), 429
            r = con().execute("SELECT * FROM users WHERE username=? AND active=1", (u,)).fetchone()
            if r and check_password_hash(r["pw_hash"], p):
                with _fails_lock:
                    _fails.pop(key, None)
                session.clear()
                session["uid"] = r["id"]
                session["csrf"] = secrets.token_urlsafe(24)
                con().execute("UPDATE users SET last_login=? WHERE id=?", (db.now_utc(), r["id"]))
                db.audit(con(), r["username"], "giris")
                con().commit()
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
            with _fails_lock:
                n += 1
                _fails[key] = (n, time.time() + 300 if n >= 5 else 0)
            time.sleep(0.5)
            flash("Kullanıcı adı ya da şifre hatalı.", "error")
        return render_template("login.html")

    @app.post("/cikis")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/sifre", methods=["GET", "POST"])
    @login_required
    def password():
        if request.method == "POST":
            cur, new = request.form.get("current", ""), request.form.get("new", "")
            if not check_password_hash(user()["pw_hash"], cur):
                flash("Mevcut şifre hatalı.", "error")
            elif len(new) < 10 or new != request.form.get("new2"):
                flash("Yeni şifre en az 10 karakter olmalı ve iki alan aynı olmalı.", "error")
            else:
                con().execute("UPDATE users SET pw_hash=?, must_change=0 WHERE id=?", (generate_password_hash(new), user()["id"]))
                audit("sifre_degisti")
                flash("Şifre değiştirildi.", "ok")
                return redirect(url_for("dashboard"))
        return render_template("password.html")

    # ------------------------------------------------------------ pano
    @app.get("/")
    @login_required
    def dashboard():
        kat = request.args.get("kategori", "Tümü")
        sums = [(r, db.run_summary(r)) for r in done_runs()]
        kats = sorted({k for _, s in sums if s for k in s.get("kategori", {})})
        trend = []
        for r, s in sums:
            m = seg_metrics(s, kat)
            if m:
                trend.append({"id": r["id"], "ad": r["name"], "tarih": tr_date(rdate(r)), "skor": m["skor"],
                              "nb_aksiyon": m["nb_aksiyon"], "kritik": m["kritik"], "kirilgan": m["kirilgan"],
                              "not_blocked": m["not_blocked"]})
        ch = [{"tarih": r["tarih"], "alan": r["alan"], "aciklama": r["aciklama"]}
              for r in con().execute("SELECT * FROM changes ORDER BY tarih, id").fetchall()]
        cur = seg_metrics(sums[-1][1], kat) if sums else None
        prev = seg_metrics(sums[-2][1], kat) if len(sums) > 1 else None
        all_runs = sorted(con().execute("SELECT * FROM runs").fetchall(), key=okey, reverse=True)
        recent = con().execute("SELECT * FROM changes ORDER BY tarih DESC, id DESC LIMIT 8").fetchall()
        return render_template("dashboard.html", kat=kat, kats=kats, cur=cur, prev=prev,
                               cur_run=sums[-1][0] if sums else None, prev_run=sums[-2][0] if len(sums) > 1 else None,
                               trend=trend, changes=ch, runs=all_runs, sums={r["id"]: s for r, s in sums}, recent=recent)

    # ------------------------------------------------------------ koşumlar
    @app.route("/simulasyon/yeni", methods=["GET", "POST"])
    @admin_required
    def run_new():
        c = con()
        dflt = {"host": db.setting(c, "target_host"), "ips": db.setting(c, "picus_ips")}
        if request.method == "GET":
            return render_template("run_new.html", d=dflt, picus_ok=bool(config.picus_token()), cf_ok=bool(config.cf_token()))
        f = request.form
        try:
            name = f.get("name", "").strip() or "Simülasyon"
            psrc, csrc = f.get("picus_source", "csv"), f.get("source", "api")
            host = f.get("host", "").strip()
            ips = cfapi.expand_ips(f.get("ips", ""))
            if csrc == "api" and not ips and not host:
                raise ValueError("Cloudflare'den çekmek için Picus IP'leri ya da hedef host girilmeli.")
            fs, fe = parse_tr(f.get("start")), parse_tr(f.get("end"))
            R, start, end, run_date, fname = None, fs, fe, None, ""
            if psrc == "csv":
                raw = read_upload(request.files.get("picus"), "Picus CSV")
                R = analysis.read_picus(io.BytesIO(raw))
                fname = request.files["picus"].filename
                ws, we = jobs.window_from(R, c)
                start, end = fs or ws, fe or we
                run_date = utc_iso(analysis.picus_window(R)[0])
            else:
                sid, rid = f.get("picus_sim", "").strip(), f.get("picus_run", "").strip()
                if not sid.isdigit() or not rid.isdigit():
                    raise ValueError("Picus simülasyonu ve koşumu seçilmeli.")
                if not config.picus_token():
                    raise ValueError("PICUS_API_TOKEN tanımlı değil (.env).")
                start = start or datetime.now(timezone.utc)
                end = end or start
            if csrc == "csv":
                hraw = read_upload(request.files.get("cf_http"), "Cloudflare HTTP istekleri CSV")
                eraw = request.files.get("cf_events")
                H = csv_df(hraw)
                E = csv_df(eraw.read()) if eraw and eraw.filename else pd.DataFrame()
            cur = c.execute(
                "INSERT INTO runs(name, picus_report, picus_file, start_utc, end_utc, host, ips, source, picus_source, picus_sim_id, "
                "picus_run_id, origin, window_fixed, run_date, status, notes, created_by, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, f.get("picus_report", "").strip() or None, fname, utc_iso(start), utc_iso(end), host, json.dumps(ips),
                 csrc, psrc, f.get("picus_sim") if psrc == "api" else None, f.get("picus_run") if psrc == "api" else None,
                 "elle", 1 if (fs and fe) else 0, run_date, "kuyrukta", f.get("notes", "").strip(), user()["username"], db.now_utc()))
            run_id = cur.lastrowid
            if R is not None:
                db.put_df(c, run_id, "picus", R)
            if csrc == "csv":
                db.put_df(c, run_id, "cf_http", H)
                db.put_df(c, run_id, "cf_events", E)
            c.commit()
            audit("kosum_ekle", f"{run_id} {name}")
            jobs.submit(run_id, fetch=(csrc == "api"), picus=(psrc == "api"))
            return redirect(url_for("run_detail", run_id=run_id))
        except (ValueError, analysis.PicusFormatError, cfapi.CFError) as e:
            flash(str(e), "error")
            return render_template("run_new.html", d=dict(dflt, **f.to_dict()), picus_ok=bool(config.picus_token()),
                                   cf_ok=bool(config.cf_token())), 400

    @app.get("/simulasyon/<int:run_id>")
    @login_required
    def run_detail(run_id):
        run = get_run(run_id)
        s = db.run_summary(run)
        prev = prev_of(run) if run["status"] == "tamam" else None
        warns = json.loads(run["warnings"] or "[]")
        cf_rows = exports.cf_karar_table(s).values.tolist() if s else []
        return render_template("run_detail.html", run=run, s=s, prev=prev, ps=db.run_summary(prev) if prev else None, cf_rows=cf_rows,
                               warns=warns, tables=exports.RUN_TABLES,
                               changes=changes_between(prev, run) if prev else [])

    @app.get("/simulasyon/<int:run_id>/durum")
    @login_required
    def run_status(run_id):
        r = get_run(run_id)
        return jsonify(status=r["status"], progress=r["progress"], log=(r["log"] or "")[-6000:], error=r["error"])

    @app.get("/simulasyon/<int:run_id>/tablo/<name>")
    @login_required
    def run_table(run_id, name):
        get_run(run_id)
        if name not in exports.RUN_TABLES:
            abort(404)
        kind, _, cols = exports.RUN_TABLES[name]
        return jsonify(exports.records(db.get_df(con(), run_id, kind), cols))

    @app.get("/simulasyon/<int:run_id>/excel")
    @login_required
    def run_excel(run_id):
        run = get_run(run_id)
        s = db.run_summary(run)
        if not s:
            abort(404)
        tables = {k: db.get_df(con(), run_id, k) for k, _, _ in exports.RUN_TABLES.values()}
        buf = exports.run_excel(run, s, tables)
        return send_file(buf, as_attachment=True, download_name=f"picus_cf_{run_id}_{tr_date(rdate(run))}.xlsx")

    @app.get("/simulasyon/<int:run_id>/rapor")
    @login_required
    def run_report(run_id):
        run = get_run(run_id)
        s = db.run_summary(run)
        if not s:
            abort(404)
        g_ = lambda k: db.get_df(con(), run_id, k)  # noqa: E731
        html = exports.risk_report(run, s, g_("actions"), g_("categories"), g_("log_block"), g_("rule_hits"))
        return Response(html, mimetype="text/html",
                        headers={"Content-Disposition": f'attachment; filename="risk_raporu_{run_id}.html"'})

    @app.post("/simulasyon/<int:run_id>/islem")
    @admin_required
    def run_action(run_id):
        run = get_run(run_id)
        op = request.form.get("islem")
        if run["status"] in ("kuyrukta", "calisiyor") and op != "duzenle":
            flash("Koşum için çalışan bir iş var.", "warn")
            return redirect(url_for("run_detail", run_id=run_id))
        if op == "analiz":
            jobs.submit(run_id, fetch=False)
        elif op == "cek":
            if run["source"] != "api":
                flash("Bu koşumun CF verisi CSV ile yüklendi; API'den çekmek için koşumu API kaynaklı yeniden oluşturun.", "warn")
                return redirect(url_for("run_detail", run_id=run_id))
            jobs.submit(run_id, fetch=True)
        elif op == "picus":
            if run["picus_source"] != "api":
                abort(400)
            jobs.submit(run_id, fetch=run["source"] == "api", picus=True)
        elif op == "sil":
            con().execute("DELETE FROM runs WHERE id=?", (run_id,))
            con().commit()
            audit("kosum_sil", f"{run_id} {run['name']}")
            flash("Koşum silindi.", "ok")
            return redirect(url_for("dashboard"))
        elif op == "duzenle":
            f = request.form
            try:
                upd = {"name": f.get("name", run["name"]).strip() or run["name"], "notes": f.get("notes", "").strip(),
                       "picus_report": f.get("picus_report", "").strip() or None}
                rd = parse_tr(f.get("run_date"))
                if rd:
                    upd["run_date"] = utc_iso(rd)
                s, e = parse_tr(f.get("start")), parse_tr(f.get("end"))
                if s and e:
                    if e <= s:
                        raise ValueError("Bitiş başlangıçtan sonra olmalı.")
                    upd.update(start_utc=utc_iso(s), end_utc=utc_iso(e), window_fixed=1)
                con().execute("UPDATE runs SET " + ", ".join(f"{k}=?" for k in upd) + " WHERE id=?", (*upd.values(), run_id))
                con().commit()
                audit("kosum_duzenle", f"{run_id}")
                flash("Kaydedildi." + (" Yeni CF aralığı için 'CF verisini yeniden çek' çalıştırın." if s and e else ""), "ok")
            except ValueError as ex:
                flash(str(ex), "error")
        else:
            abort(400)
        return redirect(url_for("run_detail", run_id=run_id))

    # ------------------------------------------------------------ Picus seçim listeleri
    @app.get("/picus/simulasyonlar")
    @admin_required
    def picus_sims():
        try:
            pc = picusapi.PicusClient(config.picus_token(), config.PICUS_URL)
            out = [{"id": x.get("simulation_id") or x.get("id"), "ad": x.get("simulation_name") or x.get("name") or "",
                    "son": picusapi.ms_to_utc(x.get("last_run_date") or x.get("updated_at") or 0)} for x in pc.simulations()]
            return jsonify(ok=True, items=[x for x in out if x["id"]])
        except picusapi.PicusError as e:
            return jsonify(ok=False, error=str(e))

    @app.get("/picus/simulasyon/<int:sid>/kosumlar")
    @admin_required
    def picus_runs(sid):
        try:
            name, runs = picusapi.PicusClient(config.picus_token(), config.PICUS_URL).runs(sid)
            have = {r["picus_run_id"] for r in con().execute("SELECT picus_run_id FROM runs WHERE picus_sim_id=?", (str(sid),))}
            return jsonify(ok=True, ad=name, items=[dict(r, var=r["id"] in have) for r in runs])
        except picusapi.PicusError as e:
            return jsonify(ok=False, error=str(e))

    # ------------------------------------------------------------ karşılaştırma
    def _cmp_runs():
        runs = done_runs()
        ids = {r["id"]: r for r in runs}
        try:
            a = ids.get(int(request.args.get("a", 0)))
            b = ids.get(int(request.args.get("b", 0)))
        except ValueError:
            a = b = None
        if not b and runs:
            b = runs[-1]
        if not a and b:
            a = prev_of(b)
        swapped = False
        if a and b and okey(a) > okey(b):
            a, b, swapped = b, a, True
        return runs, a, b, swapped

    @app.get("/karsilastir")
    @login_required
    def compare():
        runs, a, b, swapped = _cmp_runs()
        if not a or not b or a["id"] == b["id"]:
            return render_template("compare.html", runs=runs, a=a, b=b, res=None)
        if swapped:
            flash("Seçilen 'güncel' koşum daha eski olduğu için sıralama düzeltildi (koşum tarihine göre).", "warn")
        sa, sb = db.run_summary(a), db.run_summary(b)
        if sa.get("cf_yok") or sb.get("cf_yok"):
            flash("Koşumlardan birinde CF verisi eşleşmedi; kırılgan blok ve kural ailesi karşılaştırması eksik olur.", "warn")
        res = comparison(a, b)
        if res["eslesme"]["oran"] < 0.5:
            flash(f"İki koşumun testleri büyük ölçüde eşleşmedi ({res['eslesme']['ortak']} ortak test). Koşumlar farklı "
                  "simülasyon şablonlarından olabilir; Kapandı/Açık kaldı sayıları güvenilir değil.", "warn")
        kat = category_table(sa, sb)
        return render_template("compare.html", runs=runs, a=a, b=b, sa=sa, sb=sb, res=res, tables=exports.CMP_TABLES,
                               kat=kat.to_dict("records"), kat_cols=list(kat.columns), changes=changes_between(a, b))

    @app.get("/karsilastir/tablo/<name>")
    @login_required
    def compare_table(name):
        _, a, b, _ = _cmp_runs()
        if not a or not b or name not in exports.CMP_TABLES:
            abort(404)
        kind, _, cols = exports.CMP_TABLES[name]
        return jsonify(exports.records(comparison(a, b)[kind], cols))

    @app.get("/karsilastir/excel")
    @login_required
    def compare_excel():
        _, a, b, _ = _cmp_runs()
        if not a or not b:
            abort(404)
        sa, sb = db.run_summary(a), db.run_summary(b)
        buf = exports.compare_excel(a, b, sa, sb, comparison(a, b), category_table(sa, sb))
        return send_file(buf, as_attachment=True, download_name=f"karsilastirma_{a['id']}_{b['id']}.xlsx")

    # ------------------------------------------------------------ değişiklik kayıtları
    @app.route("/degisiklikler", methods=["GET", "POST"])
    @login_required
    def changes():
        if request.method == "POST":
            if user()["role"] != "admin":
                abort(403)
            f = request.form
            if f.get("islem") == "sil":
                con().execute("DELETE FROM changes WHERE id=?", (f.get("id"),))
                audit("degisiklik_sil", f.get("id", ""))
            else:
                t, a = f.get("tarih", "").strip(), f.get("aciklama", "").strip()
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", t) or not a:
                    flash("Tarih ve açıklama zorunlu.", "error")
                    return redirect(url_for("changes"))
                con().execute("INSERT INTO changes(tarih, alan, aciklama, created_by, created_at) VALUES(?,?,?,?,?)",
                              (t, f.get("alan", ""), a[:2000], user()["username"], db.now_utc()))
                audit("degisiklik_ekle", a[:120])
            con().commit()
            return redirect(url_for("changes"))
        rows = con().execute("SELECT * FROM changes ORDER BY tarih DESC, id DESC").fetchall()
        return render_template("changes.html", rows=rows, alanlar=ALANLAR, today=datetime.now(config.TR).strftime("%Y-%m-%d"))

    # ------------------------------------------------------------ ayarlar
    @app.route("/ayarlar", methods=["GET", "POST"])
    @admin_required
    def settings():
        c = con()
        if request.method == "POST":
            f = request.form
            op = f.get("islem", "kaydet")
            if op == "kaydet":
                try:
                    cfapi.expand_ips(f.get("picus_ips", ""))
                    for k in ("margin_before_min", "margin_after_min", "picus_interval_min", "picus_wait_min", "picus_lookback_days"):
                        if f.get(k, "0").strip() and not f.get(k, "0").strip().isdigit():
                            raise ValueError("Süre alanları tam sayı olmalı.")
                    if f.get("zone_id", "").strip() and not re.fullmatch(r"[0-9a-f]{32}", f.get("zone_id", "").strip()):
                        raise ValueError("Zone ID 32 karakterlik onaltılık bir değer olmalı.")
                except (ValueError, cfapi.CFError) as e:
                    flash(str(e), "error")
                    return redirect(url_for("settings"))
                for k in ("zone_id", "picus_ips", "target_host", "margin_before_min", "margin_after_min", "picus_interval_min",
                          "picus_wait_min", "picus_lookback_days"):
                    if k in f:
                        db.set_setting(c, k, f.get(k, "").strip())
                db.set_setting(c, "picus_auto", "1" if f.get("picus_auto") else "0")
                db.set_setting(c, "picus_sensitive", "1" if f.get("picus_sensitive") else "0")
                db.set_setting(c, "picus_watch", ",".join(x for x in re.split(r"[\s,;]+", f.get("picus_watch", "")) if x.isdigit()))
                c.commit()
                audit("ayar_kaydet")
                flash("Ayarlar kaydedildi.", "ok")
            elif op == "test":
                try:
                    ok, msg = cfapi.CFClient(config.cf_token(), db.setting(c, "zone_id")).test()
                    flash(msg, "ok" if ok else "error")
                except cfapi.CFError as e:
                    flash(str(e), "error")
            elif op == "picus_test":
                try:
                    flash(picusapi.PicusClient(config.picus_token(), config.PICUS_URL).test(), "ok")
                except picusapi.PicusError as e:
                    flash(str(e), "error")
            elif op == "picus_kontrol":
                import watcher
                try:
                    n = watcher.check_once(c, log=lambda m: flash(m, "warn"))
                    flash(f"Kontrol tamam: {n} yeni koşum kuyruğa alındı.", "ok")
                except picusapi.PicusError as e:
                    flash(str(e), "error")
            return redirect(url_for("settings"))
        vals = {k: db.setting(c, k) for k in config.DEFAULTS}
        return render_template("settings.html", v=vals, token_set=bool(config.cf_token()), picus_set=bool(config.picus_token()),
                               picus_url=config.PICUS_URL, data_dir=str(config.DATA_DIR))

    # ------------------------------------------------------------ kullanıcılar
    @app.route("/kullanicilar", methods=["GET", "POST"])
    @admin_required
    def users():
        c = con()
        if request.method == "POST":
            f = request.form
            op, uid = f.get("islem"), f.get("id")
            if op == "ekle":
                u, p, role = f.get("username", "").strip(), f.get("password", ""), f.get("role", "izleyici")
                if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", u) or len(p) < 10 or role not in ROLES:
                    flash("Kullanıcı adı 3-32 karakter, şifre en az 10 karakter olmalı.", "error")
                elif c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
                    flash("Bu kullanıcı adı var.", "error")
                else:
                    c.execute("INSERT INTO users(username, pw_hash, role, must_change, created_at) VALUES(?,?,?,1,?)",
                              (u, generate_password_hash(p), role, db.now_utc()))
                    audit("kullanici_ekle", u)
                    flash(f"{u} eklendi; ilk girişte şifresini değiştirecek.", "ok")
            elif uid and int(uid) != user()["id"]:
                if op == "rol" and f.get("role") in ROLES:
                    c.execute("UPDATE users SET role=? WHERE id=?", (f.get("role"), uid))
                elif op == "aktif":
                    c.execute("UPDATE users SET active = 1 - active WHERE id=?", (uid,))
                elif op == "sifirla" and len(f.get("password", "")) >= 10:
                    c.execute("UPDATE users SET pw_hash=?, must_change=1 WHERE id=?", (generate_password_hash(f["password"]), uid))
                else:
                    flash("Geçersiz işlem (şifre en az 10 karakter).", "error")
                audit("kullanici_" + (op or ""), uid)
            else:
                flash("Kendi hesabınızda bu işlemi yapamazsınız.", "warn")
            c.commit()
            return redirect(url_for("users"))
        rows = c.execute("SELECT * FROM users ORDER BY username").fetchall()
        log = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()
        return render_template("users.html", rows=rows, log=log)

    # ------------------------------------------------------------ Prod FP
    @app.route("/prod", methods=["GET", "POST"])
    @login_required
    def prod_list():
        c = con()
        runs = done_runs()
        if request.method == "POST":
            if user()["role"] != "admin":
                abort(403)
            f = request.form
            try:
                if f.get("mod") == "aralik":
                    s, e = parse_tr(f.get("start")), parse_tr(f.get("end"))
                    if not s or not e or e <= s:
                        raise ValueError("Geçerli bir başlangıç ve bitiş girin.")
                else:
                    days = int(f.get("gun", "3"))
                    e = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
                    s = e - timedelta(days=days)
                if e - s > timedelta(days=14):
                    raise ValueError("En fazla 14 günlük aralık taranabilir.")
                a, b = f.get("a") or None, f.get("b") or None
                cur = c.execute("INSERT INTO prod_scans(name, start_utc, end_utc, base_run, ref_run, status, created_by, created_at) "
                                "VALUES(?,?,?,?,?,?,?,?)",
                                (f.get("name", "").strip() or f"Prod taraması {datetime.now(config.TR):%d.%m.%Y}", utc_iso(s), utc_iso(e),
                                 a, b, "kuyrukta", user()["username"], db.now_utc()))
                c.commit()
                audit("prod_tarama", str(cur.lastrowid))
                jobs.submit_scan(cur.lastrowid)
                return redirect(url_for("prod_detail", sid=cur.lastrowid))
            except ValueError as ex:
                flash(str(ex), "error")
        scans = c.execute("SELECT * FROM prod_scans ORDER BY id DESC").fetchall()
        return render_template("prod_list.html", scans=scans, runs=runs, cur=runs[-1] if runs else None,
                               prev=runs[-2] if len(runs) > 1 else None)

    @app.get("/prod/<int:sid>")
    @login_required
    def prod_detail(sid):
        sc = scan_or_404(sid)
        if sc["status"] != "tamam":
            return render_template("prod_detail.html", sc=sc, T=None)
        a, b, prod, states, T, E, oz = build_scan(sc)
        if a and b and comparison(a, b)["eslesme"]["oran"] < 0.5:
            flash("Seçili iki koşumun testleri eşleşmedi; Picus kazancı güvenilir değil. Aynı simülasyon şablonundan iki koşum seçin.", "warn")
        k, du = request.args.get("k", ""), request.args.get("du", "")
        view = T
        if k:
            view = view[view.karar == k]
        if du:
            view = view[view.durum == du]
        return render_template("prod_detail.html", sc=sc, a=a, b=b, runs=done_runs(), T=view, total=len(T), oz=oz.to_dict("records"),
                               E=E.to_dict("records"), k=k, du=du, warns=json.loads(sc["warnings"] or "[]"),
                               states_ok=bool(states), known_n=len(db.known_fp(con())))

    @app.get("/prod/<int:sid>/durum")
    @login_required
    def prod_status(sid):
        r = scan_or_404(sid)
        return jsonify(status=r["status"], progress=r["progress"], log=(r["log"] or "")[-6000:], error=r["error"])

    @app.get("/prod/<int:sid>/kural/<rid>")
    @login_required
    def prod_rule(sid, rid):
        sc = scan_or_404(sid)
        if sc["status"] != "tamam" or not re.fullmatch(r"[0-9a-zA-Z]{6,64}", rid):
            abort(404)
        a, b, prod, states, T, E, oz = build_scan(sc)
        row = T[T.rule_id == rid]
        if not len(row):
            abort(404)
        th = (db.setting(con(), "target_host") or "").lower()

        def part(df, by):
            if not len(df):
                return []
            x = df[(df.ruleId == rid) & (df.clientRequestHTTPHost.fillna("").str.lower().str.split(":").str[0] != th)].copy()
            if not len(x):
                return []
            x["olay"] = pd.to_numeric(x.olay, errors="coerce").fillna(0).astype(int)
            return x.groupby([c for c in by if c in x.columns], as_index=False).olay.sum().sort_values("olay", ascending=False).head(60).to_dict("records")
        S = prod["samples"]
        samples = S[S.ruleId == rid].head(60).to_dict("records") if len(S) and "ruleId" in S.columns else []
        st = db.get_scan_df(con(), sid, "states")
        dep = []
        if len(st) and rid in set(st.rule_id):
            r_ = st[st.rule_id == rid].iloc[0]
            dep = json.loads(r_["dagitimlar"] or "[]")
            dep += [{"test": False, "aksiyon": "skip (exception)", "expression": e, "ad": ""} for e in json.loads(r_["skip"] or "[]")]
        return render_template("prod_rule.html", sc=sc, r=row.iloc[0].to_dict(), a=a, b=b,
                               hostpath=part(prod["hp"], ["action", "clientRequestHTTPHost", "clientRequestHTTPMethodName", "clientRequestPath"]),
                               ulke=part(prod["src"], ["clientCountryName"]), asn=part(prod["src"], ["clientASNDescription", "clientCountryName"]),
                               samples=samples, dep=dep, known=db.known_fp(con()).get(rid))

    @app.post("/prod/<int:sid>/karar")
    @admin_required
    def prod_decide(sid):
        scan_or_404(sid)
        f = request.form
        rid = f.get("rule_id", "")
        if not re.fullmatch(r"[0-9a-zA-Z]{6,64}", rid):
            abort(400)
        c = con()
        c.execute("INSERT OR IGNORE INTO rule_decisions(rule_id) VALUES(?)", (rid,))
        if "durum" in f:
            if f["durum"] not in prodfp.DURUMLAR:
                abort(400)
            c.execute("UPDATE rule_decisions SET durum=?, durum_by=?, durum_at=? WHERE rule_id=?",
                      (f["durum"], user()["username"], db.now_utc(), rid))
            audit("kural_durum", f"{rid} {f['durum']}")
        else:
            k = f.get("karar", "")
            if k and k not in prodfp.KARARLAR:
                abort(400)
            c.execute("UPDATE rule_decisions SET karar=?, note=?, updated_by=?, updated_at=? WHERE rule_id=?",
                      (k or None, f.get("note", "").strip()[:1000] or None, user()["username"], db.now_utc(), rid))
            audit("kural_karar", f"{rid} {k}")
        c.commit()
        nxt = f.get("next", "")
        return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("prod_detail", sid=sid))

    @app.get("/prod/<int:sid>/excel")
    @login_required
    def prod_excel(sid):
        sc = scan_or_404(sid)
        if sc["status"] != "tamam":
            abort(404)
        a, b, prod, states, T, E, oz = build_scan(sc)
        buf = prodfp.excel(T, E, oz, prod, db.setting(con(), "target_host"), "Cloudflare Prod Kural Karar Listesi")
        return send_file(buf, as_attachment=True, download_name=f"prod_kural_karar_{sid}.xlsx")

    @app.post("/prod/<int:sid>/sil")
    @admin_required
    def prod_delete(sid):
        scan_or_404(sid)
        con().execute("DELETE FROM prod_scans WHERE id=?", (sid,))
        con().commit()
        audit("prod_sil", str(sid))
        flash("Tarama silindi.", "ok")
        return redirect(url_for("prod_list"))

    @app.post("/istisna")
    @admin_required
    def exception_edit():
        f = request.form
        c = con()
        op = f.get("islem")
        if op == "ekle":
            rules = " ".join(RID.findall(f.get("rules", "")))
            if not rules or not (f.get("hosts") or f.get("path_eq") or f.get("path_prefix") or f.get("expression")):
                flash("Exception için en az bir kural ID ve bir koşul (host, path ya da expression) gerekli.", "error")
            else:
                n = c.execute("SELECT COALESCE(MAX(id), 0) + 1 n FROM exceptions").fetchone()["n"]
                c.execute("INSERT INTO exceptions(code, ad, hosts, path_eq, path_prefix, rules, expression, note, created_by, created_at) "
                          "VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (f"EX{n}", f.get("ad", "").strip()[:200], f.get("hosts", "").strip(), f.get("path_eq", "").strip(),
                           f.get("path_prefix", "").strip(), rules, f.get("expression", "").strip()[:2000],
                           f.get("note", "").strip()[:500], user()["username"], db.now_utc()))
                audit("istisna_ekle", f"EX{n}")
                flash(f"EX{n} eklendi.", "ok")
        elif op == "sil":
            c.execute("DELETE FROM exceptions WHERE id=?", (f.get("id"),))
            audit("istisna_sil", f.get("id", ""))
        elif op == "aktif":
            c.execute("UPDATE exceptions SET active = 1 - active WHERE id=?", (f.get("id"),))
        c.commit()
        nxt = f.get("next", "")
        return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("prod_list"))

    # ------------------------------------------------------------ bilinen FP / kapatılmış kurallar
    @app.route("/bilinen-fp", methods=["GET", "POST"])
    @login_required
    def known_fp():
        c = con()
        if request.method == "POST":
            if user()["role"] != "admin":
                abort(403)
            f = request.form
            if f.get("islem") == "sil":
                c.execute("DELETE FROM known_fp WHERE rule_id=?", (f.get("rule_id"),))
                audit("bilinen_fp_sil", f.get("rule_id", ""))
            else:
                added = 0
                for line in f.get("liste", "").splitlines():
                    m = RID.search(line)
                    if not m:
                        continue
                    ad = line[:m.start()].strip(" \t;,|-") or line[m.end():].strip(" \t;,|-")
                    c.execute("INSERT INTO known_fp(rule_id, kural, note, created_by, created_at) VALUES(?,?,?,?,?) "
                              "ON CONFLICT(rule_id) DO UPDATE SET kural=COALESCE(NULLIF(excluded.kural, ''), kural), "
                              "note=COALESCE(NULLIF(excluded.note, ''), note)",
                              (m.group(1), ad[:200], f.get("note", "").strip()[:300], user()["username"], db.now_utc()))
                    added += 1
                audit("bilinen_fp_ekle", str(added))
                flash(f"{added} kural bilinen FP listesine eklendi/güncellendi." if added else "Listede kural ID'si bulunamadı.",
                      "ok" if added else "error")
            c.commit()
            return redirect(url_for("known_fp"))
        rows = c.execute("SELECT * FROM known_fp ORDER BY kural").fetchall()
        return render_template("known_fp.html", rows=rows)

    @app.post("/liste-kontrol")
    @login_required
    def list_check():
        """Yapıştırılan Block listesini bilinen FP listesiyle karşılaştırır."""
        kn = db.known_fp(con())
        items, seen = [], set()
        for line in request.form.get("liste", "").splitlines():
            m = RID.search(line)
            if not m or m.group(1) in seen:
                continue
            seen.add(m.group(1))
            ad = line[:m.start()].strip(" \t;,|-") or line[m.end():].strip(" \t;,|-")
            items.append({"rule_id": m.group(1), "kural": ad, "fp": m.group(1) in kn, "not": (kn.get(m.group(1)) or {}).get("note", "")})
        rows = con().execute("SELECT * FROM known_fp ORDER BY kural").fetchall()
        return render_template("known_fp.html", rows=rows, check=items)
