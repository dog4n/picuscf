"""Picus Platform REST API istemcisi (salt okuma).

Kimlik: Picus > Settings > Rest API Token ile üretilen refresh token (.env: PICUS_API_TOKEN).
POST /v1/auth/token  -> ~2 saatlik access token
GET  /v1/simulations, /v1/simulations/{id} (koşum listesi: simulation_run[])
GET  /v1/simulations/{id}/run/{run}/threats                      (kampanyalar + aksiyon sonuçları)
GET  /v1/simulations/{id}/run/{run}/threats/{threat}/actions     (aksiyon detayları: zaman, CVE/CWE referansı)
POST /v2/simulations/{id}/results/reports?type=run&runId=..    (CSV rapor üretimi; write:simulations yetkisi ister)
GET  /v2/simulations/{id}/results/reports/{rep}[/download-url|/download]
Önce rapor (Picus CSV'siyle birebir aynı içerik) denenir; olmazsa threats/actions uç noktalarından tablo kurulur.
Çıktı, Picus CSV'sinin okunmuş haliyle aynı kolonlara sahip tablo (analysis.read_picus ile aynı).
"""
import io
import json
import re
import time
import zipfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import pandas as pd

try:
    import truststore
    truststore.inject_into_ssl()
except Exception:  # noqa: BLE001
    pass

HTTP_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|PROPFIND|CONNECT)\s+(\S+)", re.M)


class PicusError(Exception):
    pass


def norm_prevention(v):
    s = re.sub(r"[_\-]+", " ", str(v or "")).strip().lower()
    if s in ("blocked", "prevented", "block"):
        return "Blocked"
    if "unblock" in s or s.startswith("not block") or s in ("notblocked", "not prevented", "unprevented", "passed"):
        return "Not Blocked"
    return "Not Tested"


def ms_to_utc(v):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    if v > 10 ** 11:   # milisaniye
        v = v / 1000
    return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk(v)


def _refs(action, kind):
    """references.cve_reference / cwe_reference (tek nesne ya da liste) + metin içindeki CVE/CWE kalıpları."""
    out = []
    refs = action.get("references") or {}
    r = refs.get(f"{kind}_reference")
    for x in (r if isinstance(r, list) else [r] if r else []):
        if isinstance(x, dict):
            out.append(str(x.get("name") or ""))
        else:
            out.append(str(x))
    pat = r"CVE-\d{4}-\d+" if kind == "cve" else r"CWE-(\d+)"
    for k, v in _walk(action):
        if isinstance(v, str) and len(v) < 400:
            out += re.findall(pat, v)
    if kind == "cve":
        return ", ".join(sorted({x for o in out for x in re.findall(r"CVE-\d{4}-\d+", o)}))
    return ", ".join(sorted({x for o in out for x in re.findall(r"\d+", o)}))


def _request_line(action):
    for _, v in _walk(action):
        if isinstance(v, str):
            m = HTTP_LINE.search(v)
            if m:
                return (m.group(1) + " " + m.group(2).replace("/page{PICUSID}", ""))[:300]
    return ""


class PicusClient:
    def __init__(self, refresh_token, base="https://api.picussecurity.com", log=None):  # base: .env PICUS_API_URL
        if not refresh_token:
            raise PicusError("PICUS_API_TOKEN tanımlı değil. Picus > Settings > Rest API Token'dan üretip .env'ye ekleyin, servisi yeniden başlatın.")
        self.refresh = refresh_token.strip()
        self.base = (base or "https://api.picussecurity.com").rstrip("/")
        self.log = log or (lambda *a, **k: None)
        self._tok, self._exp = None, 0

    # ------------------------------------------------------------ http
    def _raw(self, url, auth=True):
        headers = {"User-Agent": "picuscf-platform"}
        if auth:
            headers["Authorization"] = f"Bearer {self._token()}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            raise PicusError(f"Picus indirme {e.code}: {e.read().decode(errors='replace')[:200]}") from None
        except urllib.error.URLError as e:
            raise PicusError(f"Picus indirme bağlantı hatası: {e.reason}") from None

    def _req(self, method, path, params=None, body=None, auth=True):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        headers = {"Accept": "application/json", "User-Agent": "picuscf-platform"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = f"Bearer {self._token()}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            txt = e.read().decode(errors="replace")[:300]
            raise PicusError(f"Picus API {e.code} ({path}): {txt}") from None
        except urllib.error.URLError as e:
            raise PicusError(f"Picus API'ye bağlanılamadı: {e.reason}. Proxy gerekiyorsa .env'de HTTPS_PROXY tanımlayın.") from None
        try:
            return json.loads(raw)
        except ValueError:
            raise PicusError(f"Picus API JSON dönmedi ({path}); ağ cihazı cevabı engellemiş olabilir: {raw[:120]}") from None

    def _token(self):
        if self._tok and time.time() < self._exp - 120:
            return self._tok
        r = self._req("POST", "/v1/auth/token", body={"refresh_token": self.refresh}, auth=False)
        tok = r.get("token") or r.get("access_token")
        if not tok:
            raise PicusError("Picus access token alınamadı; refresh token geçersiz ya da süresi dolmuş olabilir.")
        exp = r.get("expire_at") or 0
        self._tok = tok
        self._exp = (int(exp) / 1000 if int(exp) > 10 ** 11 else int(exp)) if exp else time.time() + 3600
        return tok

    def get(self, path, params=None, retries=4):
        for i in range(retries):
            try:
                return self._req("GET", path, params)
            except PicusError as e:
                msg = str(e)
                if " 401 " in msg and i == 0:          # token düştü: yenile
                    self._tok = None
                    continue
                if (" 429 " in msg or " 502 " in msg or " 503 " in msg or " 504 " in msg) and i < retries - 1:
                    time.sleep(2 * (i + 1))
                    continue
                raise
        raise PicusError(f"Picus API yanıt vermedi: {path}")

    def paged(self, path, key, limit=50, params=None):
        out, off = [], 0
        while True:
            r = self.get(path, dict(params or {}, limit=limit, offset=off))
            items = r.get(key) or []
            out += items
            total = int((r.get("pages") or {}).get("total_count") or 0)
            off += limit
            if not items or off >= total:
                return out
            time.sleep(0.1)

    # ------------------------------------------------------------ uç noktalar
    def test(self):
        r = self.get("/v1/simulations", {"limit": 1})
        n = (r.get("pages") or {}).get("total_count")
        return f"Bağlantı başarılı. Görünen simülasyon sayısı: {n if n is not None else '?'}"

    def simulations(self):
        return self.paged("/v1/simulations", "simulations")

    def simulation(self, sid):
        r = self.get(f"/v1/simulations/{int(sid)}")
        return r.get("Simulations", r) if isinstance(r, dict) else r

    def runs(self, sid):
        d = self.simulation(sid)
        out = []
        for x in d.get("simulation_run") or []:
            out.append({"id": str(x.get("id")), "status": x.get("status", ""),
                        "started_at": ms_to_utc(x.get("started_at")), "completed_at": ms_to_utc(x.get("completed_at"))})
        out.sort(key=lambda x: x["started_at"], reverse=True)
        return d.get("simulation_name", ""), out

    def run_tests(self, sid, rid, progress=None):
        """Koşumun tüm testlerini Picus CSV ile aynı kolonlarda döner + uyarılar."""
        progress = progress or (lambda f, m: None)
        sid, rid = int(sid), int(rid)
        threats = self.paged(f"/v1/simulations/{sid}/run/{rid}/threats", "threats")
        if not threats:
            raise PicusError("Bu koşumda kampanya (threat) dönmedi.")
        progress(0.05, f"Picus: {len(threats)} kampanya bulundu, aksiyon detayları çekiliyor…")
        rows, warns, fallback = [], [], 0
        for i, t in enumerate(threats):
            tid = t.get("threat_id")
            base = {"tid": str(tid), "kampanya": t.get("threat_name", ""), "kampanya_sonuc": norm_prevention(t.get("prevention")),
                    "severity": str(t.get("severity") or ""), "urun": ""}
            try:
                acts = self.paged(f"/v1/simulations/{sid}/run/{rid}/threats/{tid}/actions", "actions")
            except PicusError as e:
                acts = None
                if fallback == 0:
                    warns.append(f"Aksiyon detayı alınamayan kampanyalar threat özetinden alındı (ilk hata: {str(e)[:120]}).")
                fallback += 1
            if acts is None:   # yedek: threat özetindeki objectives[].actions[], zaman kampanyadan
                acts = [dict(a, started_at=t.get("started_at"), completed_at=t.get("completed_at"))
                        for o in (t.get("objectives") or []) for a in (o.get("actions") or [])]
            for a in acts:
                rows.append(dict(base,
                                 aid=str(a.get("action_id", "")), aid_alt=str(a.get("display_id") or ""),
                                 aksiyon=a.get("action_name", ""), picus=norm_prevention(a.get("prevention")),
                                 t_start=ms_to_utc(a.get("started_at") or t.get("started_at")),
                                 t_end=ms_to_utc(a.get("completed_at") or t.get("completed_at")),
                                 cve=_refs(a, "cve"), cwe=_refs(a, "cwe"), istek=_request_line(a), body_var=False))
            if i % 10 == 0 or i == len(threats) - 1:
                progress(0.05 + 0.95 * (i + 1) / len(threats), f"Picus: {i + 1}/{len(threats)} kampanya, {len(rows)} aksiyon satırı")
            time.sleep(0.05)
        if fallback:
            warns.append(f"{fallback} kampanyada aksiyon zamanı kampanya zamanından alındı (eşleşme biraz zayıflayabilir).")
        R = pd.DataFrame(rows, columns=["aid", "aid_alt", "aksiyon", "tid", "kampanya", "picus", "kampanya_sonuc", "t_start",
                                        "t_end", "cve", "cwe", "severity", "urun", "istek", "body_var"])
        R = R[R.aid != ""].reset_index(drop=True)
        if R.empty:
            raise PicusError("Picus koşumunda aksiyon bulunamadı.")
        if (R.cve == "").all() and (R.cwe == "").all():
            warns.append("Picus API CVE/CWE bilgisi döndürmedi; kategori aksiyon adından, önem kampanyadan hesaplandı.")
        return R, warns

    # ------------------------------------------------------------ rapor (CSV)
    def report_csv(self, sid, rid, sensitive=False, progress=None, timeout_s=900, rep_id=None):
        """Koşumun Picus CSV raporunu döndürür (bytes) ve rapor numarasını. rep_id verilirse mevcut rapor indirilir."""
        progress = progress or (lambda f, m: None)
        sid, rid = int(sid), int(rid)
        base = f"/v2/simulations/{sid}/results/reports"
        if not rep_id:
            r = self._req("POST", base + "?" + urllib.parse.urlencode({"type": "run", "runId": rid}),
                          body={"format": ["CSV"], "includesSensitiveData": bool(sensitive), "onlyPrevention": True})
            rep_id = str(r.get("id") or r.get("reportId") or (r.get("data") or {}).get("id") or "")
            if not rep_id:
                raise PicusError(f"Picus rapor numarası dönmedi: {str(r)[:150]}")
            progress(0.05, f"Picus raporu istendi (no {rep_id}), hazırlanıyor…")
            t0 = time.time()
            while True:
                st = self.get(f"{base}/{rep_id}")
                status = str(st.get("status") or (st.get("data") or {}).get("status") or "").upper()
                if status in ("COMPLETED", "DONE", "READY", "SUCCESS"):
                    break
                if status in ("ERROR", "FAILED"):
                    raise PicusError(f"Picus raporu üretilemedi (durum {status}).")
                if time.time() - t0 > timeout_s:
                    raise PicusError("Picus raporu zamanında hazırlanmadı.")
                progress(min(0.6, 0.05 + (time.time() - t0) / timeout_s), f"Picus raporu hazırlanıyor ({status or 'bekleniyor'})…")
                time.sleep(5)
        data = None
        try:
            u = self.get(f"{base}/{rep_id}/download-url")
            url = u.get("downloadUrl") or u.get("download_url") or (u.get("data") or {}).get("downloadUrl")
            if url:
                data = self._raw(url, auth=False)
        except PicusError:
            data = None
        if data is None:
            data = self._raw(self.base + f"{base}/{rep_id}/download")
        if data[:2] == b"PK":
            z = zipfile.ZipFile(io.BytesIO(data))
            name = next((n for n in z.namelist() if n.lower().endswith(".csv")), None)
            if not name:
                raise PicusError("Picus rapor arşivinde CSV yok.")
            data = z.read(name)
        progress(0.7, f"Picus raporu indirildi ({len(data) // 1024} KB).")
        return data, str(rep_id)


def fetch_run(client, sid, rid, sensitive=False, progress=None, rep_id=None):
    """Picus koşum tablosu: önce CSV raporu, olmazsa threats/actions. Dönen: (tablo, uyarılar, rapor no)."""
    import analysis
    progress = progress or (lambda f, m: None)
    warns = []
    try:
        data, rep = client.report_csv(sid, rid, sensitive, progress, rep_id=rep_id)
        R = analysis.read_picus(io.BytesIO(data))
        return R, warns, rep
    except (PicusError, analysis.PicusFormatError) as e:
        msg = str(e)
        if " 403" in msg:
            warns.append("Picus rapor üretimi için token'da write:simulations yetkisi yok (403). Koşum threats/actions "
                         "uç noktalarından çekildi. Alternatif: Picus'ta raporu elle üretip rapor numarasını koşuma girin.")
        else:
            warns.append(f"Picus CSV raporu alınamadı ({msg[:150]}); threats/actions uç noktalarından çekildi.")
    R, w2 = client.run_tests(sid, rid, progress)
    return R, warns + w2, None
