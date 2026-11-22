"""Cloudflare istemcisi: GraphQL Analytics (loglar) + Rulesets API (kural durumları, salt okuma).

- Alanları tek tek dener, hesapta olmayanları atlar.
- Saatlik pencerelerle çeker; sayfalama datetime imleciyle.
- Ağ cihazı (IPS/AV) cevaptaki saldırı metinleri yüzünden bir pencereyi keserse pencereyi böler,
  1 dakikaya inince path/query/user-agent olmadan çeker ve satırı işaretler.
"""
import ipaddress
import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

try:  # şirket SSL denetimi: Windows sertifika deposunu kullan
    import truststore
    truststore.inject_into_ssl()
except Exception:  # noqa: BLE001
    pass

from config import TR

API = "https://api.cloudflare.com/client/v4/graphql"
REST = "https://api.cloudflare.com/client/v4"
TRAFFIC = ["clientIP", "clientCountryName", "clientASNDescription", "clientRequestHTTPHost",
           "clientRequestHTTPMethodName", "clientRequestHTTPProtocol", "clientRequestPath",
           "clientRequestQuery", "edgeResponseStatus", "originResponseStatus", "rayName", "userAgent"]
ATTACK = ["securityAction", "securitySource", "securityRuleId", "wafAttackScore", "wafAttackScoreClass",
          "wafSqliAttackScore", "wafXssAttackScore", "wafRceAttackScore"]
BOT = ["botScore", "botScoreSrcName", "botManagementDecision", "verifiedBotCategory", "ja3Hash", "ja4"]
HTTP_FIELDS = TRAFFIC + ATTACK + BOT + ["sampleInterval"]
EVENT_FIELDS = TRAFFIC + ["action", "source", "ruleId", "rulesetId", "description", "kind", "ref", "matchIndex",
                          "botScore", "botScoreSrcName", "ja3Hash", "ja4"]
SENSITIVE = {"clientRequestPath", "clientRequestQuery", "userAgent", "ref"}


def _is_test_expr(expr, host):
    """Dağıtım expression'ı yalnızca test host'unu mu hedefliyor? (http.host eq "test" / in {"test"}; ne/not içermiyorsa)"""
    import re
    if not host:
        return False
    e, h = (expr or "").lower(), re.escape(host.lower())
    if re.search(r'http\.host\s*(ne|!=)\s*"' + h + '"', e) or re.search(r'not\s+http\.host\s+(eq|in)', e):
        return False
    return bool(re.search(r'http\.host\s*(eq|==)\s*"' + h + '"', e) or re.search(r'http\.host\s+in\s+\{[^}]*"' + h + '"', e))


class CFError(Exception):
    pass


def expand_ips(text):
    """'203.0.113.8/29, 198.51.100.4' -> IP listesi (en fazla 256 adres)."""
    out = []
    for part in str(text or "").replace("\n", ",").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise CFError(f"Geçersiz IP/CIDR: {part}")
        if net.num_addresses > 256:
            raise CFError(f"{part} çok geniş (en fazla /24).")
        out += [str(ip) for ip in net]   # ağ ve yayın adresleri dahil (bloğun tamamı)
    return list(dict.fromkeys(out))


def iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lit(v):
    return "[" + ",".join(json.dumps(x) for x in v) + "]" if isinstance(v, list) else json.dumps(v)


class CFClient:
    def __init__(self, token, zone, log=None):
        if not token:
            raise CFError("CF_API_TOKEN tanımlı değil. Uygulama klasöründeki .env dosyasına ekleyip servisi yeniden başlatın.")
        if not zone:
            raise CFError("Zone ID tanımlı değil (Ayarlar).")
        self.token, self.zone = token, zone
        self.log = log or (lambda *a, **k: None)

    def gql(self, query):
        req = urllib.request.Request(API, data=json.dumps({"query": query}).encode(),
                                     headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            try:
                return json.loads(body)
            except ValueError:
                return {"errors": [{"message": f"HTTP {e.code}: {body[:200]}"}]}
        except urllib.error.URLError as e:
            raise CFError(f"Cloudflare API'ye bağlanılamadı: {e.reason}. Proxy gerekiyorsa .env'de HTTPS_PROXY tanımlayın.")

    def _build(self, dataset, fields, flt, limit, order="datetime_ASC"):
        f = ",".join(f"{k}:{_lit(v)}" for k, v in flt.items())
        return (f'{{viewer{{zones(filter:{{zoneTag:{json.dumps(self.zone)}}}){{'
                f'{dataset}(filter:{{{f}}},limit:{limit},orderBy:[{order}]){{{" ".join(fields)}}}}}}}}}')

    def _rows(self, res, dataset):
        zones = (res.get("data") or {}).get("viewer", {}).get("zones") or []
        return zones[0].get(dataset, []) if zones else []

    def rest(self, path):
        req = urllib.request.Request(REST + path, headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            try:
                return json.loads(body)
            except ValueError:
                return {"success": False, "errors": [{"message": f"HTTP {e.code}"}]}
        except urllib.error.URLError as e:
            raise CFError(f"Cloudflare API'ye bağlanılamadı: {e.reason}. Proxy gerekiyorsa .env'de HTTPS_PROXY tanımlayın.")

    def test(self):
        end = datetime.now(timezone.utc).replace(microsecond=0)
        q = (f'{{viewer{{zones(filter:{{zoneTag:{json.dumps(self.zone)}}}){{firewallEventsAdaptiveGroups('
             f'filter:{{datetime_geq:"{iso(end - timedelta(hours=1))}",datetime_lt:"{iso(end)}"}},limit:1){{count}}}}}}}}')
        res = self.gql(q)
        if res.get("errors"):
            msg = res["errors"][0].get("message", "bilinmeyen hata")
            if "auth" in msg.lower():
                v = self.rest("/user/tokens/verify")
                if (v.get("result") or {}).get("status") == "active":
                    return False, (f"{msg}. Token aktif görünüyor: büyük ihtimalle token'da IP kısıtı var ve bu sunucunun "
                                   "internete çıkış IP'si izinli değil, ya da token'da bu zone için Analytics okuma yetkisi yok.")
            return False, msg
        if not (res.get("data") or {}).get("viewer", {}).get("zones"):
            return False, "Zone bulunamadı ya da token'ın bu zone'a erişimi yok."
        st = self.rule_states(test_only=True)
        extra = " Kural durumları da okunabiliyor (WAF okuma yetkisi var)." if st.get("ok") else \
            " Kural durumları okunamıyor (isteğe bağlı: token'a WAF okuma yetkisi eklenirse Prod FP'de kuralın prod'daki durumu da gösterilir)."
        return True, "Bağlantı başarılı (Analytics okuma çalışıyor)." + extra

    # ------------------------------------------------------------ kural durumları (Rulesets API, salt okuma)
    def rule_states(self, test_host="", test_only=False):
        """Managed ruleset dağıtımlarındaki her kuralın etkin aksiyonunu döndürür.
        {"ok": bool, "hata": str, "kurallar": {rule_id: {"prod": "log|block|kapalı|...", "dagitimlar": [...], "skip": [...]}}}
        test_host geçen expression'lar 'test dağıtımı' sayılır, diğerleri prod."""
        ep = self.rest(f"/zones/{self.zone}/rulesets/phases/http_request_firewall_managed/entrypoint")
        if not ep.get("success"):
            return {"ok": False, "hata": "; ".join(e.get("message", "") for e in ep.get("errors") or []) or "okunamadı", "kurallar": {}}
        if test_only:
            return {"ok": True, "kurallar": {}}
        rules = (ep.get("result") or {}).get("rules") or []
        defs = {}
        out = {}
        th = (test_host or "").lower()
        for r in rules:
            ap = r.get("action_parameters") or {}
            expr = r.get("expression") or ""
            if r.get("action") == "skip":
                ids = []
                for _, lst in (ap.get("rules") or {}).items():
                    ids += lst
                for rid in ids:
                    out.setdefault(rid, {"dagitimlar": [], "skip": []})["skip"].append(expr[:200])
                continue
            if r.get("action") != "execute" or not ap.get("id"):
                continue
            rsid = ap["id"]
            if rsid not in defs:
                d = self.rest(f"/zones/{self.zone}/rulesets/{rsid}")
                defs[rsid] = {x["id"]: x for x in ((d.get("result") or {}).get("rules") or [])} if d.get("success") else {}
            ov = ap.get("overrides") or {}
            cat_ov = {c.get("category"): c for c in ov.get("categories") or []}
            rule_ov = {x.get("id"): x for x in ov.get("rules") or []}
            is_test = _is_test_expr(expr, th)
            for rid, dr in (defs[rsid] or {}).items():
                act, en = dr.get("action"), dr.get("enabled", True)
                if "action" in ov:
                    act = ov["action"]
                if "enabled" in ov:
                    en = ov["enabled"]
                for c in dr.get("categories") or []:
                    if c in cat_ov:
                        act = cat_ov[c].get("action", act)
                        en = cat_ov[c].get("enabled", en)
                if rid in rule_ov:
                    act = rule_ov[rid].get("action", act)
                    en = rule_ov[rid].get("enabled", en)
                state = "kapalı" if (en is False or r.get("enabled") is False) else (act or "?")
                e = out.setdefault(rid, {"dagitimlar": [], "skip": []})
                e["dagitimlar"].append({"test": is_test, "aksiyon": state, "expression": expr[:200],
                                        "ad": r.get("description") or ""})
        for rid, e in out.items():
            prod = sorted({d["aksiyon"] for d in e["dagitimlar"] if not d["test"]})
            e["prod"] = ", ".join(prod) if prod else ""
        return {"ok": True, "kurallar": out}

    def fetch(self, dataset, candidates, base, start, end, progress=None):
        """Satır listesi, kullanılan alanlar ve uyarılar döner."""
        progress = progress or (lambda f, m: None)
        probe = dict(base, datetime_geq=iso(start), datetime_lt=iso(end))
        res = self.gql(self._build(dataset, ["datetime"], probe, 1))
        if res.get("errors"):
            raise CFError(f"{dataset}: {res['errors'][0].get('message')}")

        def field_ok(f):
            errs = self.gql(self._build(dataset, ["datetime", f], probe, 1)).get("errors")
            return not errs or errs[0].get("message", "").startswith("HTTP ")
        fields = ["datetime"] + [f for f in candidates if field_ok(f)]
        skipped = [f for f in candidates if f not in fields]
        if skipped:
            self.log(f"{dataset}: bu hesapta olmayan alanlar atlandı: {', '.join(skipped)}")
        limit = next((n for n in (10000, 5000, 1000, 100)
                      if not self.gql(self._build(dataset, ["datetime"], probe, n)).get("errors")), 100)
        reduced = [f for f in fields if f not in SENSITIVE]
        seen, rows, gaps, masked = set(), [], [], [0]

        def get(s, e, flds):
            got, cursor = [], iso(s)
            while True:
                r = self.gql(self._build(dataset, flds, dict(base, datetime_geq=cursor, datetime_lt=iso(e)), limit))
                if r.get("errors"):
                    return None, r["errors"][0].get("message", "").splitlines()[0][:80]
                page = self._rows(r, dataset)
                got += page
                if len(page) < limit:
                    return got, None
                if page[-1]["datetime"] == cursor:      # aynı saniyede limitten fazla satır: pencereyi böl
                    return None, "sayfa sınırı"
                cursor = page[-1]["datetime"]

        def collect(s, e):
            got, _ = get(s, e, fields)
            if got is None and (e - s) > timedelta(minutes=1):
                mid = s + (e - s) / 2
                return collect(s, mid) + collect(mid, e)
            if got is None:
                got, err2 = get(s, e, reduced)
                if got is None:
                    gaps.append(f"{s.astimezone(TR):%d.%m %H:%M} ({err2})")
                    return []
                for r in got:
                    r["not"] = "path/query/UA ağ cihazına takıldı"
                masked[0] += len(got)
            return got

        total = max(1.0, (end - start).total_seconds())
        t = start
        while t < end:
            te = min(t + timedelta(hours=1), end)
            for r in collect(t, te):
                k = json.dumps(r, sort_keys=True)
                if k not in seen:
                    seen.add(k)
                    rows.append(r)
            progress((te - start).total_seconds() / total,
                     f"{dataset}: {t.astimezone(TR):%d.%m %H:%M}–{te.astimezone(TR):%H:%M} → toplam {len(rows)} satır")
            t = te
        warns = []
        if masked[0]:
            warns.append(f"{dataset}: {masked[0]} satır path/query/user-agent olmadan çekildi (ağ cihazı engelledi).")
        if gaps:
            warns.append(f"{dataset}: çekilemeyen 1 dakikalık pencereler: {', '.join(gaps[:20])}")
        return rows, fields, warns


    # ------------------------------------------------------------ gruplu sorgular (Prod FP)
    def _groups_q(self, flt, dims, limit=10000):
        f = ",".join(f"{k}:{_lit(v)}" for k, v in flt.items())
        return (f'{{viewer{{zones(filter:{{zoneTag:{json.dumps(self.zone)}}}){{firewallEventsAdaptiveGroups('
                f'filter:{{{f}}},limit:{limit},orderBy:[count_DESC]){{count dimensions{{{" ".join(dims)}}}}}}}}}}}')

    def usable_dims(self, probe, cands):
        ok = []
        for c in cands:
            e = self.gql(self._groups_q(probe, [c], 1)).get("errors")
            if not e or e[0].get("message", "").startswith("HTTP "):
                ok.append(c)
        return ok

    def usable_event_fields(self, probe, cands):
        ok = []
        for c in cands:
            e = self.gql(self._build("firewallEventsAdaptive", ["datetime", c], probe, 1)).get("errors")
            if not e or e[0].get("message", "").startswith("HTTP "):
                ok.append(c)
        return ok

    def groups(self, base, dims, start, end, progress=None):
        """Saatlik pencerelerle Groups sorgusu; 10k sınırı ya da hata olursa pencereyi böler,
        en küçük pencerede path'siz dener. Dönen: ({boyut tuple: sayı}, çekilemeyen pencereler)."""
        progress = progress or (lambda f, m: None)
        out, gaps = {}, []
        fallback = [d for d in dims if d not in ("clientRequestPath",)]

        def run(s, e, d):
            res = self.gql(self._groups_q(dict(base, datetime_geq=iso(s), datetime_lt=iso(e)), d))
            if res.get("errors"):
                return None
            zones = (res.get("data") or {}).get("viewer", {}).get("zones") or []
            return zones[0].get("firewallEventsAdaptiveGroups", []) if zones else []

        def go(s, e):
            rows = run(s, e, dims)
            if (rows is None or len(rows) >= 10000) and (e - s) > timedelta(minutes=5):
                m = s + (e - s) / 2
                go(s, m); go(m, e); return
            used = dims
            if rows is None:
                rows, used = run(s, e, fallback), fallback
                if rows is None:
                    gaps.append(f"{s.astimezone(TR):%d.%m %H:%M}")
                    return
            for r in rows:
                dm = r.get("dimensions", {})
                k = tuple(dm.get(x, "") if x in used else "(alınamadı)" for x in dims)
                out[k] = out.get(k, 0) + r.get("count", 0)

        total = max(1.0, (end - start).total_seconds())
        t = start
        while t < end:
            te = min(t + timedelta(hours=1), end)
            go(t, te)
            progress((te - start).total_seconds() / total, f"{t.astimezone(TR):%d.%m %H:%M} → {len(out)} grup")
            t = te
        return out, gaps

    def sample_events(self, base, fields, start, end, limit, exclude_host=""):
        """Kuralın en yeni olayları; gün gün geriye gider. Picus host'u hariç tutulur."""
        out, t = [], end
        while t > start and len(out) < limit:
            s = max(start, t - timedelta(days=1))
            f = dict(base, datetime_geq=iso(s), datetime_lt=iso(t))
            tries = []
            if exclude_host:
                tries.append((dict(f, clientRequestHTTPHost_neq=exclude_host), fields))
            tries += [(f, fields), (f, [x for x in fields if x not in SENSITIVE])]
            for flt, flds in tries:
                res = self.gql(self._build("firewallEventsAdaptive", ["datetime"] + flds, flt, limit, order="datetime_DESC"))
                if not res.get("errors"):
                    for r in self._rows(res, "firewallEventsAdaptive"):
                        if not exclude_host or (r.get("clientRequestHTTPHost") or "").lower() != exclude_host.lower():
                            out.append(r)
                    break
            t = s
        return out[:limit]
