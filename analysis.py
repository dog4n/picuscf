"""Picus × Cloudflare analizi (picus_cf_analiz.py mantığı).

Girdi: Picus "Threat Result Table" CSV'sinin sadeleştirilmiş hali + Cloudflare httpRequestsAdaptive ve
firewallEventsAdaptive satırları. Çıktı: test, aksiyon, kategori, kural tabloları ve özet metrikler.
Payload'lar saklanmaz; sadece istek satırı (method + path) tutulur.
"""
import re

import pandas as pd

CWE_MAP = [  # (cwe listesi, kategori, temel şiddet 1-10)
    ({"78", "77", "94", "95", "917", "1336", "96"}, "Komut/Kod çalıştırma (RCE)", 10),
    ({"502"}, "Deserialization", 10),
    ({"434", "553"}, "Webshell / zararlı dosya yükleme", 9),
    ({"89", "564", "943"}, "SQL Injection", 8),
    ({"611", "776", "827"}, "XXE", 8),
    ({"287", "288", "306", "798", "284", "862", "863", "639", "290", "522"}, "Yetki atlatma / erişim kontrolü", 8),
    ({"918"}, "SSRF", 7),
    ({"98", "73"}, "Dosya dahil etme (LFI/RFI)", 7),
    ({"22", "23", "35", "36", "24"}, "Path traversal", 6),
    ({"1321"}, "Prototype pollution", 6),
    ({"444"}, "HTTP request smuggling", 6),
    ({"79", "80", "83", "87"}, "XSS", 5),
    ({"93", "113"}, "CRLF / response splitting", 4),
    ({"400", "770", "1333"}, "DoS", 4),
    ({"601"}, "Open redirect", 3),
    ({"200", "538", "552", "548", "530", "215"}, "Bilgi ifşası", 3),
]
NAME_MAP = [
    ("deserializ", "Deserialization", 10), ("webshell", "Webshell / zararlı dosya yükleme", 9),
    ("web shell", "Webshell / zararlı dosya yükleme", 9), ("upload", "Webshell / zararlı dosya yükleme", 9),
    ("template injection", "Komut/Kod çalıştırma (RCE)", 10), ("ssti", "Komut/Kod çalıştırma (RCE)", 10),
    ("command", "Komut/Kod çalıştırma (RCE)", 10), ("remote code", "Komut/Kod çalıştırma (RCE)", 10),
    ("rce", "Komut/Kod çalıştırma (RCE)", 10), ("reverse shell", "Komut/Kod çalıştırma (RCE)", 10),
    ("sql", "SQL Injection", 8), ("xxe", "XXE", 8), ("xml", "XXE", 8),
    ("authentication bypass", "Yetki atlatma / erişim kontrolü", 8), ("unauthorized", "Yetki atlatma / erişim kontrolü", 8),
    ("credential", "Yetki atlatma / erişim kontrolü", 8), ("ssrf", "SSRF", 7), ("request forgery", "SSRF", 7),
    ("file inclusion", "Dosya dahil etme (LFI/RFI)", 7), ("lfi", "Dosya dahil etme (LFI/RFI)", 7),
    ("file read", "Dosya dahil etme (LFI/RFI)", 7), ("traversal", "Path traversal", 6),
    ("prototype", "Prototype pollution", 6), ("smuggling", "HTTP request smuggling", 6),
    ("xss", "XSS", 5), ("cross-site", "XSS", 5), ("crlf", "CRLF / response splitting", 4),
    ("splitting", "CRLF / response splitting", 4), ("denial", "DoS", 4), ("dos", "DoS", 4),
    ("redirect", "Open redirect", 3), ("disclosure", "Bilgi ifşası", 3),
]
ONERI = {
    "Komut/Kod çalıştırma (RCE)": "Managed Ruleset'te RCE/code injection kurallarını aç; OWASP eşiği High (25); komut ayracı + komut adı custom rule",
    "Deserialization": "Managed deserialization kurallarını aç; body'de serileştirme işaretleri için custom rule",
    "Webshell / zararlı dosya yükleme": "Malicious Uploads (content scanning); multipart'ta tehlikeli uzantı (.php/.jsp/.aspx) custom rule",
    "SQL Injection": "OWASP High (25) + managed SQLi kuralları; attack score SQLi eşiği",
    "XXE": "Managed XXE kuralları; body'de DOCTYPE/ENTITY SYSTEM custom rule",
    "Yetki atlatma / erişim kontrolü": "Ürüne özel managed CVE kurallarını aç; hassas yönetim path'lerini dışarıya kapat",
    "SSRF": "Managed 'SSRF - Local' kuralı; parametrede iç/loopback adres custom rule",
    "Dosya dahil etme (LFI/RFI)": "Managed LFI kuralları; php://, data://, phar:// wrapper custom rule",
    "Path traversal": "Managed traversal kuralları; encode'lu ters slash (%5c) custom rule (raw.* alanları)",
    "Prototype pollution": "__proto__ / constructor.prototype custom rule",
    "HTTP request smuggling": "Origin/LB tarafında CL/TE doğrulaması; CF edge davranışını kontrol et",
    "XSS": "Managed 'Generic Payloads XSS' (önce Log); OWASP High (25)",
    "CRLF / response splitting": "Query'de encode'lu CR/LF custom rule",
    "DoS": "Rate limiting, body boyut sınırı",
    "Open redirect": "Uygulama tarafında yönlendirme beyaz listesi; managed open-redirect kuralları",
    "Bilgi ifşası": "Hassas dosya/path'leri (trace.axd, web.config, /proc, httpd.conf) engelleyen custom rule",
    "Diğer": "Ürüne özel managed kuralları kontrol et",
}
PICUS_SEV = {"critical": 15, "high": 10, "medium": 5, "low": 0}
TERMINATING = {"block": 4, "managed_challenge": 3, "challenge": 3, "jschallenge": 3, "js_challenge": 3, "connection_close": 4}
OWASP_RULESET = "4814384a9e5d4991b9815dcfc25d2f1f"     # Cloudflare OWASP Core Ruleset (genel, tüm hesaplarda aynı)
MANAGED_RULESET = "efb7b8c949ac4650a09736fc376e9aee"   # Cloudflare Managed Ruleset (genel, tüm hesaplarda aynı)
KIRILGAN = ["CF challenge (bot score)", "CF geçirdi - origin 520", "CF logu yok"]
RISKLER = ["Kritik", "Yüksek", "Orta", "Düşük"]
SINIFLAR = ["Kuralla blok", "Diğer blok", "Kırılgan blok", "Bloklanmadı", "Test edilemedi"]


class PicusFormatError(ValueError):
    pass


def cat_of(cwes, name):
    for c in cwes:
        for s, k, sev in CWE_MAP:
            if c in s:
                return k, sev
    n = (name or "").lower()
    for kw, k, sev in NAME_MAP:
        if kw in n:
            return k, sev
    return "Diğer", 4


def _col(df, *names, required=True):
    low = {c.lower().strip(): c for c in df.columns}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    if required:
        raise PicusFormatError(f"Picus dosyasında '{names[0]}' kolonu yok. Picus'tan 'Threat Result Table' CSV'si yüklenmeli.")
    return None


def _strip_link(p):
    return re.sub(r"^https://app\.picussecurity\.com\S*\s+", "", p or "")


def _request_line(p):
    first = _strip_link(p).split("\r\n", 1)[0].split("\n", 1)[0]
    m = re.match(r"^(\S+)\s+(\S+)", first)
    return (m.group(1) + " " + m.group(2).replace("/page{PICUSID}", ""))[:300] if m else ""


def _has_body(p):
    return len(_strip_link(p).partition("\r\n\r\n")[2].strip()) > 0


# ---------------------------------------------------------------- Picus
def read_picus(fileobj):
    """Picus CSV'sini okur, payload'ı istek satırına indirger. Dönen tabloda payload yoktur."""
    try:
        P = pd.read_csv(fileobj, dtype=str, low_memory=False, keep_default_na=False, encoding="utf-8-sig")
    except Exception as e:  # noqa: BLE001
        raise PicusFormatError(f"CSV okunamadı: {e}")
    cols = {
        "aid": _col(P, "actionId"), "aksiyon": _col(P, "actionName"), "tid": _col(P, "threatId"),
        "kampanya": _col(P, "threatName"), "picus": _col(P, "actionPreventionResult"),
        "kampanya_sonuc": _col(P, "threatPreventionResult", required=False),
        "t_start": _col(P, "attackStartedTimeUTC"), "t_end": _col(P, "attackEndedTimeUTC", required=False),
        "cve": _col(P, "cve", required=False), "cwe": _col(P, "cwe", required=False),
        "severity": _col(P, "severity", required=False), "urun": _col(P, "affectedProducts", required=False),
    }
    R = pd.DataFrame({k: (P[c] if c else "") for k, c in cols.items()})
    pl = _col(P, "actionPayload", required=False)
    if pl:
        R["istek"] = P[pl].map(_request_line)
        R["body_var"] = P[pl].map(_has_body)
    else:
        R["istek"], R["body_var"] = "", False
    R = R[R.aid.str.strip() != ""].reset_index(drop=True)
    if R.empty:
        raise PicusFormatError("Picus dosyasında test satırı yok.")
    return R


def picus_window(R):
    t0 = pd.to_datetime(R.t_start.str.replace(" UTC", "", regex=False), utc=True, errors="coerce")
    t1 = pd.to_datetime(R.t_end.astype(str).str.replace(" UTC", "", regex=False), utc=True, errors="coerce")
    start = t0.min()
    end = max(x for x in (t0.max(), t1.max()) if pd.notna(x)) if (pd.notna(t0.max()) or pd.notna(t1.max())) else None
    if pd.isna(start) or end is None:
        raise PicusFormatError("Picus dosyasında saldırı zamanları okunamadı (attackStartedTimeUTC).")
    return start.to_pydatetime(), end.to_pydatetime()


# ---------------------------------------------------------------- yardımcılar
def _s(v):
    return "" if v is None or (isinstance(v, float) and pd.isna(v)) else str(v)


def _first(s):
    """İlk boş olmayan değer."""
    for v in s:
        if str(v).strip() not in ("", "nan", "None"):
            return v
    return ""


def _ensure(df, cols):
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df


def kural_ailesi(picus, cf_karar, src, ruleset, desc):
    if cf_karar in ("CF logu yok", "Belirsiz") or cf_karar.startswith("CF geçirdi"):
        if picus != "Blocked":
            return ""
        return "Kural yok (origin 520 / log yok)" if cf_karar in ("CF geçirdi - origin 520", "CF logu yok") else "Kural yok (diğer)"
    if not src and not desc:
        return "Kural belirsiz"
    if ruleset == OWASP_RULESET:
        return "OWASP Core"
    if ruleset == MANAGED_RULESET:
        return "CF Managed"
    sl = (src or "").lower()
    if sl == "firewallmanaged":
        return "OWASP Core" if re.match(r"^9\d{5}\b", desc or "") else "CF Managed"
    if sl in ("firewallcustom", "firewallrules"):
        return "Custom – bot score" if "bot" in (desc or "").lower() else "Custom rule"
    return src or "Kural belirsiz"


def sinif(picus, cf_karar):
    if picus == "Not Blocked":
        return "Bloklanmadı"
    if picus != "Blocked":
        return "Test edilemedi"
    if cf_karar in ("CF blokladı", "CF challenge"):
        return "Kuralla blok"
    if cf_karar in KIRILGAN:
        return "Kırılgan blok"
    return "Diğer blok"


def metrics(T, A, cf_yok=False):
    """Bir test kümesi (T) ve onun bloklanmayan aksiyonları (A) için özet metrikler.
    cf_yok: koşumda hiç CF verisi eşleşmediyse kırılgan blok hesaplanamaz (None)."""
    vc = T.picus.value_counts()
    B, NB, NT = int(vc.get("Blocked", 0)), int(vc.get("Not Blocked", 0)), int(vc.get("Not Tested", 0))
    K = T[(T.picus == "Blocked") & T.cf_karar.isin(KIRILGAN)]
    r = A.risk.value_counts() if len(A) else pd.Series(dtype=int)
    return {
        "test": int(len(T)), "blocked": B, "not_blocked": NB, "not_tested": NT,
        "skor": round(100 * B / (B + NB), 1) if B + NB else None,
        "nb_aksiyon": int(len(A)),
        "kritik": int(r.get("Kritik", 0)), "yuksek": int(r.get("Yüksek", 0)),
        "orta": int(r.get("Orta", 0)), "dusuk": int(r.get("Düşük", 0)),
        "kirilgan": None if cf_yok else int(len(K)),
        "kirilgan_bot": None if cf_yok else int((K.cf_karar == "CF challenge (bot score)").sum()),
        "kirilgan_520": None if cf_yok else int((K.cf_karar == "CF geçirdi - origin 520").sum()),
        "kirilgan_logyok": None if cf_yok else int((K.cf_karar == "CF logu yok").sum()),
        "siniflar": {s: int((T.sinif == s).sum()) for s in SINIFLAR},
    }


# ---------------------------------------------------------------- ana analiz
def analyze(R, H, E):
    R = R.copy()
    if "aid_alt" not in R.columns:
        R["aid_alt"] = ""
    R["aid_alt"] = R.aid_alt.fillna("").astype(str)
    R["_t"] = pd.to_datetime(R.t_start.astype(str).str.replace(" UTC", "", regex=False), utc=True, errors="coerce")
    R["body_var"] = R.body_var.astype(str).str.lower().isin(["true", "1"])

    def sev_max(s):
        v = [PICUS_SEV.get(x.strip().lower(), -1) for x in s if str(x).strip()]
        return max(v) if v else -1

    meta = R.groupby("aid").agg(
        aksiyon=("aksiyon", "first"),
        cve=("cve", lambda s: ", ".join(sorted({x for v in s for x in re.findall(r"CVE-\d{4}-\d+", str(v))}))),
        cwe=("cwe", lambda s: sorted({x for v in s for x in re.findall(r"\d+", str(v))})),
        sev=("severity", sev_max), urun=("urun", "first"), istek=("istek", "first"), body_var=("body_var", "first"))
    kat = meta.apply(lambda r: cat_of(r.cwe, r.aksiyon), axis=1)
    meta["kategori"] = [k for k, _ in kat]
    meta["kat_siddet"] = [s for _, s in kat]

    T = R.drop_duplicates(["aid", "tid"]).copy()
    has_camp = bool((R.kampanya_sonuc.astype(str).str.strip() != "").any())
    T = T[["aid", "aid_alt", "aksiyon", "tid", "kampanya", "picus", "kampanya_sonuc", "_t"]].reset_index(drop=True)

    # ---- Cloudflare
    H = _ensure(H.copy(), ["datetime", "rayName", "clientRequestPath", "securityAction", "securitySource", "securityRuleId",
                           "edgeResponseStatus", "wafAttackScore", "wafAttackScoreClass", "botScore"])
    E = _ensure(E.copy(), ["datetime", "rayName", "clientRequestPath", "action", "source", "ruleId", "rulesetId", "description"])
    H = H.fillna("").astype(str)
    E = E.fillna("").astype(str)
    for d in (H, E):
        d["_t"] = pd.to_datetime(d["datetime"], utc=True, errors="coerce")
        d["_pid"] = d["clientRequestPath"].str.extract(r"page(\d+)")[0]
    miss = E[(E.rayName != "") & ~E.rayName.isin(H.rayName)].drop_duplicates("rayName")
    H["_src"] = "http"
    if len(miss):
        add = pd.DataFrame({c: (miss[c].values if c in miss else "") for c in H.columns if not c.startswith("_")})
        add["_t"], add["_pid"], add["_src"] = miss["_t"].values, miss["_pid"].values, "events"
        H = pd.concat([H, add], ignore_index=True)
    H["_t"] = pd.to_datetime(H["_t"], utc=True, errors="coerce")

    E["_ord"] = E.action.str.lower().map(TERMINATING).fillna(0)
    E["kural"] = E.action + ": " + E.description + " [" + E.ruleId + "]"
    if len(E):
        rules_by_ray = E.groupby("rayName").agg(
            kurallar=("kural", lambda s: " | ".join(dict.fromkeys(s))),
            log_kurallar=("kural", lambda s: " | ".join(dict.fromkeys(x for x in s if x.lower().startswith("log:")))))
        term = E.sort_values("_ord").drop_duplicates("rayName", keep="last").set_index("rayName")
        term = term[term._ord > 0]
    else:
        idx = pd.Index([], dtype=object, name="rayName")
        rules_by_ray = pd.DataFrame({"kurallar": pd.Series(dtype=object), "log_kurallar": pd.Series(dtype=object)}, index=idx)
        term = pd.DataFrame({c: pd.Series(dtype=object) for c in ["action", "description", "ruleId", "source", "rulesetId"]}, index=idx)
    H = H.join(rules_by_ray, on="rayName")
    H["term_action"] = H.rayName.map(term["action"]).fillna("")
    H["term_desc"] = H.rayName.map(term["description"]).fillna("")
    H["term_rule"] = H.rayName.map(term["ruleId"]).fillna("")
    H["term_source"] = H.rayName.map(term["source"]).fillna("")
    H["term_ruleset"] = H.rayName.map(term["rulesetId"]).fillna("")
    # event'i olmayan ama securityAction'ı olan istekler: kaynak/kural bilgisini http'den al
    no_ev = H.term_rule == ""
    H.loc[no_ev, "term_source"] = H.loc[no_ev, "securitySource"]
    H.loc[no_ev, "term_rule"] = H.loc[no_ev, "securityRuleId"]

    def cf_karar(r):
        act = r.term_action or (r.securityAction if r.securityAction not in ("", "unknown") else "")
        act = act.lower()
        if act in ("block", "connection_close"):
            return "CF blokladı"
        if "challenge" in act:
            return "CF challenge (bot score)" if "bot" in r.term_desc.lower() else "CF challenge"
        st = r.edgeResponseStatus
        if st == "520":
            return "CF geçirdi - origin 520"
        if st in ("200", "201", "204", "301", "302", "304"):
            return f"CF geçirdi - origin {st}"
        return f"CF geçirdi - HTTP {st}" if st else "Belirsiz"

    H["cf_karar"] = H.apply(cf_karar, axis=1) if len(H) else pd.Series(dtype=str)
    H["cf_blokladi"] = H.cf_karar.str.startswith("CF blok") | H.cf_karar.str.startswith("CF challenge")

    # ---- eşleştirme: actionId (URL'deki /page<ID>) + zaman, tutarlılık öncelikli; kalanlar zamanla
    hg = H.dropna(subset=["_pid"]).groupby("_pid").groups if len(H) else {}
    pairs = []
    via = {}
    for i, p in T.iterrows():
        cands = list(hg.get(str(p.aid), []))
        if not cands and p.aid_alt:
            cands = list(hg.get(str(p.aid_alt), []))
            if cands:
                via[i] = "alt"
        for j in cands:
            dt = abs((H.at[j, "_t"] - p._t).total_seconds()) if pd.notna(p._t) and pd.notna(H.at[j, "_t"]) else 0
            if dt > 600:
                continue
            inc = (p.picus == "Not Blocked" and H.at[j, "cf_blokladi"]) or (p.picus == "Blocked" and H.at[j, "cf_karar"].endswith(" 200"))
            pairs.append((dt + (120 if inc else 0), i, j))
    pairs.sort()
    ui, hj, m = set(), set(), {}
    for _, i, j in pairs:
        if i in ui or j in hj:
            continue
        ui.add(i); hj.add(j); m[i] = j
    if len(H):
        free = H[~H.index.isin(hj)]
        for i, p in T[(~T.index.isin(m.keys())) & (T.picus != "Not Tested")].iterrows():
            if pd.isna(p._t):
                continue
            w = free[(free._t >= p._t - pd.Timedelta(seconds=4)) & (free._t <= p._t + pd.Timedelta(seconds=6)) & (~free.index.isin(hj))]
            if len(w):
                j = (w._t - p._t).abs().idxmin(); m[i] = j; hj.add(j)
    T["cf_idx"] = T.index.map(m)
    cf_yok = not m
    hc = ["rayName", "cf_karar", "term_desc", "term_rule", "term_source", "term_ruleset", "kurallar", "log_kurallar",
          "edgeResponseStatus", "wafAttackScore", "wafAttackScoreClass", "botScore", "_src"]
    T = T.join(H[hc], on="cf_idx")
    T["cf_karar"] = T.cf_karar.fillna("CF verisi yok" if cf_yok else "CF logu yok")
    for c in hc:
        if c != "cf_karar":
            T[c] = T[c].fillna("")
    T = T.join(meta[["kategori", "kat_siddet", "cve", "sev", "urun", "istek", "body_var"]], on="aid")
    T["kural_ailesi"] = ["CF verisi yok" if cf_yok and p == "Blocked" else kural_ailesi(p, k, s, rs, d) for p, k, s, rs, d in
                         zip(T.picus, T.cf_karar, T.term_source, T.term_ruleset, T.term_desc)]
    T["sinif"] = [sinif(p, k) for p, k in zip(T.picus, T.cf_karar)]

    # ---- bloklanmayan aksiyonlar ve kritiklik
    nbT = T[T.picus == "Not Blocked"]
    sole = nbT.groupby("tid").aid.agg(lambda s: s.iloc[0] if len(s) == 1 else None).dropna().value_counts()
    A = nbT.groupby("aid").agg(
        aksiyon=("aksiyon", "first"), kategori=("kategori", "first"), kat_siddet=("kat_siddet", "first"),
        cve=("cve", "first"), sev=("sev", "first"), urun=("urun", "first"), istek=("istek", "first"),
        nb_kampanya=("tid", "nunique"), kampanyalar=("kampanya", lambda s: "; ".join(dict.fromkeys(x.strip() for x in s))),
        cf_karar=("cf_karar", lambda s: ", ".join(dict.fromkeys(s))),
        log_kurallar=("log_kurallar", lambda s: " | ".join(dict.fromkeys(x for x in s if x))),
        attack_score=("wafAttackScore", _first), score_class=("wafAttackScoreClass", _first),
        ray=("rayName", _first))
    A["tek_basina"] = A.index.map(sole).fillna(0).astype(int)

    def puanla(r):
        p, neden = r.kat_siddet * 6, [f"{r.kategori}"]
        sv = r.sev if r.sev is not None else -1
        if sv >= 0:
            p += sv
            neden.append({15: "Picus önem: Critical", 10: "Picus önem: High", 5: "Picus önem: Medium", 0: "Picus önem: Low"}.get(sv, ""))
        if r.cve:
            p += 10; neden.append(f"bilinen açık ({r.cve.split(',')[0]}{'…' if ',' in r.cve else ''})")
        if r.nb_kampanya > 1:
            p += min(9, 3 * (r.nb_kampanya - 1)); neden.append(f"{r.nb_kampanya} kampanyada geçti")
        if r.tek_basina:
            p += 6; neden.append(f"{r.tek_basina} kampanyayı tek başına düşürüyor")
        if "origin 200" in str(r.cf_karar):
            p += 5; neden.append("origin'e ulaştı (HTTP 200)")
        if str(r.score_class) in ("clean", "likely_clean"):
            p += 3; neden.append(f"attack score {r.score_class} ({r.attack_score}) - ML görmüyor")
        if r.log_kurallar:
            neden.append("Log modunda yakalayan kural var → Block'a çekilirse kapanır")
        return p, "; ".join(x for x in neden if x)

    if len(A):
        pn = A.apply(puanla, axis=1)
        A["puan"] = [int(p) for p, _ in pn]
        A["neden"] = [n for _, n in pn]
        A["risk"] = pd.cut(A.puan, [-1, 49, 64, 79, 999], labels=["Düşük", "Orta", "Yüksek", "Kritik"]).astype(str)
        A = A.sort_values(["puan", "nb_kampanya"], ascending=False)
    else:
        A["puan"], A["neden"], A["risk"] = pd.Series(dtype=int), pd.Series(dtype=str), pd.Series(dtype=str)
    T = T.join(A[["risk", "puan"]], on="aid")
    T["risk"] = T.risk.where(T.picus == "Not Blocked", "").fillna("")
    T["puan"] = T.puan.where(T.picus == "Not Blocked")

    # Log'da yakalanan ama bloklanmayan → Block'a çekilecek kurallar
    lg = [(k.replace("log: ", "", 1), aid) for aid, r in A.iterrows()
          for k in dict.fromkeys(x.strip() for x in str(r.log_kurallar).split("|") if x.strip())]
    LG = pd.DataFrame(lg, columns=["kural", "aid"])
    if len(LG):
        LG = LG.groupby("kural").agg(kapanacak_aksiyon=("aid", "nunique"),
                                     ornek=("aid", lambda s: "; ".join(A.loc[list(s)[:3], "aksiyon"]))
                                     ).sort_values("kapanacak_aksiyon", ascending=False).reset_index()
    else:
        LG = pd.DataFrame(columns=["kural", "kapanacak_aksiyon", "ornek"])

    K = T[(T.picus == "Blocked") & T.cf_karar.isin(KIRILGAN)] if not cf_yok else T.iloc[0:0]

    # kural isabetleri
    if len(E):
        RH = E.merge(T[["rayName", "aid", "picus"]][T.rayName != ""], on="rayName", how="left")
        RS = RH.groupby(["action", "description", "ruleId", "source"], dropna=False).agg(
            istek=("rayName", "nunique"), picus_aksiyon=("aid", "nunique"),
            picus_blocked=("picus", lambda s: int((s == "Blocked").sum())),
            picus_not_blocked=("picus", lambda s: int((s == "Not Blocked").sum()))
        ).reset_index().sort_values("istek", ascending=False)
    else:
        RS = pd.DataFrame(columns=["action", "description", "ruleId", "source", "istek", "picus_aksiyon", "picus_blocked", "picus_not_blocked"])

    if len(A):
        KR = A.groupby("kategori").agg(
            nb_aksiyon=("aksiyon", "size"), kritik=("risk", lambda s: int((s == "Kritik").sum())),
            yuksek=("risk", lambda s: int((s == "Yüksek").sum())), nb_test=("nb_kampanya", "sum"),
            ornek=("aksiyon", lambda s: "; ".join(s.head(3)))).sort_values(["kritik", "yuksek", "nb_aksiyon"], ascending=False).reset_index()
        KR["oneri"] = KR.kategori.map(lambda k: ONERI.get(k, ONERI["Diğer"]))
    else:
        KR = pd.DataFrame(columns=["kategori", "nb_aksiyon", "kritik", "yuksek", "nb_test", "ornek", "oneri"])

    # ---- özet
    camp = T.groupby("tid").agg(sonuc=("kampanya_sonuc", "first"), nb=("picus", lambda s: int((s == "Not Blocked").sum())))
    camp_bl = int((camp.sonuc == "Blocked").sum()) if has_camp else int((camp.nb == 0).sum())
    ozet = metrics(T, A, cf_yok)
    ozet.update({
        "kampanya_blocked": camp_bl, "kampanya_toplam": int(len(camp)),
        "eslesen": int(T.cf_idx.notna().sum()), "eslesen_display_id": int(sum(1 for i in via if pd.notna(T.at[i, "cf_idx"]))),
        "cf_yok": cf_yok, "cf_istek": int((H._src == "http").sum()) if len(H) else 0,
        "cf_olay": int(len(E)),
        "cf_karar": {k: {p: int(n) for p, n in g.picus.value_counts().items()} for k, g in T.groupby("cf_karar")},
        "kural_ailesi": {k: int(n) for k, n in T[T.picus == "Blocked"].kural_ailesi.value_counts().items()},
        "kategori": {k: metrics(g, A[A.kategori == k], cf_yok) for k, g in T.groupby("kategori")},
    })
    T["zaman"] = T._t.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    T = T.drop(columns=["_t", "cf_idx"])
    return {"tests": T, "actions": A.reset_index(), "categories": KR, "rule_hits": RS,
            "log_block": LG, "fragile": K.drop(columns=["_t", "cf_idx"], errors="ignore"), "summary": ozet}


# ---------------------------------------------------------------- koşum karşılaştırma
def _durum_test(a, b):
    if b == "Not Blocked":
        return "Açık kaldı" if a == "Not Blocked" else "Geriledi" if a == "Blocked" else "Yeni test (açık)"
    if a == "Not Blocked":
        return "Kapandı" if b == "Blocked" else "Test edilemedi"
    if b == "Blocked":
        return "Bloklu kaldı" if a == "Blocked" else "Yeni test (bloklu)"
    if a == "Blocked":
        return "Bu koşumda test edilemedi"
    return "İki koşumda da test edilemedi"


def _key(s):
    """Eşleştirme anahtarı: metin, baş/son ve çoklu boşluk temizlenmiş, küçük harf
    (CSV'de kampanya adları sonda boşlukla gelebiliyor)."""
    return s.fillna("").astype(str).str.strip().str.replace(r"\s+", " ", regex=True).str.lower()


def _choose_keys(Ta, Tb):
    """İki koşumun testlerini eşleştirecek anahtarı seçer. Picus CSV'sindeki actionId ile API'deki action_id/display_id
    farklı olabildiği için kombinasyonlar denenir, en çok ortak test vereni seçilir. Son çare: aksiyon + kampanya adı."""
    cands = [(ia, ib, ctx) for ia in ("aid", "aid_alt") for ib in ("aid", "aid_alt") for ctx in ("tid", "kampanya")]
    cands.append(("aksiyon", "aksiyon", "kampanya"))
    best, bn = ("aid", "aid", "tid"), -1
    for ia, ib, ctx in cands:
        if ia not in Ta.columns or ib not in Tb.columns:
            continue
        ka = {(x, y) for x, y in zip(_key(Ta[ia]), _key(Ta[ctx])) if x not in ("", "nan", "none")}
        kb = {(x, y) for x, y in zip(_key(Tb[ib]), _key(Tb[ctx])) if x not in ("", "nan", "none")}
        n = len(ka & kb)
        if n > bn:
            best, bn = (ia, ib, ctx), n
    return best, max(bn, 0)


def compare(Ta, Tb, Ab, Aa):
    """Ta/Aa: önceki koşum, Tb/Ab: güncel koşum (tests, actions tabloları)."""
    (ia, ib, ctx), n_ortak = _choose_keys(Ta, Tb)
    prio = {"Not Blocked": 0, "Blocked": 1}

    def prep(T, idc):
        T = T.copy()
        T["_id"] = _key(T[idc])
        T["_ctx"] = _key(T[ctx])
        T = T[~T._id.isin(["", "nan", "none"])]
        T["_p"] = T.picus.map(prio).fillna(2)
        return T.sort_values("_p").drop_duplicates(["_id", "_ctx"]).drop(columns="_p")

    Ta, Tb = prep(Ta, ia), prep(Tb, ib)
    keep = ["_id", "_ctx", "aid", "aksiyon", "kampanya", "kategori", "picus", "cf_karar", "kural_ailesi", "term_desc", "term_rule", "rayName"]
    a = _ensure(Ta.copy(), keep)[keep].rename(columns={c: c + "_a" for c in keep if c not in ("_id", "_ctx")})
    b = _ensure(Tb.copy(), keep)[keep].rename(columns={c: c + "_b" for c in keep if c not in ("_id", "_ctx")})
    M = a.merge(b, on=["_id", "_ctx"], how="outer")
    for c in ("aid", "aksiyon", "kampanya", "kategori"):
        M[c] = M[c + "_b"].fillna(M[c + "_a"])
    M = M.fillna("")
    M["durum"] = [_durum_test(x, y) for x, y in zip(M.picus_a, M.picus_b)]
    tg = M[["aid", "aksiyon", "kategori", "kampanya", "picus_a", "picus_b", "durum", "cf_karar_a", "cf_karar_b",
            "kural_ailesi_b", "term_desc_b", "term_rule_b", "rayName_b"]].rename(columns={
                "picus_a": "onceki", "picus_b": "guncel", "kural_ailesi_b": "kural_ailesi", "term_desc_b": "kural",
                "term_rule_b": "kural_id", "rayName_b": "ray"})

    # aksiyon düzeyi (_id üzerinden; risk/puan koşumun kendi aid'siyle bulunur)
    def st(T):
        return T.groupby("_id").picus.agg(lambda s: "NB" if (s == "Not Blocked").any() else "B" if (s == "Blocked").any() else "NT")
    sa, sb = st(Ta), st(Tb)
    ids = sorted(set(sa.index[sa == "NB"]) | set(sb.index[sb == "NB"]))
    xa = Aa.set_index("aid") if len(Aa) else pd.DataFrame()
    xb = Ab.set_index("aid") if len(Ab) else pd.DataFrame()
    info_a = Ta.drop_duplicates("_id").set_index("_id")
    info_b = Tb.drop_duplicates("_id").set_index("_id")
    nb_a = Ta[Ta.picus == "Not Blocked"]._id.value_counts()
    nb_b = Tb[Tb.picus == "Not Blocked"]._id.value_counts()
    rows = []
    for k in ids:
        da, dbb = sa.get(k), sb.get(k)
        if dbb == "NB":
            d = "Açık kaldı" if da == "NB" else "Geriledi" if da == "B" else "Yeni test (açık)"
        elif da == "NB":
            d = "Kapandı" if dbb == "B" else "Test edilemedi"
        else:
            continue
        inf = info_b if k in info_b.index else info_a
        src, src_info = (xb, info_b) if dbb == "NB" else (xa, info_a)
        oid = src_info.at[k, "aid"] if k in src_info.index else None
        r = src.loc[oid] if oid is not None and len(src) and oid in src.index else None
        if isinstance(r, pd.DataFrame):
            r = r.iloc[0]
        rows.append({
            "aid": inf.at[k, "aid"], "aksiyon": inf.at[k, "aksiyon"], "kategori": inf.at[k, "kategori"],
            "cve": _s(inf.at[k, "cve"]) if "cve" in inf.columns else "",
            "durum": d, "risk": _s(r["risk"]) if r is not None else "",
            "puan": int(r["puan"]) if r is not None and pd.notna(r["puan"]) else None,
            "nb_test_onceki": int(nb_a.get(k, 0)), "nb_test_guncel": int(nb_b.get(k, 0)),
            "neden": _s(r["neden"]) if r is not None else "",
        })
    AD = pd.DataFrame(rows, columns=["aid", "aksiyon", "kategori", "cve", "durum", "risk", "puan", "nb_test_onceki", "nb_test_guncel", "neden"])
    sira = {"Geriledi": 0, "Açık kaldı": 1, "Yeni test (açık)": 2, "Test edilemedi": 3, "Kapandı": 4}
    rsira = {"Kritik": 0, "Yüksek": 1, "Orta": 2, "Düşük": 3}
    if len(AD):
        AD = AD.assign(_d=AD.durum.map(sira), _r=AD.risk.map(rsira).fillna(9), _p=-AD.puan.fillna(0)) \
               .sort_values(["_d", "_r", "_p"]).drop(columns=["_d", "_r", "_p"]).reset_index(drop=True)

    kap = tg[tg.durum == "Kapandı"]
    KY = kap.groupby(["kural_ailesi", "kural", "kural_id"]).agg(kapanan_test=("aid", "size"), kapanan_aksiyon=("aid", "nunique")
                                                                ).reset_index().sort_values("kapanan_test", ascending=False)
    n_min = max(1, min(len(Ta), len(Tb)))
    return {"tests": tg[~tg.durum.isin(["Bloklu kaldı", "İki koşumda da test edilemedi"])].reset_index(drop=True),
            "actions": AD, "sources": KY,
            "counts": {k: int(v) for k, v in tg.durum.value_counts().items()},
            "aile": {k: int(v) for k, v in kap.kural_ailesi.replace("", "Kural belirsiz").value_counts().items()},
            "eslesme": {"anahtar": f"{ia}/{ib}+{ctx}", "ortak": int(n_ortak), "oran": round(n_ortak / n_min, 3)}}
