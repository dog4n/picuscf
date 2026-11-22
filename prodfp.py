"""Prod FP analizi ve kural karar listesi.

Prod'daki WAF olayları (test host'u hariç) ile Picus koşumlarından gelen kural kazancı birleştirilir; her kural için
öneri karar, en çok tetiklendiği host/path, TR ve insan oranı hesaplanır. Exception'lar host + path koşullarıyla
tanımlanır; Cloudflare expression'ı ve exception sonrası kalan olay hesaplanır.

Önemli: kapatılmış (disabled) ya da skip'e alınmış bir kural Cloudflare'de HİÇ log üretmez. Bu yüzden prod'da olayı
görünmeyen bir kural "temiz" sayılmaz: kuralın prod'da açık olduğu doğrulanamıyorsa "G – Ölçülemedi" önerilir.
Bilinen FP listesindeki kurallar her zaman "F" olur ve asla doğrudan Block önerilmez.
"""
import re
from datetime import timezone

import pandas as pd

KARARLAR = {
    "A": "A – Doğrudan Block",
    "B": "B – Exception ile Block",
    "C": "C – Prod'da kapalı kalsın",
    "D": "D – Gerçek saldırı, Block önerilir (Picus dışı)",
    "E": "E – Prod'da kapalı kalsın (Picus dışı, FP)",
    "F": "F – Bilinen FP: Block'a alma",
    "G": "G – Ölçülemedi: önce Log'da doğrula",
}
DURUMLAR = ["Bekliyor", "Log'da izleniyor", "Uygulandı", "Zaten Block", "Geri alındı", "Ertelendi", "Uygulanmayacak"]
RULESETS = {"efb7b8c949ac4650a09736fc376e9aee": "CF Managed", "4814384a9e5d4991b9815dcfc25d2f1f": "OWASP Core"}
GAIN_AILE = ("CF Managed", "OWASP Core")
SALDIRI_ADI = ("fake", "scanner", "malware", "web shell", "webshell", "exploit")
A_MAX_OLAY = 5        # Picus kazancı olan kural prod'da en fazla bu kadar Log olayı ürettiyse doğrudan Block
B_MIN_KAZANC = 5      # kazanç bu kadar ve üstüyse FP yüksek olsa da exception ile Block'a değer
B_MAX_OLAY = 100      # kazanç düşükse bile prod olayı bu kadar azsa exception ile yönetilebilir
D_MAX_TR = 0.5        # Picus dışı kuralda TR oranı bunun altındaysa saldırı trafiği sayılır
INSAN_BOT = 30        # botScore >= 30 insan kabul edilir


def norm_path(p):
    p = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{guid}", p or "")
    return re.sub(r"\d{3,}", "{n}", p)[:200]


def _iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- Cloudflare'den çekme
def fetch(client, start, end, test_host, n_samples=40, progress=None, log=None):
    """Prod WAF olaylarını (tüm aksiyonlar) gruplar halinde çeker. Dönen: {rules, hp, src, samples} + uyarılar."""
    progress = progress or (lambda f, m: None)
    base = {}
    probe = dict(base, datetime_geq=_iso(start), datetime_lt=_iso(end))
    rule_dims = client.usable_dims(probe, ["ruleId", "action", "description", "rulesetId", "source"])
    hp_dims = client.usable_dims(probe, ["ruleId", "action", "clientRequestHTTPHost", "clientRequestHTTPMethodName", "clientRequestPath"])
    src_dims = client.usable_dims(probe, ["ruleId", "action", "clientRequestHTTPHost", "clientCountryName", "clientASNDescription"])
    if "ruleId" not in rule_dims:
        raise ValueError("Cloudflare firewallEventsAdaptiveGroups ruleId boyutunu vermedi.")
    warns = []

    def grp(dims, label, a, b):
        out, gaps = client.groups(base, dims, start, end, progress=lambda f, m: progress(a + f * (b - a), f"{label}: {m}"))
        if gaps:
            warns.append(f"{label}: çekilemeyen pencereler: {', '.join(gaps[:15])}")
        return pd.DataFrame([dict(zip(dims, k), olay=c) for k, c in out.items()], columns=dims + ["olay"])

    rules = grp(rule_dims, "kural toplamı", 0.0, 0.25)
    hp = grp(hp_dims, "kural × host × path", 0.25, 0.55)
    if "clientRequestPath" in hp.columns:
        hp["clientRequestPath"] = hp.clientRequestPath.map(norm_path)
        hp = hp.groupby([c for c in hp.columns if c != "olay"], as_index=False).olay.sum()
    src = grp(src_dims, "kural × ülke × ASN", 0.55, 0.8)
    fields = client.usable_event_fields(probe, ["action", "rayName", "clientIP", "clientCountryName", "clientASNDescription",
                                                "clientRequestHTTPHost", "clientRequestHTTPMethodName", "clientRequestPath",
                                                "userAgent", "botScore", "wafAttackScore", "description", "ruleId"])
    rids = [r for r in rules.ruleId.unique() if r]
    samples = []
    for i, rid in enumerate(rids):
        rows = client.sample_events(dict(base, ruleId=rid), fields, start, end, n_samples, exclude_host=test_host)
        samples += [dict(r, ruleId=r.get("ruleId") or rid) for r in rows]
        if i % 5 == 0 or i == len(rids) - 1:
            progress(0.8 + 0.2 * (i + 1) / max(1, len(rids)), f"örnek olaylar: {i + 1}/{len(rids)} kural")
    S = pd.DataFrame(samples)
    for c in ("clientRequestPath", "userAgent"):
        if len(S) and c in S.columns:
            S[c] = S[c].fillna("").astype(str).str[:200]
    return {"rules": rules, "hp": hp, "src": src, "samples": S}, warns


# ---------------------------------------------------------------- exception'lar
def _lines(v):
    return [x.strip() for x in re.split(r"[\n,;]+", v or "") if x.strip()]


def exception_expression(ex):
    """Host ve path koşullarından Cloudflare expression'ı üretir (elle girilmiş expression varsa o kullanılır)."""
    if (ex.get("expression") or "").strip():
        return ex["expression"].strip()
    hosts = [h.lower() for h in _lines(ex.get("hosts"))]
    eq = [p.lower() for p in _lines(ex.get("path_eq"))]
    pre = [p.lower() for p in _lines(ex.get("path_prefix"))]
    parts = []
    if hosts:
        parts.append(f'http.host eq "{hosts[0]}"' if len(hosts) == 1 else "http.host in {" + " ".join(f'"{h}"' for h in hosts) + "}")
    pc = []
    if eq:
        pc.append(f'lower(http.request.uri.path) eq "{eq[0]}"' if len(eq) == 1 else
                  "lower(http.request.uri.path) in {" + " ".join(f'"{p}"' for p in eq) + "}")
    pc += [f'starts_with(lower(http.request.uri.path), "{p}")' for p in pre]
    if pc:
        parts.append(pc[0] if len(pc) == 1 else "(" + " or ".join(pc) + ")")
    return " and ".join(parts) if parts else ""


def exception_matches(ex, host, path):
    """Exception'ın bir (host, path) grubunu kapsayıp kapsamadığı. Elle expression girilmişse hesaplanamaz (None)."""
    if (ex.get("expression") or "").strip():
        return None
    hosts = [h.lower() for h in _lines(ex.get("hosts"))]
    eq = [p.lower() for p in _lines(ex.get("path_eq"))]
    pre = [p.lower() for p in _lines(ex.get("path_prefix"))]
    if not hosts and not eq and not pre:
        return False
    h, p = (host or "").lower(), (path or "").lower()
    if hosts and h not in hosts:
        return False
    if eq or pre:
        return p in eq or any(p.startswith(x) for x in pre)
    return True


def exception_rules(ex):
    return [r.strip() for r in re.split(r"[\s,;]+", ex.get("rules") or "") if r.strip()]




# ---------------------------------------------------------------- Picus kazancı
def _eligible(aile, karar, rid):
    """Kazanca sayılan kurallar: CF Managed/OWASP + doğrudan Block eden custom kurallar (bot score ve challenge hariç)."""
    return (aile.isin(GAIN_AILE) | ((aile == "Custom rule") & (karar == "CF blokladı"))) & (rid.fillna("").astype(str).str.strip() != "")


def picus_gain(Tcur, Tcmp=None):
    """Kural bazında Picus kazancı.
    Tcur: güncel koşumun test tablosu → bloklayan = güncelde bu kuralın blokladığı test.
    Tcmp: önceki→güncel karşılaştırma testleri (yoksa None) → kazanc = Not Blocked→Blocked olan ve bu kuralla kapanan test.
    Karşılaştırma yoksa kazanc = bloklayan."""
    rows = {}
    if Tcur is not None and len(Tcur) and "kural_ailesi" in Tcur.columns:
        b = Tcur[(Tcur.picus == "Blocked") & _eligible(Tcur.kural_ailesi, Tcur.cf_karar, Tcur.term_rule)]
        for rid, g in b.groupby("term_rule"):
            rows[rid] = {"rule_id": rid, "kural": g.term_desc.iloc[0], "ruleset": g.kural_ailesi.iloc[0],
                         "kazanc": 0 if Tcmp is not None else len(g), "bloklayan": len(g)}
    if Tcmp is not None and len(Tcmp):
        k = Tcmp[(Tcmp.durum == "Kapandı") & _eligible(Tcmp.kural_ailesi, Tcmp.cf_karar_b, Tcmp.kural_id)]
        for rid, g in k.groupby("kural_id"):
            d = rows.setdefault(rid, {"rule_id": rid, "kural": g.kural.iloc[0], "ruleset": g.kural_ailesi.iloc[0], "kazanc": 0, "bloklayan": 0})
            d["kazanc"] = len(g)
    return pd.DataFrame(list(rows.values()), columns=["rule_id", "kural", "ruleset", "kazanc", "bloklayan"])


# ---------------------------------------------------------------- karar tablosu
def _host(h):
    return (h or "").lower().split(":")[0]


def build(prod, gain, test_host, decisions, exceptions, known=None, states=None):
    """
    prod: fetch() çıktısı (rules, hp, src, samples); gain: picus_gain() çıktısı
    decisions: {rule_id: {karar, note, durum, ...}}; exceptions: exception kayıtları (dict listesi)
    known: bilinen FP / kapatılmış kurallar {rule_id: {...}}; states: {rule_id: prod durumu ("log", "block", "kapalı"...)}
    Dönen: (kural tablosu, exception tablosu, özet tablosu)
    """
    known, states = known or {}, states or {}
    th = _host(test_host)
    rules = prod.get("rules", pd.DataFrame())
    hp = prod.get("hp", pd.DataFrame()).copy()
    src = prod.get("src", pd.DataFrame()).copy()
    S = prod.get("samples", pd.DataFrame()).copy()
    for d in (hp, src, S):
        if len(d):
            if "clientRequestHTTPHost" not in d.columns:
                d["clientRequestHTTPHost"] = ""
            if th:
                d.drop(d[d.clientRequestHTTPHost.map(_host) == th].index, inplace=True)
            if "action" not in d.columns:
                d["action"] = "log"
            d["action"] = d.action.fillna("log").replace("", "log")
    for d in (hp, src):
        if len(d):
            d["olay"] = pd.to_numeric(d.olay, errors="coerce").fillna(0).astype(int)

    meta = {}
    for _, r in rules.iterrows() if len(rules) else []:
        rid = str(r.get("ruleId") or "")
        if rid and rid not in meta:
            meta[rid] = {"kural": r.get("description", ""), "ruleset": RULESETS.get(r.get("rulesetId", ""), r.get("source", "") or r.get("rulesetId", ""))}
    g = gain.set_index("rule_id") if len(gain) else pd.DataFrame(columns=["kural", "ruleset", "kazanc", "bloklayan"])
    for rid, r in g.iterrows():
        meta.setdefault(rid, {"kural": r.kural, "ruleset": r.ruleset})

    hl = hp[hp.action == "log"] if len(hp) else hp
    ho = hp[hp.action != "log"] if len(hp) else hp
    tot = hl.groupby("ruleId").olay.sum() if len(hl) else pd.Series(dtype=int)
    oth = ho.groupby("ruleId").olay.sum() if len(ho) else pd.Series(dtype=int)
    acts = hp.groupby(["ruleId", "action"]).olay.sum() if len(hp) else pd.Series(dtype=int)
    nh = hl.groupby("ruleId").clientRequestHTTPHost.nunique() if len(hl) else pd.Series(dtype=int)
    sl = src[src.action == "log"] if len(src) else src
    if len(sl):
        sl = sl.assign(_tr=(sl.get("clientCountryName", pd.Series("", index=sl.index)).fillna("") == "TR") * sl.olay)
        agg = sl.groupby("ruleId")[["_tr", "olay"]].sum()
        tr = agg._tr / agg.olay.clip(lower=1)
    else:
        tr = pd.Series(dtype=float)
    if len(S) and "botScore" in S.columns:
        Sl = S[S.action == "log"]
        bs = pd.to_numeric(Sl.botScore, errors="coerce")
        hum = Sl.assign(_h=bs >= INSAN_BOT)[bs.notna()].groupby("ruleId")._h.mean()
    else:
        hum = pd.Series(dtype=float)

    def top(rid, n=3):
        if not len(hl):
            return ""
        x = hl[hl.ruleId == rid].sort_values("olay", ascending=False).head(n)
        return "; ".join(f"{r.clientRequestHTTPHost} {r.get('clientRequestHTTPMethodName', '')} {r.get('clientRequestPath', '')} ({r.olay})".replace("  ", " ")
                         for _, r in x.iterrows())

    active = [e for e in exceptions if e.get("active", 1)]
    rows = []
    for rid, m in meta.items():
        kz = int(g.at[rid, "kazanc"]) if rid in g.index else 0
        bl = int(g.at[rid, "bloklayan"]) if rid in g.index else 0
        olay, diger = int(tot.get(rid, 0)), int(oth.get(rid, 0))
        if kz == 0 and olay == 0 and diger == 0:     # ne kazanç ne prod olayı (ör. sadece test host'unda tetiklenmiş)
            continue
        trv = float(tr[rid]) if rid in tr.index else None
        hv = float(hum[rid]) if rid in hum.index else None
        st = states.get(rid, "")
        aks = ", ".join(f"{a} {int(n)}" for (r_, a), n in acts.items() if r_ == rid) if len(acts) else ""
        custom = "custom" in str(m["ruleset"]).lower()
        if rid in known:
            oneri = "F"
            neden = "Bilinen FP listesinde" + (f": {known[rid].get('note')}" if known[rid].get("note") else "") + \
                    ". Exception tasarlanıp Log'da ölçülmeden Block'a alınmamalı."
        else:
            oneri, neden = _suggest(kz, olay, trv, hv, m["kural"], int(nh.get(rid, 0)))
            if oneri == "A" and olay == 0:
                if diger:
                    neden = f"Prod'da Log olayı yok; {diger} istek zaten Log dışı aksiyonla işlenmiş ({aks}) → prod'da zaten Block olabilir"
                elif "log" in st:
                    neden = "Kural prod'da Log'da açık ve bu aralıkta hiç tetiklenmedi → doğrudan Block'a alınabilir"
                else:
                    oneri = "G"
                    neden = ("Kural prod'da KAPALI: kapalı kural log üretmez, FP ölçülemedi. Önce Log'da açıp 3–7 gün izleyin"
                             if "kapalı" in st else
                             ("Custom kural prod'da olay üretmedi: prod host'larını kapsamıyorsa etkisi ölçülemez. " if custom else
                              "Prod'da hiç olay yok ve kuralın prod'da açık olduğu doğrulanamadı (kapalı kural log üretmez). ")
                             + "Önce kuralın prod'da Log'da açık olduğunu doğrulayın, 3–7 gün izleyin")
            if kz == 0 and bl > 0:
                neden += (f" | Not: güncel koşumda {bl} Picus testini bu kural blokluyor; önceki koşumda bu testler başka bir "
                          "kuralla bloklanmıştı. O kural prod'da yoksa bu kural da prod için kazançtır")
        exs = [e for e in active if rid in exception_rules(e)]
        kalan, hesap = olay, True
        if exs and len(hl):
            covered = 0
            for _, r in hl[hl.ruleId == rid].iterrows():
                ms = [exception_matches(e, r.clientRequestHTTPHost, r.get("clientRequestPath", "")) for e in exs]
                if any(v is None for v in ms):
                    hesap = False
                if any(ms):
                    covered += r.olay
            kalan = olay - covered
        d = decisions.get(rid) or {}
        karar = d.get("karar") or oneri
        notu = d.get("note") or neden
        if rid in known and karar in ("A", "B") and d.get("karar"):
            notu = "UYARI: bilinen FP listesinde! " + notu
        durum = d.get("durum") or ("Zaten Block" if (olay == 0 and diger and karar == "A") else "Bekliyor")
        rows.append({
            "karar": karar, "oneri": oneri, "elle": bool(d.get("karar")), "bilinen_fp": rid in known,
            "kural": m["kural"], "rule_id": rid, "ruleset": m["ruleset"], "kazanc": kz, "bloklayan": bl,
            "prod_olay": olay, "prod_diger": diger, "prod_aksiyon": aks, "cf_durum": st,
            "exception": ", ".join(e["code"] for e in exs), "kalan": (kalan if hesap else None) if exs else None,
            "notu": notu, "top": top(rid), "host_sayisi": int(nh.get(rid, 0)),
            "tr": round(trv, 3) if trv is not None else None, "insan": round(hv, 3) if hv is not None else None,
            "durum": durum,
            "durum_bilgi": f"{d.get('durum_by') or ''} {(d.get('durum_at') or '')[:10]}".strip() if d.get("durum") else "",
        })
    cols = ["karar", "oneri", "elle", "bilinen_fp", "kural", "rule_id", "ruleset", "kazanc", "bloklayan", "prod_olay", "prod_diger",
            "prod_aksiyon", "cf_durum", "exception", "kalan", "notu", "top", "host_sayisi", "tr", "insan", "durum", "durum_bilgi"]
    T = pd.DataFrame(rows, columns=cols)
    if len(T):
        T = T.sort_values(["karar", "kazanc", "prod_olay"], ascending=[True, False, False]).reset_index(drop=True)

    names = dict(zip(T.rule_id, T.kural)) if len(T) else {}
    ER = []
    for e in exceptions:
        rl = exception_rules(e)
        covered, hesap = 0, True
        for _, r in (hl[hl.ruleId.isin(rl)].iterrows() if len(hl) else []):
            v = exception_matches(e, r.clientRequestHTTPHost, r.get("clientRequestPath", ""))
            if v is None:
                hesap = False
                break
            if v:
                covered += r.olay
        ER.append({"id": e["id"], "code": e["code"], "ad": e.get("ad", ""), "expression": exception_expression(e),
                   "uygulama": "Skip: " + ", ".join(f"{names.get(r, r)} ({r[:8]}…)" for r in rl) if rl else "",
                   "kapsadigi_olay": covered if hesap else None, "aktif": bool(e.get("active", 1)), "notu": e.get("note", "")})
    E = pd.DataFrame(ER, columns=["id", "code", "ad", "expression", "uygulama", "kapsadigi_olay", "aktif", "notu"])

    oz = []
    for k, lbl in KARARLAR.items():
        x = T[T.karar == k] if len(T) else T
        oz.append({"karar": k, "etiket": lbl, "kural": int(len(x)), "kazanc": int(x.kazanc.sum()) if len(x) else 0,
                   "prod_olay": int(x.prod_olay.sum()) if len(x) else 0,
                   "kalan": int(sum((r.kalan if pd.notna(r.kalan) else r.prod_olay) for r in x.itertuples())) if len(x) else 0})
    return T, E, pd.DataFrame(oz)


def _suggest(kazanc, olay, tr, insan, ad, host_sayisi):
    if kazanc > 0:
        if olay <= A_MAX_OLAY:
            return "A", ("Prod Log'da görünmedi" if olay == 0 else f"Prod'da yalnızca {olay} Log olayı")
        if kazanc >= B_MIN_KAZANC or olay <= B_MAX_OLAY:
            return "B", f"Picus kazancı {kazanc} test; prod'da {olay} olay / {host_sayisi} host → exception ile Block"
        return "C", f"Kazanç düşük ({kazanc} test), prod'da {olay} olay / {host_sayisi} host → FP riski kazançtan büyük"
    trs = f"TR %{round(100 * tr)}" if tr is not None else "TR ?"
    ins = f"insan %{round(100 * insan)}" if insan is not None else "insan ?"
    if (tr is not None and tr < D_MAX_TR) or any(k in (ad or "").lower() for k in SALDIRI_ADI):
        return "D", f"{trs}, {ins} → yurtdışı/otomatik saldırı trafiği"
    return "E", f"{trs}, {ins} → meşru trafik ağırlıklı (FP)"


# ---------------------------------------------------------------- Excel
def excel(T, E, oz, prod, test_host, title):
    import exports
    cols_T = [("karar", "Karar", "f"), ("durum", "Uygulama durumu", "f"), ("kural", "Kural", "w"), ("rule_id", "Rule ID", ""),
              ("ruleset", "Ruleset", "f"), ("kazanc", "Picus kazancı (test)", "n"), ("bloklayan", "Güncelde bloklayan test", "n"),
              ("prod_olay", "Prod Log olayı", "n"), ("prod_aksiyon", "Prod aksiyonları", ""), ("cf_durum", "Prod'daki kural durumu", "f"),
              ("exception", "Exception", ""), ("kalan", "Exception sonrası kalan", "n"), ("notu", "Not", "w"),
              ("top", "En çok tetiklenen host/path", "w"), ("tr", "TR oranı", "n"), ("insan", "İnsan oranı (bot≥30)", "n"),
              ("durum_bilgi", "Durumu güncelleyen", "")]
    T2 = T.copy()
    if len(T2):
        T2["karar"] = T2.karar.map(KARARLAR)
    ozet = oz.rename(columns={"etiket": "Karar", "kural": "Kural", "kazanc": "Picus testi", "prod_olay": "Prod log",
                              "kalan": "Exception sonrası"})[["Karar", "Kural", "Picus testi", "Prod log", "Exception sonrası"]]
    ex = E.rename(columns={"code": "ID", "ad": "Ne için", "expression": "Expression", "uygulama": "Uygulama",
                           "kapsadigi_olay": "Kapsadığı olay", "notu": "Not"})[["ID", "Ne için", "Expression", "Uygulama", "Kapsadığı olay", "Not"]]
    sheets = [("Özet", ozet, 0), ("Karar listesi", exports.frame(T2, cols_T), 0), ("Exception kuralları", ex, 0)]
    hp = prod.get("hp", pd.DataFrame())
    if len(hp):
        h = hp[hp.clientRequestHTTPHost.map(_host) != _host(test_host)].copy()
        h["olay"] = pd.to_numeric(h.olay, errors="coerce")
        h = h.sort_values("olay", ascending=False).groupby("ruleId").head(20)
        h["kural"] = h.ruleId.map(dict(zip(T.rule_id, T.kural)))
        sheets.append(("Host-path detayı", h.rename(columns={"ruleId": "Rule ID", "action": "Aksiyon", "clientRequestHTTPHost": "Host",
                                                             "clientRequestHTTPMethodName": "Method", "clientRequestPath": "Path",
                                                             "olay": "Olay", "kural": "Kural"}), 0))
    S = prod.get("samples", pd.DataFrame())
    if len(S):
        keep = [c for c in ("ruleId", "description", "action", "datetime", "rayName", "clientIP", "clientCountryName", "clientASNDescription",
                            "clientRequestHTTPHost", "clientRequestHTTPMethodName", "clientRequestPath", "userAgent", "botScore",
                            "wafAttackScore") if c in S.columns]
        sheets.append(("Örnek olaylar", S[keep], 0))
    return exports._write(sheets, title=title)
