"""Tablo tanımları (ekran + Excel ortak), Excel ve HTML rapor üretimi."""
import html
import io
from datetime import datetime

import pandas as pd

import config

# (alan, başlık, tür)  tür: f=filtrelenebilir, n=sayı, w=uzun metin, t=zaman, ''=düz
RUN_TABLES = {
    "aksiyonlar": ("actions", "Bloklanmayan aksiyonlar", [
        ("risk", "Risk", "f"), ("puan", "Puan", "n"), ("aid", "ActionID", ""), ("aksiyon", "Aksiyon", "w"),
        ("kategori", "Kategori", "f"), ("cve", "CVE", ""), ("neden", "Neden kritik", "w"),
        ("nb_kampanya", "Geçtiği kampanya", "n"), ("tek_basina", "Tek başına düşürdüğü", "n"),
        ("cf_karar", "CF kararı", "f"), ("log_kurallar", "Log'da yakalayan kurallar", "w"),
        ("ray", "Örnek Ray ID", ""), ("istek", "İstek", "w"), ("kampanyalar", "Kampanyalar", "w")]),
    "testler": ("tests", "Tüm testler", [
        ("zaman", "Zaman (TR)", "t"), ("aid", "ActionID", ""), ("aksiyon", "Aksiyon", "w"), ("kategori", "Kategori", "f"),
        ("cve", "CVE", ""), ("kampanya", "Kampanya", "w"), ("picus", "Picus sonuç", "f"), ("cf_karar", "CF kararı", "f"),
        ("kural_ailesi", "Kural ailesi", "f"), ("term_desc", "Bloklayan/challenge kural", "w"), ("term_rule", "Kural ID", ""),
        ("kurallar", "Çarptığı tüm kurallar", "w"), ("log_kurallar", "Log'da yakalayan kurallar", "w"),
        ("edgeResponseStatus", "HTTP", "f"), ("wafAttackScore", "Attack score", "n"), ("wafAttackScoreClass", "Score sınıfı", "f"),
        ("botScore", "Bot score", "n"), ("risk", "Risk", "f"), ("rayName", "Ray ID", ""), ("istek", "İstek", "w")]),
    "kategoriler": ("categories", "Kategori risk", [
        ("kategori", "Kategori", ""), ("nb_aksiyon", "Bloklanmayan aksiyon", "n"), ("kritik", "Kritik", "n"),
        ("yuksek", "Yüksek", "n"), ("nb_test", "Bloklanmayan test", "n"), ("ornek", "Örnek aksiyonlar", "w"),
        ("oneri", "Cloudflare önerisi", "w")]),
    "kurallar": ("rule_hits", "Kural isabetleri", [
        ("action", "Aksiyon", "f"), ("description", "Kural", "w"), ("ruleId", "Kural ID", ""), ("source", "Kaynak", "f"),
        ("istek", "İstek", "n"), ("picus_aksiyon", "Picus aksiyonu", "n"), ("picus_blocked", "Picus Blocked", "n"),
        ("picus_not_blocked", "Picus Not Blocked", "n")]),
    "log_block": ("log_block", "Log→Block önerisi", [
        ("kural", "Kural (Log modunda yakalıyor)", "w"), ("kapanacak_aksiyon", "Block'a çekilirse kapanacak aksiyon", "n"),
        ("ornek", "Örnek aksiyonlar", "w")]),
    "kirilgan": ("fragile", "Kırılgan bloklar", [
        ("aid", "ActionID", ""), ("aksiyon", "Aksiyon", "w"), ("kategori", "Kategori", "f"), ("kampanya", "Kampanya", "w"),
        ("cf_karar", "CF kararı", "f"), ("term_desc", "Kural", "w"), ("rayName", "Ray ID", ""), ("zaman", "Zaman (TR)", "t")]),
}

CMP_TABLES = {
    "aksiyon_durum": ("actions", "Aksiyon durumu", [
        ("durum", "Durum", "f"), ("risk", "Risk", "f"), ("puan", "Puan", "n"), ("aid", "ActionID", ""),
        ("aksiyon", "Aksiyon", "w"), ("kategori", "Kategori", "f"), ("cve", "CVE", ""),
        ("nb_test_onceki", "Önceki NB test", "n"), ("nb_test_guncel", "Güncel NB test", "n"), ("neden", "Neden kritik", "w")]),
    "kapanis": ("sources", "Kapanış kaynağı", [
        ("kural_ailesi", "Kural ailesi", "f"), ("kural", "Kural", "w"), ("kural_id", "Kural ID", ""),
        ("kapanan_test", "Kapanan test", "n"), ("kapanan_aksiyon", "Kapanan aksiyon", "n")]),
    "test_gecis": ("tests", "Test geçişleri", [
        ("durum", "Durum", "f"), ("aid", "ActionID", ""), ("aksiyon", "Aksiyon", "w"), ("kategori", "Kategori", "f"),
        ("kampanya", "Kampanya", "w"), ("onceki", "Önceki", "f"), ("guncel", "Güncel", "f"),
        ("cf_karar_a", "Önceki CF kararı", "f"), ("cf_karar_b", "Güncel CF kararı", "f"), ("kural_ailesi", "Kural ailesi", "f"),
        ("kural", "Kural", "w"), ("kural_id", "Kural ID", ""), ("ray", "Ray ID", "")]),
}


def tr_time(v):
    try:
        t = pd.Timestamp(v)
        if t.tzinfo is None:
            t = t.tz_localize("UTC")
        return t.tz_convert(config.TR).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:  # noqa: BLE001
        return v or ""


def frame(df, cols):
    """Tabloyu ekranda/Excel'de gösterilecek kolonlara ve biçime çevirir."""
    out = pd.DataFrame(index=df.index)
    for key, label, kind in cols:
        s = df[key] if key in df.columns else pd.Series("", index=df.index)
        if kind == "t":
            s = s.map(tr_time)
        elif kind == "n":
            s = pd.to_numeric(s, errors="coerce")
        else:
            s = s.fillna("").astype(str)
        out[label] = s
    return out


def records(df, cols):
    f = frame(df, cols)
    f = f.astype(object).where(pd.notna(f), None)
    return {"columns": [{"label": l, "kind": k} for _, l, k in cols], "rows": f.values.tolist()}


# ---------------------------------------------------------------- Excel
def _style(wb):
    from openpyxl.styles import Alignment, Font, PatternFill
    for ws in wb:
        for c in ws[1]:
            c.font = Font(bold=True)
            c.fill = PatternFill("solid", fgColor="DDE4EE")
            c.alignment = Alignment(vertical="top", wrap_text=True)
        for colc in ws.columns:
            n = max((len(str(c.value or "")) for c in colc[:300]), default=8)
            ws.column_dimensions[colc[0].column_letter].width = min(max(10, n + 2), 60)
        ws.freeze_panes = "A2"
        if ws.title != "Özet" and ws.max_row > 1:
            ws.auto_filter.ref = ws.dimensions


def _sheet(name):
    for ch in "[]:*?/\\":
        name = name.replace(ch, "")
    return name[:31]


def _write(sheets, title=None):
    from openpyxl import load_workbook
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        for name, df, startrow in sheets:
            df.to_excel(w, sheet_name=_sheet(name), index=False, startrow=startrow)
    buf.seek(0)
    wb = load_workbook(buf)
    _style(wb)
    if title:
        wb.properties.title = title[:200]
    out = io.BytesIO()
    wb.save(out)
    out.seek(0)
    return out


def summary_rows(s):
    return [
        ["Picus testi (aksiyon x kampanya)", s["test"]], ["Blocked", s["blocked"]], ["Not Blocked", s["not_blocked"]],
        ["Not Tested", s["not_tested"]], ["Aksiyon skoru (Blocked / Blocked+NB)", f"%{s['skor']}" if s["skor"] is not None else "-"],
        ["Kampanya skoru", f"{s['kampanya_blocked']} / {s['kampanya_toplam']}"],
        ["CF loguyla eşleşen test", f"{s['eslesen']} (%{round(100 * s['eslesen'] / max(1, s['test']))})"],
        ["Bloklanmayan benzersiz aksiyon", s["nb_aksiyon"]],
        ["  Kritik / Yüksek / Orta / Düşük", f"{s['kritik']} / {s['yuksek']} / {s['orta']} / {s['dusuk']}"],
        ["Kırılgan blok (bot score / origin 520 / CF logu yok)",
         "CF verisi yok (hesaplanamadı)" if s.get("kirilgan") is None else
         f"{s['kirilgan']} ({s['kirilgan_bot']} / {s['kirilgan_520']} / {s['kirilgan_logyok']})"],
    ]


def cf_karar_table(s):
    rows = []
    for k, d in sorted(s.get("cf_karar", {}).items(), key=lambda x: -sum(x[1].values())):
        rows.append([k, d.get("Blocked", 0), d.get("Not Blocked", 0), d.get("Not Tested", 0), sum(d.values())])
    return pd.DataFrame(rows, columns=["CF kararı", "Blocked", "Not Blocked", "Not Tested", "Toplam"])


def run_excel(run, s, tables):
    ozet = pd.DataFrame(summary_rows(s), columns=["Metrik", "Değer"])
    sheets = [("Özet", ozet, 0), ("Özet", cf_karar_table(s), len(ozet) + 3)]
    for key, (kind, title, cols) in RUN_TABLES.items():
        df = tables.get(kind)
        if df is not None and len(df):
            sheets.append((title, frame(df, cols), 0))
    return _write(sheets)


def compare_excel(ra, rb, sa, sb, cmp, kategoriler):
    keys = [("skor", "Aksiyon skoru (%)"), ("test", "Test"), ("blocked", "Blocked"), ("not_blocked", "Not Blocked"),
            ("not_tested", "Not Tested"), ("nb_aksiyon", "Bloklanmayan aksiyon"), ("kritik", "Kritik"), ("yuksek", "Yüksek"),
            ("orta", "Orta"), ("dusuk", "Düşük"), ("kirilgan", "Kırılgan blok"), ("kampanya_blocked", "Kampanya Blocked"),
            ("kampanya_toplam", "Kampanya toplam")]
    oz = pd.DataFrame([[lbl, sa.get(k), sb.get(k), (sb.get(k) or 0) - (sa.get(k) or 0) if sa.get(k) is not None and sb.get(k) is not None else None]
                       for k, lbl in keys], columns=["Metrik", ra["name"], rb["name"], "Fark"])
    gc = pd.DataFrame([[k, v] for k, v in cmp["counts"].items()], columns=["Test durumu", "Adet"])
    e = cmp.get("eslesme") or {}
    if e:
        gc = pd.concat([gc, pd.DataFrame([["Eşleşen ortak test", e.get("ortak")], ["Eşleşme oranı", f"%{round(100 * e.get('oran', 0))}"],
                                          ["Eşleştirme anahtarı", e.get("anahtar")]], columns=gc.columns)], ignore_index=True)
    sheets = [("Özet", oz, 0), ("Özet", gc, len(oz) + 3), ("Kategori", kategoriler, 0)]
    for key, (kind, title, cols) in CMP_TABLES.items():
        sheets.append((title, frame(cmp[kind], cols), 0))
    return _write(sheets)


# ---------------------------------------------------------------- HTML risk raporu
def risk_report(run, s, A, KR, LG, RS):
    def tbl(df, n=None):
        d = df.head(n) if n else df
        th = "".join(f"<th>{html.escape(str(c))}</th>" for c in d.columns)
        rows = "".join("<tr>" + "".join(f"<td>{html.escape('' if v is None else str(v))}</td>" for v in r) + "</tr>"
                       for r in d.astype(object).where(pd.notna(d), "").values)
        return f"<table><thead><tr>{th}</tr></thead><tbody>{rows}</tbody></table>"
    top = frame(A, [c for c in RUN_TABLES["aksiyonlar"][2] if c[0] in ("risk", "aksiyon", "kategori", "cve", "neden", "cf_karar", "ray")])
    kr = frame(KR, RUN_TABLES["kategoriler"][2])
    lg = frame(LG, RUN_TABLES["log_block"][2])
    rs = frame(RS, RUN_TABLES["kurallar"][2])
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937;max-width:1200px}"
           "h1{font-size:22px}h2{font-size:17px;margin-top:28px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}"
           "table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}th,td{border:1px solid #e5e7eb;padding:5px 7px;text-align:left;vertical-align:top}"
           "th{background:#eef2f7}.kpi{display:flex;flex-wrap:wrap;gap:10px}.kpi div{border:1px solid #e5e7eb;border-radius:8px;padding:10px 14px;min-width:150px}"
           ".kpi b{display:block;font-size:20px}.note{color:#6b7280;font-size:12px}")
    en_buyuk = html.escape(str(KR.kategori.iloc[0])) if len(KR) else "-"
    kirilgan_txt = ("Bu koşumda CF verisi eşleşmediği için kırılgan blok hesaplanamadı." if s.get("kirilgan") is None else
                    f"Ayrıca {s['kirilgan']} test WAF kuralı dışında bir nedenle durdu (bot score challenge, origin 520 ya da CF logu yok); "
                    "bu bloklar kalıcı koruma sayılmamalı.")
    lgtxt = (f"<p>Aşağıdaki kurallar bloklanmayan saldırıları <b>Log modunda zaten yakalıyor</b>. Block'a çekilirlerse listelenen "
             f"aksiyonlar kapanır (önce prod'da FP kontrolü yapın).</p>{tbl(lg, 25)}") if len(LG) else "<p>Log modunda yakalanan bloklanmamış saldırı yok.</p>"
    body = f"""<h1>Picus × Cloudflare – Bloklanmayan Saldırılar Risk Raporu</h1>
<p class=note>{html.escape(run['name'])} · oluşturma {datetime.now(config.TR):%d.%m.%Y %H:%M}</p>
<div class=kpi><div>Aksiyon skoru<b>%{s['skor']}</b></div><div>Kampanya skoru<b>{s['kampanya_blocked']}/{s['kampanya_toplam']}</b></div>
<div>Not Blocked test<b>{s['not_blocked']}</b></div><div>Bloklanmayan aksiyon<b>{s['nb_aksiyon']}</b></div>
<div>Kritik / Yüksek<b>{s['kritik']} / {s['yuksek']}</b></div><div>Kırılgan blok<b>{s['kirilgan'] if s.get('kirilgan') is not None else '—'}</b></div></div>
<h2>1. Yönetici özeti</h2>
<p>Simülasyonda {s['test']} test koşuldu; {s['not_blocked']} test Cloudflare'i geçti. Bloklanmayan {s['nb_aksiyon']} benzersiz saldırının
<b>{s['kritik']}</b>'i kritik, <b>{s['yuksek']}</b>'i yüksek riskli. En büyük risk grubu: <b>{en_buyuk}</b>. {kirilgan_txt}</p>
<h2>2. Cloudflare kararları</h2>{tbl(cf_karar_table(s))}
<h2>3. En kritik bloklanmayan saldırılar (ilk 25)</h2>{tbl(top, 25)}
<h2>4. Kategori bazında risk ve öneriler</h2>{tbl(kr)}
<h2>5. Log modunda yakalanan ama bloklanmayanlar</h2>{lgtxt}
<h2>6. En çok tetiklenen Cloudflare kuralları</h2>{tbl(rs, 25)}
<h2>7. Yöntem</h2><p class=note>Eşleştirme Picus actionId'si (URL'deki /page&lt;ID&gt;) ve zamana göre yapıldı. Kritiklik puanı:
saldırı kategorisi (CWE), Picus önem derecesi, CVE, geçtiği kampanya sayısı, kampanyayı tek başına düşürmesi, origin'e ulaşması
ve attack score'un saldırıyı görmemesi. Kural önerileri önce Log modunda denenmeli, FP kontrolünden sonra Block'a alınmalıdır.</p>"""
    return f"<!doctype html><html lang=tr><head><meta charset=utf-8><title>Risk raporu – {html.escape(run['name'])}</title><style>{css}</style></head><body>{body}</body></html>"
