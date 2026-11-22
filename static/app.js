/* Picus × Cloudflare WAF Platformu – arayüz yardımcıları (CSP: yalnızca bu dosya çalışır) */
(function () {
  "use strict";
  const $ = (s, el) => (el || document).querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (v, kind) => {
    if (v == null || v === "") return "";
    if (kind === "n" && typeof v === "number") return v.toLocaleString("tr-TR", { maximumFractionDigits: 3 });
    return String(v);
  };

  // ---------------------------------------------------------- otomatik gönderim / onay
  $$("[data-autosubmit]").forEach((el) => el.addEventListener("change", () => el.form && el.form.submit()));
  $$("form[data-confirm]").forEach((f) => f.addEventListener("submit", (e) => { if (!window.confirm(f.dataset.confirm)) e.preventDefault(); }));

  // ---------------------------------------------------------- radio ile göster/gizle
  function applyToggles() {
    $$("[data-show]").forEach((el) => {
      const [name, val] = el.dataset.show.split("=");
      const r = $(`input[name="${name}"]:checked`);
      el.style.display = r && r.value === val ? "" : "none";
    });
  }
  $$("[data-toggle] input[type=radio]").forEach((r) => r.addEventListener("change", applyToggles));
  applyToggles();

  // ---------------------------------------------------------- sekmeler
  const tabs = $$(".tabs a");
  function showTab() {
    if (!tabs.length) return;
    const id = (location.hash || tabs[0].getAttribute("href")).slice(1);
    const target = document.getElementById(id) ? id : tabs[0].getAttribute("href").slice(1);
    tabs.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + target));
    $$(".tab").forEach((s) => s.classList.toggle("on", s.id === target));
    const t = document.getElementById(target);
    if (t) $$(".tbl", t).forEach(loadTable);
  }
  window.addEventListener("hashchange", showTab);
  showTab();

  // ---------------------------------------------------------- JSON tablolar
  function loadTable(box) {
    if (box.dataset.loaded) return;
    box.dataset.loaded = "1";
    box.innerHTML = '<p class="muted">Yükleniyor…</p>';
    fetch(box.dataset.src, { credentials: "same-origin" }).then((r) => r.json()).then((d) => renderTable(box, d))
      .catch(() => { box.innerHTML = '<p class="flash error">Tablo yüklenemedi.</p>'; });
  }
  function renderTable(box, d) {
    const cols = d.columns, rows = d.rows, per = 100;
    let q = "", sortI = -1, sortDir = 1, page = 0;
    const filters = {};
    box.innerHTML = "";
    const bar = document.createElement("div"); bar.className = "bar";
    const inp = document.createElement("input"); inp.placeholder = "Ara…"; bar.appendChild(inp);
    cols.forEach((c, i) => {
      if (c.kind !== "f") return;
      const vals = Array.from(new Set(rows.map((r) => r[i]).filter((v) => v !== "" && v != null))).sort();
      if (vals.length < 2 || vals.length > 60) return;
      const s = document.createElement("select");
      s.innerHTML = `<option value="">${esc(c.label)}: tümü</option>` + vals.map((v) => `<option>${esc(v)}</option>`).join("");
      s.addEventListener("change", () => { filters[i] = s.value; page = 0; draw(); });
      bar.appendChild(s);
    });
    const cnt = document.createElement("span"); cnt.className = "muted"; bar.appendChild(cnt);
    box.appendChild(bar);
    const wrap = document.createElement("div"); wrap.className = "wrap"; box.appendChild(wrap);
    const pager = document.createElement("div"); pager.className = "pager"; box.appendChild(pager);
    inp.addEventListener("input", () => { q = inp.value.toLowerCase(); page = 0; draw(); });
    function draw() {
      let rs = rows.filter((r) => Object.entries(filters).every(([i, v]) => !v || String(r[i]) === v));
      if (q) rs = rs.filter((r) => r.some((v) => String(v == null ? "" : v).toLowerCase().includes(q)));
      if (sortI >= 0) rs = rs.slice().sort((a, b) => {
        const x = a[sortI], y = b[sortI];
        if (typeof x === "number" || typeof y === "number") return ((x == null ? -Infinity : x) - (y == null ? -Infinity : y)) * sortDir;
        return String(x == null ? "" : x).localeCompare(String(y == null ? "" : y), "tr") * sortDir;
      });
      const pages = Math.max(1, Math.ceil(rs.length / per));
      page = Math.min(page, pages - 1);
      cnt.textContent = `${rs.length.toLocaleString("tr-TR")} satır`;
      const head = cols.map((c, i) => `<th data-i="${i}" class="${c.kind === "n" ? "r" : ""}">${esc(c.label)}${i === sortI ? (sortDir > 0 ? " ▲" : " ▼") : ""}</th>`).join("");
      const body = rs.slice(page * per, page * per + per).map((r) => "<tr>" + r.map((v, i) => {
        const k = cols[i].kind;
        return `<td class="${k === "n" ? "r" : k === "w" ? "w" : ""}">${esc(fmt(v, k))}</td>`;
      }).join("") + "</tr>").join("");
      wrap.innerHTML = `<table class="list dense"><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${cols.length}" class="muted">Kayıt yok.</td></tr>`}</tbody></table>`;
      $$("th", wrap).forEach((th) => th.addEventListener("click", () => {
        const i = +th.dataset.i; sortDir = sortI === i ? -sortDir : (cols[i].kind === "n" ? -1 : 1); sortI = i; draw();
      }));
      pager.innerHTML = pages > 1 ? `<button class="btn" data-p="-1">‹</button> ${page + 1} / ${pages} <button class="btn" data-p="1">›</button>` : "";
      $$("button", pager).forEach((b) => b.addEventListener("click", () => { page = Math.max(0, Math.min(pages - 1, page + +b.dataset.p)); draw(); }));
    }
    draw();
  }

  // ---------------------------------------------------------- iş takibi
  $$(".job").forEach((box) => {
    const bar = $(".bar span", box), log = $(".log", box);
    const tick = () => fetch(box.dataset.status, { credentials: "same-origin" }).then((r) => r.json()).then((d) => {
      bar.style.width = (d.progress || 0) + "%";
      log.textContent = d.log || "";
      log.scrollTop = log.scrollHeight;
      if (d.status === "tamam" || d.status === "hata") setTimeout(() => location.reload(), 800);
      else setTimeout(tick, 2000);
    }).catch(() => setTimeout(tick, 4000));
    tick();
  });

  // ---------------------------------------------------------- Picus seçim listeleri
  const simSel = $("#picus_sim"), runSel = $("#picus_run"), loadBtn = $("#picus_load");
  function loadSims() {
    if (!simSel) return;
    simSel.innerHTML = "<option value=''>— yükleniyor —</option>";
    fetch("/picus/simulasyonlar", { credentials: "same-origin" }).then((r) => r.json()).then((d) => {
      if (!d.ok) { simSel.innerHTML = `<option value=''>Hata: ${esc(d.error)}</option>`; return; }
      simSel.innerHTML = "<option value=''>— seçin —</option>" + d.items.map((x) => `<option value="${esc(x.id)}">${esc(x.ad)} (#${esc(x.id)})</option>`).join("");
    }).catch(() => { simSel.innerHTML = "<option value=''>Picus'a ulaşılamadı</option>"; });
  }
  if (simSel) {
    if (loadBtn) loadBtn.addEventListener("click", loadSims);
    const api = $('input[name="picus_source"][value="api"]');
    if (api && api.checked) loadSims();
    if (api) api.addEventListener("change", loadSims);
    simSel.addEventListener("change", () => {
      if (!simSel.value) return;
      runSel.innerHTML = "<option value=''>— yükleniyor —</option>";
      fetch(`/picus/simulasyon/${encodeURIComponent(simSel.value)}/kosumlar`, { credentials: "same-origin" }).then((r) => r.json()).then((d) => {
        if (!d.ok) { runSel.innerHTML = `<option value=''>Hata: ${esc(d.error)}</option>`; return; }
        runSel.innerHTML = d.items.map((x) => `<option value="${esc(x.id)}">${esc(x.started_at)} · ${esc(x.status)}${x.var ? " · zaten eklendi" : ""}</option>`).join("") || "<option value=''>Koşum yok</option>";
        const nm = $('input[name="name"]');
        if (nm && !nm.value && d.ad) nm.value = d.ad;
      });
    });
  }

  // ---------------------------------------------------------- trend grafikleri (SVG)
  $$(".chart").forEach((box) => {
    const src = document.getElementById(box.dataset.src);
    if (!src) return;
    const data = JSON.parse(src.textContent || "[]").filter((x) => x[box.dataset.key] != null);
    const ch = box.dataset.changes && document.getElementById(box.dataset.changes) ? JSON.parse(document.getElementById(box.dataset.changes).textContent || "[]") : [];
    if (data.length < 1) { box.innerHTML = '<p class="muted small">Veri yok.</p>'; return; }
    const W = 600, H = 190, L = 40, R = 12, T = 12, B = 34;
    const vals = data.map((x) => +x[box.dataset.key]);
    let lo = Math.min(...vals), hi = Math.max(...vals);
    if (lo === hi) { lo -= 1; hi += 1; }
    const pad = (hi - lo) * 0.1; lo -= pad; hi += pad;
    const xs = (i) => data.length === 1 ? (L + W - R) / 2 : L + (i * (W - L - R)) / (data.length - 1);
    const ys = (v) => T + (H - T - B) * (1 - (v - lo) / (hi - lo));
    let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">`;
    svg += `<line class="axis" x1="${L}" y1="${H - B}" x2="${W - R}" y2="${H - B}"/>`;
    [lo + pad, (lo + hi) / 2, hi - pad].forEach((v) => { svg += `<text x="2" y="${ys(v) + 3}">${(Math.round(v * 10) / 10).toLocaleString("tr-TR")}</text>`; });
    // değişiklik işaretleri: iki koşum arasındaki tarihlere
    ch.forEach((c) => {
      for (let i = 1; i < data.length; i++) {
        if (c.tarih > data[i - 1].tarih && c.tarih <= data[i].tarih) {
          const x = (xs(i - 1) + xs(i)) / 2;
          svg += `<line class="ch" x1="${x}" y1="${T}" x2="${x}" y2="${H - B}"><title>${esc(c.tarih + " " + c.aciklama)}</title></line>`;
        }
      }
    });
    svg += `<polyline class="ln" points="${data.map((x, i) => xs(i) + "," + ys(+x[box.dataset.key])).join(" ")}"/>`;
    data.forEach((x, i) => {
      svg += `<circle class="pt" cx="${xs(i)}" cy="${ys(+x[box.dataset.key])}" r="3.5"><title>${esc(x.ad + " · " + x.tarih + ": " + x[box.dataset.key])}</title></circle>`;
      svg += `<text x="${xs(i)}" y="${H - B + 14}" text-anchor="middle">${esc(x.tarih.slice(5))}</text>`;
      svg += `<text x="${xs(i)}" y="${ys(+x[box.dataset.key]) - 7}" text-anchor="middle">${esc((+x[box.dataset.key]).toLocaleString("tr-TR"))}</text>`;
    });
    box.innerHTML = svg + "</svg>";
  });
})();
