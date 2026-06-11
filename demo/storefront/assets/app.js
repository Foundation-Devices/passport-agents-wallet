/* Satoshi Supply Co. — storefront (server-backed)
 * - catalog + invoices come from the server (single source of truth)
 * - checkout fetches GET /api/checkout/:product; the AGENT fetches the SAME invoice
 *   and pays it (no pasted address). Server polls testnet4 and flips status to paid.
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const fmtSats = (n) => n.toLocaleString("en-US") + " sats";
  const toBtc = (sats) => (sats / 1e8).toFixed(8);

  let CATALOG = { products: [], explorerTx: "https://mempool.space/testnet4/tx" };

  async function getJSON(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(url + " -> " + r.status);
    return r.json();
  }

  // ---- catalog ----
  async function loadCatalog() {
    CATALOG = await getJSON("/api/catalog");
    const grid = $("product-grid");
    grid.innerHTML = "";
    CATALOG.products.forEach((p) => {
      const card = document.createElement("article");
      card.className = "card";
      card.innerHTML = `
        <div class="card-art">${p.art}<span class="chip">${p.tag}</span></div>
        <div class="card-body">
          <h3 class="card-name">${p.name}</h3>
          <p class="card-variant">${p.variant}</p>
          <p class="card-blurb">${p.blurb}</p>
          <div class="card-foot">
            <span class="price">${p.sats.toLocaleString("en-US")}<span class="unit">sats</span></span>
            <a class="btn small" href="#/p/${p.id}">Buy with Bitcoin</a>
          </div>
        </div>`;
      grid.appendChild(card);
    });
  }

  // ---- QR ----
  function renderQR(text) {
    const el = $("qr");
    el.innerHTML = "";
    try {
      const qr = qrcode(0, "M");
      qr.addData(text);
      qr.make();
      el.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 1, scalable: true });
    } catch (e) {
      el.textContent = "QR error";
    }
  }

  // ---- live status (server is the source of truth) ----
  let pollTimer = null;
  let paidShown = false;
  function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
  function setState(kind, text) {
    $("pay-state").className = "pay-state state-" + kind;
    $("pay-state-text").textContent = text;
  }

  function watchOrder(order) {
    paidShown = false;
    const tick = async () => {
      let o;
      try { o = await getJSON("/api/order/" + order.id); } catch (_) { return; }
      if (o.txid) {
        const a = $("inv-txlink");
        a.href = `${CATALOG.explorerTx}/${o.txid}`;
        a.hidden = false;
      }
      if (o.status === "paid") {
        setState("confirmed", "Payment received");
        showPaid(o);
        stopPolling();
      } else if (o.agentAccessed) {
        setState("detected", "Agent is paying…");
      }
    };
    tick();
    pollTimer = setInterval(tick, 2500);
  }

  function showPaid(order) {
    if (paidShown) return;
    paidShown = true;
    $("paid-order").textContent = "#" + order.id;
    $("paid-detail").textContent = `${order.name} · ${fmtSats(order.amountSats)} received on testnet4.`;
    const a = $("paid-txlink");
    if (order.txid) { a.href = `${CATALOG.explorerTx}/${order.txid}`; a.hidden = false; }
    else { a.hidden = true; }
    $("paid-overlay").hidden = false;
  }

  // ---- views ----
  function showView(name) {
    $("view-catalog").hidden = name !== "catalog";
    $("view-checkout").hidden = name !== "checkout";
    window.scrollTo(0, 0);
  }

  async function openCheckout(productId) {
    stopPolling();
    paidShown = false;
    $("paid-overlay").hidden = true;
    let order;
    try { order = await getJSON("/api/checkout/" + productId); } catch (_) {
      showView("catalog");
      return;
    }
    $("order-art").textContent = (CATALOG.products.find((p) => p.id === productId) || {}).art || "🪙";
    $("order-tag").textContent = (CATALOG.products.find((p) => p.id === productId) || {}).tag || "";
    $("order-name").textContent = order.name;
    $("order-variant").textContent = (CATALOG.products.find((p) => p.id === productId) || {}).variant || "";
    $("order-amount").textContent = fmtSats(order.amountSats);
    $("inv-amount").textContent = `${fmtSats(order.amountSats)}  (${toBtc(order.amountSats)} tBTC)`;
    $("inv-amount").dataset.copy = toBtc(order.amountSats);
    $("inv-address").textContent = order.address;
    $("inv-bip21").textContent = order.bip21;
    $("inv-txlink").hidden = true;

    setState("waiting", "Awaiting payment");
    renderQR(order.bip21);
    showView("checkout");
    watchOrder(order);
  }

  // ---- router ----
  function route() {
    const h = location.hash || "#/";
    const m = h.match(/^#\/p\/(.+)$/);
    if (m) { openCheckout(m[1]); return; }
    stopPolling();
    showView("catalog");
  }

  // ---- copy buttons ----
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest(".copy-btn");
    if (!btn) return;
    const src = $(btn.dataset.copy);
    if (!src) return;
    const text = src.dataset.copy || src.textContent;
    try {
      await navigator.clipboard.writeText(text.trim());
      const old = btn.textContent;
      btn.textContent = "copied ✓"; btn.classList.add("copied");
      setTimeout(() => { btn.textContent = old; btn.classList.remove("copied"); }, 1400);
    } catch (_) {}
  });

  window.addEventListener("hashchange", route);
  loadCatalog().then(route).catch((e) => {
    $("product-grid").innerHTML = '<p class="muted">Could not reach the shop server. Is it running?</p>';
  });
})();
