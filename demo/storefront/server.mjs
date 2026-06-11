// Satoshi Supply Co. — demo storefront server.
//
// Makes the shop the single source of truth for each order's on-chain invoice, so
// an AI agent can FETCH the invoice (GET /api/checkout/:product) and pay it without
// anyone pasting an address. The browser displays the same order; the server polls
// mempool.space testnet4 and flips it to paid. Real testnet4 merchant addresses come
// from merchant.json (see gen-merchant.mjs).
//
// Run:  node server.mjs           (serves http://127.0.0.1:3015)
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { products, merchantName, explorerApi, explorerTx } from './catalog.mjs';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const PORT = Number(process.env.PORT) || 3015;
const HOST = '127.0.0.1';
const STATE_FILE = join(__dirname, '.server-state.json');

if (!existsSync(join(__dirname, 'merchant.json'))) {
  console.error('merchant.json missing — run `node gen-merchant.mjs` first.');
  process.exit(1);
}
const merchant = JSON.parse(readFileSync(join(__dirname, 'merchant.json'), 'utf8'));
const POOL = merchant.addresses.map((a) => a.address);
const byId = new Map(products.map((p) => [p.id, p]));

// ---- order state (persisted so a server restart mid-demo doesn't re-issue a paid address) ----
let cursor = 0; // next pool index
const orders = new Map(); // id -> order
const activeByProduct = new Map(); // productId -> order id (current unpaid order)
let nextId = 1;

function persist() {
  const snap = { cursor, nextId, orders: [...orders.values()], active: [...activeByProduct] };
  writeFile(STATE_FILE, JSON.stringify(snap)).catch(() => {});
}
function restore() {
  if (!existsSync(STATE_FILE)) return;
  try {
    const s = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
    cursor = s.cursor || 0;
    nextId = s.nextId || 1;
    for (const o of s.orders || []) orders.set(o.id, o);
    for (const [p, id] of s.active || []) activeByProduct.set(p, id);
  } catch (_) {}
}
restore();

const toBtc = (sats) => (sats / 1e8).toFixed(8);
function bip21(address, sats, label) {
  const p = new URLSearchParams({ amount: toBtc(sats) });
  if (label) p.set('label', label);
  return `bitcoin:${address}?${p.toString()}`;
}

// Return the active unpaid order for a product, creating one (next pool address) if none.
function checkout(productId) {
  const product = byId.get(productId);
  if (!product) return null;
  const activeId = activeByProduct.get(productId);
  if (activeId && orders.has(activeId) && orders.get(activeId).status !== 'paid') {
    return orders.get(activeId);
  }
  const address = POOL[cursor % POOL.length];
  cursor += 1;
  const order = {
    id: `SSC-${String(nextId).padStart(4, '0')}`,
    productId,
    name: product.name,
    amountSats: product.sats,
    address,
    bip21: bip21(address, product.sats, `${merchantName} - ${product.name}`),
    status: 'awaiting',
    txid: null,
    createdAt: Date.now(),
  };
  nextId += 1;
  orders.set(order.id, order);
  activeByProduct.set(productId, order.id);
  persist();
  return order;
}

// ---- background: watch awaiting orders on testnet4, flip to paid ----
async function pollPayments() {
  const awaiting = [...orders.values()].filter((o) => o.status === 'awaiting');
  for (const o of awaiting) {
    try {
      const r = await fetch(`${explorerApi}/address/${o.address}`);
      if (!r.ok) continue;
      const info = await r.json();
      const seen = (info.mempool_stats?.funded_txo_sum || 0) + (info.chain_stats?.funded_txo_sum || 0);
      const anyTx = (info.mempool_stats?.tx_count || 0) + (info.chain_stats?.tx_count || 0) > 0;
      if (seen >= o.amountSats || anyTx) {
        o.status = 'paid';
        // best-effort txid for the explorer link
        try {
          const tr = await fetch(`${explorerApi}/address/${o.address}/txs`);
          const txs = tr.ok ? await tr.json() : [];
          if (Array.isArray(txs) && txs.length) o.txid = txs[0].txid;
        } catch (_) {}
        if (activeByProduct.get(o.productId) === o.id) activeByProduct.delete(o.productId); // rotate next time
        persist();
        console.log(`✓ paid: ${o.id} ${o.name} (${o.amountSats} sats) ${o.txid || ''}`);
      }
    } catch (_) {}
  }
}
setInterval(pollPayments, 3000);

// ---- http ----
const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'access-control-allow-origin': '*' });
  res.end(body);
}
async function serveStatic(req, res) {
  let path = decodeURIComponent(new URL(req.url, `http://${HOST}`).pathname);
  if (path === '/') path = '/index.html';
  const full = normalize(join(__dirname, path));
  if (!full.startsWith(__dirname)) { res.writeHead(403); return res.end('forbidden'); }
  try {
    const data = await readFile(full);
    res.writeHead(200, { 'content-type': MIME[extname(full)] || 'application/octet-stream', 'cache-control': 'no-store' });
    res.end(data);
  } catch (_) {
    res.writeHead(404); res.end('not found');
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}`);
  const path = url.pathname;

  if (path === '/api/catalog') {
    return sendJson(res, 200, { merchant: merchantName, network: 'testnet4', explorerTx, products });
  }
  // Get (or create) the active invoice for a product — the agent + the browser both
  // call this and get the SAME order, so they agree on the address with no paste.
  const m = path.match(/^\/api\/checkout\/([a-z0-9_-]+)$/i);
  if (m) {
    const order = checkout(m[1]);
    if (!order) return sendJson(res, 404, { error: `unknown product: ${m[1]}` });
    return sendJson(res, 200, { ...order, explorerTx });
  }
  // Agent-facing invoice fetch — same order as /checkout, but flags that the agent
  // has engaged, so the open checkout page can show "Agent is paying…" before the
  // on-chain payment lands. This is the endpoint the demo agent calls.
  const ma = path.match(/^\/api\/agent\/invoice\/([a-z0-9_-]+)$/i);
  if (ma) {
    const order = checkout(ma[1]);
    if (!order) return sendJson(res, 404, { error: `unknown product: ${ma[1]}` });
    order.agentAccessed = Date.now();
    persist();
    console.log(`→ agent fetched invoice: ${order.id} ${order.name} (${order.amountSats} sats)`);
    return sendJson(res, 200, { ...order, explorerTx });
  }
  if (path === '/api/orders') {
    return sendJson(res, 200, { orders: [...orders.values()], explorerTx });
  }
  const mo = path.match(/^\/api\/order\/(SSC-\d+)$/);
  if (mo) {
    const o = orders.get(mo[1]);
    return o ? sendJson(res, 200, { ...o, explorerTx }) : sendJson(res, 404, { error: 'no such order' });
  }
  return serveStatic(req, res);
});

server.listen(PORT, HOST, () => {
  console.log(`Satoshi Supply Co. on http://${HOST}:${PORT}  (${products.length} products, ${POOL.length}-address pool)`);
  console.log(`Agent: GET http://${HOST}:${PORT}/api/checkout/<product>  e.g. /api/checkout/beans`);
});
