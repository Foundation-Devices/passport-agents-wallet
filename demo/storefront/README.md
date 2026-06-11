# Satoshi Supply Co. — demo storefront

A small, pretty fake shop that takes **real on-chain testnet4 Bitcoin**. It exists
for one video: an **AI agent** is told (in plain language) to buy something here, and a
**Passport Prime** co-signs the payment — small orders clear unattended, larger ones
wait for a tap on the device.

The shop is the **single source of truth** for each order's invoice. The browser shows
it, and the **agent fetches the same invoice over a URL and pays it** — nobody pastes an
address. The server then watches the testnet4 mempool and flips the order to **paid**.

## Architecture

```
catalog.mjs   the products (names, sats prices, art) — shared
merchant.json generated: a throwaway testnet4 key + 50 real tb1q… addresses (gitignored)
server.mjs    Node server: static files + JSON API + mempool polling (the brains)
index.html    the page;  assets/app.js (API-driven UI),  assets/styles.css,  assets/qrcode.js
```

**API** (what the agent uses):

| Endpoint | What |
|---|---|
| `GET /api/catalog` | products (browser renders the grid from this) |
| `GET /api/checkout/:product` | the active unpaid order for a product — **creates one (next pool address) if none**, returns the SAME order on repeat calls. Both the browser and the agent call this, so they agree on the address. |
| `GET /api/orders` / `GET /api/order/:id` | order status (the browser polls this; the server marks `paid` when it sees the payment) |

When an order is paid, its product's slot is freed so the **next** checkout rotates to a
fresh address — rehearsals don't poison the next take.

## Run

```bash
node gen-merchant.mjs      # first time only: writes merchant.json (rm it to re-roll the key)
node server.mjs            # → http://127.0.0.1:3015
```

(`node` only — no build step, no npm install needed at runtime. `gen-merchant.mjs` uses
the dev deps in `package.json`.)

## The agentic flow (the real part)

You just talk to the agent; it gets the payment info itself:

1. You (or the agent) open a product. The shop issues an order with a real testnet4
   address + amount and shows the BIP21 + QR.
2. You say: **"go buy the beans and pay it."**
3. The agent calls `GET /api/checkout/beans`, reads `{address, amountSats, bip21}`, then:
   - `nunchuk tx create --wallet <W> --to <address> --amount <sats> --currency sat`
   - `nunchuk tx sign … --fingerprint <AGENT_FP>` (agent key)
   - `prime-usb sign --psbt <psbt>` → in-policy auto-signs; over-policy exits 10 (tap on Prime)
   - `nunchuk tx sign … --psbt <signed>` then `nunchuk tx broadcast …`
4. The server sees the payment land on the address and flips the order to **Paid**.

Full signer runbook: `../../host/skills/prime-hsm/SKILL.md`.

## Tune the demo

Edit `sats` (and names/art) in `catalog.mjs`, restart `node server.mjs`. Pick a device
per-tx limit and straddle it — some products under (auto-sign, no tap), some over (Prime
tap). Keep amounts small so live testnet4 funding is one faucet hit per wallet.

| Product | sats | vs a 10,000-sat limit |
|---|---|---|
| Single-Origin Beans | 2,500 | under → **auto-signs**, no tap |
| Cold Brew Concentrate | 4,000 | under → auto-signs |
| Ceramic Pour-Over Kit | 12,000 | over → **Prime tap** |
| The Sovereign Hoodie | 25,000 | over → Prime tap |
| Founders' Carry Case | 40,000 | over → Prime tap |

## Notes

- **testnet4 only.** Nothing here has real value; the merchant key is disposable.
- Order state persists to `.server-state.json` (gitignored) so a server restart mid-demo
  doesn't re-issue a paid address. Delete it for a clean slate.
- Payment detection polls `https://mempool.space/testnet4/api` every 3s, server-side
  (so the browser needs no cross-origin calls).
