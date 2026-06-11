// The shop catalog — shared by the server (amounts + pool assignment) and surfaced
// to the browser via GET /api/catalog. `sats` is the on-chain price (testnet4). Tune
// these around your device per-tx limit so some clear automatically and some need a tap.
export const merchantName = 'Satoshi Supply Co.';

export const products = [
  { id: 'beans',    name: 'Single-Origin Beans',  variant: '250g whole bean',      sats: 2500,  art: '☕', tag: 'Everyday', blurb: 'Washed Huila, roasted last week. The desk-default.' },
  { id: 'coldbrew', name: 'Cold Brew Concentrate', variant: '1L bottle',            sats: 4000,  art: '🫙', tag: 'Everyday', blurb: '18-hour steep. Cut it 1:1 and thank yourself.' },
  { id: 'pourover', name: 'Ceramic Pour-Over Kit', variant: 'Dripper + 02 filters', sats: 12000, art: '⚗️', tag: 'Gear',     blurb: 'Hand-glazed dripper, slow bloom, no plastic.' },
  { id: 'hoodie',   name: 'The Sovereign Hoodie',  variant: 'Heavyweight, unisex',  sats: 25000, art: '🧥', tag: 'Apparel',  blurb: '500gsm loopback cotton. Runs warm, ages well.' },
  { id: 'case',     name: "Founders' Carry Case",  variant: 'Hard shell, foam-cut', sats: 40000, art: '🧳', tag: 'Gear',     blurb: 'Machined latch, custom foam. Travel-proof.' },
];

export const explorerApi = 'https://mempool.space/testnet4/api';
export const explorerTx = 'https://mempool.space/testnet4/tx';
