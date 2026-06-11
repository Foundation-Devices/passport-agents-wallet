// Generate a fresh testnet (tb1) BIP84 merchant key + a handful of receive
// addresses for the demo storefront. testnet4 shares testnet3's address format,
// so these tb1q... addresses are valid testnet4 payment destinations.
//
// Output: merchant.json  { mnemonic, fingerprint, xpub, addresses[] }
// The mnemonic is saved so the merchant wallet is real + reproducible (you could
// sweep the demo coins later). Run once: `node gen-merchant.mjs`.
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';
import { writeFileSync, existsSync } from 'node:fs';

if (existsSync('./merchant.json')) {
  console.error('merchant.json already exists — refusing to overwrite. Delete it first to regenerate.');
  process.exit(1);
}

const mnemonic = generateMnemonic(wordlist, 128); // 12 words is plenty for a throwaway merchant
const seed = mnemonicToSeedSync(mnemonic);
const root = HDKey.fromMasterSeed(seed);
const fingerprint = Buffer.from(new DataView(new ArrayBuffer(4)).buffer);
new DataView(fingerprint.buffer).setUint32(0, root.fingerprint, false);

const net = btc.TEST_NETWORK; // testnet (tb1)
const account = root.derive("m/84'/1'/0'");

const addresses = [];
for (let i = 0; i < 50; i++) {
  const child = account.deriveChild(0).deriveChild(i); // m/84'/1'/0'/0/i
  const p2wpkh = btc.p2wpkh(child.publicKey, net);
  addresses.push({ index: i, path: `m/84'/1'/0'/0/${i}`, address: p2wpkh.address });
}

const out = {
  network: 'testnet4',
  mnemonic,
  fingerprint: fingerprint.toString('hex'),
  xpub: account.publicExtendedKey,
  addresses,
};
writeFileSync('./merchant.json', JSON.stringify(out, null, 2));
console.log('Wrote merchant.json');
console.log('Fingerprint:', out.fingerprint);
for (const a of addresses) console.log(`  ${a.path}  ${a.address}`);
