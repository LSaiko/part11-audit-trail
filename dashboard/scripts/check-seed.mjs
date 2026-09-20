// Build-time parity proof: the TypeScript verifier must reproduce the digests Python produced
// for tests/seed_parity.json (pinned by tests/test_seed_parity.py), and the seed stream must
// verify intact while its tampered copy must break at entry #5 (index 4).
// Runs on Node >= 22.18 (native type stripping): `node scripts/check-seed.mjs`.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildSeed, signaturePayload, tamper, verifySeedSignature } from "../src/seed.ts";
import { entryHash, recordHash, verifyChain } from "../src/verify.ts";

const fixture = JSON.parse(readFileSync(new URL("../../tests/seed_parity.json", import.meta.url), "utf8"));
for (const { args, expected } of fixture.entry_hash) assert.equal(await entryHash(...args), expected, `entry_hash ${JSON.stringify(args)}`);
for (const { content, expected } of fixture.record_hash) assert.equal(await recordHash(content), expected, `record_hash ${JSON.stringify(content)}`);

const seed = await buildSeed();
const intact = await verifyChain(seed.events);
assert.deepEqual([intact.chain_valid, intact.first_broken_link, intact.total_events_checked], [true, null, 12]);
const sig = seed.signatures[0];
assert.ok(signaturePayload(sig).startsWith('{"id":"'));
const ok = await verifySeedSignature(seed, sig);
assert.deepEqual([ok.record_hash_matches, ok.signature_valid], [true, true]);

const bad = tamper(seed);
const broken = await verifyChain(bad.events);
assert.deepEqual([broken.chain_valid, broken.first_broken_link], [false, 4]);
const changed = await verifySeedSignature(bad, sig);
assert.deepEqual([changed.record_hash_matches, changed.signature_valid], [false, true]);
assert.equal(await verifyChain([...seed.events.slice(0, 3), ...seed.events.slice(4)]).then((r) => r.first_broken_link), 3);

console.log(`seed parity OK: ${fixture.entry_hash.length + fixture.record_hash.length} digests match Python; seed chain intact (12 events), tampered copy breaks at #5`);
