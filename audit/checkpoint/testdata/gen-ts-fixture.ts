import { writeFileSync } from "node:fs";
import { createCheckpoint, createConsistencyProof, createInclusionProof, verifyConsistencyProof, verifyInclusionProof } from "../src/audit/checkpoint.js";
import { createReceipt, verifyReceipt } from "../src/audit/checkpoint-receipt.js";
import { fieldValuesOf } from "../src/audit/checkpoint-leaves.js";
import { computeRowHash } from "../src/audit/chain.js";
import { generateCheckpointKeyPair, verifyCheckpoint } from "../src/audit/checkpoint-sign.js";
import { enableAuditChain, insertAuditRow } from "../src/audit/index.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";
import { asc } from "drizzle-orm";

const HMAC = "interop-fixture-hmac-key";
const T0 = new Date("2026-10-01T00:00:00Z");
// Fixed output path, relative to sdk/packages/core/.tmp-ex/ where this script is run from.
const out = new URL("../../../../go/audit/checkpoint/testdata/ts-fixture.json", import.meta.url);

const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
await createTables(db, "sqlite");
await db.insert(users).values({ id: "u1", email: "u1@example.com", name: "U1", username: "u1", createdAt: T0, updatedAt: T0 });
for (const id of ["a1", "a2", "a3"]) {
	await db.insert(agents).values({ id, ownerId: "u1", name: id, type: "autonomous", status: "active", tokenHash: `h-${id}`, tokenPrefix: "kv_x", metadata: {}, createdAt: T0, updatedAt: T0 });
}
enableAuditChain(db, { hmacKey: HMAC });

const weird = {
	n: 1.5, big: 1e21, small: 1e-7, neg: -0.25, int: 42, t: true, nul: null,
	s: "héllo   \"q\" \n\t <>& \u0001 \u007f 😀",
	nested: { b: 1, a: [1, null, true, { z: 1, y: "x" }] },
	"😀": "astral", "～": "bmp-high", "é": "latin",
};
async function add(id: string, agentId: string, sec: number, parameters: unknown) {
	await insertAuditRow(db, {
		id, agentId, userId: "u1", action: "execute", resource: `mcp:github:${id}`,
		parameters: parameters as never, result: sec % 3 === 0 ? "denied" : "allowed", reason: sec % 3 === 0 ? "policy" : null,
		durationMs: 5 + sec, timestamp: new Date(T0.getTime() + sec * 1000), approverId: "u1", ip: sec % 2 ? "10.0.0.1" : null,
	});
}
for (let i = 1; i <= 5; i++) await add(`r${i}`, i % 2 ? "a1" : "a2", i, i === 2 ? weird : { secret: `param-of-r${i}` });
// A version 1 row (raw ids hashed) on its own agent chain.
{
	const base = { id: "v1row", agentId: "a3", userId: "u1", action: "execute", resource: "mcp:legacy", parameters: { legacy: true }, result: "allowed", reason: null, durationMs: 3, timestamp: new Date(T0.getTime() + 6000), hashVersion: 1, approverId: null, ip: null } as never;
	const hash = await computeRowHash(base, 1, null, HMAC);
	await db.insert(auditLogs).values({ ...(base as object), chainSeq: 1, prevHash: null, hash } as never);
}
const k1 = await generateCheckpointKeyPair("k1");
const k2 = await generateCheckpointKeyPair("k2");
const now1 = new Date("2026-10-02T00:00:00Z");
const now2 = new Date("2026-10-03T00:00:00Z");
const cp1 = await createCheckpoint(db, { signer: k1.signer, now: now1, hmacKey: HMAC });
if (!cp1.success) throw new Error(cp1.error.message);
for (let i = 7; i <= 12; i++) await add(`r${i}`, i % 2 ? "a1" : "a2", i, { i });
const cp2 = await createCheckpoint(db, { signer: k2.signer, now: now2, hmacKey: HMAC });
if (!cp2.success) throw new Error(cp2.error.message);

const rowsRaw = await db.select().from(auditLogs).orderBy(asc(auditLogs.timestamp), asc(auditLogs.id));
const rows = rowsRaw.map((r) => ({ id: r.id, hash: r.hash, hashVersion: r.hashVersion ?? 1, timestampMs: r.timestamp.getTime(), fields: fieldValuesOf(r) }));

const pubs = [k1.publicKey, k2.publicKey];
const inclusion: unknown[] = [];
const cp2Rows = rows.slice(0, cp2.data.size);
for (const r of cp2Rows) {
	const p = await createInclusionProof(db, r.id, cp2.data, { hmacKey: HMAC });
	if (!p.success) throw new Error(p.error.message);
	inclusion.push({ proof: p.data, checkpoint: cp2.data, expected: await verifyInclusionProof(p.data, cp2.data, pubs) });
}
const cons = await createConsistencyProof(db, cp1.data, cp2.data, { hmacKey: HMAC });
if (!cons.success) throw new Error(cons.error.message);
const receipts: unknown[] = [];
async function rc(name: string, rowId: string, cp: typeof cp2.data, reveal: string[]) {
	const r = await createReceipt(db, rowId, cp, { reveal, hmacKey: HMAC });
	if (!r.success) throw new Error(r.error.message);
	receipts.push({ name, receipt: r.data, expected: await verifyReceipt(r.data, pubs) });
}
await rc("v2 weird params revealed", "r2", cp2.data, ["action", "parameters", "result", "timestamp", "durationMs", "ip"]);
await rc("v2 nothing revealed", "r3", cp2.data, []);
await rc("v2 everything revealed", "r4", cp2.data, ["id","action","resource","parameters","result","reason","durationMs","tokensCost","ip","userAgent","cacheHit","timestamp","policyVersion","delegationChain","inputProvenance","idPseudonyms"]);
await rc("v1 row", "v1row", cp2.data, ["id", "action", "agentId", "userId"]);
await rc("v2 older checkpoint", "r1", cp1.data, ["action", "resource"]);

const first = receipts[0] as { receipt: { checkpoint: unknown; decision: { revealed: Record<string, { value: unknown }> } } };
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
const neg: unknown[] = [];
async function negCp(name: string, mut: (c: any) => void, keys = pubs) {
	const c = clone(cp2.data); mut(c); neg.push({ name, kind: "checkpoint", checkpoint: c, keys, expected: await verifyCheckpoint(c, keys) });
}
await negCp("root tampered", (c) => { c.rootHash = "0".repeat(64); });
await negCp("size tampered", (c) => { c.size += 1; });
await negCp("alg none", (c) => { c.alg = "none"; });
await negCp("alg HS256", (c) => { c.alg = "HS256"; });
await negCp("unknown keyId", (c) => { c.keyId = "k9"; });
await negCp("keyId swapped to k1", (c) => { c.keyId = "k1"; });
await negCp("wrong key set", () => {}, [k1.publicKey]);
await negCp("signature truncated", (c) => { c.signature = c.signature.slice(0, 10); });
await negCp("since tampered", (c) => { c.since = 5; });
await negCp("uppercase root", (c) => { c.rootHash = c.rootHash.toUpperCase(); });
const ip0 = clone((inclusion[3] as { proof: any }).proof);
const negProof = async (name: string, mut: (p: any) => void) => {
	const p = clone(ip0); mut(p); neg.push({ name, kind: "inclusion", proof: p, checkpoint: cp2.data, keys: pubs, expected: await verifyInclusionProof(p, cp2.data, pubs) });
};
await negProof("path flipped", (p) => { p.path[0] = p.path[0].replace(/^./, (c: string) => (c === "0" ? "1" : "0")); });
await negProof("index wrong", (p) => { p.leafIndex += 1; });
await negProof("treeSize wrong", (p) => { p.treeSize += 1; });
await negProof("path truncated", (p) => { p.path.pop(); });
await negProof("path extended", (p) => { p.path.push(p.path[0]); });
await negProof("leafHash tampered", (p) => { p.leafHash = "1".repeat(64); });
{
	const c = clone(cons.data); c.path[0] = "2".repeat(64);
	neg.push({ name: "consistency path tampered", kind: "consistency", proof: c, older: cp1.data, newer: cp2.data, keys: pubs, expected: await verifyConsistencyProof(c, cp1.data, cp2.data, pubs) });
	neg.push({ name: "consistency swapped order", kind: "consistency", proof: cons.data, older: cp2.data, newer: cp1.data, keys: pubs, expected: await verifyConsistencyProof(cons.data, cp2.data, cp1.data, pubs) });
}
const negReceipt = async (name: string, mut: (r: any) => void) => {
	const r = clone((receipts[0] as { receipt: unknown }).receipt) as any; mut(r); neg.push({ name, kind: "receipt", receipt: r, keys: pubs, expected: await verifyReceipt(r, pubs) });
};
await negReceipt("revealed value changed", (r) => { r.decision.revealed.result.value = "allowed-x"; });
await negReceipt("revealed salt changed", (r) => { r.decision.revealed.result.salt = "3".repeat(64); });
await negReceipt("row hash changed", (r) => { r.decision.rowHash = "4".repeat(64); });
await negReceipt("commitment changed", (r) => { const k = Object.keys(r.decision.commitments)[0] as string; r.decision.commitments[k] = "5".repeat(64); });
await negReceipt("hashVersion changed", (r) => { r.decision.hashVersion = 1; });
await negReceipt("rowId mismatch", (r) => { r.proof.rowId = "other"; });
await negReceipt("field moved to extra name", (r) => { r.decision.commitments.bogus = "6".repeat(64); });
await negReceipt("checkpoint swapped to older", (r) => { r.checkpoint = clone(cp1.data); });
void first;

const jwk = (k: any) => ({ d: k.privateKeyJwk.d, x: k.privateKeyJwk.x });
writeFileSync(out, JSON.stringify({
	note: "Generated by the TypeScript SDK (packages/core). Regenerate with scripts in testdata/README.md.",
	hmacKey: HMAC, now1: now1.getTime(), now2: now2.getTime(),
	publicKeys: pubs, privateKeys: { k1: jwk(k1), k2: jwk(k2) },
	rows, checkpoints: { cp1: cp1.data, cp2: cp2.data },
	inclusion, consistency: { proof: cons.data, older: cp1.data, newer: cp2.data, expected: await verifyConsistencyProof(cons.data, cp1.data, cp2.data, pubs) },
	receipts, negative: neg,
}, null, 1));
console.log("rows", rows.length, "cp1", cp1.data.size, "cp2", cp2.data.size, "neg", neg.length);
