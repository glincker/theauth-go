/**
 * Verifies testdata/go-fixture.json (written by the Go package) with the
 * TypeScript SDK verifiers. Copy this file to sdk/packages/core/.tmp-ex/ and run:
 *   npx tsx .tmp-ex/verify-go-fixture.ts
 */
import { readFileSync } from "node:fs";
import { verifyConsistencyProof, verifyInclusionProof } from "../src/audit/checkpoint.js";
import { verifyReceipt } from "../src/audit/checkpoint-receipt.js";
import { verifyCheckpoint } from "../src/audit/checkpoint-sign.js";

// Fixed input path, relative to sdk/packages/core/.tmp-ex/ where this script is run from.
const fixtureUrl = new URL("../../../../go/audit/checkpoint/testdata/go-fixture.json", import.meta.url);
const fx = JSON.parse(readFileSync(fixtureUrl, "utf8"));
let failures = 0;
let checks = 0;
function expect(name: string, got: { valid: boolean; reason?: string }, want: string | null) {
	checks++;
	const ok = want === null ? got.valid : !got.valid && got.reason === want;
	if (!ok) {
		failures++;
		console.error(`FAIL ${name}: got ${JSON.stringify(got)} want ${want ?? "valid"}`);
	}
}
const keys = fx.publicKeys;
const c = fx.consistency;
const results: Array<[string, Promise<any>, string | null]> = [];
fx.inclusion.forEach((x: any, i: number) => results.push([`inclusion ${i}`, verifyInclusionProof(x.proof, x.checkpoint, keys), null]));
results.push(["consistency", verifyConsistencyProof(c.proof, c.older, c.newer, keys), null]);
for (const r of fx.receipts) results.push([`receipt ${r.name}`, verifyReceipt(r.receipt, keys), null]);
for (const n of fx.negative) {
	const p =
		n.kind === "checkpoint" ? verifyCheckpoint(n.checkpoint, n.keys)
		: n.kind === "inclusion" ? verifyInclusionProof(n.proof, n.checkpoint, n.keys)
		: n.kind === "consistency" ? verifyConsistencyProof(n.proof, n.older, n.newer, n.keys)
		: verifyReceipt(n.receipt, n.keys);
	results.push([`negative ${n.name}`, p, n.expectedReason]);
}
for (const [name, p, want] of results) expect(name, await p, want);
console.log(`${checks} checks run, ${failures} failures`);
process.exit(failures ? 1 : 0);
