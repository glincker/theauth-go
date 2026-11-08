import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createPublicKey } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

// Run from the Go repo root with the TypeScript repo next to it: THEAUTH_CORE=../sdk/packages/core tsx iot/attest/testdata/gen-vectors.mts iot/attest/testdata/vectors.json
const CORE = resolve(process.env.THEAUTH_CORE ?? "../sdk/packages/core");
const req = createRequire(`${CORE}/package.json`);
const { calculateJwkThumbprint } = await import(pathToFileURL(req.resolve("jose")).href);
const A = `${CORE}/src/device/attestation`;
const att = await import(`${A}/index.ts`);
const { parseCertificate } = await import(`${A}/x509.ts`);
const { keyThumbprint } = await import(`${A}/key-thumbprint.ts`);
const { decodeCborExact } = await import(`${A}/cbor.ts`);
const { fromBase64Url, toBase64Url } = await import(`${CORE}/src/crypto/web-crypto.ts`);

const fx = (n: string) => JSON.parse(readFileSync(`${CORE}/tests/fixtures/${n}.json`, "utf8"));
const droid = fx("android-key-attestation");
const apple = fx("apple-app-attest");
const tpm = fx("tpm2-quote-gce");

// biome-ignore lint/suspicious/noExplicitAny: generator script
type Any = any;
const vectors: Any[] = [];

async function run(verifier: string, name: string, make: () => Any, opts: Any, input: Any, extra: Any = {}) {
	// opts: TS options (with functions); wire: JSON options for Go
	let result: Any;
	let throws: string | undefined;
	let seen: string[] | undefined;
	try {
		const { options, wire } = opts;
		const v = make()(options.ts);
		seen = options.seen;
		result = await v(input);
		vectors.push({ verifier, name, options: wire, input: strip(input, extra), ...extra, expect: normalize(result), ...(seen && { seenSerials: seen }) });
	} catch (e) {
		throws = e instanceof Error ? e.message : String(e);
		vectors.push({ verifier, name, options: opts.wire, input: strip(input, extra), ...extra, throws });
	}
}
// Evidence that comes from a fixture is referenced, not copied, to keep the file small.
function strip(input: Any, extra: Any) {
	if (!extra.evidenceRef) return input;
	const { evidence: _e, ...rest } = input;
	return rest;
}
function normalize(r: Any) {
	return JSON.parse(JSON.stringify(r));
}

const NOW = "2026-10-18T00:00:00Z";
const chainOf = (n: string): string[] => [...droid.chains[n]];
const CHAINS = Object.keys(droid.chains);

// Section: Android
type AOpts = { ts: Any; seen?: string[] };
function aopts(wire: Any, tsExtra: Any = {}, rootsRef?: string, nowIso = NOW): { options: AOpts; wire: Any } {
	const roots = rootsRef?.startsWith("chain3:") ? [chainOf(rootsRef.slice(7))[3]] : undefined;
	const ts = { revocation: "disabled", bootPolicy: "any", bindKey: false, now: () => new Date(nowIso), ...(roots && { roots }), ...tsExtra };
	return { options: { ts }, wire: { revocation: "disabled", bootPolicy: "any", bindKey: false, now: nowIso, ...(rootsRef && { rootsRef }), ...wire } };
}
const mkA = () => att.createAndroidKeyAttestationVerifier;
const ev = (name: string, drop: number[] = [], order?: number[]) => {
	const c = chainOf(name);
	const list = order ? order.map((i) => c[i]) : c.filter((_, i) => !drop.includes(i));
	return JSON.stringify(list);
};
const aref = (name: string, drop: number[] = [], order?: number[]) => ({ chain: name, drop, ...(order && { order }) });
const ain = (e: string, nonce: string | null = "abc", extra: Any = {}) => ({ evidence: e, ...(nonce !== null && { nonce }), enrollmentId: "e1", ...extra });

async function android() {
	for (const n of CHAINS) {
		await run("android", `default roots ${n}`, mkA, aopts({}), ain(ev(n)), { evidenceRef: aref(n) });
		await run("android", `pinned own root ${n}`, mkA, aopts({}, {}, `chain3:${n}`), ain(ev(n)), { evidenceRef: aref(n) });
	}
	const ECSB = "algorithm_EC_SecurityLevel_StrongBox";
	const RSASB = "algorithm_RSA_SecurityLevel_StrongBox";
	const TEE0 = "algorithm_EC_SecurityLevel_TEE";
	const TEE1 = "algorithm_RSA_SecurityLevel_TEE";
	await run("android", "broken EC strongbox without cert1", mkA, aopts({}, {}, `chain3:${ECSB}`), ain(ev(ECSB, [1])), { evidenceRef: aref(ECSB, [1]) });
	await run("android", "strict boot policy", mkA, aopts({ bootPolicy: "verified" }, { bootPolicy: "verified" }), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	await run("android", "boot verified_or_self_signed", mkA, aopts({ bootPolicy: "verified_or_self_signed" }, { bootPolicy: "verified_or_self_signed" }), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	await run("android", "wrong nonce", mkA, aopts({}), ain(ev(TEE0), "abd"), { evidenceRef: aref(TEE0) });
	await run("android", "hex nonce", mkA, aopts({ challengeEncoding: "hex" }, { challengeEncoding: "hex" }), ain(ev(TEE0), "616263"), { evidenceRef: aref(TEE0) });
	await run("android", "bad hex nonce", mkA, aopts({ challengeEncoding: "hex" }, { challengeEncoding: "hex" }), ain(ev(TEE0), "61626"), { evidenceRef: aref(TEE0) });
	await run("android", "base64url nonce", mkA, aopts({ challengeEncoding: "base64url" }, { challengeEncoding: "base64url" }), ain(ev(TEE0), "YWJj"), { evidenceRef: aref(TEE0) });
	await run("android", "no nonce", mkA, aopts({}), ain(ev(TEE0), null), { evidenceRef: aref(TEE0) });
	await run("android", "min level strongbox on strongbox", mkA, aopts({ minSecurityLevel: "strongbox" }, { minSecurityLevel: "strongbox" }, `chain3:${RSASB}`), ain(ev(RSASB)), { evidenceRef: aref(RSASB) });
	await run("android", "min level strongbox on tee", mkA, aopts({ minSecurityLevel: "strongbox" }, { minSecurityLevel: "strongbox" }), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	// tampering
	const c = chainOf(TEE0);
	const leaf = Buffer.from(c[0] as string, "base64");
	leaf[leaf.length - 3] = (leaf[leaf.length - 3] ?? 0) ^ 0xff;
	await run("android", "tampered leaf signature", mkA, aopts({}), ain(JSON.stringify([leaf.toString("base64"), ...c.slice(1)])));
	const body = Buffer.from(c[0] as string, "base64");
	body[80] = (body[80] ?? 0) ^ 0x01;
	await run("android", "tampered leaf tbs", mkA, aopts({}), ain(JSON.stringify([body.toString("base64"), ...c.slice(1)])));
	await run("android", "missing intermediate", mkA, aopts({}), ain(ev(TEE0, [1])), { evidenceRef: aref(TEE0, [1]) });
	await run("android", "reordered chain", mkA, aopts({}), ain(ev(TEE0, [], [0, 2, 1, 3])), { evidenceRef: aref(TEE0, [], [0, 2, 1, 3]) });
	await run("android", "leafless chain", mkA, aopts({}), ain(ev(TEE0, [0])), { evidenceRef: aref(TEE0, [0]) });
	await run("android", "object form", mkA, aopts({}), ain(JSON.stringify({ chain: chainOf(TEE0) })));
	// revocation
	const serials = chainOf(TEE0).map((x) => parseCertificate(Buffer.from(x, "base64")).serialHex);
	{
		const seen: string[] = [];
		const ts = { revocation: (s: string) => { seen.push(s); return false; } };
		await run("android", "revocation none revoked", mkA, { options: { ts: { ...aopts({}).options.ts, ...ts }, seen }, wire: { ...aopts({}).wire, revocation: { revoked: [] } } }, ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	}
	await run("android", "revocation second revoked", mkA, { options: { ts: { ...aopts({}).options.ts, revocation: async (s: string) => s === serials[1] } }, wire: { ...aopts({}).wire, revocation: { revoked: [serials[1]] } } }, ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	// validity
	await run("android", "validity 2029 strongbox", mkA, aopts({}, {}, `chain3:${RSASB}`, "2029-01-01T00:00:00Z"), ain(ev(RSASB)), { evidenceRef: aref(RSASB) });
	await run("android", "validity 2046 tee factory", mkA, aopts({}, {}, undefined, "2046-01-01T00:00:00Z"), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	await run("android", "validity 2046 tee rsa", mkA, aopts({}, {}, undefined, "2046-01-01T00:00:00Z"), ain(ev(TEE1)), { evidenceRef: aref(TEE1) });
	await run("android", "validity 1999", mkA, aopts({}, {}, undefined, "1999-01-01T00:00:00Z"), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	// binding
	for (const n of [TEE0, TEE1]) {
		const l = parseCertificate(Buffer.from(chainOf(n)[0] as string, "base64"));
		let thumb = "";
		try {
			const jwk = createPublicKey({ key: Buffer.from(l.spki), format: "der", type: "spki" }).export({ format: "jwk" });
			thumb = await calculateJwkThumbprint(jwk, "sha256");
		} catch {}
		const direct = await keyThumbprint(l.spki);
		const b = aopts({ bindKey: true }, { bindKey: true });
		await run("android", `bind good ${n}`, mkA, b, ain(ev(n), "abc", { credentialKind: "jwk", credentialKeyThumbprint: thumb }), { evidenceRef: aref(n), thumbprintOf: "leaf" });
		if (direct) vectors[vectors.length - 1].note = `thumb jose=${thumb === direct}`;
		await run("android", `bind other ${n}`, mkA, b, ain(ev(n), "abc", { credentialKind: "jwk", credentialKeyThumbprint: "other" }), { evidenceRef: aref(n) });
		await run("android", `bind psk ${n}`, mkA, b, ain(ev(n), "abc", { credentialKind: "psk" }), { evidenceRef: aref(n) });
		await run("android", `bind missing ${n}`, mkA, b, ain(ev(n)), { evidenceRef: aref(n) });
	}
	await run("android", "packages denied", mkA, aopts({ allowedPackages: ["com.example"] }, { allowedPackages: ["com.example"] }), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	await run("android", "packages allowed", mkA, aopts({ allowedPackages: ["android"] }, { allowedPackages: ["android"] }), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	await run("android", "packages empty list", mkA, aopts({ allowedPackages: [] }, { allowedPackages: [] }), ain(ev(TEE0)), { evidenceRef: aref(TEE0) });
	for (const bad of ["not json", "[]", '["!!!"]', "{}", JSON.stringify([1]), JSON.stringify(new Array(9).fill("AA==")), "null", '{"chain":"x"}', JSON.stringify(["AA=="]), JSON.stringify(["AAAA"])]) {
		await run("android", `malformed ${bad.slice(0, 20)}`, mkA, aopts({}), ain(bad));
	}
	// revocation required at construction
	vectors.push({ verifier: "android", name: "revocation choice is required", options: { constructWithoutRevocation: true }, input: {}, throws: "construct" });
}

// Section: Apple
const APPLE = Object.keys(apple.fixtures);
const afx = (n: string) => apple.fixtures[n];
const aev = (n: string) => JSON.stringify({ attestation: afx(n).attestation, keyId: afx(n).keyId });
function popts(n: string, wireExtra: Any = {}, tsExtra: Any = {}, nowIso?: string) {
	const now = nowIso ?? afx(n).checkTime;
	const wire = { appIds: [afx(n).appId], environment: afx(n).environment, clientDataHash: afx(n).clientDataHash, bind: "none", now, ...wireExtra };
	const ts = { appIds: wire.appIds, environment: wire.environment, clientDataHash: wire.clientDataHash, bind: wire.bind, now: () => new Date(wire.now), ...tsExtra };
	// wireExtra keys override TS options too (same names) except roots handled by rootsRef
	for (const [k, v] of Object.entries(wireExtra)) if (k !== "rootsRef" && k !== "now") (ts as Any)[k] = v;
	return { options: { ts }, wire };
}
const mkP = () => att.createAppleAppAttestVerifier;
const pin = (n: string, extra: Any = {}) => ({ evidence: aev(n), nonce: afx(n).nonce, enrollmentId: "e1", ...extra });
function leafOf(n: string) {
	const obj = decodeCborExact(fromBase64Url(afx(n).attestation)) as Map<string, unknown>;
	const stmt = obj.get("attStmt") as Map<string, unknown>;
	return parseCertificate((stmt.get("x5c") as Uint8Array[])[0] as Uint8Array);
}
function idx(bytes: Uint8Array, text: string) {
	const m = new TextEncoder().encode(text);
	for (let i = 0; i < bytes.length - m.length; i++) if (m.every((b, j) => bytes[i + j] === b)) return i;
	throw new Error("nf");
}
async function appleVectors() {
	for (const n of APPLE) {
		await run("apple", `ok ${n}`, mkP, popts(n), pin(n), { evidenceRef: { fixture: n } });
		const thumb = (await keyThumbprint(leafOf(n).spki)) as string;
		const o = popts(n, { bind: "attested-key" });
		await run("apple", `attested-key good ${n}`, mkP, o, pin(n, { credentialKind: "jwk", credentialKeyThumbprint: thumb }), { evidenceRef: { fixture: n } });
		await run("apple", `attested-key other ${n}`, mkP, o, pin(n, { credentialKind: "jwk", credentialKeyThumbprint: "other" }), { evidenceRef: { fixture: n } });
		await run("apple", `attested-key psk ${n}`, mkP, o, pin(n, { credentialKind: "psk" }), { evidenceRef: { fixture: n } });
		await run("apple", `attested-key missing ${n}`, mkP, o, pin(n), { evidenceRef: { fixture: n } });
	}
	{
		const n = "termakan_ios_27_0_1";
		const o = popts(n, { bind: "client-data" });
		const nonce = afx(n).nonce.slice(0, afx(n).nonce.lastIndexOf(":"));
		const base = { evidence: aev(n), nonce, enrollmentId: "e1", credentialKind: "jwk", credentialKeyThumbprint: "10Z" };
		await run("apple", "client-data good", mkP, o, base, { evidenceRef: { fixture: n } });
		await run("apple", "client-data wrong thumb", mkP, o, { ...base, credentialKeyThumbprint: "10X" }, { evidenceRef: { fixture: n } });
		await run("apple", "client-data psk", mkP, o, { ...base, credentialKind: "psk" }, { evidenceRef: { fixture: n } });
		await run("apple", "client-data no credential", mkP, o, { evidence: aev(n), nonce: afx(n).nonce, enrollmentId: "e1" }, { evidenceRef: { fixture: n } });
	}
	const v = "veehaitch_ios_14_4";
	{
		const o = popts(v);
		delete (o.options.ts as Any).bind;
		delete (o.wire as Any).bind;
		await run("apple", "default bind refuses bare nonce", mkP, o, pin(v), { evidenceRef: { fixture: v } });
		await run("apple", "wrong nonce", mkP, popts(v), pin(v, { nonce: "wurzelpfropg" }), { evidenceRef: { fixture: v } });
		await run("apple", "no nonce", mkP, popts(v), { evidence: aev(v), enrollmentId: "e1" }, { evidenceRef: { fixture: v } });
		await run("apple", "raw hash wrong mode", mkP, popts(v, { clientDataHash: "raw" }), pin(v), { evidenceRef: { fixture: v } });
		await run("apple", "expired", mkP, popts(v, {}, {}, "2026-10-18T00:00:00Z"), pin(v), { evidenceRef: { fixture: v } });
		await run("apple", "foreign root", mkP, popts(v, { rootsRef: "google" }, { roots: att.GOOGLE_ATTESTATION_ROOTS }), pin(v), { evidenceRef: { fixture: v } });
		await run("apple", "development fixture in production", mkP, popts(v, { environment: "production" }), pin(v), { evidenceRef: { fixture: v } });
		await run("apple", "category on old fixture", mkP, popts(v, { allowedValidationCategories: [1] }), pin(v), { evidenceRef: { fixture: v } });
		// tampering
		const bad = fromBase64Url(afx(v).keyId);
		bad[0] = (bad[0] as number) ^ 1;
		await run("apple", "tampered keyId", mkP, popts(v), { ...pin(v), evidence: JSON.stringify({ attestation: afx(v).attestation, keyId: toBase64Url(bad) }) });
		const att1 = fromBase64Url(afx(v).attestation);
		const r = idx(att1, "receipt");
		att1[r + 7 + 3 + 50] = (att1[r + 7 + 3 + 50] as number) ^ 1;
		await run("apple", "tampered receipt", mkP, popts(v), { ...pin(v), evidence: JSON.stringify({ attestation: toBase64Url(att1), keyId: afx(v).keyId }) });
		const att2 = fromBase64Url(afx(v).attestation);
		const at = idx(att2, "authData");
		att2[at + 8 + 2 + 5] = (att2[at + 8 + 2 + 5] as number) ^ 1;
		await run("apple", "tampered authData", mkP, popts(v), { ...pin(v), evidence: JSON.stringify({ attestation: toBase64Url(att2), keyId: afx(v).keyId }) });
		for (const e of ["", "[]", "{}", '{"attestation":"AA","keyId":"AA"}', '{"attestation":1,"keyId":"AA"}', JSON.stringify({ attestation: toBase64Url(new Uint8Array([0xa0])), keyId: "AA" }), '{"attestation":"!!","keyId":"AA"}', "null"]) {
			await run("apple", `malformed ${e.slice(0, 24)}`, mkP, popts(v), { evidence: e, nonce: "x", enrollmentId: "e" });
		}
	}
	{
		const n = "termakan_ios_27_0_1";
		await run("apple", "other app", mkP, popts(n, { appIds: ["ABCDE12345.com.other"] }), pin(n), { evidenceRef: { fixture: n } });
		await run("apple", "empty app list", mkP, popts(n, { appIds: [] }), pin(n), { evidenceRef: { fixture: n } });
		await run("apple", "development expected on production fixture", mkP, popts(n, { environment: "development" }), pin(n), { evidenceRef: { fixture: n } });
		await run("apple", "any environment", mkP, popts(n, { environment: "any" }), pin(n), { evidenceRef: { fixture: n } });
		await run("apple", "hex challenge encoding", mkP, popts(n, { challengeEncoding: "hex" }), pin(n, { nonce: "zz" }), { evidenceRef: { fixture: n } });
	}
	{
		const n = "apple_guide_sample";
		await run("apple", "category allowed", mkP, popts(n, { allowedValidationCategories: [1] }), pin(n), { evidenceRef: { fixture: n } });
		await run("apple", "category denied", mkP, popts(n, { allowedValidationCategories: [3] }), pin(n), { evidenceRef: { fixture: n } });
		await run("apple", "category empty list", mkP, popts(n, { allowedValidationCategories: [] }), pin(n), { evidenceRef: { fixture: n } });
	}
}

// Section: TPM
const BANKS = ["sha1", "sha256", "sha384"];
const mkT = () => att.createTpm2QuoteVerifier;
function topts(wireExtra: Any = {}, tsExtra: Any = {}, nowIso = NOW) {
	const wire = { rootsRef: "tpmRoot", challengeEncoding: "hex", now: nowIso, ...wireExtra };
	const ts: Any = { roots: [tpm.rootCertificate], challengeEncoding: "hex", now: () => new Date(nowIso), ...tsExtra };
	for (const [k, v] of Object.entries(wireExtra)) if (!["rootsRef", "now", "challengeEncoding"].includes(k)) ts[k] = v;
	if ("challengeEncoding" in wireExtra) ts.challengeEncoding = wireExtra.challengeEncoding;
	if (wire.rootsRef === "none") delete ts.roots;
	return { options: { ts }, wire };
}
const tev = (bank: string, group = "withNonce", patch: Any = {}) =>
	JSON.stringify({ akPublic: tpm.akPublic, akCertificates: tpm.akCertificates, quote: tpm[group][bank].quote, signature: tpm[group][bank].signature, pcrs: tpm[group][bank].pcrs, ...patch });
const tref = (bank: string, group = "withNonce") => ({ bank, group });
const tin = (e: string, nonce: string | null = tpm.nonceHex) => ({ evidence: e, ...(nonce !== null && { nonce }), enrollmentId: "e1" });
async function tpmVectors() {
	for (const b of BANKS) await run("tpm", `ok ${b}`, mkT, topts(), tin(tev(b)), { evidenceRef: tref(b) });
	const pcrs = tpm.withNonce.sha256.pcrs.sha256;
	await run("tpm", "expected pcrs good", mkT, topts({ expectedPcrs: { sha256: { 0: pcrs["0"], 7: pcrs["7"] } } }), tin(tev("sha256")), { evidenceRef: tref("sha256") });
	await run("tpm", "expected pcrs bad", mkT, topts({ expectedPcrs: { sha256: { 7: "00".repeat(32) } } }), tin(tev("sha256")), { evidenceRef: tref("sha256") });
	await run("tpm", "wrong nonce", mkT, topts(), tin(tev("sha256"), "9010"), { evidenceRef: tref("sha256") });
	await run("tpm", "quote without nonce", mkT, topts(), tin(tev("sha256", "withoutNonce")), { evidenceRef: tref("sha256", "withoutNonce") });
	await run("tpm", "no nonce", mkT, topts(), tin(tev("sha256"), null), { evidenceRef: tref("sha256") });
	await run("tpm", "empty nonce", mkT, topts(), tin(tev("sha256"), ""), { evidenceRef: tref("sha256") });
	await run("tpm", "unsafe clock tolerated", mkT, topts({ requireSafeClock: false }), tin(tev("sha256")), { evidenceRef: tref("sha256") });
	const p2 = structuredClone(tpm.withNonce.sha256.pcrs);
	p2.sha256["3"] = "11".repeat(32);
	await run("tpm", "tampered pcrs", mkT, topts(), tin(tev("sha256", "withNonce", { pcrs: p2 })));
	const q = fromBase64Url(tpm.withNonce.sha256.quote);
	q[q.length - 3] = (q[q.length - 3] as number) ^ 1;
	await run("tpm", "tampered quote", mkT, topts(), tin(tev("sha256", "withNonce", { quote: toBase64Url(q) })));
	const s = fromBase64Url(tpm.withNonce.sha256.signature);
	s[40] = (s[40] as number) ^ 1;
	await run("tpm", "tampered signature", mkT, topts(), tin(tev("sha256", "withNonce", { signature: toBase64Url(s) })));
	const miss = structuredClone(tpm.withNonce.sha256.pcrs);
	delete miss.sha256["5"];
	await run("tpm", "missing pcr", mkT, topts(), tin(tev("sha256", "withNonce", { pcrs: miss })));
	const odd = structuredClone(tpm.withNonce.sha256.pcrs);
	odd.sha256["5"] = "abc";
	await run("tpm", "odd hex pcr", mkT, topts(), tin(tev("sha256", "withNonce", { pcrs: odd })));
	const pub = fromBase64Url(tpm.akPublic);
	pub[5] = (pub[5] as number) & ~0x01;
	await run("tpm", "ak not restricted", mkT, topts(), tin(tev("sha256", "withNonce", { akPublic: toBase64Url(pub) })));
	await run("tpm", "foreign root", mkT, topts({ rootsRef: "apple" }, { roots: att.APPLE_APP_ATTEST_ROOTS }), tin(tev("sha256")), { evidenceRef: tref("sha256") });
	await run("tpm", "missing chain", mkT, topts(), tin(tev("sha256", "withNonce", { akCertificates: [] })));
	await run("tpm", "expired chain", mkT, topts({}, {}, "2121-01-01T00:00:00Z"), tin(tev("sha256")), { evidenceRef: tref("sha256") });
	await run("tpm", "unverified ak allowed", mkT, topts({ rootsRef: "none", allowUnverifiedAk: true }), tin(tev("sha256")), { evidenceRef: tref("sha256") });
	for (const e of ["", "[]", "{}", '{"akPublic":"AA","quote":"AA","signature":"AA"}', "null", JSON.stringify({ akPublic: "!!", quote: "AA", signature: "AA" })]) {
		await run("tpm", `malformed ${e.slice(0, 24)}`, mkT, topts(), tin(e));
	}
	vectors.push({ verifier: "tpm", name: "roots or allowUnverifiedAk is required", options: { constructWithoutRoots: true }, input: {}, throws: "construct" });
	// ECDSA keys made here (code path only)
	const u16 = (n: number) => [n >> 8, n & 0xff];
	const u32 = (n: number) => [...u16(n >>> 16), ...u16(n & 0xffff)];
	const sized = (b: Uint8Array | number[]) => [...u16(b.length), ...b];
	const cat = (...p: (Uint8Array | number[])[]) => Uint8Array.from(p.flatMap((x) => [...x]));
	for (const [curveName, curveId, size, hashAlg, hashName] of [["P-256", 3, 32, 0x0b, "SHA-256"], ["P-384", 4, 48, 0x0c, "SHA-384"]] as const) {
		const nonce = new TextEncoder().encode("n1");
		const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curveName }, true, ["sign", "verify"]);
		const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
		const x = fromBase64Url(jwk.x as string);
		const y = fromBase64Url(jwk.y as string);
		const attrs = 0x10000 | 0x40000 | 0x2 | 0x10 | 0x20 | 0x40;
		const pubB = cat(u16(0x23), u16(0x0b), u32(attrs), sized([]), u16(0x10), u16(0x18), u16(hashAlg), u16(curveId), u16(0x10), sized(x), sized(y));
		const pcr = new Uint8Array(size).fill(7);
		const pcrDigest = new Uint8Array(await crypto.subtle.digest(hashName, pcr));
		const quote = cat(u32(0xff544347), u16(0x8018), sized([0, 11, 1, 2]), sized(nonce), new Uint8Array(8), u32(1), u32(2), [1], new Uint8Array(8), u32(1), u16(hashAlg), [3], [0x01, 0, 0], sized(pcrDigest));
		const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: hashName }, kp.privateKey, quote));
		const sig = cat(u16(0x18), u16(hashAlg), sized(raw.subarray(0, size)), sized(raw.subarray(size)));
		const bank = hashAlg === 0x0b ? "sha256" : "sha384";
		const hex = Array.from(pcr, (b) => b.toString(16).padStart(2, "0")).join("");
		const e = JSON.stringify({ akPublic: toBase64Url(pubB), quote: toBase64Url(quote), signature: toBase64Url(sig), pcrs: { [bank]: { 0: hex } } });
		const o = topts({ rootsRef: "none", allowUnverifiedAk: true, challengeEncoding: "utf8" });
		await run("tpm", `generated ecdsa ${curveName} ok`, mkT, o, { evidence: e, nonce: "n1", enrollmentId: "e" });
		await run("tpm", `generated ecdsa ${curveName} other nonce`, mkT, o, { evidence: e, nonce: "n2", enrollmentId: "e" });
		const o2 = topts({ challengeEncoding: "utf8" });
		await run("tpm", `generated ecdsa ${curveName} foreign cert`, mkT, o2, { evidence: JSON.stringify({ ...JSON.parse(e), akCertificates: tpm.akCertificates }), nonce: "n1", enrollmentId: "e" });
	}
}

await android();
await appleVectors();
await tpmVectors();
writeFileSync(process.argv[2] as string, `${JSON.stringify({ generator: "TypeScript verifiers in sdk/packages/core/src/device/attestation, see testdata/README.md", vectors }, null, 1)}\n`);
console.log(vectors.length, "vectors;", vectors.filter((v) => v.throws).length, "throw;", vectors.filter((v) => v.expect?.ok).length, "ok");
