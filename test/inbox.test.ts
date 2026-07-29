import { test } from "node:test";
import assert from "node:assert/strict";

import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

import { mailkiteInbox } from "../src/index.js";

const SECRET = "whsec_test_secret";
const NOW = 1_785_000_000_000; // fixed clock so replay-window tests are deterministic

/** Sign a payload the way MailKite does: HMAC-SHA256 over `{timestamp}.{payload}`. */
async function sign(payload: string, timestamp: string, secret = SECRET): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${payload}`));
	return Array.from(new Uint8Array(mac))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/** Record every outbound MailKite call so reply/provision behaviour can be asserted. */
function stubFetch(body: unknown = { id: "msg_sent", status: "sent" }) {
	const calls: { url: string; body: any }[] = [];
	const impl = (async (url: any, init: any) => {
		calls.push({ url: String(url), body: init?.body ? JSON.parse(init.body) : undefined });
		return {
			ok: true,
			status: 200,
			statusText: "OK",
			text: async () => JSON.stringify(body),
		};
	}) as unknown as typeof fetch;
	return Object.assign(impl, { calls });
}

async function harness(overrides: Record<string, unknown> = {}) {
	const fetchImpl = stubFetch();
	// The memory adapter needs every model declared up front, including ours.
	const db: Record<string, any[]> = {
		user: [],
		session: [],
		account: [],
		verification: [],
		mailkiteMailbox: [],
		mailkiteMessage: [],
	};
	const auth = betterAuth({
		baseURL: "http://localhost:3000",
		secret: "test-secret-value-at-least-32-chars-long",
		database: memoryAdapter(db),
		emailAndPassword: { enabled: true },
		plugins: [
			mailkiteInbox({
				apiKey: "mk_live_test",
				domain: "acme.com",
				webhookSecret: SECRET,
				baseURL: "https://acme.com",
				fetch: fetchImpl,
				now: () => NOW,
				...overrides,
			}),
		],
	});
	return { auth, db, fetchImpl };
}

/** Sign up a user and return headers carrying their session. */
async function signIn(auth: any, email: string) {
	const res = await auth.api.signUpEmail({
		body: { email, password: "password1234", name: email.split("@")[0] },
		returnHeaders: true,
	});
	const setCookie = res.headers.get("set-cookie") ?? "";
	const headers = new Headers({ cookie: setCookie.split(";")[0] });
	return { headers, user: res.response?.user ?? res.user };
}

/** POST a signed inbound delivery. */
async function deliver(auth: any, payload: object, opts: { timestamp?: string; signature?: string } = {}) {
	const raw = JSON.stringify(payload);
	const timestamp = opts.timestamp ?? String(Math.floor(NOW / 1000));
	const signature = opts.signature ?? (await sign(raw, timestamp));
	return auth.api.mailkiteInboxWebhook({
		body: payload,
		headers: new Headers({
			"x-mailkite-signature": signature,
			"x-mailkite-timestamp": timestamp,
			"content-type": "application/json",
		}),
	});
}

// --- config -----------------------------------------------------------------

test("refuses to construct without a webhook secret", () => {
	assert.throws(
		() => mailkiteInbox({ apiKey: "k", domain: "acme.com", webhookSecret: "" } as any),
		/webhookSecret/,
	);
});

test("refuses to construct without apiKey or domain", () => {
	assert.throws(() => mailkiteInbox({ apiKey: "", domain: "a.com", webhookSecret: "s" } as any), /apiKey/);
	assert.throws(() => mailkiteInbox({ apiKey: "k", domain: "", webhookSecret: "s" } as any), /domain/);
});

// --- provisioning -----------------------------------------------------------

test("provisions a personal mailbox and registers the inbound route", async () => {
	const { auth, fetchImpl } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");

	const res: any = await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });

	assert.equal(res.address, "ada@acme.com");
	const routeCall = (fetchImpl as any).calls.find((c: any) => c.url.includes("/api/routes"));
	assert.ok(routeCall, "should register a route");
	assert.equal(routeCall.body.address, "ada@acme.com");
	assert.match(routeCall.body.target, /\/api\/auth\/mailkite\/inbox\/webhook$/);
});

test("rejects a duplicate address", async () => {
	const { auth } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "support" }, headers });

	await assert.rejects(
		() => auth.api.mailkiteProvisionMailbox({ body: { localPart: "support" }, headers }),
		/already taken/i,
	);
});

test("provisioning requires a session", async () => {
	const { auth } = await harness();
	await assert.rejects(() => auth.api.mailkiteProvisionMailbox({ body: { localPart: "nobody" } }));
});

// --- webhook: signature + replay --------------------------------------------

test("stores a signed delivery for a known mailbox", async () => {
	const { auth } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });

	const res: any = await deliver(auth, {
		id: "msg_1",
		from: "Customer <c@out.com>",
		to: "ada@acme.com",
		subject: "Hello",
		text: "hi there",
	});

	assert.deepEqual({ received: res.received, stored: res.stored }, { received: true, stored: true });
});

test("rejects an invalid signature", async () => {
	const { auth } = await harness();
	await assert.rejects(
		() => deliver(auth, { id: "m", from: "a@b.com", to: "ada@acme.com" }, { signature: "deadbeef" }),
		/signature/i,
	);
});

test("rejects a signature made with the wrong secret", async () => {
	const { auth } = await harness();
	const payload = { id: "m", from: "a@b.com", to: "ada@acme.com" };
	const ts = String(Math.floor(NOW / 1000));
	const bad = await sign(JSON.stringify(payload), ts, "whsec_wrong");
	await assert.rejects(() => deliver(auth, payload, { signature: bad, timestamp: ts }), /signature/i);
});

test("rejects a replayed delivery outside the tolerance window", async () => {
	const { auth } = await harness();
	const stale = String(Math.floor(NOW / 1000) - 3600); // an hour old
	await assert.rejects(
		() => deliver(auth, { id: "m", from: "a@b.com", to: "ada@acme.com" }, { timestamp: stale }),
		/signature/i,
	);
});

test("accepts a delivery inside the tolerance window", async () => {
	const { auth } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });

	const recent = String(Math.floor(NOW / 1000) - 120); // 2 minutes old, tolerance is 300
	const res: any = await deliver(auth, { id: "m2", from: "a@b.com", to: "ada@acme.com" }, { timestamp: recent });
	assert.equal(res.stored, true);
});

// --- webhook: delivery semantics --------------------------------------------

test("acknowledges mail for an unknown recipient without storing it", async () => {
	const { auth } = await harness();
	const res: any = await deliver(auth, { id: "m", from: "a@b.com", to: "nobody@acme.com" });
	assert.deepEqual({ received: res.received, stored: res.stored }, { received: true, stored: false });
});

test("redelivery of the same message is idempotent", async () => {
	const { auth } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });

	const payload = { id: "msg_dupe", from: "a@b.com", to: "ada@acme.com", text: "x" };
	const first: any = await deliver(auth, payload);
	const second: any = await deliver(auth, payload);

	assert.equal(first.stored, true);
	assert.equal(second.stored, false);
	assert.equal(second.duplicate, true);

	const list: any = await auth.api.mailkiteListMessages({ headers });
	assert.equal(list.messages.length, 1);
});

test("normalises display-name addresses and array recipients", async () => {
	const { auth } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });

	const res: any = await deliver(auth, {
		id: "m3",
		from: "Ada L <ada@out.com>",
		to: ["Ada <ADA@acme.com>", "other@x.com"],
		text: "hi",
	});
	assert.equal(res.stored, true);

	const list: any = await auth.api.mailkiteListMessages({ headers });
	assert.equal(list.messages[0].fromAddress, "ada@out.com");
	assert.equal(list.messages[0].toAddress, "ada@acme.com");
});

test("onMessage runs, and a throwing handler does not fail the webhook", async () => {
	const seen: string[] = [];
	const { auth } = await harness({
		onMessage: (m: any) => {
			seen.push(m.messageId);
			throw new Error("handler blew up");
		},
	});
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });

	const res: any = await deliver(auth, { id: "m4", from: "a@b.com", to: "ada@acme.com", text: "x" });
	assert.equal(res.stored, true, "message must still be stored");
	assert.deepEqual(seen, ["m4"]);
});

// --- tenant isolation (the property that matters) ---------------------------

test("a user cannot list another user's mail", async () => {
	const { auth } = await harness();
	const ada = await signIn(auth, "ada@example.com");
	const bob = await signIn(auth, "bob@example.com");

	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers: ada.headers });
	await deliver(auth, { id: "m_ada", from: "x@y.com", to: "ada@acme.com", text: "private" });

	const adaList: any = await auth.api.mailkiteListMessages({ headers: ada.headers });
	const bobList: any = await auth.api.mailkiteListMessages({ headers: bob.headers });

	assert.equal(adaList.messages.length, 1);
	assert.equal(bobList.messages.length, 0, "bob must see nothing");
});

test("a user cannot read another user's message by id", async () => {
	const { auth } = await harness();
	const ada = await signIn(auth, "ada@example.com");
	const bob = await signIn(auth, "bob@example.com");

	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers: ada.headers });
	await deliver(auth, { id: "m_ada", from: "x@y.com", to: "ada@acme.com", text: "secret" });
	const adaList: any = await auth.api.mailkiteListMessages({ headers: ada.headers });
	const id = adaList.messages[0].id;

	// Must be indistinguishable from "no such message" — not a 403 that confirms it exists.
	await assert.rejects(
		() => auth.api.mailkiteGetMessage({ query: { id }, headers: bob.headers }),
		/not found/i,
	);
});

test("a mailboxId the caller does not own 404s rather than returning empty", async () => {
	const { auth } = await harness();
	const ada = await signIn(auth, "ada@example.com");
	const bob = await signIn(auth, "bob@example.com");
	const mb: any = await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers: ada.headers });

	await assert.rejects(
		() => auth.api.mailkiteListMessages({ query: { mailboxId: mb.id }, headers: bob.headers }),
		/not found/i,
	);
});

test("the mailboxId 404 is identical whether or not the caller owns any mailbox", async () => {
	// Regression: an earlier version short-circuited on "caller has no mailboxes" and
	// returned an empty list, so the two callers below got *different* responses for the
	// same foreign id — enough to probe which mailbox ids exist.
	const { auth } = await harness();
	const ada = await signIn(auth, "ada@example.com");
	const bob = await signIn(auth, "bob@example.com");
	const carol = await signIn(auth, "carol@example.com");

	const adaBox: any = await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers: ada.headers });
	// Bob owns a mailbox; Carol owns none. Both probe Ada's id.
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "bob" }, headers: bob.headers });

	const probe = async (headers: Headers) => {
		try {
			await auth.api.mailkiteListMessages({ query: { mailboxId: adaBox.id }, headers });
			return "resolved";
		} catch (e: any) {
			return `${e.status ?? "ERR"}:${e.body?.message ?? e.message}`;
		}
	};

	const withMailbox = await probe(bob.headers);
	const withoutMailbox = await probe(carol.headers);

	assert.notEqual(withMailbox, "resolved");
	assert.equal(withMailbox, withoutMailbox, "responses must be indistinguishable");
});

test("a user cannot reply from another user's mailbox", async () => {
	const { auth } = await harness();
	const ada = await signIn(auth, "ada@example.com");
	const bob = await signIn(auth, "bob@example.com");

	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers: ada.headers });
	await deliver(auth, { id: "m_ada", from: "x@y.com", to: "ada@acme.com", text: "hi" });
	const adaList: any = await auth.api.mailkiteListMessages({ headers: ada.headers });

	await assert.rejects(
		() =>
			auth.api.mailkiteReply({
				body: { messageId: adaList.messages[0].id, text: "hijack" },
				headers: bob.headers,
			}),
		/not found/i,
	);
});

test("listing requires a session", async () => {
	const { auth } = await harness();
	await assert.rejects(() => auth.api.mailkiteListMessages({}));
});

// --- read + reply -----------------------------------------------------------

test("reading a message marks it read", async () => {
	const { auth } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });
	await deliver(auth, { id: "m5", from: "x@y.com", to: "ada@acme.com", text: "hi" });

	const list: any = await auth.api.mailkiteListMessages({ headers });
	assert.equal(list.messages[0].read, false);

	const got: any = await auth.api.mailkiteGetMessage({ query: { id: list.messages[0].id }, headers });
	assert.equal(got.message.read, true);

	const after: any = await auth.api.mailkiteListMessages({ headers });
	assert.equal(after.messages[0].read, true);
});

test("reply sends from the mailbox address and threads to the original", async () => {
	const { auth, fetchImpl } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });
	await deliver(auth, {
		id: "m6",
		from: "Customer <c@out.com>",
		to: "ada@acme.com",
		subject: "Question",
		text: "?",
		messageId: "<abc@out.com>",
	});
	const list: any = await auth.api.mailkiteListMessages({ headers });

	const res: any = await auth.api.mailkiteReply({
		body: { messageId: list.messages[0].id, text: "answer" },
		headers,
	});

	assert.equal(res.status, "sent");
	const sendCall = (fetchImpl as any).calls.find((c: any) => c.url.includes("/v1/send"));
	assert.equal(sendCall.body.from, "ada@acme.com", "must send as the mailbox, not the user");
	assert.equal(sendCall.body.to, "c@out.com");
	assert.equal(sendCall.body.subject, "Re: Question");
	assert.equal(sendCall.body.inReplyTo, "<abc@out.com>");
});

test("reply requires a body", async () => {
	const { auth } = await harness();
	const { headers } = await signIn(auth, "ada@example.com");
	await auth.api.mailkiteProvisionMailbox({ body: { localPart: "ada" }, headers });
	await deliver(auth, { id: "m7", from: "x@y.com", to: "ada@acme.com" });
	const list: any = await auth.api.mailkiteListMessages({ headers });

	await assert.rejects(
		() => auth.api.mailkiteReply({ body: { messageId: list.messages[0].id }, headers }),
		/text.*html/i,
	);
});
