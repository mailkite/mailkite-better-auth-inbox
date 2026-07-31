/**
 * @mailkite/better-auth-inbox — give a Better Auth app a real mailbox.
 *
 * Every email surface Better Auth ships is outbound: it sends a magic link, an OTP, an
 * invitation. Nothing in the ecosystem lets the app *receive* — a reply to a
 * notification has nowhere to land. This plugin adds that half.
 *
 *   import { betterAuth } from "better-auth";
 *   import { mailkiteInbox } from "@mailkite/better-auth-inbox";
 *
 *   export const auth = betterAuth({
 *     plugins: [
 *       mailkiteInbox({
 *         apiKey: process.env.MAILKITE_API_KEY!,
 *         domain: "acme.com",
 *         webhookSecret: process.env.MAILKITE_WEBHOOK_SECRET!,
 *       }),
 *     ],
 *   });
 *
 * Mail addressed to a provisioned address arrives at `/mailkite/inbox/webhook`, is
 * signature-verified, and is stored against the owning mailbox. The app then reads it
 * through session-scoped endpoints — never by holding an API key in the browser.
 */
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import * as z from "zod";

import { MailKiteClient, parseSignatureHeader, verifyWebhookSignature } from "./mailkite.js";
import { schema } from "./schema.js";

export interface MailKiteInboxOptions {
	/** MailKite API key (`mk_live_…`). */
	apiKey: string;
	/** Domain new addresses are provisioned on, e.g. `acme.com`. Must be verified for receiving. */
	domain: string;
	/** Webhook signing secret, from the domain's webhook settings. */
	webhookSecret: string;
	/**
	 * Public URL of this app, used to register the inbound route.
	 * Required only if you call `provisionMailbox` — MailKite needs somewhere to POST.
	 */
	baseURL?: string;
	/** Reject webhook deliveries older than this many seconds. Default 300. */
	toleranceSeconds?: number;
	/**
	 * Called after a message is stored. Use it to notify, auto-reply, or enqueue work.
	 * Throwing here does NOT fail the webhook — the message is already persisted, and a
	 * non-2xx would make MailKite redeliver a message we already have.
	 */
	onMessage?: (message: StoredMessage) => void | Promise<void>;
	/** Override the API base URL. */
	baseUrl?: string;
	/** Inject a fetch implementation (tests). */
	fetch?: typeof fetch;
	/** Injectable clock for tests. */
	now?: () => number;
}

/** A message as stored and returned by this plugin. */
export interface StoredMessage {
	id: string;
	mailboxId: string;
	messageId: string;
	/** "inbound" for mail received, "outbound" for a reply this app sent. */
	direction?: "inbound" | "outbound" | string;
	fromAddress: string;
	toAddress: string;
	subject?: string | null;
	text?: string | null;
	html?: string | null;
	threadId?: string | null;
	read?: boolean;
	receivedAt: Date;
}

interface MailboxRow {
	id: string;
	address: string;
	userId?: string | null;
	organizationId?: string | null;
	domainId?: string | null;
	createdAt: Date;
}

/**
 * One address as MailKite serialises it: `{ address, name? }`, never a bare string.
 * Strings are still accepted so a hand-rolled test fixture or an older edge doesn't
 * hard-fail, but the object form is what production sends.
 */
const addressish = z.union([
	z.string(),
	z.object({ address: z.string(), name: z.string().nullish() }),
]);

/**
 * The `email.received` body MailKite POSTs.
 *
 * Mirrors sdks/spec/schemas/email-received-event.json, which is the published contract.
 * 0.1.x invented a different shape — `from` as a string, `to` as a string or string[],
 * and `messageId`/`inReplyTo` fields that do not exist — so every delivery that got past
 * signature checking was then rejected 400 by this parser. Threading is `threadId`.
 * Unknown keys are ignored rather than rejected, so MailKite adding a field is not a
 * breaking change for apps pinned to an older plugin.
 */
const inboundPayload = z.object({
	id: z.string(),
	from: addressish,
	to: z.union([addressish, z.array(addressish)]),
	subject: z.string().nullish(),
	text: z.string().nullish(),
	html: z.string().nullish(),
	threadId: z.string().nullish(),
	receivedAt: z.number().nullish(),
});

/** Normalise `to` — MailKite may send a string or an array. */
function firstRecipient(to: unknown): string {
	const first = Array.isArray(to) ? to[0] : to;
	return addressOf(first);
}

/** Pull the address out of `{ address, name? }`, or pass a bare string through. */
function addressOf(value: unknown): string {
	if (typeof value === "string") return value;
	if (value && typeof value === "object" && "address" in value) {
		return String((value as { address?: unknown }).address ?? "");
	}
	return "";
}

/** Strip display names: `Ada <a@b.com>` → `a@b.com`, and lowercase for matching. */
function normaliseAddress(address: string): string {
	const angle = address.match(/<([^>]+)>/);
	return (angle?.[1] ?? address).trim().toLowerCase();
}

/**
 * Give a Better Auth app a mailbox: receive email as verified webhooks, then list,
 * read and reply through session-scoped endpoints.
 */
export const mailkiteInbox = (options: MailKiteInboxOptions) => {
	if (!options.apiKey) throw new Error("@mailkite/better-auth-inbox: `apiKey` is required.");
	if (!options.domain) throw new Error("@mailkite/better-auth-inbox: `domain` is required.");
	if (!options.webhookSecret) {
		throw new Error("@mailkite/better-auth-inbox: `webhookSecret` is required — unsigned webhooks are not accepted.");
	}

	const client = new MailKiteClient({
		apiKey: options.apiKey,
		baseUrl: options.baseUrl,
		fetch: options.fetch,
	});

	/**
	 * Resolve which mailboxes the caller may read.
	 *
	 * This is the whole access rule, in one place: a session reads its own personal
	 * mailboxes plus the mailbox of its active organization. Every read endpoint goes
	 * through here rather than filtering ad hoc, so there is one thing to get right.
	 */
	async function readableMailboxes(ctx: any): Promise<MailboxRow[]> {
		const session = ctx.context.session;
		const userId: string = session.user.id;
		const activeOrganizationId: string | undefined = session.session?.activeOrganizationId ?? undefined;

		const own: MailboxRow[] = await ctx.context.adapter.findMany({
			model: "mailkiteMailbox",
			where: [{ field: "userId", value: userId }],
		});

		if (!activeOrganizationId) return own;

		const orgOwned: MailboxRow[] = await ctx.context.adapter.findMany({
			model: "mailkiteMailbox",
			where: [{ field: "organizationId", value: activeOrganizationId }],
		});

		const seen = new Set(own.map((m) => m.id));
		return [...own, ...orgOwned.filter((m) => !seen.has(m.id))];
	}

	/** Fetch messages across a set of already-authorised mailboxes, newest first. */
	async function messagesFor(ctx: any, mailboxes: MailboxRow[], limit: number): Promise<StoredMessage[]> {
		const messages: StoredMessage[] = [];
		for (const mailbox of mailboxes) {
			const rows: StoredMessage[] = await ctx.context.adapter.findMany({
				model: "mailkiteMessage",
				where: [{ field: "mailboxId", value: mailbox.id }],
				limit,
				sortBy: { field: "receivedAt", direction: "desc" },
			});
			messages.push(...rows);
		}
		messages.sort((a, b) => new Date(b.receivedAt).getTime() - new Date(a.receivedAt).getTime());
		return messages.slice(0, limit);
	}

	return {
		id: "mailkite-inbox",
		schema,

		endpoints: {
			/**
			 * Inbound webhook. Public by necessity — MailKite has no session — but every
			 * delivery must carry a valid signature and a fresh timestamp.
			 */
			mailkiteInboxWebhook: createAuthEndpoint(
				"/mailkite/inbox/webhook",
				{ method: "POST", metadata: { isAction: false } },
				async (ctx) => {
					const raw =
						typeof ctx.body === "string" ? ctx.body : JSON.stringify(ctx.body ?? {});

					// ONE header, `t=<msEpoch>,v1=<hex>`. There is no x-mailkite-timestamp.
					const sig = parseSignatureHeader(ctx.headers?.get("x-mailkite-signature"));
					if (!sig) {
						throw new APIError("UNAUTHORIZED", { message: "Invalid webhook signature." });
					}

					// Which key signed this? MailKite signs a route's deliveries with that
					// route's own secret, falling back to the account secret, so a
					// provisioned mailbox needs its stored secret rather than the
					// configured one. The claimed recipient only *selects* a candidate key
					// — it grants nothing, because the HMAC below still has to verify
					// against it. Both candidates are tried so catch-all deliveries (signed
					// with the configured secret) keep working alongside provisioned ones.
					const candidates: string[] = [];
					const claimedTo = ((): string => {
						try {
							const body = typeof ctx.body === "string" ? JSON.parse(ctx.body) : ctx.body;
							return normaliseAddress(firstRecipient(body?.to ?? ""));
						} catch {
							return "";
						}
					})();
					if (claimedTo) {
						const box: (MailboxRow & { signingSecret?: string | null }) | null =
							await ctx.context.adapter.findOne({
								model: "mailkiteMailbox",
								where: [{ field: "address", value: claimedTo }],
							});
						if (box?.signingSecret) candidates.push(box.signingSecret);
					}
					candidates.push(options.webhookSecret);

					let ok = false;
					for (const secret of candidates) {
						if (
							await verifyWebhookSignature({
								payload: raw,
								signature: sig.signature,
								timestamp: sig.timestamp,
								secret,
								toleranceSeconds: options.toleranceSeconds,
								now: options.now,
							})
						) {
							ok = true;
							break;
						}
					}
					if (!ok) {
						throw new APIError("UNAUTHORIZED", { message: "Invalid webhook signature." });
					}

					const parsed = inboundPayload.safeParse(
						typeof ctx.body === "string" ? JSON.parse(ctx.body) : ctx.body,
					);
					if (!parsed.success) {
						throw new APIError("BAD_REQUEST", { message: "Unrecognised inbound payload." });
					}
					const event = parsed.data;

					const recipient = normaliseAddress(firstRecipient(event.to));
					const mailbox: MailboxRow | null = await ctx.context.adapter.findOne({
						model: "mailkiteMailbox",
						where: [{ field: "address", value: recipient }],
					});
					// Unknown recipient: acknowledge so MailKite stops retrying, but store nothing.
					// Retrying a delivery we will never have a mailbox for helps no one.
					if (!mailbox) return ctx.json({ received: true, stored: false });

					// Idempotency: redelivery of a message we already hold is a no-op success.
					const existing = await ctx.context.adapter.findOne({
						model: "mailkiteMessage",
						where: [{ field: "messageId", value: event.id }],
					});
					if (existing) return ctx.json({ received: true, stored: false, duplicate: true });

					const stored: StoredMessage = await ctx.context.adapter.create({
						model: "mailkiteMessage",
						data: {
							mailboxId: mailbox.id,
							messageId: event.id,
							direction: "inbound",
							fromAddress: normaliseAddress(addressOf(event.from)),
							toAddress: recipient,
							subject: event.subject ?? null,
							text: event.text ?? null,
							html: event.html ?? null,
							threadId: event.threadId ?? null,
							read: false,
							// MailKite reports when the mail ARRIVED, which survives an
							// auto-retry hours later; fall back to now only if absent.
							receivedAt: new Date(event.receivedAt ?? options.now?.() ?? Date.now()),
						},
					});

					if (options.onMessage) {
						try {
							await options.onMessage(stored);
						} catch {
							// Swallowed on purpose: the message is persisted. Signalling failure
							// would trigger redelivery of mail we already stored.
						}
					}

					return ctx.json({ received: true, stored: true, id: stored.id });
				},
			),

			/** Provision an address for the caller, or for their active organization. */
			mailkiteProvisionMailbox: createAuthEndpoint(
				"/mailkite/inbox/provision",
				{
					method: "POST",
					use: [sessionMiddleware],
					body: z.object({
						/** Local part, e.g. "support" → support@yourdomain. */
						localPart: z.string().min(1).max(64).regex(/^[a-z0-9._-]+$/i, "Invalid local part."),
						/** Attach to the active organization instead of the user. */
						forOrganization: z.boolean().optional(),
					}),
				},
				async (ctx) => {
					const session = ctx.context.session;
					const address = `${ctx.body.localPart.toLowerCase()}@${options.domain}`;

					const clash = await ctx.context.adapter.findOne({
						model: "mailkiteMailbox",
						where: [{ field: "address", value: address }],
					});
					if (clash) throw new APIError("BAD_REQUEST", { message: "That address is already taken." });

					let organizationId: string | null = null;
					if (ctx.body.forOrganization) {
						organizationId = session.session?.activeOrganizationId ?? null;
						if (!organizationId) {
							throw new APIError("BAD_REQUEST", {
								message: "No active organization on this session.",
							});
						}
					}

					// Register the inbound route first. If MailKite rejects it, we must not
					// leave a row promising an address that will never receive anything.
					let signingSecret: string | null = null;
					if (options.baseURL) {
						const route = await client.createRoute(address, `${options.baseURL.replace(/\/+$/, "")}/api/auth/mailkite/inbox/webhook`);
						// MailKite mints a secret per route and signs THIS route's deliveries
						// with it, not with the configured domain secret. Storing it here is
						// what lets the webhook verify mail sent to this address.
						signingSecret = route.signing_secret ?? null;
					}

					const mailbox: MailboxRow = await ctx.context.adapter.create({
						model: "mailkiteMailbox",
						data: {
							address,
							userId: organizationId ? null : session.user.id,
							organizationId,
							signingSecret,
							createdAt: new Date(options.now?.() ?? Date.now()),
						},
					});

					return ctx.json({ id: mailbox.id, address: mailbox.address });
				},
			),

			/** List messages the caller may read, newest first. */
			/**
			 * The caller's mailboxes — their personal ones plus their active
			 * organization's. Without this an app has no way to answer "what is my
			 * address?" after a reload: `provision` returns it once, and nothing else
			 * exposes it, so the address had to be kept in client state and was lost
			 * on refresh.
			 */
			mailkiteListMailboxes: createAuthEndpoint(
				"/mailkite/inbox/mailboxes",
				{ method: "GET", use: [sessionMiddleware] },
				async (ctx) => {
					const mailboxes = await readableMailboxes(ctx);
					// Never the signing secret — it is a credential, and this response
					// reaches the browser.
					return ctx.json({
						mailboxes: mailboxes.map((m) => ({
							id: m.id,
							address: m.address,
							organizationId: m.organizationId ?? null,
							createdAt: m.createdAt,
						})),
					});
				},
			),

			mailkiteListMessages: createAuthEndpoint(
				"/mailkite/inbox/messages",
				{
					method: "GET",
					use: [sessionMiddleware],
					query: z
						.object({
							limit: z.coerce.number().min(1).max(100).optional(),
							mailboxId: z.string().optional(),
						})
						.optional(),
				},
				async (ctx) => {
					const mailboxes = await readableMailboxes(ctx);

					// Order matters. An explicit mailboxId is validated FIRST, before any
					// empty-set shortcut: if a caller with no mailboxes got `{messages: []}`
					// while a caller with mailboxes got a 404, the difference between those
					// two responses is itself a probe for which ids exist.
					if (ctx.query?.mailboxId) {
						const target = mailboxes.find((m) => m.id === ctx.query!.mailboxId);
						if (!target) throw new APIError("NOT_FOUND", { message: "Mailbox not found." });
						return ctx.json({ messages: await messagesFor(ctx, [target], ctx.query?.limit ?? 50) });
					}

					if (mailboxes.length === 0) return ctx.json({ messages: [] });
					const allowed = mailboxes;

					return ctx.json({ messages: await messagesFor(ctx, allowed, ctx.query?.limit ?? 50) });
				},
			),

			/** Read one message. 404s rather than 403s on someone else's mail. */
			mailkiteGetMessage: createAuthEndpoint(
				"/mailkite/inbox/message",
				{
					method: "GET",
					use: [sessionMiddleware],
					query: z.object({ id: z.string() }),
				},
				async (ctx) => {
					const message: StoredMessage | null = await ctx.context.adapter.findOne({
						model: "mailkiteMessage",
						where: [{ field: "id", value: ctx.query.id }],
					});
					const mailboxes = await readableMailboxes(ctx);
					// Same 404 whether the message is missing or simply not theirs, so the
					// response can't be used to confirm that an id exists.
					if (!message || !mailboxes.some((m) => m.id === message.mailboxId)) {
						throw new APIError("NOT_FOUND", { message: "Message not found." });
					}

					if (!message.read) {
						await ctx.context.adapter.update({
							model: "mailkiteMessage",
							where: [{ field: "id", value: message.id }],
							update: { read: true },
						});
					}

					return ctx.json({ message: { ...message, read: true } });
				},
			),

			/** Reply to a message, from the mailbox that received it. */
			mailkiteReply: createAuthEndpoint(
				"/mailkite/inbox/reply",
				{
					method: "POST",
					use: [sessionMiddleware],
					body: z.object({
						messageId: z.string(),
						text: z.string().optional(),
						html: z.string().optional(),
						subject: z.string().optional(),
					}),
				},
				async (ctx) => {
					if (!ctx.body.text && !ctx.body.html) {
						throw new APIError("BAD_REQUEST", { message: "Provide `text` or `html`." });
					}

					const message: StoredMessage | null = await ctx.context.adapter.findOne({
						model: "mailkiteMessage",
						where: [{ field: "id", value: ctx.body.messageId }],
					});
					const mailboxes = await readableMailboxes(ctx);
					const mailbox = message && mailboxes.find((m) => m.id === message.mailboxId);
					if (!message || !mailbox) {
						throw new APIError("NOT_FOUND", { message: "Message not found." });
					}

					const result = await client.send({
						// From the mailbox that received it, never the caller's own address —
						// the mailbox is the identity the other party already knows.
						from: mailbox.address,
						to: message.fromAddress,
						subject: ctx.body.subject ?? (message.subject ? `Re: ${message.subject}` : "Re:"),
						text: ctx.body.text,
						html: ctx.body.html,
						inReplyTo: message.threadId ?? undefined,
					});

					// Persist our own reply so the conversation contains both halves.
					// threadId falls back to the original's messageId: MailKite only sets
					// threadId once a conversation exists, so the first inbound message of
					// a thread has none, and grouping on it alone would orphan the reply.
					const threadId = message.threadId ?? message.messageId;
					const stored: StoredMessage = await ctx.context.adapter.create({
						model: "mailkiteMessage",
						data: {
							mailboxId: mailbox.id,
							messageId: result.id,
							direction: "outbound",
							fromAddress: mailbox.address,
							toAddress: message.fromAddress,
							subject: ctx.body.subject ?? (message.subject ? `Re: ${message.subject}` : "Re:"),
							text: ctx.body.text ?? null,
							html: ctx.body.html ?? null,
							threadId,
							read: true,
							receivedAt: new Date(options.now?.() ?? Date.now()),
						},
					});

					// Backfill the original so both ends share a grouping key.
					if (!message.threadId) {
						await ctx.context.adapter.update({
							model: "mailkiteMessage",
							where: [{ field: "id", value: message.id }],
							update: { threadId },
						});
					}

					return ctx.json({ id: result.id, status: result.status, message: stored });
				},
			),
		},

		rateLimit: [
			{
				pathMatcher: (path: string) => path.startsWith("/mailkite/inbox/"),
				window: 60,
				max: 60,
			},
			{
				// Provisioning creates real routes upstream; keep it tight.
				pathMatcher: (path: string) => path === "/mailkite/inbox/provision",
				window: 3600,
				max: 10,
			},
		],
	} satisfies BetterAuthPlugin;
};

export { MailKiteApiError, verifyWebhookSignature } from "./mailkite.js";
export { schema } from "./schema.js";
export default mailkiteInbox;
