/**
 * Minimal MailKite REST client and webhook verification.
 *
 * Deliberately dependency-free: the plugin ships into someone else's auth server, so
 * it should not drag a transitive tree in behind it.
 */

const DEFAULT_BASE_URL = "https://api.mailkite.dev";

/** Thrown when the MailKite API rejects a call. */
export class MailKiteApiError extends Error {
	readonly status: number;
	readonly body: unknown;

	constructor(status: number, message: string, body?: unknown) {
		super(message);
		this.name = "MailKiteApiError";
		this.status = status;
		this.body = body;
	}
}

export interface MailKiteClientOptions {
	apiKey: string;
	baseUrl?: string;
	fetch?: typeof fetch;
}

export interface SendMessageInput {
	from: string;
	to: string | string[];
	subject?: string;
	text?: string;
	html?: string;
	replyTo?: string;
	inReplyTo?: string;
}

export interface SendResult {
	id: string;
	status: string;
}

/** A thin wrapper over the endpoints this plugin needs. */
export class MailKiteClient {
	private readonly apiKey: string;
	private readonly baseUrl: string;
	private readonly fetchImpl: typeof fetch;

	constructor(options: MailKiteClientOptions) {
		this.apiKey = options.apiKey;
		this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
		this.fetchImpl = options.fetch ?? globalThis.fetch;
	}

	private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
		const headers: Record<string, string> = { Authorization: `Bearer ${this.apiKey}` };
		if (body !== undefined) headers["Content-Type"] = "application/json";

		const res = await this.fetchImpl(this.baseUrl + path, {
			method,
			headers,
			body: body === undefined ? undefined : JSON.stringify(body),
		});

		const raw = await res.text();
		const data = raw ? JSON.parse(raw) : null;
		if (!res.ok) {
			const message =
				(data && typeof data === "object" && "error" in data && String((data as any).error)) ||
				res.statusText ||
				`HTTP ${res.status}`;
			throw new MailKiteApiError(res.status, message, data);
		}
		return data as T;
	}

	/** Send a message. Used by the reply endpoint. */
	send(message: SendMessageInput): Promise<SendResult> {
		return this.request<SendResult>("POST", "/v1/send", message);
	}

	/** Create an inbound route so mail to `address` reaches our webhook. */
	/**
	 * Point one address at our inbound webhook.
	 *
	 * The field names are `match` and `destination` — NOT `address`/`target`. 0.1.0
	 * shipped the latter, so `provision` failed with a bare `{"error":"match required"}`
	 * 400 against every real deployment. The unit tests passed because they asserted
	 * against a stub that accepted whatever was sent; only a live call caught it.
	 */
	createRoute(address: string, webhookUrl: string): Promise<{ id: string }> {
		return this.request<{ id: string }>("POST", "/api/routes", {
			match: address,
			action: "webhook",
			destination: webhookUrl,
		});
	}
}

/**
 * Constant-time string comparison.
 *
 * A plain `===` on a signature leaks, through timing, how many leading bytes matched,
 * which is enough to forge one byte at a time. Compares full length regardless of
 * where the first mismatch is.
 */
function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return diff === 0;
}

/** Hex-encode bytes without pulling in Node's Buffer, so this works on edge runtimes. */
function toHex(bytes: ArrayBuffer): string {
	return Array.from(new Uint8Array(bytes))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export interface VerifyWebhookOptions {
	/** Raw request body — must be the exact bytes received, not a re-serialized object. */
	payload: string;
	/** Value of the signature header. */
	signature: string;
	/** Value of the timestamp header. */
	timestamp: string;
	secret: string;
	/** Reject events older than this many seconds. Default 300. Pass 0 to disable. */
	toleranceSeconds?: number;
	/** Injectable clock for tests. */
	now?: () => number;
}

/**
 * Verify an inbound MailKite webhook: HMAC-SHA256 over `{timestamp}.{payload}`.
 *
 * Returns true only when the signature matches AND the timestamp is inside the
 * tolerance window — the timestamp check is what stops a captured-and-replayed
 * delivery from being accepted forever.
 */
export async function verifyWebhookSignature(options: VerifyWebhookOptions): Promise<boolean> {
	const { payload, signature, timestamp, secret } = options;
	if (!payload || !signature || !timestamp || !secret) return false;

	const tolerance = options.toleranceSeconds ?? 300;
	if (tolerance > 0) {
		const ts = Number(timestamp);
		if (!Number.isFinite(ts)) return false;
		const nowSeconds = (options.now?.() ?? Date.now()) / 1000;
		if (Math.abs(nowSeconds - ts) > tolerance) return false;
	}

	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${payload}`));

	// Accept a bare hex digest or a `sha256=` prefixed one.
	const provided = signature.startsWith("sha256=") ? signature.slice(7) : signature;
	return timingSafeEqual(toHex(mac), provided);
}
