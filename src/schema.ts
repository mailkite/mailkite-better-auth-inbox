/**
 * Database schema for the MailKite inbox plugin.
 *
 * Two tables:
 *
 * - `mailkiteMailbox` — the address ↔ owner mapping. An owner is a user, or an
 *   organization when the `organization` plugin is in play. This is the ACL anchor:
 *   every read is scoped through it, so a user can never see another tenant's mail.
 * - `mailkiteMessage` — inbound messages, keyed to a mailbox. Kept deliberately thin;
 *   MailKite remains the mail store, and this is a local index so the app can list and
 *   thread without a round trip per render.
 */
export const schema = {
	mailkiteMailbox: {
		fields: {
			/** Full address, e.g. `support@acme.com`. Unique across the deployment. */
			address: {
				type: "string",
				required: true,
				unique: true,
				index: true,
			},
			/** Owning user. Null when the mailbox belongs to an organization. */
			userId: {
				type: "string",
				required: false,
				references: { model: "user", field: "id" },
				index: true,
			},
			/**
			 * Owning organization. Null for personal mailboxes.
			 * Not declared as a reference: the `organization` plugin is optional, and a
			 * foreign key to a table that may not exist would break migrations for apps
			 * that only want personal inboxes.
			 */
			organizationId: {
				type: "string",
				required: false,
				index: true,
			},
			/** MailKite domain id (`dom_…`), when the address was provisioned through us. */
			domainId: {
				type: "string",
				required: false,
			},
			/**
			 * This mailbox's own webhook signing secret (`whsec_…`).
			 *
			 * MailKite mints a secret per route and signs that route's deliveries with it
			 * (`route.signing_secret ?? accountSecret`), so a provisioned address is NOT
			 * signed with the domain-level `webhookSecret` you configured. 0.1.x never
			 * stored this, so every delivery to a provisioned address failed verification.
			 * Null for mailboxes that arrive via the domain catch-all, which do use the
			 * configured secret.
			 */
			signingSecret: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
				defaultValue: () => new Date(),
			},
		},
	},
	mailkiteMessage: {
		fields: {
			mailboxId: {
				type: "string",
				required: true,
				references: { model: "mailkiteMailbox", field: "id" },
				index: true,
			},
			/** MailKite message id (`msg_…`). Unique so webhook redelivery is idempotent. */
			messageId: {
				type: "string",
				required: true,
				unique: true,
				index: true,
			},
			fromAddress: { type: "string", required: true },
			toAddress: { type: "string", required: true },
			subject: { type: "string", required: false },
			text: { type: "string", required: false },
			html: { type: "string", required: false },
			/** RFC Message-ID of the inbound mail, used to thread replies. */
			threadId: { type: "string", required: false, index: true },
			read: {
				type: "boolean",
				required: false,
				defaultValue: false,
			},
			receivedAt: {
				type: "date",
				required: true,
				defaultValue: () => new Date(),
			},
		},
	},
} as const;
