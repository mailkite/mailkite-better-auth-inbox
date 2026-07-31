# @mailkite/better-auth-inbox

Give a [Better Auth](https://better-auth.com) app a real mailbox.

Every email surface Better Auth ships is **outbound** — a magic link, an OTP, an
invitation. When someone replies, there is nowhere for it to land. This plugin adds the
other half: your app receives email as signature-verified webhooks, stores it against the
owning user or organization, and lets the browser read and reply through
session-authenticated endpoints.

No auth library offers this. Neither does Resend, nor `@better-auth/infra`.

```bash
npm install @mailkite/better-auth-inbox
```

## Setup

```ts
import { betterAuth } from "better-auth";
import { mailkiteInbox } from "@mailkite/better-auth-inbox";

export const auth = betterAuth({
  plugins: [
    mailkiteInbox({
      apiKey: process.env.MAILKITE_API_KEY!,
      domain: "acme.com",                    // verified for receiving
      webhookSecret: process.env.MAILKITE_WEBHOOK_SECRET!,
      baseURL: "https://acme.com",           // where MailKite POSTs deliveries
    }),
  ],
});
```

Run your migration (`npx @better-auth/cli migrate`) to create the two tables, then point
the domain's webhook at `/api/auth/mailkite/inbox/webhook`.

### Client

```ts
import { createAuthClient } from "better-auth/client";
import { mailkiteInboxClient } from "@mailkite/better-auth-inbox/client";

const client = createAuthClient({ plugins: [mailkiteInboxClient()] });
```

The browser never holds a MailKite API key — every call is session-authenticated against
your own auth server, which does the privileged work.

## Endpoints

| Route | Auth | What |
|---|---|---|
| `POST /mailkite/inbox/webhook` | signature | Inbound delivery from MailKite |
| `POST /mailkite/inbox/provision` | session | Claim an address for the user or their active org |
| `GET /mailkite/inbox/mailboxes` | session | The caller's addresses — so an app can show "your address" after a reload |
| `GET /mailkite/inbox/messages` | session | List readable messages, newest first. Pass `mailboxId` to scope to one address |
| `GET /mailkite/inbox/message?id=` | session | Read one, marks it read |
| `POST /mailkite/inbox/reply` | session | Reply from the mailbox that received it |

## Per-organization inboxes

With Better Auth's `organization` plugin, pass `forOrganization: true` and the mailbox
belongs to the session's active organization rather than the user — so every member of
that org shares one inbox, and switching orgs switches the mail.

```ts
await client.mailkite.inbox.provision({ localPart: "support", forOrganization: true });
```

## Reacting to mail

```ts
mailkiteInbox({
  // …
  onMessage: async (message) => {
    await notifySlack(message.subject);
  },
});
```

A throwing handler does **not** fail the webhook. The message is already stored, and a
non-2xx would make MailKite redeliver mail you already hold.

## Options

| Option | Notes |
|---|---|
| `apiKey` | **Required.** MailKite API key. |
| `domain` | **Required.** Domain addresses are provisioned on. |
| `webhookSecret` | **Required.** Unsigned webhooks are never accepted. |
| `baseURL` | Public URL of the app; needed to register inbound routes. |
| `toleranceSeconds` | Replay window. Default 300. |
| `onMessage` | Runs after a message is stored. |
| `baseUrl` · `fetch` · `now` | Overrides for staging and tests. |

## Security

This is multi-tenant mail, so the boundaries are the product:

- **One access rule, one place.** Every read resolves through the same
  `readableMailboxes` check — the caller's own mailboxes plus their active
  organization's. Endpoints never filter ad hoc.
- **Webhooks are HMAC-SHA256 verified** over `{timestamp}.{payload}`, compared in
  constant time, with a timestamp window so a captured delivery can't be replayed forever.
- **Foreign resources 404, never 403.** A 403 confirms the id exists. The response for
  "no such message" and "not yours" is byte-identical, including for callers who own no
  mailbox at all — there is a regression test asserting exactly that.
- **Replies send from the mailbox**, never the caller's address — the mailbox is the
  identity the other party already knows.
- **Redelivery is idempotent**, keyed on MailKite's message id.

## License

MIT
