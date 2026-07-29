/**
 * Client plugin — gives the Better Auth client typed methods for the inbox endpoints.
 *
 *   import { createAuthClient } from "better-auth/client";
 *   import { mailkiteInboxClient } from "@mailkite/better-auth-inbox/client";
 *
 *   const client = createAuthClient({ plugins: [mailkiteInboxClient()] });
 *   const { data } = await client.mailkite.inbox.messages();
 *
 * The browser never holds a MailKite API key: every call is session-authenticated
 * against your own auth server, which does the privileged work.
 */
import type { BetterAuthClientPlugin } from "better-auth";

import type { mailkiteInbox } from "./index.js";

export const mailkiteInboxClient = () => {
	return {
		id: "mailkite-inbox",
		$InferServerPlugin: {} as ReturnType<typeof mailkiteInbox>,
		pathMethods: {
			"/mailkite/inbox/messages": "GET",
			"/mailkite/inbox/message": "GET",
			"/mailkite/inbox/provision": "POST",
			"/mailkite/inbox/reply": "POST",
		},
	} satisfies BetterAuthClientPlugin;
};

export default mailkiteInboxClient;
