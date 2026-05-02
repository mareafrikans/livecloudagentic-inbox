import { routeAgentRequest } from "agents";
import { Hono } from "hono";
import { jwtVerify, createRemoteJWKSet } from "jose";
import { createRequestHandler } from "react-router";
import { app as apiApp, receiveEmail } from "./index";
import { EmailMCP } from "./mcp";
import type { Env } from "./types";

export { MailboxDO } from "./durableObject";
export { EmailAgent } from "./agent";
export { EmailMCP } from "./mcp";

declare module "react-router" {
	export interface AppLoadContext {
		cloudflare: {
			env: Env;
			ctx: ExecutionContext;
		};
	}
}

const requestHandler = createRequestHandler(
	() => import("virtual:react-router/server-build"),
	import.meta.env.MODE,
);

function getAccessUrls(teamDomain: string) {
	const certsPath = "/cdn-cgi/access/certs";
	const teamUrl = new URL(teamDomain);
	const issuer = teamUrl.origin;
	const certsUrl = teamUrl.pathname.endsWith(certsPath)
		? teamUrl
		: new URL(certsPath, issuer);

	return { issuer, certsUrl };
}

const app = new Hono<{ Bindings: Env }>();

app.use("*", async (c, next) => {
	if (import.meta.env.DEV) { return next(); }
	const { POLICY_AUD, TEAM_DOMAIN } = c.env;
	if (!POLICY_AUD || !TEAM_DOMAIN) {
		return c.text("Cloudflare Access must be configured. Set POLICY_AUD and TEAM_DOMAIN.", 500);
	}
	const token = c.req.header("cf-access-jwt-assertion");
	if (!token) { return c.text("Missing required CF Access JWT", 403); }
	try {
		const { issuer, certsUrl } = getAccessUrls(TEAM_DOMAIN);
		const JWKS = createRemoteJWKSet(certsUrl);
		await jwtVerify(token, JWKS, { issuer, audience: POLICY_AUD });
	} catch {
		return c.text("Invalid or expired Access token", 403);
	}
	return next();
});

const mcpHandler = EmailMCP.serve("/mcp", { binding: "EMAIL_MCP" });
app.all("/mcp", async (c) => mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext));
app.all("/mcp/*", async (c) => mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext));

app.route("/", apiApp);

app.all("/agents/*", async (c) => {
	const response = await routeAgentRequest(c.req.raw, c.env);
	if (response) return response;
	return c.text("Agent not found", 404);
});

app.all("*", (c) => {
	return requestHandler(c.req.raw, {
		cloudflare: { env: c.env, ctx: c.executionCtx as ExecutionContext },
	});
});

export default {
	fetch: app.fetch,
	async email(event: { raw: ReadableStream; rawSize: number }, env: Env, ctx: ExecutionContext) {
		try {
			(env as any).SKIP_PROMPT_INJECTION_CHECK = "true";
			await receiveEmail(event, env, ctx);
		} catch (e) {
			console.error("Failed to process incoming email:", (e as Error).message);
			throw e;
		}
	},
};
