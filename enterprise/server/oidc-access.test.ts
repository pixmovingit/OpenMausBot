// Real HTTP, cookies and SessionRegistry; only the configured HTTPS IdP is
// substituted through fetchImpl. No live identity provider or public DNS.
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createServer, request, type IncomingMessage, type ServerResponse } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { oidcSsoConfiguration } from "../../server/enterprise.ts";
import { resolveRequestAuth } from "../../server/request-auth.ts";
import { SessionRegistry, type Scope } from "../../server/sessions.ts";
import { removeTempDir } from "../../server/testing/cleanup.ts";
import { createOidcAccess } from "./oidc-access.ts";

const issuer = "https://idp.example.test";
const env = {
  OMB_OIDC_ISSUER: issuer,
  OMB_OIDC_CLIENT_ID: "omb-client",
  OMB_OIDC_CLIENT_SECRET: "omb-secret",
  OMB_PUBLIC_URL: "https://home.example.test",
  OMB_OIDC_ADMIN_GROUPS: "omb-admins",
};
const email = "member@example.test";
const subject = "user-1";

let home: string;
let sessions: SessionRegistry;
let localScopes: Scope[] | null;
let clock: number;
let licensed: boolean;
let outage: boolean;
let userinfo: Record<string, unknown> | null;
let codes: Map<string, { challenge: string; nonce: string }>;
let accessTokens: Map<string, string>;
let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;
let server: ReturnType<typeof createServer>;
let port: number;
let access: ReturnType<typeof createOidcAccess>;
let streams: Map<string, ServerResponse>;
const closed = vi.fn();
const remote = vi.fn<typeof fetch>();

async function signIdToken(input: { nonce: string; groups?: string[]; email?: string; sub?: string }) {
  return new SignJWT({
    email: input.email ?? email,
    nonce: input.nonce,
    groups: input.groups ?? ["omb-admins"],
  })
    .setProtectedHeader({ alg: "RS256", kid: "test" })
    .setIssuer(issuer)
    .setAudience(env.OMB_OIDC_CLIENT_ID)
    .setSubject(input.sub ?? subject)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), "omb-oidc-access-"));
  clock = Date.now();
  licensed = true;
  outage = false;
  localScopes = ["admin", "client"];
  userinfo = { sub: subject, email, groups: ["omb-admins"] };
  codes = new Map();
  accessTokens = new Map();
  streams = new Map();
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  publicJwk = { ...await exportJWK(pair.publicKey), kid: "test", alg: "RS256", use: "sig" };
  sessions = new SessionRegistry({ file: join(home, "sessions.json"), emailScopes: () => localScopes });
  closed.mockReset().mockImplementation((id: string) => streams.get(id)?.end());
  sessions.onSessionRevoked(closed);
  remote.mockReset().mockImplementation(async (url, init) => {
    if (outage) throw new Error("PRIVATE upstream failure");
    const href = String(url);
    if (href === `${issuer}/.well-known/openid-configuration`) {
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
      });
    }
    if (href === `${issuer}/jwks`) return Response.json({ keys: [publicJwk] });
    if (href === `${issuer}/token`) {
      expect(init).toMatchObject({ method: "POST", credentials: "omit", redirect: "error" });
      const form = new URLSearchParams(String(init?.body));
      expect(form.get("client_id")).toBe(env.OMB_OIDC_CLIENT_ID);
      expect(form.get("client_secret")).toBe(env.OMB_OIDC_CLIENT_SECRET);
      const code = codes.get(form.get("code") ?? "");
      if (!code || code.challenge !== createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url")) {
        return Response.json({ error: "invalid_grant" }, { status: 401 });
      }
      codes.delete(form.get("code")!);
      const accessToken = randomBytes(24).toString("base64url");
      accessTokens.set(accessToken, subject);
      return Response.json({
        access_token: accessToken,
        token_type: "Bearer",
        id_token: await signIdToken({ nonce: code.nonce }),
        expires_in: 3600,
      });
    }
    if (href === `${issuer}/userinfo`) {
      const presented = String((init?.headers && Reflect.get(Object(init.headers), "authorization")) ?? "");
      const token = presented.match(/^Bearer (\S+)$/)?.[1] ?? "";
      if (!accessTokens.has(token) || !userinfo) return Response.json({}, { status: 401 });
      return Response.json(userinfo);
    }
    throw new Error(`unexpected fetch ${href}`);
  });
  access = createOidcAccess({
    sessions, cookieName: "session", closeSessionStreams: closed, entitled: () => licensed,
    env, now: () => clock, fetchImpl: remote,
  });
  server = createServer(async (req, res) => {
    const url = new URL(req.url!, env.OMB_PUBLIC_URL);
    if (await access.handlePublic(req, res, url)) return;
    const gate = resolveRequestAuth(req, { sessions, cookieName: "session", streamPath: "/api/events", url });
    const failure = gate.auth ? await access.authorize(req, gate.auth) : gate;
    if (failure) { res.writeHead(failure.status); res.end(); return; }
    if (url.pathname === "/api/events" && gate.auth?.kind === "session") {
      streams.set(gate.auth.session.id, res);
      res.writeHead(200, { "content-type": "text/event-stream" }); res.write("data: ready\n\n"); return;
    }
    res.writeHead(200); res.end(JSON.stringify(gate.auth?.scopes));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as { port: number }).port;
});

afterEach(async () => {
  for (const stream of streams.values()) stream.end();
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await removeTempDir(home);
});

function call(path: string, cookie?: string, host = "home.example.test", forwardedFor = "203.0.113.7") {
  return new Promise<{ status: number; cookies: string[]; location: string; body: string; retryAfter?: string }>((resolve, reject) => {
    const req = request({ hostname: "127.0.0.1", port, path, headers: { host, "x-forwarded-for": forwardedFor, ...(cookie ? { cookie } : {}) } }, (res) => {
      let body = ""; res.on("data", (chunk) => body += chunk);
      res.on("end", () => resolve({
        status: res.statusCode!, cookies: res.headers["set-cookie"] ?? [], location: res.headers.location ?? "",
        body, retryAfter: res.headers["retry-after"],
      }));
    });
    req.on("error", reject); req.end();
  });
}

async function begin() {
  const start = await call("/api/auth/oidc/start");
  expect(start.status).toBe(302);
  const target = new URL(start.location);
  expect(target.origin + target.pathname).toBe(`${issuer}/authorize`);
  expect(target.searchParams.get("client_id")).toBe(env.OMB_OIDC_CLIENT_ID);
  expect(target.searchParams.get("code_challenge_method")).toBe("S256");
  const state = target.searchParams.get("state")!;
  const nonce = target.searchParams.get("nonce")!;
  const code = randomBytes(24).toString("base64url");
  codes.set(code, { challenge: target.searchParams.get("code_challenge")!, nonce });
  const cookie = start.cookies[0].split(";")[0];
  expect(start.cookies[0]).toMatch(/^__Host-session_oidc=/);
  return { cookie, callback: `/api/auth/oidc/callback?state=${state}&code=${code}`, code };
}

async function login() {
  const pending = await begin();
  const reply = await call(pending.callback, pending.cookie);
  expect(reply.status).toBe(302); expect(reply.location).toBe("/");
  const cookie = reply.cookies.find((value) => value.startsWith("session="))!.split(";")[0];
  const session = sessions.authenticate(cookie.slice("session=".length))!;
  expect(session.userId).toBe(`oidc:${subject}`);
  expect(session.membershipAuthority).toBe("oidc");
  return { cookie, session };
}

describe("OIDC SSO sign-in and continuous access", () => {
  it("redirects the root and pairing page; exchanges PKCE for a scoped OIDC session", async () => {
    expect((await call("/")).location).toBe("/api/auth/oidc/start");
    expect((await call("/pair")).location).toBe("/api/auth/oidc/start");
    const { cookie } = await login();
    expect((await call("/api/auth/session", cookie)).body).toBe('["admin","client"]');
    expect((await call("/", cookie)).status).toBe(200);
  });

  it("maps non-admin groups to client scope only", async () => {
    userinfo = { sub: subject, email, groups: ["readers"] };
    remote.mockImplementation(async (url, init) => {
      const href = String(url);
      if (href === `${issuer}/.well-known/openid-configuration`) {
        return Response.json({
          issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
          userinfo_endpoint: `${issuer}/userinfo`, jwks_uri: `${issuer}/jwks`,
        });
      }
      if (href === `${issuer}/jwks`) return Response.json({ keys: [publicJwk] });
      if (href === `${issuer}/token`) {
        const form = new URLSearchParams(String(init?.body));
        const code = codes.get(form.get("code") ?? "");
        if (!code) return Response.json({}, { status: 401 });
        codes.delete(form.get("code")!);
        const accessToken = randomBytes(24).toString("base64url");
        accessTokens.set(accessToken, subject);
        return Response.json({
          access_token: accessToken, token_type: "Bearer", expires_in: 3600,
          id_token: await signIdToken({ nonce: code.nonce, groups: ["readers"] }),
        });
      }
      if (href === `${issuer}/userinfo`) return Response.json(userinfo);
      throw new Error(href);
    });
    localScopes = ["client"];
    const { cookie } = await login();
    expect((await call("/api/auth/session", cookie)).body).toBe('["client"]');
  });

  it("rejects state/cookie mismatch, expiry, duplicate params and replay", async () => {
    const pending = await begin();
    for (const [path, cookie] of [[pending.callback, ""], [pending.callback, `${pending.cookie}wrong`], [`${pending.callback}&state=other`, pending.cookie]]) {
      expect((await call(path, cookie)).status).toBe(400);
    }
    expect((await call(pending.callback, pending.cookie)).status).toBe(302);
    expect((await call(pending.callback, pending.cookie)).status).toBe(400);
    const expired = await begin();
    clock += 300_001;
    expect((await call(expired.callback, expired.cookie)).status).toBe(400);
  });

  it("binds public and authenticated routes to the tenant Host", async () => {
    expect((await call("/api/auth/oidc/start", undefined, "wrong.example.test")).status).toBe(403);
    const { cookie, session } = await login();
    expect((await call("/api/auth/session", cookie, "wrong.example.test")).status).toBe(403);
    expect(sessions.isLive(session.id)).toBe(true);
  });

  it("checks local membership and never promotes an existing client session", async () => {
    userinfo = { sub: subject, email, groups: ["readers"] };
    localScopes = ["client"];
    remote.mockImplementation(async (url, init) => {
      const href = String(url);
      if (href.endsWith("openid-configuration")) {
        return Response.json({
          issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
          userinfo_endpoint: `${issuer}/userinfo`, jwks_uri: `${issuer}/jwks`,
        });
      }
      if (href.endsWith("/jwks")) return Response.json({ keys: [publicJwk] });
      if (href.endsWith("/token")) {
        const form = new URLSearchParams(String(init?.body));
        const code = codes.get(form.get("code") ?? "")!;
        codes.delete(form.get("code")!);
        const accessToken = randomBytes(24).toString("base64url");
        accessTokens.set(accessToken, subject);
        return Response.json({
          access_token: accessToken, token_type: "Bearer", expires_in: 3600,
          id_token: await signIdToken({ nonce: code.nonce, groups: ["readers"] }),
        });
      }
      return Response.json(userinfo);
    });
    const { cookie, session } = await login();
    userinfo = { sub: subject, email, groups: ["omb-admins"] };
    localScopes = ["admin", "client"];
    expect((await call("/api/auth/session", cookie)).body).toBe('["client"]');
    localScopes = null;
    expect((await call("/api/auth/session", cookie)).status).toBe(401);
    expect(sessions.isLive(session.id)).toBe(false);
  });

  it("lets oidc membership skip the local allow-list while still enforcing userinfo revocation", async () => {
    const oidcEnv = { ...env, OMB_OIDC_MEMBERSHIP: "oidc" };
    localScopes = null;
    sessions = new SessionRegistry({
      file: join(home, "sessions.json"),
      emailScopes: () => localScopes,
      oidcMembership: oidcSsoConfiguration(oidcEnv)?.oidcMembership === true,
    });
    sessions.onSessionRevoked(closed);
    access = createOidcAccess({
      sessions, cookieName: "session", closeSessionStreams: closed, entitled: () => licensed,
      env: oidcEnv, now: () => clock, fetchImpl: remote,
    });
    const { cookie, session } = await login();
    expect(session.membershipAuthority).toBe("oidc");
    expect((await call("/api/auth/session", cookie)).body).toBe('["admin","client"]');
    userinfo = null;
    expect((await call("/api/auth/session", cookie)).status).toBe(401);
    expect(sessions.isLive(session.id)).toBe(false);
  });

  it("fails closed during an IdP outage without revoking the session", async () => {
    const { cookie, session } = await login();
    outage = true;
    expect((await call("/api/auth/session", cookie)).status).toBe(503);
    expect(closed).toHaveBeenCalledWith(session.id);
    expect(sessions.isLive(session.id)).toBe(true);
    outage = false;
    expect((await call("/api/auth/session", cookie)).status).toBe(200);
  });

  it("rejects non-OIDC remote sessions while preserving loopback owner access", async () => {
    const paired = sessions.issue({ label: "QR device", scopes: ["admin", "client"] });
    expect((await call("/api/auth/session", `session=${paired.token}`)).status).toBe(401);
    expect(await access.authorize({} as IncomingMessage, { kind: "loopback", scopes: ["admin", "client"] })).toBeNull();
  });

  it("requires a live sso entitlement without blocking the local owner", async () => {
    const { cookie } = await login();
    licensed = false;
    expect((await call("/api/auth/oidc/start")).status).toBe(503);
    expect((await call("/api/auth/session", cookie)).status).toBe(503);
    expect(await access.authorize({} as IncomingMessage, { kind: "loopback", scopes: ["admin", "client"] })).toBeNull();
  });

  it.each([
    { OMB_OIDC_ISSUER: "http://idp.example.test" },
    { OMB_OIDC_CLIENT_ID: "" },
    { OMB_PUBLIC_URL: "http://home.example.test" },
    { OMB_OIDC_MEMBERSHIP: "portal" },
    { OMB_ADMIN_URL: "https://admin.example.test" },
  ])("fails closed with invalid or conflicting configuration: %j", async (patch) => {
    access = createOidcAccess({
      sessions, cookieName: "session", closeSessionStreams: closed, entitled: () => true,
      env: { ...env, ...patch }, fetchImpl: remote,
    });
    expect((await call("/api/auth/oidc/start")).status).toBe(503);
  });
});
