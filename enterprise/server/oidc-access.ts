// Self-hosted OIDC SSO: the home is the RP. Opt-in via OMB_OIDC_*; exclusive
// remote sign-in; mutually exclusive with the hosted portal adapter.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import {
  oidcSsoConfiguration,
  type OidcSsoConfiguration,
  type WorkspaceAccess,
  type WorkspaceAccessOptions,
} from "../../server/enterprise.ts";
import { isAllowedOrigin, isLoopbackHost, isProxied, parseCookies, requestSource, serializeSessionCookie } from "../../server/request-auth.ts";
import { cookieMaxAgeSeconds, type Scope, type SessionRecord } from "../../server/sessions.ts";

const START = "/api/auth/oidc/start";
const CALLBACK = "/api/auth/oidc/callback";
const TTL_MS = 300_000;
const MAX_PENDING = 1_000;
const START_WINDOW_MS = 60_000;
const STARTS_PER_SOURCE = 20;
const DISCOVERY_TTL_MS = 300_000;
const unavailable = { status: 503 as const, error: "Workspace sign-in is unavailable. Try again shortly." };
const denied = { status: 401 as const, error: "Workspace access ended. Sign in again." };

type Discovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  issuer: string;
};

type Pending = { verifier: string; nonce: string; expiresAt: number };
type Observed = { session: SessionRecord; accessToken: string };

function equal(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function claimList(value: unknown): string[] {
  if (typeof value === "string") return value.trim() ? [value.trim()] : [];
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0).map((entry) => entry.trim());
}

function scopesFor(claims: Record<string, unknown>, adminGroups: readonly string[]): Scope[] {
  if (!adminGroups.length) return ["client"];
  const groups = new Set([...claimList(claims.groups), ...claimList(claims.roles)]);
  return adminGroups.some((group) => groups.has(group)) ? ["admin", "client"] : ["client"];
}

function emailOf(claims: Record<string, unknown>): string | null {
  const email = claims.email;
  if (typeof email !== "string" || email.length > 320 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return null;
  return email.toLowerCase();
}

function parseDiscovery(body: unknown, issuer: string): Discovery | null {
  if (!body || typeof body !== "object") return null;
  const record = body as Record<string, unknown>;
  const fields = ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "issuer"] as const;
  for (const field of fields) {
    if (typeof record[field] !== "string" || !String(record[field]).startsWith("https://")) return null;
  }
  if (record.issuer !== issuer && record.issuer !== `${issuer}/`) return null;
  return {
    authorization_endpoint: record.authorization_endpoint as string,
    token_endpoint: record.token_endpoint as string,
    userinfo_endpoint: record.userinfo_endpoint as string,
    jwks_uri: record.jwks_uri as string,
    issuer: record.issuer as string,
  };
}

export function createOidcAccess(options: WorkspaceAccessOptions): WorkspaceAccess {
  const env = options.env ?? process.env;
  const now = options.now ?? Date.now;
  const fetchImpl = options.fetchImpl ?? fetch;
  const config = oidcSsoConfiguration(env);
  const cookieName = `__Host-${options.cookieName}_oidc`;
  const pending = new Map<string, Pending>();
  const starts = new Map<string, { count: number; expiresAt: number }>();
  const observed = new Map<string, Observed>();
  let discovery: { value: Discovery; expiresAt: number } | null = null;
  let jwks: ReturnType<typeof createLocalJWKSet> | null = null;
  let checking = false;

  const clearCookie = () => serializeSessionCookie(cookieName, "", { secure: true, maxAgeSeconds: 0 });
  const tenantHost = (req: IncomingMessage) => config !== null && req.headers.host?.toLowerCase() === config.tenant.host;
  const localOwner = (req: IncomingMessage) => !isProxied(req) && isLoopbackHost(req.headers.host) && isAllowedOrigin(typeof req.headers.origin === "string" ? req.headers.origin : undefined);
  const redirect = (res: ServerResponse, to: string) => {
    res.writeHead(302, { location: to, "cache-control": "no-store", "referrer-policy": "no-referrer" });
    res.end();
  };
  const failurePage = (res: ServerResponse, status: number, message = "Workspace sign-in could not finish.") => {
    res.setHeader("set-cookie", clearCookie());
    res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer" });
    res.end(`<!doctype html><title>Workspace sign-in</title><p>${message}</p><a href="${START}">Try signing in again</a>`);
  };

  const loadDiscovery = async (cfg: OidcSsoConfiguration): Promise<Discovery | null> => {
    if (discovery && discovery.expiresAt > now() && jwks) return discovery.value;
    try {
      const response = await fetchImpl(new URL("/.well-known/openid-configuration", cfg.issuer), {
        method: "GET", credentials: "omit", redirect: "error", signal: AbortSignal.timeout(5_000),
        headers: { accept: "application/json" },
      });
      if (!response.ok) return null;
      const parsed = parseDiscovery(await response.json(), cfg.issuer.origin);
      if (!parsed || !options.entitled()) return null;
      const keysResponse = await fetchImpl(parsed.jwks_uri, {
        method: "GET", credentials: "omit", redirect: "error", signal: AbortSignal.timeout(5_000),
        headers: { accept: "application/json" },
      });
      if (!keysResponse.ok) return null;
      const keySet = await keysResponse.json() as JSONWebKeySet;
      if (!Array.isArray(keySet.keys) || keySet.keys.length === 0) return null;
      jwks = createLocalJWKSet(keySet);
      discovery = { value: parsed, expiresAt: now() + DISCOVERY_TTL_MS };
      return parsed;
    } catch { return null; }
  };

  const userinfo = async (cfg: OidcSsoConfiguration, meta: Discovery, accessToken: string): Promise<Record<string, unknown> | null | "outage"> => {
    try {
      const response = await fetchImpl(meta.userinfo_endpoint, {
        method: "GET", credentials: "omit", redirect: "error", signal: AbortSignal.timeout(5_000),
        headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      });
      if (response.status === 401 || response.status === 403) return null;
      if (!response.ok) return "outage";
      const body = await response.json() as unknown;
      return body && typeof body === "object" ? body as Record<string, unknown> : null;
    } catch { return "outage"; }
  };

  const check = async (entry: Observed) => {
    if (!options.sessions.isLive(entry.session.id)) { observed.delete(entry.session.id); return denied; }
    if (!config || !options.entitled()) return unavailable;
    const meta = await loadDiscovery(config);
    if (!meta) {
      options.closeSessionStreams(entry.session.id);
      return unavailable;
    }
    const claims = await userinfo(config, meta, entry.accessToken);
    if (claims === "outage") {
      options.closeSessionStreams(entry.session.id);
      return unavailable;
    }
    if (!claims) {
      options.sessions.revoke(entry.session.id);
      observed.delete(entry.session.id);
      return denied;
    }
    const email = emailOf(claims);
    const subject = typeof claims.sub === "string" ? claims.sub : "";
    const nextScopes = scopesFor(claims, config.adminGroups);
    if (!email || !subject || entry.session.userId !== `oidc:${subject}` || email !== entry.session.email?.toLowerCase()
      || entry.session.scopes.some((scope) => !nextScopes.includes(scope))) {
      options.sessions.revoke(entry.session.id);
      observed.delete(entry.session.id);
      return denied;
    }
    return options.sessions.isLive(entry.session.id) ? null : denied;
  };

  const access: WorkspaceAccess = {
    async handlePublic(req, res, url) {
      const path = url.pathname;
      if (req.method !== "GET" || !["/", "/pair", START, CALLBACK].includes(path)) return false;
      if ((path === "/" || path === "/pair") && localOwner(req)) return false;
      if (!config || !options.entitled()) { failurePage(res, 503); return true; }
      if (!tenantHost(req)) { failurePage(res, 403); return true; }
      if (path === "/pair") { redirect(res, START); return true; }
      if (path === "/") {
        const token = parseCookies(req.headers.cookie).get(options.cookieName);
        const session = options.sessions.authenticate(token);
        if (session) {
          const failure = await access.authorize(req, { kind: "session", session, scopes: session.scopes, via: "cookie" });
          if (!failure) return false;
          if (failure.status === 503) { failurePage(res, 503, failure.error); return true; }
        }
        redirect(res, START); return true;
      }
      if (path === START) {
        const time = now();
        for (const [state, value] of pending) if (value.expiresAt <= time) pending.delete(state);
        for (const [source, value] of starts) if (value.expiresAt <= time) starts.delete(source);
        const source = requestSource(req), recent = starts.get(source);
        if (pending.size >= MAX_PENDING || (recent?.count ?? 0) >= STARTS_PER_SOURCE || (!recent && starts.size >= MAX_PENDING)) {
          res.writeHead(429, {
            "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer",
            "retry-after": String(START_WINDOW_MS / 1_000),
          });
          res.end("<!doctype html><title>Workspace sign-in</title><p>Too many sign-in attempts. Try again shortly.</p>");
          return true;
        }
        starts.set(source, { count: (recent?.count ?? 0) + 1, expiresAt: recent?.expiresAt ?? time + START_WINDOW_MS });
        const meta = await loadDiscovery(config);
        if (!meta) { failurePage(res, 503); return true; }
        const state = randomBytes(32).toString("base64url");
        const verifier = randomBytes(32).toString("base64url");
        const nonce = randomBytes(32).toString("base64url");
        pending.set(state, { verifier, nonce, expiresAt: time + TTL_MS });
        res.setHeader("set-cookie", serializeSessionCookie(cookieName, `${state}.${verifier}`, { secure: true, maxAgeSeconds: TTL_MS / 1_000 }));
        const target = new URL(meta.authorization_endpoint);
        target.search = new URLSearchParams({
          response_type: "code",
          client_id: config.clientId,
          redirect_uri: new URL(CALLBACK, config.tenant).href,
          scope: "openid email profile",
          state,
          nonce,
          code_challenge: createHash("sha256").update(verifier).digest("base64url"),
          code_challenge_method: "S256",
        }).toString();
        redirect(res, target.href); return true;
      }

      const state = url.searchParams.get("state") ?? "";
      const code = url.searchParams.get("code") ?? "";
      const saved = pending.get(state);
      const cookie = parseCookies(req.headers.cookie).get(cookieName) ?? "";
      if (!saved || saved.expiresAt <= now() || !equal(cookie, `${state}.${saved.verifier}`)
        || !code || code.length > 512 || url.searchParams.getAll("state").length !== 1 || url.searchParams.getAll("code").length !== 1) {
        failurePage(res, 400); return true;
      }
      pending.delete(state);
      res.setHeader("set-cookie", clearCookie());
      const meta = await loadDiscovery(config);
      if (!meta || !jwks) { failurePage(res, 503); return true; }
      let tokenBody: Record<string, unknown>;
      try {
        const form = new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: new URL(CALLBACK, config.tenant).href,
          client_id: config.clientId,
          client_secret: config.clientSecret,
          code_verifier: saved.verifier,
        });
        const response = await fetchImpl(meta.token_endpoint, {
          method: "POST", credentials: "omit", redirect: "error", signal: AbortSignal.timeout(5_000),
          headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
          body: form,
        });
        if (!response.ok || !options.entitled()) { failurePage(res, response.status === 401 ? 401 : 503); return true; }
        tokenBody = await response.json() as Record<string, unknown>;
      } catch { failurePage(res, 503); return true; }
      const idToken = tokenBody.id_token;
      const accessToken = tokenBody.access_token;
      if (typeof idToken !== "string" || typeof accessToken !== "string" || !idToken || !accessToken) {
        failurePage(res, 503); return true;
      }
      let claims: Record<string, unknown>;
      try {
        const verified = await jwtVerify(idToken, jwks, {
          issuer: [config.issuer.origin, `${config.issuer.origin}/`],
          audience: config.clientId,
          algorithms: ["RS256", "ES256"],
          requiredClaims: ["sub", "exp", "iat"],
          clockTolerance: 30,
        });
        if (verified.payload.nonce !== saved.nonce) { failurePage(res, 401); return true; }
        claims = verified.payload as Record<string, unknown>;
      } catch { failurePage(res, 401); return true; }
      const email = emailOf(claims);
      const subject = typeof claims.sub === "string" ? claims.sub : "";
      if (!email || !subject || subject.includes(":") || subject.length > 255) { failurePage(res, 401); return true; }
      const issued = options.sessions.issueOidc({ email, subject, scopes: scopesFor(claims, config.adminGroups) });
      const record = options.sessions.authenticate(issued.token);
      if (!record) { failurePage(res, 403); return true; }
      observed.set(record.id, { session: record, accessToken });
      res.setHeader("set-cookie", [
        clearCookie(),
        serializeSessionCookie(options.cookieName, issued.token, { secure: true, maxAgeSeconds: cookieMaxAgeSeconds(record) }),
      ]);
      redirect(res, "/"); return true;
    },
    async authorize(req, auth) {
      if (auth.kind === "loopback") return null;
      if (!config || !options.entitled()) return unavailable;
      if (!tenantHost(req)) return { status: 403, error: "Use the configured workspace address." };
      if (!auth.session.userId?.startsWith("oidc:") || auth.session.userId.length <= "oidc:".length) return denied;
      const entry = observed.get(auth.session.id);
      if (!entry) {
        // Session survived a restart without its access token: require a fresh sign-in.
        options.sessions.revoke(auth.session.id);
        return denied;
      }
      entry.session = auth.session;
      return check(entry);
    },
    async revalidate() {
      if (checking) return;
      checking = true;
      try { await Promise.all([...observed.values()].map(check)); }
      finally { checking = false; }
    },
  };
  return access;
}
