# Self-hosted OIDC SSO

This recipe covers the enterprise `sso` adapter that turns a self-hosted home
into an OpenID Connect relying party. It never talks to a live identity
provider or the operator's production data: tests substitute the IdP through
`fetchImpl` and run against an isolated temporary data directory.

## Configuration

| Variable | Required | Notes |
| --- | --- | --- |
| `OMB_LICENSE_KEY` | yes | must include the `sso` entitlement |
| `OMB_OIDC_ISSUER` | yes | HTTPS issuer origin |
| `OMB_OIDC_CLIENT_ID` | yes | confidential client |
| `OMB_OIDC_CLIENT_SECRET` | yes | kept only in the process environment |
| `OMB_PUBLIC_URL` | yes | exact HTTPS tenant origin |
| `OMB_OIDC_ADMIN_GROUPS` | no | comma-separated; match `groups` or `roles` for `admin` |
| `OMB_OIDC_MEMBERSHIP` | no | `local` (default) or `oidc` |

Register `{OMB_PUBLIC_URL}/api/auth/oidc/callback` on the IdP, with scopes
`openid email profile` (plus whatever claim carries groups). Any partial
`OMB_OIDC_*` opts the server into exclusive remote SSO and fails closed until
the set is complete and licensed. Hosted portal variables (`OMB_ADMIN_*`) must
not be set on the same process.

## Protocol

1. `GET /api/auth/oidc/start` allocates bounded PKCE state, sets a
   `__Host-…_oidc` cookie, discovers the issuer, and redirects to the
   authorization endpoint with `code_challenge` and `nonce`.
2. `GET /api/auth/oidc/callback` validates state and cookie, exchanges the
   code, verifies the `id_token` (issuer, audience, expiry, nonce) against
   the IdP JWKS, maps groups to scopes, and issues `userId: oidc:<sub>`.
3. Authenticated remote requests re-check membership at the IdP
   `userinfo_endpoint`. Revocation or demotion ends the session; an IdP
   outage returns `503` and closes streams without treating the outage as
   permanent removal.
4. Remote pairing and email OTP routes return `403`. Loopback without a
   session is service trust unless `OMB_LOOPBACK_TRUST=owner`.

## Isolated tests

```sh
pnpm exec vitest run enterprise/server/oidc-access.test.ts server/enterprise.test.ts
```

The OIDC suite covers happy-path PKCE, host binding, group→scope mapping,
local allow-list narrowing, `OMB_OIDC_MEMBERSHIP=oidc`, outage recovery,
entitlement withdrawal, and conflict with hosted portal configuration.
Core `server/enterprise.test.ts` covers configuration probing and the
dynamic `createOidcAccess` factory hook.
