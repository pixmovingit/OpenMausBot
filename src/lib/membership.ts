export interface Membership {
  authority: "local" | "portal" | "oidc";
  pairingCodes: boolean;
  remoteSignIn: "pairing" | "portal" | "oidc";
  peopleUrl: string | null;
}

export function readMembership(config: unknown): Membership {
  const raw = config && typeof config === "object" ? (config as { membership?: unknown }).membership : undefined;
  const value = raw && typeof raw === "object"
    ? raw as { authority?: unknown; pairingCodes?: unknown; peopleUrl?: unknown; remoteSignIn?: unknown }
    : {};
  let peopleUrl: string | null = null;
  if (typeof value.peopleUrl === "string") {
    try {
      if (new URL(value.peopleUrl).protocol === "https:") peopleUrl = value.peopleUrl;
    } catch {
      peopleUrl = null;
    }
  }
  const authority = value.authority === "portal" || value.authority === "oidc" ? value.authority : "local";
  const remoteSignIn = value.remoteSignIn === "portal" || value.remoteSignIn === "oidc" || value.remoteSignIn === "pairing"
    ? value.remoteSignIn
    : authority === "portal" ? "portal" : authority === "oidc" ? "oidc" : value.pairingCodes === false ? "portal" : "pairing";
  return { authority, pairingCodes: value.pairingCodes !== false, remoteSignIn, peopleUrl };
}
