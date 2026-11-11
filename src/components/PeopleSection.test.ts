import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { readMembership } from "../lib/membership";
import {
  inviteLink,
  lastSeenLabel,
  mergePeople,
  orphanDevices,
  OrphanDevices,
  PeopleTable,
  peopleFromSessions,
  PortalPeople,
  type Person,
} from "./PeopleSection";

describe("people helpers", () => {
  it("builds an invite link that opens the sign-in page with the address filled in", () => {
    expect(inviteLink("https://acme.agentada.cc/", "Bob@Acme.test")).toBe("https://acme.agentada.cc/pair?email=Bob%40Acme.test");
    expect(inviteLink("https://acme.agentada.cc", "@acme.test")).toBe("https://acme.agentada.cc/pair");
  });

  it("joins the sign-in list with devices and this month's usage, by address", () => {
    const people = mergePeople(
      { admins: ["Ada@Example.test"], members: ["bob@acme.test", "@acme.test", "ada@example.test"] },
      [
        { id: "a1", label: "Laptop", scopes: ["admin", "client"], email: "ada@example.test", lastSeenAt: 1_000 },
        { id: "a2", label: "Phone", scopes: ["admin", "client"], email: "ADA@example.test", lastSeenAt: 5_000 },
        { id: "orphan", label: "phone", scopes: ["client"], lastSeenAt: 9_000 },
      ],
      [{ key: "user:ada@example.test", turns: 12, costUsd: 3.5 }, { key: "owner", turns: 1, costUsd: 0.1 }],
    );
    expect(people).toEqual([
      {
        entry: "ada@example.test",
        role: "admin",
        isDomain: false,
        lastSeenAt: 5_000,
        devices: 2,
        sessions: [
          { id: "a1", label: "Laptop", scopes: ["admin", "client"], lastSeenAt: 1_000, email: "ada@example.test" },
          { id: "a2", label: "Phone", scopes: ["admin", "client"], lastSeenAt: 5_000, email: "ada@example.test" },
        ],
        turns: 12,
        costUsd: 3.5,
      },
      { entry: "bob@acme.test", role: "member", isDomain: false, lastSeenAt: null, devices: 0, sessions: [], turns: 0, costUsd: null },
      { entry: "@acme.test", role: "member", isDomain: true, lastSeenAt: null, devices: 0, sessions: [], turns: 0, costUsd: null },
    ]);
    expect(orphanDevices([
      { id: "orphan", label: "phone", scopes: ["client"], lastSeenAt: 9_000 },
      { id: "a1", label: "Laptop", scopes: ["admin", "client"], lastSeenAt: 1_000, email: "ada@example.test" },
    ])).toEqual([{ id: "orphan", label: "phone", scopes: ["client"], lastSeenAt: 9_000 }]);
    const estimated = mergePeople({ admins: ["ada@example.test"], members: [] }, [], [{ key: "user:ada@example.test", turns: 2, costUsd: 1.5, estimatedUsd: 0.5 }]);
    expect(estimated[0]).toMatchObject({ costUsd: 1.5, estimated: true, sessions: [] });
    expect(renderToStaticMarkup(createElement(PeopleTable, { people: estimated, busy: false, onRole() {}, onRemove() {}, onLink() {} }))).toContain("~$1.50");
    expect(lastSeenLabel(null)).toBe("Never");
    expect(lastSeenLabel(Date.now() - 60_000)).toBe("Today");
    expect(lastSeenLabel(Date.parse("2026-09-01T12:00:00Z"), Date.parse("2026-09-10T12:00:00Z"))).toBe("2026-09-01");
  });
});

describe("people table", () => {
  const people: Person[] = [
    {
      entry: "ada@example.test",
      role: "admin",
      isDomain: false,
      lastSeenAt: null,
      devices: 2,
      sessions: [
        { id: "a1", label: "Laptop", scopes: ["admin", "client"], lastSeenAt: 1_000, email: "ada@example.test" },
        { id: "a2", label: "Phone", scopes: ["client"], lastSeenAt: 2_000, email: "ada@example.test" },
      ],
      turns: 12,
      costUsd: 3.5,
    },
    { entry: "@acme.test", role: "member", isDomain: true, lastSeenAt: null, devices: 0, sessions: [], turns: 0, costUsd: null },
  ];
  const noop = () => {};

  it("shows role chips, devices, spend, and the actions that fit each row", () => {
    const html = renderToStaticMarkup(createElement(PeopleTable, {
      people,
      busy: false,
      onRole: noop,
      onRemove: noop,
      onLink: noop,
      onSignOutAll: noop,
    }));
    expect(html).toContain("ada@example.test");
    expect(html).toContain("Admin");
    expect(html).toContain("2 device(s)");
    expect(html).toContain("$3.50");
    expect(html).toContain("Never");
    expect(html).toContain("everyone at acme.test");
    expect(html).toContain(">Make user<");
    expect(html).toContain(">Make admin<");
    expect(html).toContain(">Remove<");
    expect(html).toContain("Sign out all devices");
    expect(html).toContain('aria-label="Invite link"');
  });

  it("says so when nobody is on the list", () => {
    expect(renderToStaticMarkup(createElement(PeopleTable, { people: [], busy: false, onRole: noop, onRemove: noop, onLink: noop }))).toContain("Nobody yet");
  });

  it("lists paired devices without email for sign-out and demotion", () => {
    const html = renderToStaticMarkup(createElement(OrphanDevices, {
      devices: [{ id: "p1", label: "Spare laptop", scopes: ["admin", "client"], lastSeenAt: 3_000 }],
      busy: false,
      currentId: null,
      onSignOut: noop,
      onDemote: noop,
      onPromoteBlocked: noop,
    }));
    expect(html).toContain("data-people-orphans");
    expect(html).toContain("Paired devices without email");
    expect(html).toContain("Spare laptop");
    expect(html).toContain(">Make user<");
    expect(html).toContain(">Sign out<");
  });
});

describe("people on a workspace the organisation's Admin manages", () => {
  const url = "https://admin.example.test/people?workspace=acme";

  it("reads who decides membership defensively, defaulting to this server's own list", () => {
    expect(readMembership({ membership: { authority: "portal", pairingCodes: false, peopleUrl: url } })).toEqual({ authority: "portal", pairingCodes: false, remoteSignIn: "portal", peopleUrl: url });
    expect(readMembership({ membership: { authority: "oidc", pairingCodes: false, remoteSignIn: "oidc" } })).toEqual({ authority: "oidc", pairingCodes: false, remoteSignIn: "oidc", peopleUrl: null });
    expect(readMembership({})).toEqual({ authority: "local", pairingCodes: true, remoteSignIn: "pairing", peopleUrl: null });
    expect(readMembership(null)).toEqual({ authority: "local", pairingCodes: true, remoteSignIn: "pairing", peopleUrl: null });
    for (const peopleUrl of ["javascript:alert(1)", "http://admin.example.test/people", "not a url", 7]) {
      expect(readMembership({ membership: { authority: "portal", peopleUrl } }).peopleUrl, String(peopleUrl)).toBeNull();
    }
  });

  it("lists who signed in, by address, with role from their sessions", () => {
    const people = peopleFromSessions(
      [
        { id: "b1", label: "Phone", email: "Bob@acme.test", lastSeenAt: 2_000, scopes: ["client"] },
        { id: "a1", label: "Laptop", email: "ada@acme.test", lastSeenAt: 1_000, scopes: ["admin", "client"] },
        { id: "b2", label: "Tablet", email: "bob@acme.test", lastSeenAt: 7_000, scopes: ["client"] },
        { id: "orphan", label: "QR", lastSeenAt: 9_000, scopes: ["admin", "client"] },
      ],
      [{ key: "user:bob@acme.test", turns: 3, costUsd: 1.25 }],
    );
    expect(people).toEqual([
      {
        entry: "ada@acme.test",
        role: "admin",
        isDomain: false,
        lastSeenAt: 1_000,
        devices: 1,
        sessions: [{ id: "a1", label: "Laptop", scopes: ["admin", "client"], lastSeenAt: 1_000, email: "ada@acme.test" }],
        turns: 0,
        costUsd: null,
      },
      {
        entry: "bob@acme.test",
        role: "member",
        isDomain: false,
        lastSeenAt: 7_000,
        devices: 2,
        sessions: [
          { id: "b1", label: "Phone", scopes: ["client"], lastSeenAt: 2_000, email: "bob@acme.test" },
          { id: "b2", label: "Tablet", scopes: ["client"], lastSeenAt: 7_000, email: "bob@acme.test" },
        ],
        turns: 3,
        costUsd: 1.25,
      },
    ]);
  });

  it("says where people are managed, links there safely, and offers nothing to edit membership", () => {
    const people: Person[] = [{
      entry: "bob@acme.test",
      role: "member",
      isDomain: false,
      lastSeenAt: null,
      devices: 1,
      sessions: [{ id: "b1", label: "Phone", scopes: ["client"], lastSeenAt: 1_000, email: "bob@acme.test" }],
      turns: 3,
      costUsd: 1.25,
    }];
    const html = renderToStaticMarkup(createElement(PortalPeople, {
      peopleUrl: url,
      people,
      orphans: [],
      busy: false,
      currentId: null,
      onSignOutDevice: () => {},
    }));
    expect(html).toContain("data-people-portal");
    expect(html).toContain("People are managed in your organization&#x27;s Admin");
    expect(html).toContain(`href="${url}"`);
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain("Manage people in Admin");
    expect(html).toContain("bob@acme.test");
    expect(html).toContain("$1.25");
    expect(html).not.toMatch(/Make admin|Make user|>Remove<|Invite link|<input|<form|pairing code|ends their account sessions/);
    expect(renderToStaticMarkup(createElement(PortalPeople, {
      peopleUrl: null,
      people: [],
      orphans: [],
      busy: false,
      currentId: null,
      onSignOutDevice: () => {},
    }))).toContain("Nobody has signed in here yet.");
  });
});
