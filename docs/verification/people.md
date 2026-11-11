# Adding people to a hosted workspace

## Sub-features

- Settings → People: who may sign in with an emailed code, their role, when
  each person was last seen, what they spent this month, devices under each
  address, and an invite link per person that opens the sign-in page with the
  address filled in. Paired devices with no email appear in a separate group.
- The owner (or a bootstrap script on the box) names the first admin; from
  then on any admin invites, promotes, demotes and removes people from the
  card. Promotions apply at the next sign-in; removal and lost permissions
  revoke existing account sessions immediately. **Sign out all devices**
  (`DELETE /api/auth/sessions?email=`) ends every local email session for that
  address without removing them from the allow-list. A single device uses
  `DELETE /api/auth/sessions/:id`. An admin-scoped pairing device can be
  demoted in place with `PATCH /api/auth/sessions/:id` `{ "scopes": ["client"] }`;
  promotion never widens an existing credential (mint a new admin pairing
  code under Remote access instead).
- Removing someone also ends their open account streams and stream tickets.
  Independently paired devices are listed on the People card and can still be
  managed under Remote access (which mints pairing codes).

- On a workspace whose members the organization's Admin manages
  (`OMB_ADMIN_MEMBERSHIP=portal`) the card is read-only for membership: who
  has signed in, what they spent, and a **Manage people in Admin** link
  (`<OMB_ADMIN_URL>/people?workspace=<slug>`, from `GET /api/config`
  `membership.peopleUrl`). Device sign-out on this installation remains
  available. Remote access there lists signed-in devices and offers no
  pairing code, since a hosted workspace refuses them.

## Driving it

```sh
pnpm exec vitest run server/people-invite.test.ts server/email-signin.test.ts server/sessions.test.ts src/components/PeopleSection.test.ts src/lib/session.test.ts
```

`server/people-invite.test.ts` boots the real server with no sign-in list and a
stubbed control plane, then walks the card's own requests: the owner adds the
first admin, the admin signs in with the emailed code and invites a user,
the user's link serves the sign-in page, the user gets a chat-only cookie
session and cannot change the list, a promotion applies to the next sign-in
while the device already issued keeps its scopes, a removal refuses new
sign-ins and revokes all old account cookies and tickets, a `@domain` entry
welcomes everyone there and nobody at a look-alike domain, an admin can sign
out every device for an address without removing them, and can demote a
paired device without widening scopes on PATCH.

In the served UI, on a server with a public address: open Settings → People
(the profile menu at the bottom of the sidebar, then Settings), type an
address, pick a role, press Invite. The address appears in the table and the
invite link shows above it. Open that link in another browser: the sign-in
page has the address filled in and the address is gone from the address bar;
the code arrives by email; after it, the app opens as that person and the
People card (Refresh) shows their device and "Today". Expand the row to sign
out one device, or use **Sign out all devices**. Remove them: they drop from
the table at once, a new sign-in for them is refused, and their current
account sessions end. Reinviting them requires a fresh sign-in; old cookies
do not regain access. Pairing-code devices without email appear under
**Paired devices without email**.

## Not proven here

The real emailed code comes from the control plane, so a live run needs an
address you can read. Removing the last admin is allowed and turns email
sign-in off until someone on the box, or an independently paired
administrator, adds an entry again.
