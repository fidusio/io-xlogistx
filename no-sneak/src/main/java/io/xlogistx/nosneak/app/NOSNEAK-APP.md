# io.xlogistx.nosneak.app

Swing desktop front-end for the NoSneak security tooling. This package contains the
application entry point and a **mock** UI prototype that wires together the screens,
navigation, and a stubbed session/security layer. The mock exists to prove out the UX
and screen flow ahead of binding the real PQC scanner and security backend.

> **Status:** prototype. Most screens are placeholders, and the security/session
> layer is mocked (see `mock/MockSecManager` and `mock.utility.Session`). Nothing here
> talks to the live scanner yet.

## Layout

```
io.xlogistx.nosneak.app
├── Main.java                      ← entry point + top-level JFrame
└── mock/                          ← prototype UI (screens, menu, mock security)
    ├── AppShell.java              ← root content pane, CardLayout host
    ├── LoginPanel.java            ← login/register screen (method + mode toggle)
    ├── PQCRegistryPanel.java      ← PQC file-sharing registry view
    ├── SubjectPanel.java          ← subject account view (master–detail)
    ├── SubjectSecManagerPanel.java← security-manager admin view (master–detail)
    ├── ScanPanel.java             ← network scanner view (placeholder)
    ├── MenuBarFactory.java        ← builds the application menu bar
    ├── MockSecManager.java        ← stub SubjectSecurityManager (zoxweb)
    └── utility/
        ├── AppContext.java        ← per-app service locator (Session + Navigator)
        ├── Session.java           ← auth state + login/register/logout (mock)
        ├── Navigator.java         ← top-level screen switching over a CardLayout
        ├── CardStack.java         ← reusable CardLayout wrapper (in-panel sections)
        └── PanelBuilder.java      ← shared Swing layout helpers
```

## Entry point

### `Main`
Bootstraps the app: installs the FlatLaf **FlatLightLaf** look-and-feel and shows
`Main.AppFrame` on the Swing EDT. The nested `AppFrame` (a `JFrame`, 800×600,
title "NoSneak") creates the single `AppContext`, builds the menu bar via
`MenuBarFactory`, and installs `AppShell` as the content pane. The menu bar starts
hidden and is toggled visible/invisible by subscribing to `session().onAuthChange(...)`
— it only appears once the user is authenticated.

## `mock` — UI screens & wiring

### `AppShell`
The root panel (`BorderLayout`). Hosts a `CardLayout` content area registering one card
per `Navigator.Screen` (`LOGIN`, `MAIN`, `SUBJECT`, `SCAN`, `MANAGER`) plus a footer
status bar. On construction it builds the `Navigator`, registers it on the `AppContext`,
and wires `session().onAuthChange(...)` so that a successful auth navigates to `SUBJECT`
and a logout navigates back to `LOGIN`. The footer (left: `session: … | subject: …`,
right: status) also subscribes to auth changes. Starts on the `LOGIN` screen.

### `LoginPanel`
The authentication screen, registered as the `LOGIN` card. Built on a `GridBagLayout`
with the NoSneak branding (icon/title/wordmark) above the credential area. Two orthogonal
selectors:

- **Method** (a `JToggleButton` group over a `CardStack`): `Subject / Password`,
  `API Key`, `Passkey` — switches which credential card is shown.
- **Mode** (a toggle button): flips between **Login** and **Register**. The mode
  re-labels each method's action button and changes which `Session` call it makes
  (`login*` vs `register*`); it is not a separate set of cards.

`applyMode()` adapts the password card and selectors to the current mode:
- In **Register** mode the password card reveals a **Confirm Password** field;
  submission compares it against the password and blocks (error dialog) on mismatch.
  Switching back to **Login** hides and clears it.
- **API key is login-only**: the API Key selector is hidden in Register mode (you can't
  register with an API key), and selecting it while switching to Register falls back to
  the Password card.
- **Passkey is hidden everywhere** for now (`passkeySelector.setVisible(false)`); its card
  is a "NOT IMPLEMENTED" placeholder.

The password card also has an optional **DomainAppID** field. Field rows are laid out by
`PanelBuilder.buildJPanelWithFields(JComponent...)`.

### `PQCRegistryPanel`
The `MAIN` screen — PQC file-sharing registry. A `JSplitPane` with a `TreeTextWidget`
(file tree, from `io.xlogistx.gui`) on the left and a `JTable` global registry
(columns: *Public Key*, *Documents*) on the right.

### `SubjectPanel`
The `SUBJECT` screen — the signed-in subject's own account view, laid out as a
**master–detail**: a left selector of `JToggleButton`s driving a right-hand `CardStack`,
one card per section. Two sections exist today:

- **Profile** — the real field rows: First/Last name, Username, Email, Date of birth
  (optional), a **Mailing address** block (Street optional, City, State/region, Postal
  code, Country), and a **Save Changes** button. Wrapped in a `JScrollPane`.
- **Login credential** (card key `Credentials`) — currently placeholder buttons plus a
  **+ Add login method** action.

The master–detail shell is assembled by `PanelBuilder.buildDefaultSplitPanel(...)`. The
Simple/Technical toggle and the per-credential nested Edit views are **not built yet** —
see *In progress* below for target behavior. (Note: the subject's identifiers — emails,
usernames, handles — are **folded into Profile** as grouped identifier rows rather than a
separate *Principal IDs* card; the current code renders only a single `Username` and single
`Email`, so the grouped identifier rows are still target behavior, not built.)

### `SubjectSecManagerPanel`
The `MANAGER` screen — an admin view over the security model (the UI front for zoxweb's
`SubjectSecurityManager`). Same **master–detail** shape as `SubjectPanel`
(`JToggleButton` selectors + `CardStack` + `PanelBuilder.buildDefaultSplitPanel`), with
five sections, each a header + description + search bar + `JTable` stub. Each table is
wrapped in a `JScrollPane` so its column header row renders, and each carries a trailing
unlabeled (`""`) actions column reserved for per-row controls (edit/remove):

- **Subjects** — security subjects and their principals, credentials, and grants
  (columns: Name, Primary principal, Owns, ⋯actions).
- **Permissions** — permission definitions, scoped by application/AppID
  (columns: Permission, Description, ⋯actions).
- **Roles** — named bundles of permissions (columns: Role, Description, ⋯actions).
- **Role groups** — bundles of roles granted together (columns: Role Group, Roles, ⋯actions).
- **Grants** — permission/role/role-group grants bound to subjects
  (columns: Subject, Grant Type, Granted, ⋯actions).

All tables are empty `DefaultTableModel` stubs; search and the actions column are not
wired. Reached from **View → Subject Security Manager**.

> Scope distinction: `SubjectPanel` manages **your own** account; `SubjectSecManagerPanel`
> is the **admin** view over all subjects/permissions/roles/grants.

### `ScanPanel`
The `SCAN` screen — network scanner view. Placeholder ("NOT IMPLEMENTED"); intended to
front the NMap/PQC scanning backend.

### `MenuBarFactory`
Builds the application `JMenuBar`: `File`, `View`, `Tools`, `Help`, and a right-aligned
`Mode` menu (with a "Technical Mode" checkbox). **File** has a placeholder *Test* item and
**Logout** (`session().logout()`). The **View** items navigate via the `AppContext`'s
`Navigator` — *Network scanner* → `SCAN`, *PQC file sharing* → `MAIN`, *Subject Profile* →
`SUBJECT`, *Subject Security Manager* → `MANAGER`.

#### Navigation model
The app uses **two independent navigation layers**, deliberately kept separate:

- **Top menu bar (`JMenuBar`)** — app-level destinations. The **View** menu drives the
  `Navigator` between top-level screens: *Network scanner* → `SCAN`, *PQC file sharing* →
  `MAIN`, *Subject Profile* → `SUBJECT`, *Subject Security Manager* → `MANAGER`. (There is
  no separate "Subject" menu; the subject screen is reached from **View → Subject
  Profile**.)
- **Left selector inside a panel** — sub-section switching *within* a screen, via a local
  `CardStack` (e.g. `SubjectPanel`'s Profile / Login credential, or
  `SubjectSecManagerPanel`'s Subjects / Permissions / Roles / Role groups / Grants). This
  is local to the panel and does **not** go through the top-level `Navigator`.

In short: the top menu chooses *which screen*; a panel's left selector chooses *which
section of that screen*. They are separate `CardLayout`s (the in-panel ones wrapped by
`CardStack`).

### `MockSecManager`
A stub implementation of zoxweb's `SubjectSecurityManager`. Every operation
(login, subject/credential/permission/role/role-group CRUD and grants) is a no-op
returning empty/`null`; `login(...)` always throws. Stands in for the real security
manager so the UI can be developed independently.

## `mock.utility` — application services

### `AppContext`
Lightweight per-application service locator. Owns the single `Session` and holds the
`Navigator` (injected by `AppShell` once the card host exists). Accessors: `session()`,
`nav()`, `setNavigator(...)`. Passed down to screens and the menu factory so they share
one session and one navigator.

### `Session`
Mock authentication/session state built on `PropertyChangeSupport`. Tracks
`authenticated` + `subject`, and exposes mock `loginUsernamePassword` / `loginAPIKey` /
`loginPasskey`, matching `register*` variants, and `logout`. `registerUsernamePassword`
runs the candidate through zoxweb's `FilterType.PASSWORD` before delegating to
`loginUsernamePassword`; `registerAPIKey` / `registerPasskey` currently delegate straight
to their `login` counterparts. Each state change fires an `"authenticated"` property
event; listeners subscribe via `onAuthChange(...)` — this is how `AppFrame` toggles the
menu bar and `AppShell` navigates on login/logout.

### `Navigator`
Thin top-level screen-switcher over a `CardLayout`. Defines the `Screen` enum
(`LOGIN, REGISTER, MAIN, SCAN, SUBJECT, MANAGER`) and `show(Screen)` flips the shared
content panel to the matching card (cards are keyed by `Screen.name()`). Note: `REGISTER`
is currently **unused** — register is a *mode* of the `LOGIN` screen, not its own
screen/card.

### `CardStack`
A small reusable wrapper around a `CardLayout` + backing `JPanel`, used for **in-panel**
section switching (distinct from the top-level `Navigator`). API: `view()` returns the
card host, `add(Component, name)` registers a card, `show(name)` flips to it. Used by
`LoginPanel` (method cards), `SubjectPanel`, and `SubjectSecManagerPanel` (section cards).

### `PanelBuilder`
Shared Swing layout helpers (formerly `PaneBuilder`):
- `buildHorizontalSplitView(left, right, divLocation, resizeWeight)` — a configured
  `JSplitPane`.
- `buildDefaultSplitPanel(content, JToggleButton...)` — the standard master–detail shell:
  a left sidebar of grouped toggle buttons (a `ButtonGroup`) and the supplied `content` on
  the right, wired through `buildHorizontalSplitView`.
- `buildJPanelWithFields(JComponent...)` — a single-column `GridBagLayout` form stacking
  the given components vertically.

## How it fits together

```
Main.AppFrame
  └─ AppContext ── Session (auth state, PropertyChange events)
                └─ Navigator (CardLayout screen switching)
  ├─ MenuBarFactory.buildMenu(ctx)   → View menu drives Navigator; File → Logout
  └─ AppShell(ctx)                   → CardLayout host for all screens
        ├─ LoginPanel           (LOGIN)   → Session.login*/register*  ──┐
        ├─ PQCRegistryPanel     (MAIN)                                  │ onAuthChange
        ├─ SubjectPanel         (SUBJECT)                               │  → nav to SUBJECT
        ├─ SubjectSecManagerPanel (MANAGER)                            │  + show menu bar
        └─ ScanPanel            (SCAN)                                  │  (logout → LOGIN)
                                                              Session ◄─┘
```

The flow is event-driven through `Session`'s property-change events: screens and the
frame react to auth changes rather than calling each other directly, with `AppContext`
providing the shared `Session`/`Navigator` and `Navigator` centralizing all top-level
screen transitions (in-panel section transitions go through each panel's own `CardStack`).

## In progress

### Subject Panel — intended behavior (`SubjectPanel`)

> Spec for what the `SUBJECT` screen is meant to do. The current code wires the
> master–detail shell and the *Profile* field rows; *Login credential* is still a
> placeholder section. The subject's identifiers (emails/usernames/handles) are **folded
> into Profile** as grouped identifier rows — there is no separate *Principal IDs* card;
> today the code renders only a single `Username` and single `Email`, so the grouped rows
> below are target behavior. The behaviors below are the target.

Where a signed-in subject views and manages **their own account**. Reached from **View →
Subject Profile** in the top menu bar (also where the app lands on successful auth).
Sections run down the left side; selecting a section changes what's shown on the right.
Everything here is scoped to the signed-in subject — app-wide settings and other areas
(scanner, file sharing, the security-manager admin view) live elsewhere.

#### Tier toggle (Simple / Technical)
> Target behavior. **Not wired yet:** the `Mode` menu's "Technical Mode"
> `JCheckBoxMenuItem` (in `MenuBarFactory`) exists but has no action listener, and
> `SubjectPanel` has no toggle at all.

The intent is a **single Technical-mode flag**, reflected in two places that stay in sync:
the `Mode` menu checkbox and a top-right toggle in `SubjectPanel`.

Behavior contract: **Technical** reveals underlying detail (schema field names, `NS*`
tokens, SPKI fingerprints, KEM/algorithm specifics); **Simple** hides them. It is
**presentational only** — it changes *how much is shown*, never *what you can do*; it
never gates capability.

#### Profile
Basic account details plus the subject's identifiers, all on one card.
- **First name**, **Last name** — editable.
- **Identifiers (Principal IDs)** — the emails, usernames, and handles that identify this
  subject (maps to `PrincipalInfo`, resolving to the subject), folded into Profile as
  **grouped rows** rather than a separate section. A subject can have more than one — this
  is how they sign in / are addressed under multiple identifiers while remaining one
  account.
  - Each entry shows the address/handle and its status (primary, alias, verified).
  - **Edit** adjusts an existing entry.
  - **Add identifier** registers a new email/username/handle, which requires verification
    before it becomes active.
  - At least one **email** identifier is required (changeable, not clearable); changing or
    adding one triggers a verification step rather than saving silently. *(Current code
    renders a single `Username` and single `Email` field — the grouped multi-identifier
    rows are target behavior.)*
- **Date of birth** — optional, editable.
- **Mailing address** (Street optional, City, State/region, Postal code, Country) —
  optional postal address for billing or shipping.
- **Canonical ID** — a stable lookup key; if surfaced, changes are gated (admin-only /
  uniqueness-checked) to avoid breaking references. *(Not currently rendered.)*

A **Save changes** button commits edits. System-managed fields (GUIDs, timestamps) are
not surfaced on this screen.

#### Login credentials
The different ways a subject can sign in. A subject can register more than one and mix
types.

- **Password** — never displayed (cannot be shown or recovered). The only action is to
  replace it: enter current password, then the new one twice to confirm.
- **Passkey** (hardware key / device biometrics) — shows the registered device and when
  it was last used; can be removed. Nothing secret is shown (only the public key is
  stored).
- **API key** (for apps/services) — shown masked by default (`nsk_live_••••…`).
  **Reveal** (eye icon) shows the full key; **Copy** copies it; **Rotate** issues a new
  key and immediately invalidates the old one; **Revoke** disables it.

**Security model (contract):**
- **Password** — **write-only** from the UI's perspective. Never displayed or recovered;
  the only operation is *replace* (current + new + confirm). Stored as a verifier.
- **API key** — a **retrievable shared secret**: masked by default, with **Reveal**,
  **Copy**, **Rotate** (issues new + invalidates old), **Revoke**.
- **Passkey** — only the **public key** is held; nothing secret is shown. Manage = view
  device + remove.

> Key distinction: a **password** is a one-way secret NoSneak only verifies and can never
> show; an **API key** is a retrievable-shared secret you can view, copy, and rotate.

> Note: reveal-on-demand for API keys implies the backend retains the raw secret. An
> alternative (show-once-at-creation + store a hash) is a design decision still open.

**Add login method** lets a subject register an additional password, passkey, or API key.

#### Summary
The Subject panel lets a subject (1) edit profile details — including the multiple
identifiers (Principal IDs) pointing to their account, folded into Profile as grouped rows
(email changes verified, canonical ID protected) — and (2) manage how they sign in — update password, manage passkeys, and
view/rotate API keys.

## Needed fixes / updates

Tracked work items for the `mock` UI.

### Register flow (`LoginPanel` / `Session`)
- **Password filter / validation.** `Session.registerUsernamePassword` already gates on
  `FilterType.PASSWORD`, but a failed filter currently fails **silently** — surface the
  failure to the user (error dialog) and keep them on the register form.
- **Confirmation warning on Register.** Clicking **Register** must prompt a confirmation
  dialog before proceeding (e.g. "Register using this email / username?").

### Method availability (`LoginPanel`)
- **API key is add-only, never register.** Registration via API key is already removed
  from the UI; API keys are *attached* to an existing account from the Subject panel's
  *Login credentials*, not created at registration.
- **Passkey hidden everywhere.** The Passkey method is not implemented — it stays hidden in
  **both** login and register modes via `passkeySelector.setVisible(false)` until built
  out.

### Subject panel (`SubjectPanel`)
- **Tier toggle not wired.** The `Mode` menu's "Technical Mode" `JCheckBoxMenuItem` has no
  action listener, and `SubjectPanel` has no toggle. Add the toggle, back both controls
  with a single shared Technical-mode flag, and make Simple/Technical actually
  show/hide the underlying detail (per the *Tier toggle* contract above).
- **Profile is static.** The field rows render but nothing is wired: **Save Changes** is a
  no-op, Email changes don't trigger verification, and Canonical ID is not yet surfaced as
  a gated/read-only field.
- **Identifiers (Principal IDs) folded into Profile, not yet built.** Profile currently
  renders a single `Username` and single `Email`. Replace them with grouped identifier
  rows (email/username/handle + status: primary/alias/verified), wire **Edit**, and make
  **+ Add identifier** create an entry that requires verification. This is folded into the
  Profile card — there is no separate *Principal IDs* section.
- **Login credentials is placeholder.** Replace the placeholder buttons with real
  credential rows and the nested per-credential detail views (password replace; passkey
  view-device/remove; API-key reveal/copy/rotate/revoke) reached via **Edit** with a
  back-link, plus **+ Add login method**.

### Subject Security Manager (`SubjectSecManagerPanel`)
- **All tables are empty stubs** and **search is not wired.** Bind the Subjects /
  Permissions / Roles / Role groups / Grants tables to real data and make the per-section
  search bars filter, once `MockSecManager` is replaced with a real backend.

> These are UI/UX gaps in the prototype; the underlying `Session.register*` methods are
> still mocks and `MockSecManager` is a no-op stub, so all of the above will need real
> backend wiring alongside the UI work.