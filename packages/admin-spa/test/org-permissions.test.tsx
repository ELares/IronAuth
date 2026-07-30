// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The permission surfaces (issue #98), exercised through the ONE typed client with a
// stubbed fetch so every assertion is a concrete URL, body, or DOM node.
//
// Covered here, and grouped by the thing each group is actually guarding:
//
//   The permissions ONE ROLE grants: the list, the attach, the detach addressed by
//   the (role, permission) PAIR rather than by the mapping row id, and the verbatim
//   422 when the permission is not a live entry of this environment.
//
//   The DEFAULT ROLE designation: the current designation read off `is_default`, the
//   PUT that MOVES it, the clear that deletes nothing, and the THREE state reading,
//   because "no role on this page holds it" is not the same statement as "no role
//   holds it" while a next page exists.
//
//   The ENVIRONMENT scoped half: the vocabulary CRUD (whose relabel must never put
//   the immutable `slug` or `kind` on the body) and the per audience claim opt-in
//   (whose write must carry ONLY `permission_claims_enabled`). Plus the placement
//   itself: the organization detail must make no environment scoped permission call,
//   because a vocabulary panel under one organization would misstate what it is.
//
//   The WIDENED malformed-2xx guard on the effective-roles read. This is the load
//   bearing group. The pre issue #98 guard refused to coerce a bad body into an empty
//   role array because that renders a silent authorization DOWNGRADE, and the two
//   fields issue #98 added each have their own version of that reading: a bad
//   permission list must not render as "holds no permissions", and a bad budget must
//   not render as "within budget, the token will carry it all". Both are asserted to
//   fail LOUD, and to fail loud for the RIGHT field.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { LocationProvider } from "preact-iso";
import { Routes } from "../src/app";
import { SECTIONS } from "../src/ui/sections";
import { MembershipRolesPanel } from "../src/ui/MemberRolesView";
import {
  OrgDefaultRolePanel,
  readDefaultRole,
} from "../src/ui/OrgDefaultRoleView";
import { OrgRolePermissionsPanel } from "../src/ui/OrgRolePermissionsView";
import { OrgRolesPanel } from "../src/ui/OrgRolesView";
import { OrganizationDetail } from "../src/ui/OrganizationsView";
import { PermissionsList } from "../src/ui/PermissionsView";
import { activeScope, resetScope } from "../src/scope/store";

interface Call {
  url: string;
  method: string;
  body: string | null;
  idempotencyKey: string | null;
}

const BASE = "http://management.test/admin/api";
const ENV = `${BASE}/v1/tenants/ten_a/environments/env_a`;
const ORG = `${ENV}/organizations/org_a`;

let container: HTMLDivElement | null = null;
const realFetch = globalThis.fetch;

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
}

// Tear the current mount down, for the few tests that mount TWICE to compare two
// server answers. Without it the first container stays in the document holding a
// live component that keeps answering the stub.
function unmountCurrent(): void {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
}

function setManagementBase(url: string): void {
  let el = document.querySelector('meta[name="ironauth-management-base"]');
  if (el === null) {
    el = document.createElement("meta");
    el.setAttribute("name", "ironauth-management-base");
    document.head.appendChild(el);
  }
  el.setAttribute("content", url);
}

function stubFetch(respond: (call: Call) => Response): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = vi.fn(
    async (input: RequestInfo | URL): Promise<Response> => {
      const request = input as Request;
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : request.url;
      const method = input instanceof Request ? request.method : "GET";
      let body: string | null = null;
      let idempotencyKey: string | null = null;
      if (input instanceof Request) {
        const text = await input.clone().text();
        body = text === "" ? null : text;
        idempotencyKey = input.headers.get("idempotency-key");
      }
      const call: Call = { url, method, body, idempotencyKey };
      calls.push(call);
      return respond(call);
    },
  ) as typeof globalThis.fetch;
  return calls;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function noContent(): Response {
  return new Response(null, { status: 204, headers: { "content-length": "0" } });
}

async function flush(): Promise<void> {
  for (let i = 0; i < 6; i += 1) {
    await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }
}

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const found = Array.from(root.querySelectorAll("button")).find(
    (element) => element.textContent === label,
  );
  if (found === undefined) {
    throw new Error(`no button labelled ${label}`);
  }
  return found;
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector(selector) as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

function choose(root: HTMLElement, selector: string, value: string): void {
  const select = root.querySelector(selector) as HTMLSelectElement;
  select.value = value;
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

function rowsOf(root: HTMLElement, label: string): HTMLElement[] {
  const list = root.querySelector(`[aria-label="${label}"]`);
  return list === null ? [] : Array.from(list.querySelectorAll("li"));
}

const SCOPE = {
  tenantId: "ten_a",
  environmentId: "env_a",
  organizationId: "org_a",
};

function makeRole(id: string, slug: string, isDefault: boolean) {
  return {
    id,
    slug,
    display_name: slug,
    organization_id: "org_a",
    metadata: {},
    is_default: isDefault,
    created_at_unix_ms: 0,
    updated_at_unix_ms: 0,
  };
}

const mapping = {
  id: "rpm_a",
  organization_id: "org_a",
  role_id: "rol_a",
  permission_id: "prm_a",
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
};

const permission = {
  id: "prm_a",
  kind: "permission",
  slug: "billing.invoice.read",
  display_name: "Read invoices",
  metadata: {},
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
};

// A SECOND vocabulary entry, so every list assertion below pins a count, an order,
// and one row per entry. With a one item fixture the whole list could be truncated
// to its first row and stay green, which is the failure mode a permission list can
// least afford: an entry that is attached and never shown.
const permissionB = {
  ...permission,
  id: "prm_b",
  slug: "billing.invoice.write",
  display_name: "Write invoices",
};

const resourceServer = {
  id: "rsv_a",
  audience: "https://api.example.test/billing",
  token_format: "at_jwt",
  permission_claims_enabled: false,
  access_token_ttl_secs: null,
  created_at_unix_ms: 0,
};

// A SECOND registered audience, for the same reason, and one that is ALREADY opted
// in: a truncated list would hide an audience that is receiving the claim, which is
// exactly what an operator comes to this panel to find out.
const resourceServerB = {
  ...resourceServer,
  id: "rsv_b",
  audience: "https://api.example.test/reports",
  permission_claims_enabled: true,
};

// A within-budget verdict, and the shape every effective-roles body here builds on.
const BUDGET = {
  permission_count: 0,
  max_permission_count: 64,
  warn_permission_count: 48,
  max_token_bytes: 4096,
  warn_token_bytes: 3072,
  approaching: false,
};

function effective(
  roles: unknown[],
  permissions: unknown = [],
  budget: unknown = undefined,
): unknown {
  const count = Array.isArray(permissions) ? permissions.length : 0;
  return {
    roles,
    permissions,
    permission_budget:
      budget === undefined
        ? { ...BUDGET, permission_count: count }
        : budget,
  };
}

const MEMBER = {
  ...SCOPE,
  membershipId: "omb_a",
  organizationActive: true,
  membershipState: "active",
};

// Mount the member roles panel with a chosen effective-roles body. The direct grants
// half always answers a POPULATED page, so every assertion below can also check that
// a failure in the resolved half did not hide the configuration that is on file.
function openMember(body: unknown): HTMLDivElement {
  stubFetch((call) =>
    call.url.endsWith("/effective-roles")
      ? json(body)
      : json({
          items: [
            {
              id: "mrl_a",
              membership_id: "omb_a",
              role_id: "rol_a",
              organization_id: "org_a",
              created_at_unix_ms: 0,
              updated_at_unix_ms: 0,
            },
          ],
        }),
  );
  return mount(<MembershipRolesPanel {...MEMBER} />);
}

beforeEach(() => {
  setManagementBase(BASE);
  activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
});

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
  globalThis.fetch = realFetch;
  resetScope();
});

describe("the permissions one role grants", () => {
  it("lists a mapping and attaches one at the documented POST with a key", async () => {
    const calls = stubFetch((call) =>
      call.method === "POST" ? json(mapping, 201) : json({ items: [mapping] }),
    );
    const root = mount(<OrgRolePermissionsPanel {...SCOPE} roleId="rol_a" />);
    await flush();

    const rows = rowsOf(root, "Permissions the role grants");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("prm_a");
    // The mapping row id is shown for audit correlation.
    expect(rows[0].textContent).toContain("rpm_a");

    const listsBefore = calls.filter(
      (call) => call.url === `${ORG}/roles/rol_a/permissions` && call.method === "GET",
    ).length;
    type(root, "#org-role-permission-id", "prm_b");
    await flush();
    button(root, "Attach permission").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`${ORG}/roles/rol_a/permissions`);
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ permission_id: "prm_b" });
    // A retried submit must attach it once, so the create is key guarded.
    expect(post?.idempotencyKey).toMatch(/^[0-9a-f]{32}$/);
    expect(root.textContent).toContain("Permission attached to the role.");
    // The list is RE-READ rather than repainted from the request, so what is shown
    // is the stored mapping set and not what this app hoped it would be.
    const listsAfter = calls.filter(
      (call) => call.url === `${ORG}/roles/rol_a/permissions` && call.method === "GET",
    ).length;
    expect(listsAfter).toBeGreaterThan(listsBefore);
    // And the field is CLEARED, so a second submit cannot silently re-attach the id
    // that is still sitting in it.
    const field = root.querySelector(
      "#org-role-permission-id",
    ) as HTMLInputElement;
    expect(field.value).toBe("");
  });

  it("detaches by the (role, permission) PAIR, never by the mapping row id", async () => {
    const calls = stubFetch((call) =>
      call.method === "DELETE" ? noContent() : json({ items: [mapping] }),
    );
    const root = mount(<OrgRolePermissionsPanel {...SCOPE} roleId="rol_a" />);
    await flush();

    button(root, "Detach from role").click();
    await flush();
    // Armed, not fired: a detach is a deliberate two step.
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    // And the prompt says what a detach does and does NOT do: it is the words that
    // stop an operator reading this as deleting the vocabulary entry.
    expect(root.textContent).toContain(
      "Every member who resolves this role stops holding it at the next token issuance",
    );
    expect(root.textContent).toContain(
      "the permission itself stays defined in the environment",
    );

    const listsBefore = calls.filter(
      (call) => call.url === `${ORG}/roles/rol_a/permissions` && call.method === "GET",
    ).length;
    button(root, "Confirm detach from role").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toBe(`${ORG}/roles/rol_a/permissions/prm_a`);
    // The mapping id is carried for audit correlation and no endpoint accepts it.
    expect(del?.url).not.toContain("rpm_a");
    // And the list is re-read, so the detached row leaves the panel.
    const listsAfter = calls.filter(
      (call) => call.url === `${ORG}/roles/rol_a/permissions` && call.method === "GET",
    ).length;
    expect(listsAfter).toBeGreaterThan(listsBefore);
  });

  it("renders one row per mapping even when two carry the same permission id", async () => {
    // What this pins is NO TRUNCATION and no deduplication: two mapping rows on file
    // are two rows on screen. It is deliberately not evidence about the key: measured
    // on this Preact version a duplicate key collapses no row either, so keying these
    // rows by permission_id would leave this green. The property is worth pinning
    // regardless, because a caller that "tidied" the list by unique permission would
    // hide a mapping the detach control addresses.
    stubFetch(() =>
      json({ items: [mapping, { ...mapping, id: "rpm_b" }] }),
    );
    const root = mount(<OrgRolePermissionsPanel {...SCOPE} roleId="rol_a" />);
    await flush();
    const rows = rowsOf(root, "Permissions the role grants");
    expect(rows.length).toBe(2);
    // And they are DISTINGUISHABLE, by the mapping id each carries.
    expect(rows[0].textContent).toContain("rpm_a");
    expect(rows[1].textContent).toContain("rpm_b");
  });

  it("surfaces a more-exist note rather than under-reporting what the role carries", async () => {
    stubFetch(() => json({ items: [mapping], next_cursor: "opaque_rp_2" }));
    const root = mount(<OrgRolePermissionsPanel {...SCOPE} roleId="rol_a" />);
    await flush();
    expect(root.textContent).toContain(
      "More permissions carried by this role exist",
    );
    expect(root.textContent).not.toContain("opaque_rp_2");
  });

  it("says so plainly when the role carries no permissions", async () => {
    stubFetch(() => json({ items: [] }));
    const root = mount(<OrgRolePermissionsPanel {...SCOPE} roleId="rol_a" />);
    await flush();
    expect(root.textContent).toContain("This role carries no permissions");
  });

  it("renders the refusal of a foreign permission verbatim, hostile text staying inert", async () => {
    // The 422 for a permission that is not a live entry of THIS environment is
    // worded by the server; rewording it would cost the operator the reason.
    const hostile = '<img src=x onerror="steal()"> not in this environment';
    stubFetch((call) =>
      call.method === "POST"
        ? json({ error: "unprocessable_entity", message: hostile }, 422)
        : json({ items: [] }),
    );
    const root = mount(<OrgRolePermissionsPanel {...SCOPE} roleId="rol_a" />);
    await flush();
    type(root, "#org-role-permission-id", "prm_elsewhere");
    await flush();
    button(root, "Attach permission").click();
    await flush();

    expect(root.querySelector(".errorbody")).not.toBeNull();
    expect(root.textContent).toContain(hostile);
    expect(root.querySelector("img")).toBeNull();
    expect(root.textContent).not.toContain("Permission attached to the role.");
  });

  it("is mounted INSIDE the role detail of the organization view", async () => {
    // The wiring, not the panel: opening a role must read that role's permissions,
    // and nothing must be read for a role the operator has not opened.
    const role = makeRole("rol_a", "billing.admin", false);
    const calls = stubFetch((call) => {
      if (call.url.endsWith("/roles/rol_a/permissions")) {
        return json({ items: [mapping] });
      }
      if (call.url.endsWith("/roles/rol_a")) {
        return json(role);
      }
      return json({ items: [role] });
    });
    const root = mount(<OrgRolesPanel {...SCOPE} />);
    await flush();
    expect(calls.some((call) => call.url.includes("/permissions"))).toBe(false);

    button(root, "billing.admin").click();
    await flush();

    expect(
      calls.some((call) => call.url === `${ORG}/roles/rol_a/permissions`),
    ).toBe(true);
    expect(rowsOf(root, "Permissions the role grants").length).toBe(1);
  });
});

describe("the default role of one organization", () => {
  it("reads the designation off is_default and PUTs a MOVE with no key", async () => {
    // The holder is the SECOND option on purpose. With it first, "the selector starts
    // on the role that holds the designation" is also satisfied by a selector that
    // simply starts on items[0] and never looks at is_default at all.
    let designated = "rol_b";
    const calls = stubFetch((call) =>
      call.method === "PUT"
        ? json(makeRole("rol_a", "billing.admin", true))
        : json({
            items: [
              makeRole("rol_a", "billing.admin", designated === "rol_a"),
              makeRole("rol_b", "support.agent", designated === "rol_b"),
              makeRole("rol_c", "audit.reader", designated === "rol_c"),
            ],
          }),
    );
    const root = mount(<OrgDefaultRolePanel {...SCOPE} />);
    await flush();

    expect(root.textContent).toContain("The default role is support.agent");
    // The selector starts on the role that HOLDS the designation, which is not the
    // first option here.
    const select = root.querySelector("#org-default-role") as HTMLSelectElement;
    expect(select.value).toBe("rol_b");
    // Every role is offered, in the order the server returned them.
    const options = Array.from(select.querySelectorAll("option"));
    expect(options.map((option) => option.value)).toEqual([
      "rol_a",
      "rol_b",
      "rol_c",
    ]);

    const listsBefore = calls.filter(
      (call) => call.url === `${ORG}/roles` && call.method === "GET",
    ).length;
    choose(root, "#org-default-role", "rol_a");
    await flush();
    // The designation the RELOAD will report is rol_c and not the rol_a this session
    // asked for, which is what a second console session designating concurrently
    // looks like from here (the contract even documents the 409 for the race). It is
    // the only arrangement in which the reload and the choice reset are observable:
    // if the write always answered with what was sent, keeping the stale choice and
    // dropping it would look identical.
    designated = "rol_c";
    button(root, "Designate default role").click();
    await flush();

    const put = calls.find((call) => call.method === "PUT");
    expect(put?.url).toBe(`${ORG}/default-role`);
    // What is SENT is what the control DISPLAYS.
    expect(JSON.parse(put?.body ?? "{}")).toEqual({ role_id: "rol_a" });
    // An absolute-value PUT of a single valued property: applying it twice reaches
    // the same state, so the contract documents no Idempotency-Key and none is sent.
    expect(put?.idempotencyKey).toBeNull();
    expect(root.textContent).toContain("Default role designated.");
    // The roles are RE-READ, so the panel reports the STORED designation rather than
    // the one this app just asked for.
    const listsAfter = calls.filter(
      (call) => call.url === `${ORG}/roles` && call.method === "GET",
    ).length;
    expect(listsAfter).toBeGreaterThan(listsBefore);
    expect(root.textContent).toContain("The default role is audit.reader");
    expect(root.textContent).not.toContain("The default role is billing.admin");
    // And the control follows the STORED designation rather than staying pinned at
    // the rol_a this session chose. Note precisely what this does and does not pin:
    // the observable outcome, not the `setChoice(null)` line. The reload flips the
    // boundary back to loading and unmounts the form, so the choice state dies with
    // it either way; removing that line leaves this green, which was measured rather
    // than assumed, and the panel says so where the state is declared.
    const after = root.querySelector("#org-default-role") as HTMLSelectElement;
    expect(after.value).toBe("rol_c");
  });

  it("clears the designation only after an explicit confirm, and says nothing is deleted", async () => {
    let held = true;
    const calls = stubFetch((call) =>
      call.method === "DELETE"
        ? noContent()
        : json({ items: [makeRole("rol_a", "billing.admin", held)] }),
    );
    const root = mount(<OrgDefaultRolePanel {...SCOPE} />);
    await flush();

    button(root, "Clear the designation").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    // The prompt must not read as deleting the role, which is what "clear" beside a
    // role name otherwise suggests.
    expect(root.textContent).toContain(
      "The role and every grant of it stay exactly as they are",
    );

    const listsBefore = calls.filter(
      (call) => call.url === `${ORG}/roles` && call.method === "GET",
    ).length;
    held = false;
    button(root, "Confirm clear the designation").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toBe(`${ORG}/default-role`);
    expect(root.textContent).toContain("Default role designation cleared.");
    // The roles are RE-READ, so the reading above follows the store rather than
    // continuing to name a role that no longer holds the designation.
    const listsAfter = calls.filter(
      (call) => call.url === `${ORG}/roles` && call.method === "GET",
    ).length;
    expect(listsAfter).toBeGreaterThan(listsBefore);
    expect(root.textContent).toContain("No role is designated");
    expect(root.textContent).not.toContain("The default role is billing.admin");
  });

  it("states there is NO default when the whole role list was read, and offers no clear", async () => {
    stubFetch(() =>
      json({ items: [makeRole("rol_a", "billing.admin", false)] }),
    );
    const root = mount(<OrgDefaultRolePanel {...SCOPE} />);
    await flush();
    expect(root.textContent).toContain("No role is designated");
    expect(root.textContent).not.toContain("cannot be read here");
    // A clear in THIS reading is answered 404 by the contract (an organization with
    // no live default role is the same not-found as an absent organization), so
    // offering the control beside a sentence saying there is nothing to clear would
    // be the console disagreeing with itself.
    expect(
      Array.from(root.querySelectorAll("button")).map(
        (element) => element.textContent,
      ),
    ).not.toContain("Clear the designation");
  });

  it("refuses to claim there is no default when roles exist BEYOND the page", async () => {
    // The honest third answer. `is_default` is read off the roles page because the
    // contract has no GET for the designation, and the roles read is keyset
    // paginated, so a designation held by a role further on is not visible here.
    // Reporting "no default" would misstate what every member of the organization
    // resolves.
    stubFetch(() =>
      json({
        items: [makeRole("rol_a", "billing.admin", false)],
        next_cursor: "opaque_roles_2",
      }),
    );
    const root = mount(<OrgDefaultRolePanel {...SCOPE} />);
    await flush();
    expect(root.textContent).toContain("cannot be read here");
    expect(root.textContent).not.toContain("No role is designated");
    expect(root.textContent).not.toContain("opaque_roles_2");
    // The clear IS offered in this reading, unlike the `none` one: a role beyond
    // this page may hold the designation, so clearing is a real action here.
    expect(
      Array.from(root.querySelectorAll("button")).map(
        (element) => element.textContent,
      ),
    ).toContain("Clear the designation");
  });

  it("says so when the organization defines no roles at all", async () => {
    stubFetch(() => json({ items: [] }));
    const root = mount(<OrgDefaultRolePanel {...SCOPE} />);
    await flush();
    expect(root.textContent).toContain("defines no roles yet");
    expect(root.querySelector("#org-default-role")).toBeNull();
  });

  it("is mounted on the organization detail", async () => {
    const calls = stubFetch((call) => {
      if (call.url.endsWith("/organizations/org_a/roles")) {
        return json({ items: [makeRole("rol_a", "billing.admin", true)] });
      }
      if (call.url.includes("/memberships") || call.url.includes("/groups")) {
        return json({ items: [] });
      }
      return json({
        id: "org_a",
        display_name: "Globex",
        active: true,
        tenant_id: "ten_a",
        environment_id: "env_a",
        created_at_unix_ms: 0,
      });
    });
    const root = mount(<OrganizationDetail organizationId="org_a" />);
    await flush();
    expect(calls.some((call) => call.url === `${ORG}/roles`)).toBe(true);
    expect(root.textContent).toContain("The default role is billing.admin");
  });

  it("states on the ROLE detail whether that role holds the designation", async () => {
    // A read only row, and the qualifier on it is load bearing: resolution needs a
    // live enabled organization AND an active membership, so "every member" would
    // overstate it in exactly the way every other string on these surfaces is
    // careful not to.
    async function openRole(isDefault: boolean): Promise<HTMLDivElement> {
      const role = makeRole("rol_a", "billing.admin", isDefault);
      stubFetch((call) => {
        if (call.url.endsWith("/roles/rol_a/permissions")) {
          return json({ items: [] });
        }
        if (call.url.endsWith("/roles/rol_a")) {
          return json(role);
        }
        return json({ items: [role] });
      });
      const root = mount(<OrgRolesPanel {...SCOPE} />);
      await flush();
      button(root, "billing.admin").click();
      await flush();
      return root;
    }

    // The value beside the "Default role" term, read off the definition list rather
    // than off the whole panel, so "yes" and "no" cannot be satisfied by some other
    // word on the page.
    function defaultRoleValue(root: HTMLElement): string {
      const term = Array.from(root.querySelectorAll(".resource-detail dt")).find(
        (element) => element.textContent === "Default role",
      );
      if (term === undefined) {
        throw new Error("the role detail names no Default role row");
      }
      return term.nextElementSibling?.textContent ?? "";
    }

    const held = await openRole(true);
    expect(defaultRoleValue(held)).toBe(
      "yes, every live active member of the organization resolves it",
    );

    unmountCurrent();
    const plain = await openRole(false);
    expect(defaultRoleValue(plain)).toBe("no");
  });

  // The tri-state reading is pure, so it is also pinned without a DOM.
  it("reads the tri-state from one page, and never guesses across the cursor", () => {
    const held = makeRole("rol_a", "billing.admin", true);
    const plain = makeRole("rol_b", "support.agent", false);
    expect(readDefaultRole({ items: [plain, held], nextCursor: null })).toEqual({
      kind: "held",
      role: held,
    });
    // A cursor does not turn a FOUND designation into an unknown one.
    expect(
      readDefaultRole({ items: [held], nextCursor: "opaque" }),
    ).toEqual({ kind: "held", role: held });
    expect(readDefaultRole({ items: [plain], nextCursor: null })).toEqual({
      kind: "none",
    });
    expect(readDefaultRole({ items: [plain], nextCursor: "opaque" })).toEqual({
      kind: "unknown",
    });
  });
});

describe("the ENVIRONMENT scoped permission vocabulary", () => {
  function open(
    respond: (call: Call) => Response | null,
  ): { root: HTMLDivElement; calls: Call[] } {
    const calls = stubFetch((call) => {
      const custom = respond(call);
      if (custom !== null) {
        return custom;
      }
      if (call.url.includes("/resource-servers")) {
        return json({ items: [resourceServer, resourceServerB] });
      }
      if (call.url.endsWith("/permissions/prm_a")) {
        return json(permission);
      }
      return json({ items: [permission, permissionB] });
    });
    const root = mount(<PermissionsList />);
    return { root, calls };
  }

  it("makes ZERO calls when no scope is selected", async () => {
    resetScope();
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<PermissionsList />);
    await flush();
    expect(root.textContent).toContain("Select a tenant and environment");
    expect(calls.length).toBe(0);
  });

  it("lists EVERY vocabulary entry of the ACTIVE environment with slug, kind, and id", async () => {
    const { root, calls } = open(() => null);
    await flush();
    const list = calls.find((call) => call.url === `${ENV}/permissions`);
    expect(list?.method).toBe("GET");
    const rows = rowsOf(root, "Permissions of the environment");
    // One row per entry, in the order the server returned them: a list that dropped
    // its tail would leave an operator believing a slug is undefined here while a
    // role somewhere carries it.
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain("billing.invoice.read");
    expect(rows[0].textContent).toContain("permission");
    expect(rows[0].textContent).toContain("prm_a");
    expect(rows[1].textContent).toContain("billing.invoice.write");
    expect(rows[1].textContent).toContain("prm_b");
    // Every path is fully substituted on every call.
    for (const call of calls) {
      expect(call.url).not.toContain("{");
      expect(call.url).not.toContain("}");
    }
  });

  it("says so plainly when the environment defines no permissions yet", async () => {
    // Asserted POSITIVELY. This string is otherwise only named in a negative, where
    // never rendering it at all would also pass.
    const { root } = open((call) =>
      call.url === `${ENV}/permissions` ? json({ items: [] }) : null,
    );
    await flush();
    expect(root.textContent).toContain(
      "No permissions yet. Define the first one above.",
    );
    expect(rowsOf(root, "Permissions of the environment")).toEqual([]);
  });

  it("defines a permission at the documented POST with a key, sending the slug CASE for case", async () => {
    const { root, calls } = open((call) =>
      call.method === "POST" ? json(permission, 201) : null,
    );
    await flush();
    // A slug the server would refuse is sent with its case and its inner
    // punctuation UNREPAIRED, so the refusal names the rule instead of the console
    // storing a name the operator did not write while a token claim carries it.
    // SURROUNDING whitespace is the one thing that is repaired, which the note says
    // and this pins, because no canonical slug can contain any: trimming it cannot
    // turn a refusal into a different stored value.
    type(root, "#permission-slug", "  Billing.Invoice.Read  ");
    type(root, "#permission-display-name", "Read invoices");
    await flush();
    button(root, "Define permission").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`${ENV}/permissions`);
    expect(JSON.parse(post?.body ?? "{}")).toEqual({
      slug: "Billing.Invoice.Read",
      display_name: "Read invoices",
    });
    expect(post?.idempotencyKey).toMatch(/^[0-9a-f]{32}$/);
    // The note must describe the behavior just measured, both halves of it.
    expect(root.textContent).toContain(
      "Case and inner punctuation are never touched here",
    );
    expect(root.textContent).toContain(
      "Surrounding whitespace is the one exception and is trimmed",
    );
    expect(root.textContent).not.toContain("It is never trimmed");
  });

  it("relabels one entry and NEVER puts the immutable slug or kind on the body", async () => {
    // The server refuses either KEY being present, null included, so a body that
    // carried one would turn every relabel into a 400. And an untouched field is
    // OMITTED rather than sent empty, which is how an RFC 7396 style partial edit
    // says "no change".
    const { root, calls } = open((call) =>
      call.method === "PATCH"
        ? json({ ...permission, display_name: "Read all invoices" })
        : null,
    );
    await flush();
    button(root, "Read invoices").click();
    await flush();

    const detail = calls.find((call) => call.url.endsWith("/permissions/prm_a"));
    expect(detail?.url).toBe(`${ENV}/permissions/prm_a`);

    type(root, "#permission-relabel", "Read all invoices");
    await flush();
    button(root, "Relabel permission").click();
    await flush();

    const patch = calls.find((call) => call.method === "PATCH");
    expect(patch?.url).toBe(`${ENV}/permissions/prm_a`);
    const body = JSON.parse(patch?.body ?? "null") as Record<string, unknown>;
    expect(body).toEqual({ display_name: "Read all invoices" });
    expect("slug" in body).toBe(false);
    expect("kind" in body).toBe(false);
  });

  it("OMITS an untouched label rather than PATCHing it empty", async () => {
    const { root, calls } = open((call) =>
      call.method === "PATCH" ? json(permission) : null,
    );
    await flush();
    button(root, "Read invoices").click();
    await flush();
    const field = root.querySelector("#permission-relabel") as HTMLInputElement;
    expect(field.value).toBe("Read invoices");

    button(root, "Relabel permission").click();
    await flush();
    const patch = calls.find((call) => call.method === "PATCH");
    expect(JSON.parse(patch?.body ?? "null")).toEqual({});
  });

  it("deletes an entry only after an explicit confirm, saying what stops", async () => {
    const { root, calls } = open((call) =>
      call.method === "DELETE" ? noContent() : null,
    );
    await flush();
    button(root, "Read invoices").click();
    await flush();

    button(root, "Delete permission").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    expect(root.textContent).toContain(
      "Every role in every organization of this environment stops carrying it",
    );

    button(root, "Confirm delete permission").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toBe(`${ENV}/permissions/prm_a`);
  });

  it("surfaces a more-exist note rather than dropping the tail of the vocabulary", async () => {
    const { root } = open((call) =>
      call.url === `${ENV}/permissions`
        ? json({ items: [permission], next_cursor: "opaque_perm_2" })
        : null,
    );
    await flush();
    expect(root.textContent).toContain("More permissions exist");
    expect(root.textContent).not.toContain("opaque_perm_2");
  });

  it("is NOT a panel of the organization detail", async () => {
    // The placement claim, asserted rather than asserted in prose. One vocabulary is
    // shared by every organization in the environment, so a panel under one
    // organization would tell the operator the entries belong to it. The detail must
    // therefore make no environment scoped permission or resource-server call.
    const calls = stubFetch((call) => {
      if (call.url.includes("/memberships") || call.url.includes("/groups")) {
        return json({ items: [] });
      }
      if (call.url.endsWith("/organizations/org_a/roles")) {
        return json({ items: [] });
      }
      return json({
        id: "org_a",
        display_name: "Globex",
        active: true,
        tenant_id: "ten_a",
        environment_id: "env_a",
        created_at_unix_ms: 0,
      });
    });
    mount(<OrganizationDetail organizationId="org_a" />);
    await flush();
    expect(calls.some((call) => call.url === `${ENV}/permissions`)).toBe(false);
    expect(calls.some((call) => call.url === `${ENV}/resource-servers`)).toBe(
      false,
    );
  });
});

describe("the permission claim opt-in per audience", () => {
  function open(
    respond: (call: Call) => Response | null,
  ): { root: HTMLDivElement; calls: Call[] } {
    const calls = stubFetch((call) => {
      const custom = respond(call);
      if (custom !== null) {
        return custom;
      }
      if (call.url.includes("/resource-servers")) {
        return json({ items: [resourceServer, resourceServerB] });
      }
      return json({ items: [] });
    });
    const root = mount(<PermissionsList />);
    return { root, calls };
  }

  it("lists EVERY resource server by audience, id, token format, and current opt-in", async () => {
    const { root, calls } = open(() => null);
    await flush();
    expect(
      calls.some((call) => call.url === `${ENV}/resource-servers`),
    ).toBe(true);
    const rows = rowsOf(root, "Resource servers of the environment");
    // One row per registered audience, in the order the server returned them. A
    // truncated list would hide an audience that IS receiving the claim, which is
    // the one thing an operator opens this panel to find out.
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain("https://api.example.test/billing");
    expect(rows[0].textContent).toContain("rsv_a");
    expect(rows[0].textContent).toContain("at_jwt");
    expect(rows[0].textContent).toContain("permission claim disabled");
    expect(rows[1].textContent).toContain("https://api.example.test/reports");
    expect(rows[1].textContent).toContain("rsv_b");
    // And the two rows read DIFFERENTLY, so the status is read per row rather than
    // painted once from the first one.
    expect(rows[1].textContent).toContain("permission claim enabled");
    expect(rows[1].textContent).not.toContain("permission claim disabled");
  });

  it("surfaces a more-exist note rather than dropping the tail of the audiences", async () => {
    const { root } = open((call) =>
      call.url.includes("/resource-servers")
        ? json({
            items: [resourceServer, resourceServerB],
            next_cursor: "opaque_rsv_2",
          })
        : null,
    );
    await flush();
    expect(root.textContent).toContain("More resource servers exist");
    expect(root.textContent).not.toContain("opaque_rsv_2");
  });

  it("enables the claim with a body carrying ONLY permission_claims_enabled", async () => {
    // The three read-only fields are refused if PRESENT AT ALL, null included, and
    // that refusal is deliberate: a caller who believed they had also changed the
    // token format must not be told 200. So this app sends the one editable key.
    const { root, calls } = open((call) =>
      call.method === "PATCH"
        ? json({ ...resourceServer, permission_claims_enabled: true })
        : null,
    );
    await flush();
    button(root, "Enable the claim").click();
    await flush();

    const patch = calls.find((call) => call.method === "PATCH");
    expect(patch?.url).toBe(`${ENV}/resource-servers/rsv_a`);
    const body = JSON.parse(patch?.body ?? "null") as Record<string, unknown>;
    expect(body).toEqual({ permission_claims_enabled: true });
    expect("token_format" in body).toBe(false);
    expect("audience" in body).toBe(false);
    expect("access_token_ttl_secs" in body).toBe(false);
    // The list is RE-READ rather than the row being repainted from the request, so
    // what is shown is the stored state and not what this app hoped it would be.
    expect(
      calls.filter((call) => call.url === `${ENV}/resource-servers`).length,
    ).toBeGreaterThan(1);
  });

  it("disables the claim only after a confirm that says nothing about who holds what changes", async () => {
    const { root, calls } = open((call) => {
      if (call.method === "PATCH") {
        return json(resourceServer);
      }
      if (call.url.includes("/resource-servers")) {
        return json({
          items: [{ ...resourceServer, permission_claims_enabled: true }],
        });
      }
      return null;
    });
    await flush();

    button(root, "Disable the claim").click();
    await flush();
    expect(calls.some((call) => call.method === "PATCH")).toBe(false);
    expect(root.textContent).toContain(
      "Nothing about who holds which permission changes",
    );

    button(root, "Confirm disable the claim").click();
    await flush();
    const patch = calls.find((call) => call.method === "PATCH");
    expect(JSON.parse(patch?.body ?? "null")).toEqual({
      permission_claims_enabled: false,
    });
  });

  it("renders the opaque-token refusal verbatim rather than guessing it locally", async () => {
    // Whether a token format can carry a claim is the servers answer, given as a
    // typed 422. The console does not pre-judge it, so the operator reads the rule.
    const hostile = '<img src=x onerror="steal()"> opaque tokens carry no claims';
    const { root } = open((call) => {
      if (call.method === "PATCH") {
        return json({ error: "unprocessable_entity", message: hostile }, 422);
      }
      if (call.url.includes("/resource-servers")) {
        return json({
          items: [{ ...resourceServer, token_format: "opaque" }],
        });
      }
      return null;
    });
    await flush();
    button(root, "Enable the claim").click();
    await flush();

    expect(root.querySelector(".errorbody")).not.toBeNull();
    expect(root.textContent).toContain(hostile);
    expect(root.querySelector("img")).toBeNull();
    expect(root.textContent).not.toContain("Permission claim enabled");
  });

  it("says so when no resource server is registered", async () => {
    const { root } = open((call) =>
      call.url.includes("/resource-servers") ? json({ items: [] }) : null,
    );
    await flush();
    expect(root.textContent).toContain(
      "No resource servers are registered in this environment",
    );
  });
});

describe("the permission union and the budget verdict on a member", () => {
  it("lists the whole resolved permission set and the element budget", async () => {
    const root = openMember(
      effective(
        [{ slug: "billing.admin", source: "direct" }],
        ["billing.invoice.read", "billing.invoice.write"],
      ),
    );
    await flush();
    const rows = rowsOf(root, "Effective permissions");
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain("billing.invoice.read");
    expect(rows[1].textContent).toContain("billing.invoice.write");
    expect(root.textContent).toContain("2 of at most 64");
    // The byte bounds are CONTEXT, and the panel says the verdict is the element
    // count only, so "within budget" is never read as covering the token size.
    expect(root.textContent).toContain("the byte verdict belongs to the token mint");
  });

  it("does not hide a permission set behind an empty role list", async () => {
    // The permission half renders ALONGSIDE the empty roles note rather than inside
    // the branch it replaces, so a set that is somehow non empty is still shown.
    const root = openMember(effective([], ["billing.invoice.read"]));
    await flush();
    expect(root.textContent).toContain("resolves no roles in this organization");
    expect(rowsOf(root, "Effective permissions").length).toBe(1);
  });

  it("renders one row per listed permission even when a slug repeats", async () => {
    // Truncation and deduplication, not the key: a duplicate key collapses no row
    // under either keying strategy here, which was measured rather than assumed.
    const root = openMember(
      effective([], ["billing.invoice.read", "billing.invoice.read"]),
    );
    await flush();
    expect(rowsOf(root, "Effective permissions").length).toBe(2);
  });

  it("labels a DEFAULT role path as the designation, never as a direct grant", async () => {
    // A `default` path is carried by the designation and no withdrawal on this
    // surface removes it, so calling it "granted directly" would send an operator
    // looking for a row that does not exist.
    const root = openMember(
      effective([{ slug: "base.member", source: "default" }]),
    );
    await flush();
    const rows = rowsOf(root, "Effective role grant paths");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("the default role of the organization");
    expect(rows[0].textContent).not.toContain("granted directly");
  });

  it("states an OVERFLOW as a withheld claim, and that nothing was lost", async () => {
    // The module contract is what the NEXT issuance would carry, so a view that
    // showed the full list while the mint will withhold it would be exactly the
    // misleading answer. And the words must not imply the attachments went missing.
    const root = openMember(
      effective([], ["billing.invoice.read"], {
        ...BUDGET,
        permission_count: 1,
        max_permission_count: 1,
        overflow: "budget_exceeded",
      }),
    );
    await flush();
    expect(root.textContent).toContain(
      "The next access token will carry NO permission claim",
    );
    expect(root.textContent).toContain("budget_exceeded");
    expect(root.textContent).toContain("still held and still on file");
    // The set itself is NEVER shortened: this is the one surface that can show an
    // operator what a token will not carry.
    expect(rowsOf(root, "Effective permissions").length).toBe(1);
  });

  it("states an APPROACHING budget as a COUNT verdict, never as what the token carries", async () => {
    // The note may say only what this view knows. It knows the ELEMENT count, which
    // is the only half the management plane evaluates; the mint withholds on the byte
    // bound as WELL, measured on the real compact token, and with the shipped
    // defaults the two disagree across most of the warning band (a 200 element set of
    // ordinary slugs is inside the 256 element maximum while the claim alone already
    // exceeds the 4096 byte token maximum). A note promising the token carries the
    // whole claim would be wrong in exactly the direction that stops an operator
    // looking, which is also why it must not promise emission: a plain code exchange
    // naming no RFC 8707 resource carries no permission claim at all.
    const root = openMember(
      effective([], ["billing.invoice.read"], {
        ...BUDGET,
        permission_count: 1,
        warn_permission_count: 1,
        approaching: true,
      }),
    );
    await flush();
    expect(root.textContent).toContain(
      "the element count alone withholds nothing",
    );
    expect(root.textContent).toContain(
      "That is not a statement that the next token carries the whole claim",
    );
    expect(root.textContent).toContain("the mint withholds on the byte bound");
    expect(root.textContent).toContain(
      "only an audience that has opted in receives the claim at all",
    );
    // The sentence this replaced, which was false three independent ways.
    expect(root.textContent).not.toContain("still carries the whole claim");
    expect(root.textContent).not.toContain("will carry NO permission claim");
  });

  it("carries the audience opt-in condition on the within-budget reading too", async () => {
    // A within-budget set is the reading an operator lands on most often, so it is the
    // one that must not read as a promise of emission either.
    const root = openMember(effective([], ["billing.invoice.read"]));
    await flush();
    expect(root.textContent).toContain(
      "an access token carries the permission claim only for a resource server that has opted in",
    );
  });

  it("shows only the WITHHELD note when a body somehow carries both readings", async () => {
    // Not server reachable: `evaluate` sets `approaching` to `!over && count > warn`,
    // so the two are mutually exclusive by a server invariant. The conjunct that
    // enforces it here is exercised anyway, because if the invariant ever moved the
    // panel must not print "the element count alone withholds nothing" directly under
    // "will carry NO permission claim".
    const root = openMember(
      effective([], ["billing.invoice.read"], {
        ...BUDGET,
        permission_count: 1,
        max_permission_count: 1,
        warn_permission_count: 1,
        approaching: true,
        overflow: "pdp_required",
      }),
    );
    await flush();
    expect(root.textContent).toContain(
      "The next access token will carry NO permission claim",
    );
    expect(root.textContent).toContain("pdp_required");
    expect(root.textContent).not.toContain(
      "the element count alone withholds nothing",
    );
  });

  it("says the verdict is unreliable when the budget counted a different set", async () => {
    const root = openMember(
      effective([], ["billing.invoice.read"], {
        ...BUDGET,
        permission_count: 7,
      }),
    );
    await flush();
    expect(root.textContent).toContain(
      "does not describe the set shown",
    );
  });

  it("shows no budget note about withholding when the set is within budget", async () => {
    const root = openMember(effective([], ["billing.invoice.read"]));
    await flush();
    expect(root.textContent).not.toContain("will carry NO permission claim");
    expect(root.textContent).not.toContain("does not describe the set shown");
  });

  it("says plainly that the roles carry NO permissions when the set is empty", async () => {
    // Asserted POSITIVELY. The malformed-body group names this string only in a
    // negative, where never rendering it at all would also pass.
    const root = openMember(
      effective([{ slug: "billing.admin", source: "direct" }], []),
    );
    await flush();
    expect(root.textContent).toContain(
      "These roles carry no permissions in this organization.",
    );
    expect(rowsOf(root, "Effective permissions")).toEqual([]);
    // And with resolution UNGATED that empty set really does mean no attachments, so
    // the suppression note must not appear.
    expect(root.textContent).not.toContain("still on file and is not lost");
  });

  it("explains an empty permission set when the ORGANIZATION is disabled", async () => {
    // The reading the roles half already refuses to leave unexplained, one field
    // over: a member of a disabled organization resolves no role, so carries no
    // permission either, while every attachment behind it is untouched.
    stubFetch((call) =>
      call.url.endsWith("/effective-roles")
        ? json(effective([], []))
        : json({ items: [] }),
    );
    const root = mount(
      <MembershipRolesPanel {...MEMBER} organizationActive={false} />,
    );
    await flush();
    expect(root.textContent).toContain(
      "These roles carry no permissions in this organization.",
    );
    expect(root.textContent).toContain(
      "Every attachment is still on file and is not lost.",
    );
  });

  it("explains an empty permission set when the MEMBERSHIP is not active", async () => {
    stubFetch((call) =>
      call.url.endsWith("/effective-roles")
        ? json(effective([], []))
        : json({ items: [] }),
    );
    const root = mount(
      <MembershipRolesPanel {...MEMBER} membershipState="suspended" />,
    );
    await flush();
    expect(root.textContent).toContain(
      "Every attachment is still on file and is not lost.",
    );
  });

  it("does not claim a gate over the permission set when resolution is ungated", async () => {
    const root = openMember(effective([], []));
    await flush();
    expect(root.textContent).not.toContain(
      "Every attachment is still on file and is not lost.",
    );
  });
});

// The load bearing group. Each case is a 2xx whose body cannot be read, and each
// must fail LOUD rather than render as a benign state, because every one of those
// benign states is a silent authorization DOWNGRADE: an operator is told a member
// holds less, or that a token will carry more, than is true.
describe("the WIDENED malformed-2xx guard on the effective-roles read", () => {
  // What must never appear for any of these bodies: the two "there is nothing here"
  // readings, and the within-budget arithmetic.
  function expectLoudFailure(root: HTMLDivElement): void {
    expect(root.querySelector(".errorbody")).not.toBeNull();
    expect(root.textContent).not.toContain(
      "resolves no roles in this organization",
    );
    expect(root.textContent).not.toContain(
      "These roles carry no permissions in this organization",
    );
    expect(rowsOf(root, "Effective permissions")).toEqual([]);
    // And the configuration on file is still visible: the failure is confined to
    // the resolved half.
    expect(rowsOf(root, "Roles granted directly to the member").length).toBe(1);
  }

  it("refuses a body with NO permissions field", async () => {
    const root = openMember({
      roles: [],
      permission_budget: { ...BUDGET },
    });
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission list",
    );
    expect(root.textContent).toContain("not being reported as empty");
    expectLoudFailure(root);
  });

  it("refuses a permissions field that is not an array", async () => {
    const root = openMember(effective([], "billing.invoice.read"));
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission list",
    );
    expectLoudFailure(root);
  });

  it("refuses a permissions array carrying a non string entry", async () => {
    // The list IS the claim, so an entry that is not a string means this is not the
    // resolved set. Rendering the readable entries and dropping the rest would be a
    // shortened answer presented as complete.
    const root = openMember(effective([], ["billing.invoice.read", 7]));
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission list",
    );
    expect(root.textContent).not.toContain("billing.invoice.read");
    expectLoudFailure(root);
  });

  it("refuses a body with NO permission_budget field", async () => {
    const root = openMember({ roles: [], permissions: [] });
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission budget",
    );
    expect(root.textContent).toContain("not being reported as within budget");
    expectLoudFailure(root);
  });

  it("refuses a permission_budget that is not an object", async () => {
    const root = openMember(effective([], [], "within budget"));
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission budget",
    );
    expectLoudFailure(root);
  });

  it("refuses a permission_budget missing ANY ONE of its six required fields", async () => {
    // EVERY field, in a loop, and that is the whole point of the loop. Omitting one
    // chosen field pins exactly that one check: with only `max_permission_count`
    // omitted, deleting any of the other five from the guard leaves the suite green,
    // so five of the six checks are decoration and the group billed as load bearing
    // covers one sixth of what its name claims.
    const keys = [
      "approaching",
      "permission_count",
      "max_permission_count",
      "warn_permission_count",
      "max_token_bytes",
      "warn_token_bytes",
    ] as const;
    expect(Object.keys(BUDGET).sort()).toEqual([...keys].sort());

    for (const key of keys) {
      const partial: Record<string, unknown> = { ...BUDGET };
      delete partial[key];
      const root = openMember(effective([], [], partial));
      await flush();
      expect(
        root.textContent,
        `omitting ${key} must be refused`,
      ).toContain("did not carry a readable permission budget");
      expectLoudFailure(root);
      unmountCurrent();
    }
  });

  it("refuses a permission_budget whose counted field is present but not a number", async () => {
    // The other half of the same six checks: a `typeof` test that were relaxed to a
    // mere presence test would let a string through and put it into the arithmetic
    // the panel prints.
    for (const key of [
      "permission_count",
      "max_permission_count",
      "warn_permission_count",
      "max_token_bytes",
      "warn_token_bytes",
    ]) {
      const root = openMember(effective([], [], { ...BUDGET, [key]: "64" }));
      await flush();
      expect(root.textContent, `a string ${key} must be refused`).toContain(
        "did not carry a readable permission budget",
      );
      unmountCurrent();
    }
    // And `approaching` is a boolean, not a truthy value.
    const root = openMember(effective([], [], { ...BUDGET, approaching: 1 }));
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission budget",
    );
    expectLoudFailure(root);
  });

  it("refuses a NULL permission_budget through the crafted refusal, not a crash", async () => {
    // A distinct shape from both "absent" and "not an object": `typeof null` is
    // "object", so a check written as a bare typeof test would fall through it and
    // then read a field off null. It must reach the same worded refusal as the rest.
    const root = openMember({ roles: [], permissions: [], permission_budget: null });
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission budget",
    );
    expect(root.textContent).toContain("not being reported as within budget");
    expectLoudFailure(root);
  });

  it("refuses an EMPTY overflow string rather than naming a status that has no name", async () => {
    // Not server reachable: `overflow` is absent or one of two non empty
    // `permissions_status` values. It is refused rather than absorbed because both
    // ways of absorbing it are worse. Read as "no overflow" it reports a withholding
    // as within budget, the downgrade this guard exists to prevent; let through, the
    // panel prints a sentence naming a status with an empty name.
    const root = openMember(
      effective([], ["billing.invoice.read"], { ...BUDGET, overflow: "" }),
    );
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission budget",
    );
    expect(root.textContent).not.toContain("reporting  instead");
    expectLoudFailure(root);
  });

  it("refuses a permission_budget whose overflow is not a string", async () => {
    // The one field that decides whether the panel says the claim is withheld. A
    // value it cannot read must not fall through to "no overflow", which would tell
    // an operator the token WILL carry a set the mint may be about to withhold: they
    // would stop looking.
    const root = openMember(
      effective([], ["billing.invoice.read"], { ...BUDGET, overflow: 7 }),
    );
    await flush();
    expect(root.textContent).toContain(
      "did not carry a readable permission budget",
    );
    expect(root.textContent).not.toContain("of at most 64");
    expectLoudFailure(root);
  });

  it("ACCEPTS the legal within-budget body, so the guard is not merely strict", async () => {
    // The other half: `overflow` is documented as ABSENT rather than null when the
    // set is within the maximum, and null is also legal, so neither may be refused.
    const root = openMember(effective([], ["billing.invoice.read"]));
    await flush();
    expect(root.querySelector(".errorbody")).toBeNull();
    expect(rowsOf(root, "Effective permissions").length).toBe(1);

    unmountCurrent();
    const withNull = openMember(
      effective([], ["billing.invoice.read"], { ...BUDGET, overflow: null }),
    );
    await flush();
    expect(withNull.querySelector(".errorbody")).toBeNull();
  });

  it("still refuses a body with no roles list, unchanged by the widening", async () => {
    const root = openMember({ ok: true });
    await flush();
    expect(root.textContent).toContain("did not carry a role list");
    expectLoudFailure(root);
  });
});

// The two things a reader can reach the vocabulary through, and the one sentence the
// two permission pages must not disagree about.
describe("the permissions section in the console frame", () => {
  it("is a nav section AND a route, so the entry is reachable", async () => {
    // Both halves, because either alone is a broken console that looks whole: a nav
    // entry with no route renders the Overview fallback, and a route with no entry is
    // unreachable without typing the URL.
    expect(SECTIONS.map((section) => section.href)).toContain("/permissions");
    expect(
      SECTIONS.find((section) => section.href === "/permissions")?.label,
    ).toBe("Permissions");

    // And the route resolves to the permission surface rather than the fallback. No
    // scope is active, so the surface prompts and makes ZERO calls.
    resetScope();
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(
      <LocationProvider url="/permissions">
        <Routes />
      </LocationProvider>,
    );
    await flush();
    expect(root.textContent).toContain(
      "Select a tenant and environment to manage its permissions.",
    );
    expect(root.textContent).not.toContain("This section lists");
    expect(calls.length).toBe(0);
  });

  it("does not promise a token claim on the attach page that the mint may not make", async () => {
    // The two pages of issue #98 must agree. The vocabulary page states the condition
    // ("only for a resource server that has opted in"), and the role attach panel is
    // where an operator actually lands while attaching, so an absolute promise there
    // is the version they would read. It is false three independent ways: a code
    // exchange naming no RFC 8707 resource emits no permission claim at all, a mixed
    // audience target suppresses it, and an opaque token format suppresses it.
    stubFetch(() => json({ items: [mapping] }));
    const root = mount(<OrgRolePermissionsPanel {...SCOPE} roleId="rol_a" />);
    await flush();
    expect(root.textContent).toContain(
      "Holding a permission and receiving it in a token are two different things",
    );
    expect(root.textContent).toContain(
      "only for a resource server that has opted in",
    );
    expect(root.textContent).not.toContain(
      "the next access token carries them as its permission claim",
    );
  });
});
