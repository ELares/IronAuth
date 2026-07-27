// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organization roles and groups surface (issue #97), exercised through the
// ONE typed client with a stubbed fetch so every assertion is a concrete URL,
// body, or DOM node.
//
// Covered: the roles CRUD; the groups CRUD including the dedicated MOVE; the tree
// rendering (including a group whose parent is unreadable, which must still
// appear); the group members add / list / remove; both assignment surfaces; and
// the effective-roles view, whose duplicate-slug case is the reason that view
// exists and is asserted to render as TWO distinct rows.
//
// It also carries the four assertions the organizations review demanded, because
// they apply to every scoped surface: zero network calls with no active scope, a
// hostile error body rendered as inert text, a keyset next_cursor surfaced rather
// than the tail being dropped, and a fully substituted path with no leftover
// placeholder.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { MembershipRolesPanel } from "../src/ui/MemberRolesView";
import { OrgGroupsPanel } from "../src/ui/OrgGroupsView";
import { OrgRolesPanel } from "../src/ui/OrgRolesView";
import { OrganizationDetail } from "../src/ui/OrganizationsView";
import { activeScope, resetScope } from "../src/scope/store";

interface Call {
  url: string;
  method: string;
  body: string | null;
  idempotencyKey: string | null;
}

const BASE = "http://management.test/admin/api";
const ORG = `${BASE}/v1/tenants/ten_a/environments/env_a/organizations/org_a`;

let container: HTMLDivElement | null = null;
const realFetch = globalThis.fetch;

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
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

function setScope(): void {
  activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
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

const role = {
  id: "rol_a",
  slug: "billing.admin",
  display_name: "Billing Administrator",
  organization_id: "org_a",
  metadata: {},
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
};

function makeGroup(
  id: string,
  slug: string,
  displayName: string,
  parentId: string | null,
) {
  return {
    id,
    slug,
    display_name: displayName,
    organization_id: "org_a",
    parent_id: parentId,
    metadata: {},
    created_at_unix_ms: 0,
    updated_at_unix_ms: 0,
  };
}

const groupA = makeGroup("grp_a", "engineering", "Engineering", null);
const groupB = makeGroup("grp_b", "platform", "Platform", "grp_a");

beforeEach(() => {
  setManagementBase(BASE);
  setScope();
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

describe("the organization roles panel", () => {
  it("lists each role with its immutable slug and its id", async () => {
    stubFetch(() => json({ items: [role] }));
    const root = mount(<OrgRolesPanel {...SCOPE} />);
    await flush();
    expect(root.textContent).toContain("Billing Administrator");
    expect(root.textContent).toContain("billing.admin");
    expect(root.textContent).toContain("rol_a");
  });

  it("shows the empty state when the organization defines no roles", async () => {
    stubFetch(() => json({ items: [] }));
    const root = mount(<OrgRolesPanel {...SCOPE} />);
    await flush();
    expect(root.textContent).toContain("No roles yet");
    // The empty state REPLACES the list, so no empty list element is rendered.
    expect(root.querySelector(".resource-list")).toBeNull();
  });

  it("surfaces a more-exist note when the roles read returns a next cursor", async () => {
    stubFetch(() => json({ items: [role], next_cursor: "opaque_roles_2" }));
    const root = mount(<OrgRolesPanel {...SCOPE} />);
    await flush();
    expect(root.textContent).toContain("More roles exist");
    // The cursor is a pagination token, never surfaced as a value to copy.
    expect(root.textContent).not.toContain("opaque_roles_2");
  });

  it("defines a role at the documented POST with the slug, the name, and a key", async () => {
    const calls = stubFetch((call) =>
      call.method === "POST" ? json(role, 201) : json({ items: [] }),
    );
    const root = mount(<OrgRolesPanel {...SCOPE} />);
    await flush();

    type(root, "#org-role-slug", "billing.admin");
    type(root, "#org-role-display-name", "Billing Administrator");
    await flush();
    button(root, "Define role").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`${ORG}/roles`);
    expect(JSON.parse(post?.body ?? "{}")).toEqual({
      slug: "billing.admin",
      display_name: "Billing Administrator",
    });
    // A retried submit must define the role once, so the create is key guarded.
    expect(post?.idempotencyKey).toMatch(/^[0-9a-f]{32}$/);
    expect(root.textContent).toContain("Role defined.");
  });

  it("reads one role fresh and renames only its label", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "PATCH") {
        return json({ ...role, display_name: "Billing Owner" });
      }
      if (call.url.endsWith("/roles/rol_a")) {
        return json(role);
      }
      return json({ items: [role] });
    });
    const root = mount(<OrgRolesPanel {...SCOPE} />);
    await flush();

    button(root, "Billing Administrator").click();
    await flush();
    const detail = calls.find((call) => call.url.endsWith("/roles/rol_a"));
    expect(detail?.url).toBe(`${ORG}/roles/rol_a`);

    type(root, "#org-role-rename", "Billing Owner");
    await flush();
    button(root, "Rename role").click();
    await flush();

    const patch = calls.find((call) => call.method === "PATCH");
    expect(patch?.url).toBe(`${ORG}/roles/rol_a`);
    // The slug is immutable, so it is never on a rename body.
    expect(JSON.parse(patch?.body ?? "{}")).toEqual({
      display_name: "Billing Owner",
    });
    expect(root.textContent).toContain("Role renamed.");
  });

  it("deletes a role only after an explicit confirm", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "DELETE") {
        return noContent();
      }
      if (call.url.endsWith("/roles/rol_a")) {
        return json(role);
      }
      return json({ items: [role] });
    });
    const root = mount(<OrgRolesPanel {...SCOPE} />);
    await flush();
    button(root, "Billing Administrator").click();
    await flush();

    button(root, "Delete role").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);

    button(root, "Confirm delete role").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toBe(`${ORG}/roles/rol_a`);
  });
});

describe("the organization groups panel", () => {
  it("renders the hierarchy as a tree, nesting a child under its parent", async () => {
    stubFetch(() => json({ items: [groupA, groupB] }));
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    await flush();

    const rows = rowsOf(root, "Group hierarchy of the organization");
    expect(rows.length).toBe(2);
    expect(rows.map((row) => row.getAttribute("role"))).toEqual([
      "treeitem",
      "treeitem",
    ]);
    // The nesting is carried by aria-level, so it is announced and not merely
    // drawn: the root is level 1 and its child is level 2.
    expect(rows.map((row) => row.getAttribute("aria-level"))).toEqual([
      "1",
      "2",
    ]);
    expect(rows[0].textContent).toContain("Engineering");
    expect(rows[1].textContent).toContain("Platform");
  });

  it("still shows a group whose parent is unreadable, marked and explained", async () => {
    // `grp_gone` is not on this page: deleted, or beyond the page read. Building
    // the tree only from declared roots would drop this row and its subtree.
    // The child is listed BEFORE its parent, which the oldest-first page order
    // allows once a group has been moved: the subtree must still nest.
    const orphan = makeGroup("grp_o", "orphan", "Orphan", "grp_gone");
    const child = makeGroup("grp_c", "child", "Child", "grp_o");
    stubFetch(() => json({ items: [groupA, child, orphan] }));
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    await flush();

    const rows = rowsOf(root, "Group hierarchy of the organization");
    expect(rows.length).toBe(3);
    expect(rows.map((row) => row.getAttribute("aria-level"))).toEqual([
      "1",
      "1",
      "2",
    ]);
    expect(rows[1].textContent).toContain("Orphan");
    expect(rows[1].textContent).toContain("detached parent");
    expect(rows[2].textContent).toContain("Child");
    expect(root.textContent).toContain("names a parent that is not readable");
  });

  it("does not call a well parented tree detached", async () => {
    stubFetch(() => json({ items: [groupA, groupB] }));
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    await flush();
    expect(root.textContent).not.toContain("detached parent");
  });

  it("surfaces a more-exist note when the groups read returns a next cursor", async () => {
    stubFetch(() => json({ items: [groupA], next_cursor: "opaque_groups_2" }));
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    await flush();
    expect(root.textContent).toContain("More groups exist");
    expect(root.textContent).not.toContain("opaque_groups_2");
  });

  it("defines a group under the chosen parent at the documented POST", async () => {
    const calls = stubFetch((call) =>
      call.method === "POST"
        ? json(groupB, 201)
        : json({ items: [groupA] }),
    );
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    await flush();

    type(root, "#org-group-slug", "platform");
    type(root, "#org-group-display-name", "Platform");
    choose(root, "#org-group-parent", "grp_a");
    await flush();
    button(root, "Define group").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`${ORG}/groups`);
    expect(JSON.parse(post?.body ?? "{}")).toEqual({
      slug: "platform",
      display_name: "Platform",
      parent_id: "grp_a",
    });
    expect(post?.idempotencyKey).toMatch(/^[0-9a-f]{32}$/);
  });

  it("defines a top level group when no parent is chosen", async () => {
    const calls = stubFetch((call) =>
      call.method === "POST" ? json(groupA, 201) : json({ items: [] }),
    );
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    await flush();

    type(root, "#org-group-slug", "engineering");
    type(root, "#org-group-display-name", "Engineering");
    await flush();
    button(root, "Define group").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(JSON.parse(post?.body ?? "{}").parent_id).toBeNull();
  });
});

// The group detail: opening a group reads it fresh and mounts its members and
// granted roles. Every test here opens `Engineering` first.
describe("one group", () => {
  function openGroup(
    respond: (call: Call) => Response | null,
  ): { root: HTMLDivElement; calls: Call[] } {
    const calls = stubFetch((call) => {
      const custom = respond(call);
      if (custom !== null) {
        return custom;
      }
      if (call.url.endsWith("/groups/grp_a/members")) {
        return json({ items: [] });
      }
      if (call.url.endsWith("/groups/grp_a/roles")) {
        return json({ items: [] });
      }
      if (call.url.endsWith("/groups/grp_a")) {
        return json(groupA);
      }
      return json({ items: [groupA, groupB] });
    });
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    return { root, calls };
  }

  it("forms a fully substituted path with no leftover placeholder", async () => {
    const { root, calls } = openGroup(() => null);
    await flush();
    button(root, "Engineering").click();
    await flush();

    const detail = calls.find((call) => call.url.endsWith("/groups/grp_a"));
    expect(detail?.url).toBe(`${ORG}/groups/grp_a`);
    // No unsubstituted path parameter survives into the wire URL, on any call.
    for (const call of calls) {
      expect(call.url).not.toContain("{");
      expect(call.url).not.toContain("}");
    }
  });

  it("renames the group without touching its place in the hierarchy", async () => {
    const { root, calls } = openGroup((call) =>
      call.method === "PATCH"
        ? json({ ...groupA, display_name: "Engineering Org" })
        : null,
    );
    await flush();
    button(root, "Engineering").click();
    await flush();

    type(root, "#org-group-rename", "Engineering Org");
    await flush();
    button(root, "Rename group").click();
    await flush();

    const patch = calls.find((call) => call.method === "PATCH");
    expect(patch?.url).toBe(`${ORG}/groups/grp_a`);
    // The parent is deliberately absent from a rename body: moving a group is
    // its own operation, so a rename can never reshape the hierarchy.
    expect(JSON.parse(patch?.body ?? "{}")).toEqual({
      display_name: "Engineering Org",
    });
  });

  it("moves the group through the dedicated parent operation", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "PUT") {
        return json({ ...groupB, parent_id: null });
      }
      if (call.url.endsWith("/groups/grp_b/members")) {
        return json({ items: [] });
      }
      if (call.url.endsWith("/groups/grp_b/roles")) {
        return json({ items: [] });
      }
      if (call.url.endsWith("/groups/grp_b")) {
        return json(groupB);
      }
      return json({ items: [groupA, groupB] });
    });
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    await flush();
    button(root, "Platform").click();
    await flush();

    choose(root, "#org-group-move-parent", "");
    await flush();
    button(root, "Move group").click();
    await flush();

    const put = calls.find((call) => call.method === "PUT");
    expect(put?.url).toBe(`${ORG}/groups/grp_b/parent`);
    expect(JSON.parse(put?.body ?? "{}")).toEqual({ parent_id: null });
    expect(root.textContent).toContain("Group moved.");
  });

  it("does not offer the group itself or its subtree as a new parent", async () => {
    const { root } = openGroup(() => null);
    await flush();
    button(root, "Engineering").click();
    await flush();

    const select = root.querySelector(
      "#org-group-move-parent",
    ) as HTMLSelectElement;
    const values = Array.from(select.options).map((option) => option.value);
    // Only the empty "no parent" sentinel remains: Engineering is the group
    // itself and Platform is beneath it, so both would be a cycle.
    expect(values).toEqual([""]);
  });

  it("renders a refused move verbatim, a hostile message staying inert text", async () => {
    const hostile = '<img src=x onerror="steal()"> and <script>evil()</script>';
    const { root } = openGroup((call) =>
      call.method === "PUT"
        ? json({ error: "unprocessable_entity", message: hostile }, 422)
        : null,
    );
    await flush();
    button(root, "Engineering").click();
    await flush();
    button(root, "Move group").click();
    await flush();

    expect(root.querySelector(".errorbody")).not.toBeNull();
    // The server worded the refusal; it is shown unchanged and as TEXT.
    expect(root.textContent).toContain(hostile);
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("script")).toBeNull();
  });

  it("deletes the group only after an explicit confirm", async () => {
    const { root, calls } = openGroup((call) =>
      call.method === "DELETE" ? noContent() : null,
    );
    await flush();
    button(root, "Engineering").click();
    await flush();

    button(root, "Delete group").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);

    button(root, "Confirm delete group").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toBe(`${ORG}/groups/grp_a`);
  });
});

describe("the members of one group", () => {
  const binding = {
    id: "gmb_a",
    group_id: "grp_a",
    membership_id: "omb_a",
    organization_id: "org_a",
    created_at_unix_ms: 0,
    updated_at_unix_ms: 0,
  };

  function open(members: unknown): { root: HTMLDivElement; calls: Call[] } {
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json(binding, 201);
      }
      if (call.method === "DELETE") {
        return noContent();
      }
      if (call.url.endsWith("/groups/grp_a/members")) {
        return json(members);
      }
      if (call.url.endsWith("/groups/grp_a/roles")) {
        return json({ items: [] });
      }
      if (call.url.endsWith("/groups/grp_a")) {
        return json(groupA);
      }
      return json({ items: [groupA] });
    });
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    return { root, calls };
  }

  it("lists a binding by MEMBERSHIP id, adds one, and removes it after confirm", async () => {
    const { root, calls } = open({ items: [binding] });
    await flush();
    button(root, "Engineering").click();
    await flush();

    const rows = rowsOf(root, "Members of the group");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("omb_a");
    expect(rows[0].textContent).toContain("gmb_a");

    type(root, "#org-group-member-id", "omb_b");
    await flush();
    button(root, "Add to group").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`${ORG}/groups/grp_a/members`);
    // A MEMBERSHIP id, never a bare user id.
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ membership_id: "omb_b" });
    expect(post?.idempotencyKey).toMatch(/^[0-9a-f]{32}$/);

    button(root, "Remove from group").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    button(root, "Confirm remove from group").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    // Addressed by the (group, membership) PAIR, not by the binding id.
    expect(del?.url).toBe(`${ORG}/groups/grp_a/members/omb_a`);
    expect(del?.url).not.toContain("gmb_a");
  });

  it("surfaces a more-exist note rather than dropping the tail", async () => {
    const { root } = open({ items: [binding], next_cursor: "opaque_gm_2" });
    await flush();
    button(root, "Engineering").click();
    await flush();
    expect(root.textContent).toContain("More group members exist");
    expect(root.textContent).not.toContain("opaque_gm_2");
  });
});

describe("the roles one group grants", () => {
  const assignment = {
    id: "grl_a",
    group_id: "grp_a",
    role_id: "rol_a",
    organization_id: "org_a",
    created_at_unix_ms: 0,
    updated_at_unix_ms: 0,
  };

  function open(): { root: HTMLDivElement; calls: Call[] } {
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json(assignment, 201);
      }
      if (call.method === "DELETE") {
        return noContent();
      }
      if (call.url.endsWith("/groups/grp_a/members")) {
        return json({ items: [] });
      }
      if (call.url.endsWith("/groups/grp_a/roles")) {
        return json({ items: [assignment] });
      }
      if (call.url.endsWith("/groups/grp_a")) {
        return json(groupA);
      }
      return json({ items: [groupA] });
    });
    const root = mount(<OrgGroupsPanel {...SCOPE} />);
    return { root, calls };
  }

  it("lists, grants, and withdraws by the group and role PAIR", async () => {
    const { root, calls } = open();
    await flush();
    button(root, "Engineering").click();
    await flush();

    const rows = rowsOf(root, "Roles the group grants");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("rol_a");

    type(root, "#org-group-role-id", "rol_b");
    await flush();
    button(root, "Grant to group").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`${ORG}/groups/grp_a/roles`);
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ role_id: "rol_b" });
    expect(post?.idempotencyKey).toMatch(/^[0-9a-f]{32}$/);

    button(root, "Withdraw from group").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    button(root, "Confirm withdraw from group").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toBe(`${ORG}/groups/grp_a/roles/rol_a`);
    // The assignment id is carried for audit correlation, never as the address.
    expect(del?.url).not.toContain("grl_a");
  });
});

describe("the roles of one member", () => {
  const direct = {
    id: "mrl_a",
    membership_id: "omb_a",
    role_id: "rol_a",
    organization_id: "org_a",
    created_at_unix_ms: 0,
    updated_at_unix_ms: 0,
  };
  const MEMBER = {
    ...SCOPE,
    membershipId: "omb_a",
    organizationActive: true,
    membershipState: "active",
  };

  function open(
    directPage: unknown,
    effective: unknown,
  ): { root: HTMLDivElement; calls: Call[] } {
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json(direct, 201);
      }
      if (call.method === "DELETE") {
        return noContent();
      }
      if (call.url.endsWith("/memberships/omb_a/effective-roles")) {
        return json(effective);
      }
      return json(directPage);
    });
    const root = mount(<MembershipRolesPanel {...MEMBER} />);
    return { root, calls };
  }

  it("lists, grants, and withdraws the DIRECT grants by the pair", async () => {
    const { root, calls } = open({ items: [direct] }, { roles: [] });
    await flush();

    const rows = rowsOf(root, "Roles granted directly to the member");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("rol_a");

    type(root, "#org-membership-role-id", "rol_b");
    await flush();
    button(root, "Grant to member").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`${ORG}/memberships/omb_a/roles`);
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ role_id: "rol_b" });
    expect(post?.idempotencyKey).toMatch(/^[0-9a-f]{32}$/);

    button(root, "Withdraw from member").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    button(root, "Confirm withdraw from member").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toBe(`${ORG}/memberships/omb_a/roles/rol_a`);
    expect(del?.url).not.toContain("mrl_a");
  });

  it("surfaces a more-exist note on the direct grants", async () => {
    const { root } = open(
      { items: [direct], next_cursor: "opaque_mr_2" },
      { roles: [] },
    );
    await flush();
    expect(root.textContent).toContain("More direct role grants exist");
    expect(root.textContent).not.toContain("opaque_mr_2");
  });

  it("re-reads the resolved picture after a grant changes", async () => {
    const { root, calls } = open({ items: [direct] }, { roles: [] });
    await flush();
    const before = calls.filter((call) =>
      call.url.endsWith("/effective-roles"),
    ).length;

    type(root, "#org-membership-role-id", "rol_b");
    await flush();
    button(root, "Grant to member").click();
    await flush();

    const after = calls.filter((call) =>
      call.url.endsWith("/effective-roles"),
    ).length;
    // The resolution is the servers, so it is re-read rather than inferred.
    expect(after).toBeGreaterThan(before);
  });

  it("reads the effective roles from the documented path", async () => {
    const { calls } = open({ items: [] }, { roles: [] });
    await flush();
    const read = calls.find((call) => call.url.endsWith("/effective-roles"));
    expect(read?.url).toBe(`${ORG}/memberships/omb_a/effective-roles`);
    expect(read?.method).toBe("GET");
  });

  it("shows the provenance of every grant path, not just the slugs", async () => {
    const { root } = open(
      { items: [] },
      {
        roles: [
          { slug: "billing.admin", source: "direct" },
          {
            slug: "support.agent",
            source: "group",
            via_group_id: "grp_a",
          },
        ],
      },
    );
    await flush();

    const rows = rowsOf(root, "Effective role grant paths");
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain("billing.admin");
    expect(rows[0].textContent).toContain("granted directly");
    expect(rows[1].textContent).toContain("support.agent");
    expect(rows[1].textContent).toContain("through a group");
    // WHICH group carries the grant is the operator answer, so the id is shown.
    expect(rows[1].textContent).toContain("grp_a");
  });

  it("renders a slug held two ways as TWO rows and never collapses them", async () => {
    // The whole point of the view. A role held directly AND through a group is
    // two grant paths. Collapsing them to one row would show the operator a
    // single grant to withdraw, they would withdraw it, and the role would
    // survive by the path that was hidden.
    const { root } = open(
      { items: [] },
      {
        roles: [
          { slug: "billing.admin", source: "direct" },
          {
            slug: "billing.admin",
            source: "group",
            via_group_id: "grp_a",
          },
        ],
      },
    );
    await flush();

    const rows = rowsOf(root, "Effective role grant paths");
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain("billing.admin");
    expect(rows[1].textContent).toContain("billing.admin");
    // The two rows are DISTINCT: one names no group, the other names grp_a.
    expect(rows[0].textContent).toContain("granted directly");
    expect(rows[0].textContent).not.toContain("grp_a");
    expect(rows[1].textContent).toContain("through a group");
    expect(rows[1].textContent).toContain("grp_a");
    // And the operator is told what the repetition means.
    expect(root.textContent).toContain(
      "held by more than one path, so withdrawing a single grant leaves the role in place",
    );
  });

  it("says so plainly when a member resolves no roles at all", async () => {
    const { root } = open({ items: [] }, { roles: [] });
    await flush();
    expect(root.textContent).toContain("resolves no roles in this organization");
    expect(rowsOf(root, "Effective role grant paths")).toEqual([]);
    // Nothing is gating resolution, so an empty set really does mean no grants.
    expect(root.textContent).not.toContain("still on file");
  });

  it("explains an empty resolved set when the organization is disabled", async () => {
    // A disabled organization mints no roles for anyone while every grant stays
    // on file. Without this the operator sees a populated direct-grant list next
    // to an empty resolved set and reasonably concludes the grants were lost.
    const calls = stubFetch((call) =>
      call.url.endsWith("/effective-roles")
        ? json({ roles: [] })
        : json({ items: [direct] }),
    );
    const root = mount(
      <MembershipRolesPanel {...MEMBER} organizationActive={false} />,
    );
    await flush();
    expect(calls.length).toBeGreaterThan(0);
    expect(root.textContent).toContain("This organization is disabled");
    expect(root.textContent).toContain("still on file and are not lost");
    // The configuration is NOT hidden: the direct grant is still listed.
    expect(rowsOf(root, "Roles granted directly to the member").length).toBe(1);
  });

  it("explains an empty resolved set when the membership is not active", async () => {
    stubFetch((call) =>
      call.url.endsWith("/effective-roles")
        ? json({ roles: [] })
        : json({ items: [direct] }),
    );
    const root = mount(
      <MembershipRolesPanel {...MEMBER} membershipState="removed" />,
    );
    await flush();
    expect(root.textContent).toContain("This membership is removed");
    expect(root.textContent).toContain("still on file and are not lost");
  });

  it("renders a resolution FAULT as an error, never as an empty role set", async () => {
    // The server fails closed and loud on a resolution fault, because an empty
    // set is indistinguishable from a member who legitimately holds nothing:
    // swallowing the failure would render a silent authorization DOWNGRADE. The
    // console must not undo that by reading a non 2xx as no roles.
    const hostile = '<img src=x onerror="steal()"> resolution failed';
    stubFetch((call) =>
      call.url.endsWith("/effective-roles")
        ? json({ error: "server_error", message: hostile }, 500)
        : json({ items: [] }),
    );
    const root = mount(<MembershipRolesPanel {...MEMBER} />);
    await flush();

    expect(root.querySelector(".errorbody")).not.toBeNull();
    expect(root.textContent).toContain(hostile);
    expect(root.querySelector("img")).toBeNull();
    // And emphatically NOT the "this member holds nothing" reading.
    expect(root.textContent).not.toContain(
      "resolves no roles in this organization",
    );
    expect(rowsOf(root, "Effective role grant paths")).toEqual([]);
  });

  it("does not claim a gate when the member actually resolves roles", async () => {
    const { root } = open(
      { items: [] },
      { roles: [{ slug: "billing.admin", source: "direct" }] },
    );
    await flush();
    expect(root.textContent).not.toContain("still on file");
  });
});

describe("the roles and groups panels inside the organization detail", () => {
  it("makes ZERO calls when no scope is selected", async () => {
    resetScope();
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<OrganizationDetail organizationId="org_a" />);
    await flush();
    expect(root.textContent).toContain("Select a tenant and environment");
    expect(calls.length).toBe(0);
    // Specifically: no roles, groups, or effective-roles read escapes.
    expect(root.querySelector('[aria-label="Roles of the organization"]')).toBeNull();
  });

  it("mounts the roles and groups panels under the organization", async () => {
    const calls = stubFetch((call) => {
      if (call.url.endsWith("/organizations/org_a/roles")) {
        return json({ items: [role] });
      }
      if (call.url.endsWith("/organizations/org_a/groups")) {
        return json({ items: [groupA] });
      }
      if (call.url.includes("/memberships")) {
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
    expect(calls.some((call) => call.url === `${ORG}/groups`)).toBe(true);
    expect(root.textContent).toContain("Billing Administrator");
    expect(root.textContent).toContain("Engineering");
  });

  it("opens the roles of one member from that member row", async () => {
    const member = {
      id: "omb_a",
      user_id: "usr_a",
      organization_id: "org_a",
      state: "active",
      metadata: {},
      created_at_unix_ms: 0,
    };
    const calls = stubFetch((call) => {
      if (call.url.endsWith("/memberships/omb_a/effective-roles")) {
        return json({
          roles: [
            { slug: "billing.admin", source: "direct" },
            {
              slug: "billing.admin",
              source: "group",
              via_group_id: "grp_a",
            },
          ],
        });
      }
      if (call.url.endsWith("/organizations/org_a/memberships")) {
        return json({ items: [member] });
      }
      if (call.url.includes("/roles") || call.url.includes("/groups")) {
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

    // Nothing is read for a member until the operator asks.
    expect(
      calls.some((call) => call.url.includes("/effective-roles")),
    ).toBe(false);

    button(root, "Show roles").click();
    await flush();

    expect(
      calls.some(
        (call) => call.url === `${ORG}/memberships/omb_a/effective-roles`,
      ),
    ).toBe(true);
    const rows = rowsOf(root, "Effective role grant paths");
    expect(rows.length).toBe(2);
  });
});
