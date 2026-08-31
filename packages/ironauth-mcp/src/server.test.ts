// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The admin MCP server's three rules (issue #123 criteria 4, 5 and 6).
 *
 * Every test drives the real `AdminMcpServer` against a fake management API that records what it
 * was asked. Recording the requests is what makes the entry-path assertion possible at all: the
 * criterion is about a header the server must send, and a test that only checked the result
 * would pass whether or not it did.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AdminMcpServer } from './server.js';
import { TOOLS } from './tools.js';

const API = 'https://admin.example';

/** A fake management API. `permissions: null` means an unrestricted credential. */
function api(options: { permissions: string[] | null; meFails?: boolean }) {
  const calls: Array<{ url: string; method: string; headers: Headers; body?: string }> = [];
  const send = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    const headers = new Headers(init?.headers as HeadersInit | undefined);
    calls.push({
      url,
      method: init?.method ?? 'GET',
      headers,
      body: typeof init?.body === 'string' ? init.body : undefined,
    });
    if (url === `${API}/v1/me`) {
      if (options.meFails) {
        return new Response('nope', { status: 503 });
      }
      return new Response(
        JSON.stringify({
          plane: 'management_key',
          tenant_id: 'ten_x',
          environment_id: 'env_y',
          permissions: options.permissions,
          unrestricted: options.permissions === null,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { calls, send: send as unknown as typeof fetch };
}

function serverWith(permissions: string[] | null, meFails = false) {
  const fake = api({ permissions, meFails });
  return {
    fake,
    server: new AdminMcpServer({ apiBase: API, apiKey: 'mk_secret', fetch: fake.send }),
  };
}

// ---------------------------------------------------------------------------
// Criterion 4: per-tool scope checks, and read-only exposes no mutating tools.
// ---------------------------------------------------------------------------

test('a read-scoped key is offered no mutating tool at all', async () => {
  const { server } = serverWith(['management.read']);
  const offered = await server.listTools();
  assert.ok(offered.length > 0, 'it should still be offered the reads');
  for (const tool of offered) {
    assert.equal(tool.requires, 'management.read', `${tool.name} was offered to a read-only key`);
    // FILTERED, not annotated: an MCP client shows what it is given, so a tool listed as
    // "unavailable" is a tool an agent will try.
    assert.equal(tool.destructive, false, `${tool.name} is destructive and was offered`);
  }
  // And the mutating tools really do exist -- otherwise this test would pass against a server
  // that has no mutating tools at all, which is a different thing entirely.
  assert.ok(
    TOOLS.some((tool) => tool.requires !== 'management.read'),
    'the surface must contain mutating tools for the filter to mean anything',
  );
});

test('invoking a tool the key may not use is forbidden, whatever the arguments', async () => {
  const { server, fake } = serverWith(['management.read']);
  const result = await server.callTool('delete_user', {
    tenant_id: 'ten_x',
    environment_id: 'env_y',
    user_id: 'usr_1',
    confirm: true,
  });
  assert.deepEqual(result, { kind: 'forbidden', requires: 'management.write_users' });
  // AND NOTHING WAS CALLED. A client-side check that still issued the request would be no check
  // at all -- the API would refuse it, but the agent would have asked.
  assert.equal(
    fake.calls.filter((call) => call.url.includes('/users/')).length,
    0,
    'a forbidden tool must not reach the API',
  );
});

test('the permission check runs BEFORE the arguments are looked at', async () => {
  // Otherwise an agent probing with empty arguments could tell "this tool exists and I may not
  // use it" from "this tool wants arguments", which is a small map of the surface it cannot see.
  const { server } = serverWith(['management.read']);
  const result = await server.callTool('delete_user', {});
  assert.equal(result.kind, 'forbidden');
});

test('a key holding the permission may drive the tool', async () => {
  const { server, fake } = serverWith(['management.read', 'management.write_users']);
  const offered = await server.listTools();
  assert.ok(offered.some((tool) => tool.name === 'delete_user'), 'it is offered now');
  const result = await server.callTool('delete_user', {
    tenant_id: 'ten_x',
    environment_id: 'env_y',
    user_id: 'usr_1',
    confirm: true,
  });
  assert.equal(result.kind, 'ok');
  assert.ok(fake.calls.some((call) => call.url.endsWith('/users/usr_1')));
});

test('an unrestricted credential is offered everything', async () => {
  const { server } = serverWith(null);
  const offered = await server.listTools();
  assert.equal(offered.length, TOOLS.length);
});

test('an unreadable /v1/me offers NOTHING rather than guessing', async () => {
  // Fail closed. An unreachable introspection endpoint must not be the reason an agent is
  // offered a delete.
  const { server } = serverWith(['management.read'], true);
  assert.deepEqual(await server.listTools(), []);
  const result = await server.callTool('list_tenants', {});
  assert.equal(result.kind, 'forbidden');
});

// ---------------------------------------------------------------------------
// Criterion 6: destructive tools require explicit confirmation.
// ---------------------------------------------------------------------------

test('every destructive tool refuses without confirm, and none reaches the API', async () => {
  // OVER THE WHOLE SURFACE rather than one example: the criterion is about a class of tools, and
  // a test of one is satisfied by a server that special-cased it.
  const destructive = TOOLS.filter((tool) => tool.destructive);
  assert.ok(destructive.length >= 3, `the surface should have destructive tools: ${destructive.length}`);
  for (const tool of destructive) {
    const { server, fake } = serverWith(null);
    const args: Record<string, unknown> = {};
    for (const key of tool.required) {
      args[key] = 'x';
    }
    const refused = await server.callTool(tool.name, args);
    assert.equal(refused.kind, 'needs_confirmation', tool.name);
    assert.equal(
      fake.calls.filter((call) => call.url !== `${API}/v1/me`).length,
      0,
      `${tool.name} reached the API without confirmation`,
    );

    // AND WITH confirmation it runs, so the refusal above is the confirmation gate and not the
    // tool being broken.
    const confirmed = await server.callTool(tool.name, { ...args, confirm: true });
    assert.equal(confirmed.kind, 'ok', tool.name);
  }
});

test('a truthy-but-not-true confirm is not a confirmation', async () => {
  // `confirm: "yes"` is what a model produces when it is guessing at the shape rather than
  // acting on the message, and treating it as consent defeats the parameter.
  for (const value of ['true', 'yes', 1, {}, [] as unknown]) {
    const { server } = serverWith(null);
    const result = await server.callTool('delete_user', {
      tenant_id: 'ten_x',
      environment_id: 'env_y',
      user_id: 'usr_1',
      confirm: value,
    });
    assert.equal(result.kind, 'needs_confirmation', `confirm: ${JSON.stringify(value)}`);
  }
});

test('a non-destructive write needs no confirmation', async () => {
  // A confirmation on every write would train an operator to pass confirm reflexively, which is
  // exactly how the parameter stops protecting the deletes it exists for.
  const { server } = serverWith(null);
  const result = await server.callTool('create_user', {
    tenant_id: 'ten_x',
    environment_id: 'env_y',
    identifier: 'a@example.test',
  });
  assert.equal(result.kind, 'ok');
});

// ---------------------------------------------------------------------------
// Criterion 5: every request is marked with the MCP entry path.
// ---------------------------------------------------------------------------

test('EVERY request this server makes carries the MCP entry path', async () => {
  const { server, fake } = serverWith(null);
  await server.listTools();
  for (const tool of TOOLS) {
    const args: Record<string, unknown> = { confirm: true };
    for (const key of tool.required) {
      args[key] = 'x';
    }
    await server.callTool(tool.name, args);
  }
  assert.ok(fake.calls.length > TOOLS.length, 'the calls were recorded');
  for (const call of fake.calls) {
    assert.equal(
      call.headers.get('x-ironauth-entry-path'),
      'mcp',
      `${call.method} ${call.url} was sent without the entry path`,
    );
    // AND AUTHENTICATED WITH THE SCOPED KEY. "The MCP server holds no super-admin ambient
    // authority" is a property of what it sends, so it is asserted on every request rather than
    // trusted to the constructor.
    assert.equal(call.headers.get('authorization'), 'Bearer mk_secret', call.url);
  }
});

test('confirm is never forwarded to the management API', async () => {
  // It is this server's own control. Sending it upstream would put a word the management API has
  // no opinion about into a body it validates strictly.
  const { server, fake } = serverWith(null);
  await server.callTool('create_user', {
    tenant_id: 'ten_x',
    environment_id: 'env_y',
    identifier: 'a@example.test',
    confirm: true,
  });
  const call = fake.calls.find((c) => c.method === 'POST');
  assert.ok(call, 'the create reached the API');
  assert.ok(!(call.body ?? '').includes('confirm'), `confirm was forwarded: ${call.body}`);
  assert.ok((call.body ?? '').includes('a@example.test'), 'the real arguments were forwarded');
});

// ---------------------------------------------------------------------------
// The surface itself.
// ---------------------------------------------------------------------------

test('every tool declares a permission and a destructiveness', () => {
  // The declaration IS the enforcement: a tool whose permission is a field can be filtered
  // before it is advertised, and one whose destructiveness is a field cannot be added without
  // answering the question. This asserts the surface has no half-declared member.
  const names = new Set<string>();
  for (const tool of TOOLS) {
    assert.ok(tool.name.length > 0);
    assert.ok(!names.has(tool.name), `duplicate tool name ${tool.name}`);
    names.add(tool.name);
    assert.ok(tool.description.length > 10, `${tool.name} needs a description an agent can use`);
    assert.equal(typeof tool.destructive, 'boolean', tool.name);
    // Every DELETE is destructive. The reverse is not required -- a destructive POST is
    // imaginable -- but a delete that forgot to say so is the defect this catches.
    if (tool.method === 'DELETE') {
      assert.equal(tool.destructive, true, `${tool.name} is a DELETE and must be destructive`);
    }
    // Every placeholder in the path is a required argument, or the path would be driven with a
    // literal `{brace}` segment.
    for (const match of tool.path.matchAll(/\{(\w+)\}/g)) {
      assert.ok(tool.required.includes(match[1]!), `${tool.name} does not require ${match[1]}`);
    }
  }
});

test('an unknown tool is an unknown tool', async () => {
  const { server } = serverWith(null);
  assert.deepEqual(await server.callTool('drop_database', {}), {
    kind: 'unknown_tool',
    name: 'drop_database',
  });
});

test('a missing required argument is reported, not sent', async () => {
  const { server, fake } = serverWith(null);
  const result = await server.callTool('get_user', { tenant_id: 'ten_x' });
  assert.deepEqual(result, { kind: 'invalid', missing: ['environment_id', 'user_id'] });
  assert.equal(fake.calls.filter((call) => call.url !== `${API}/v1/me`).length, 0);
});

test('every tool names an operation the contract publishes', async () => {
  // THE TEST THAT FOUND A REAL BUG. This surface first shipped a `delete_application` tool
  // driving `DELETE .../applications/{client_id}`, which the management API does not serve --
  // and every other test here passed, because the fake API answers 200 to anything.
  //
  // An agent would have been offered a delete that always 404s. The published contract is the
  // only thing that could have caught it, so the tools are checked against the contract.
  const { readFileSync } = await import('node:fs');
  const contract = JSON.parse(
    readFileSync(new URL('../../../docs/openapi/management.json', import.meta.url), 'utf8'),
  ) as { paths: Record<string, Record<string, unknown>> };

  for (const tool of TOOLS) {
    const operations = contract.paths[tool.path];
    assert.ok(operations, `${tool.name} drives ${tool.path}, which the contract does not publish`);
    assert.ok(
      operations[tool.method.toLowerCase()],
      `${tool.name} drives ${tool.method} ${tool.path}, and the contract publishes no such method`,
    );
  }
});
