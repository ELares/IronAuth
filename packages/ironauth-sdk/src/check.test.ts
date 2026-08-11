// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The uniform `check()` (issue #100, criterion 6).
 *
 * The criterion is that ONE call resolves via claims, via the AuthZEN endpoint, or via a
 * customer PDP "interchangeably, by configuration". So the central test asks the SAME
 * question through all three and requires the same answer; anything less proves three
 * functions that happen to live in one file.
 *
 * The rest is the fail-CLOSED sweep. This function IS the authorization decision, so every
 * way it can fail has to deny, and the ways are easy to get wrong one at a time: a truthy
 * body, a non-2xx with a valid body, an absent claim, a claim of the wrong type.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { check, permissionSlug, type CheckConfig, type CheckRequest } from './check.js';

const REQUEST: CheckRequest = {
  subject: { type: 'user', id: 'usr_1' },
  resourceType: 'billing.invoice',
  action: 'read',
  organizationId: 'org_1',
};

/** A `fetch` that answers one canned response and records what it was called with. */
function stubFetch(status: number, body: unknown): typeof fetch & { calls: RequestInit[] } {
  const calls: RequestInit[] = [];
  const impl = (async (_url: string | URL | Request, init?: RequestInit) => {
    calls.push(init ?? {});
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    } as Response;
  }) as typeof fetch & { calls: RequestInit[] };
  impl.calls = calls;
  return impl;
}

describe('permissionSlug', () => {
  it('is the pure join the PDP builds, so a resource type may contain dots', () => {
    assert.equal(permissionSlug(REQUEST), 'billing.invoice.read');
  });
});

describe('check resolves interchangeably', () => {
  it('answers the SAME question identically through all three resolvers', async () => {
    const allowed: CheckConfig[] = [
      { mode: 'claims', claims: () => ({ permissions: ['billing.invoice.read'] }) },
      {
        mode: 'authzen',
        endpoint: 'https://ironauth.test/access/v1/evaluation',
        fetchImpl: stubFetch(200, { decision: true }),
      },
      {
        mode: 'pdp',
        endpoint: 'https://fga.test/evaluate',
        fetchImpl: stubFetch(200, { decision: true }),
      },
    ];
    for (const config of allowed) {
      assert.equal(await check(config, REQUEST), true, `${config.mode} should allow`);
    }

    const denied: CheckConfig[] = [
      { mode: 'claims', claims: () => ({ permissions: ['billing.invoice.write'] }) },
      {
        mode: 'authzen',
        endpoint: 'https://ironauth.test/access/v1/evaluation',
        fetchImpl: stubFetch(200, { decision: false }),
      },
      {
        mode: 'pdp',
        endpoint: 'https://fga.test/evaluate',
        fetchImpl: stubFetch(200, { decision: false }),
      },
    ];
    for (const config of denied) {
      assert.equal(await check(config, REQUEST), false, `${config.mode} should deny`);
    }
  });

  it('sends the AuthZEN wire shape, so IronAuth and a customer PDP take the same body', async () => {
    const fetchImpl = stubFetch(200, { decision: true });
    await check(
      { mode: 'authzen', endpoint: 'https://ironauth.test/e', token: 's3cr3t', fetchImpl },
      REQUEST,
    );
    assert.equal(fetchImpl.calls.length, 1);
    const sent = JSON.parse(String(fetchImpl.calls[0]?.body));
    assert.deepEqual(sent, {
      subject: { type: 'user', id: 'usr_1' },
      resource: { type: 'billing.invoice' },
      action: { name: 'read' },
      context: { organization_id: 'org_1' },
    });
    const headers = fetchImpl.calls[0]?.headers as Record<string, string>;
    assert.equal(headers['authorization'], 'Bearer s3cr3t');
  });
});

describe('check fails closed', () => {
  it('denies for every endpoint failure shape', async () => {
    const shapes: Array<[string, CheckConfig]> = [
      ['a 500 with a valid allow body', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: stubFetch(500, { decision: true }),
      }],
      ['a 403 with a valid allow body', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: stubFetch(403, { decision: true }),
      }],
      ['a body with no decision', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: stubFetch(200, {}),
      }],
      ['a decision that is the STRING "true"', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: stubFetch(200, { decision: 'true' }),
      }],
      ['a decision that is the number 1', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: stubFetch(200, { decision: 1 }),
      }],
      ['a null body', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: stubFetch(200, null),
      }],
      ['a transport error', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: (async () => {
          throw new Error('connection refused');
        }) as unknown as typeof fetch,
      }],
      ['a body that will not parse', {
        mode: 'authzen', endpoint: 'https://x.test/e',
        fetchImpl: (async () => ({
          ok: true,
          status: 200,
          json: async () => {
            throw new Error('not json');
          },
        })) as unknown as typeof fetch,
      }],
    ];
    for (const [label, config] of shapes) {
      assert.equal(
        await check(config, REQUEST),
        false,
        `${label} must DENY: this function is the authorization decision, so a failure that ` +
          `granted would be a failure that grants`,
      );
    }
  });

  it('denies for every claims failure shape, including the PDP-overflow token', async () => {
    const shapes: Array<[string, CheckConfig]> = [
      ['no token at all', { mode: 'claims', claims: () => null }],
      ['an undefined token', { mode: 'claims', claims: () => undefined }],
      ['no permissions claim', { mode: 'claims', claims: () => ({ sub: 'usr_1' }) }],
      // The overflow case: an over-budget subject's token carries no usable list, and the
      // right answer is DENY so the deployment notices it must ask the PDP instead.
      ['a permissions claim that is not a list', {
        mode: 'claims', claims: () => ({ permissions: 'pdp_required' }),
      }],
      ['an empty permissions list', { mode: 'claims', claims: () => ({ permissions: [] }) }],
      ['a near-miss slug', {
        mode: 'claims', claims: () => ({ permissions: ['billing.invoice.rea'] }),
      }],
      ['a slug differing only in case', {
        mode: 'claims', claims: () => ({ permissions: ['Billing.Invoice.Read'] }),
      }],
    ];
    for (const [label, config] of shapes) {
      assert.equal(await check(config, REQUEST), false, `${label} must DENY`);
    }
  });

  it('reads the CURRENT token, not one captured when the middleware was built', async () => {
    // The mistake this guards against authorizes every request as whoever logged in first.
    let current: Record<string, unknown> | null = { permissions: ['billing.invoice.read'] };
    const config: CheckConfig = { mode: 'claims', claims: () => current };
    assert.equal(await check(config, REQUEST), true);
    current = { permissions: [] };
    assert.equal(
      await check(config, REQUEST),
      false,
      'the resolver kept the token from the first request, so every later caller is ' +
        'authorized as the first one',
    );
  });

  it('honours a configured claim name so an enriched claim can carry the permissions', async () => {
    const config: CheckConfig = {
      mode: 'claims',
      claimName: 'fga_permissions',
      claims: () => ({ permissions: [], fga_permissions: ['billing.invoice.read'] }),
    };
    assert.equal(await check(config, REQUEST), true);
  });
});
