// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The admin MCP tool surface, declared as DATA (issue #123).
 *
 * Every tool states the management permission it requires and whether it is destructive. Both
 * are properties of the tool rather than checks written inside it, and that is the whole design:
 *
 * - a tool whose permission is a FIELD can be filtered before it is ever advertised, which is
 *   what criterion 4's "a key scoped to read-only exposes no mutating tools" asks for; and
 * - a tool whose destructiveness is a FIELD cannot be added without answering the question,
 *   because the type requires it.
 *
 * A tool that checked its own permission inside its handler would satisfy the failing-closed
 * half and none of the listing half, and the next tool added would be the one whose author
 * forgot.
 *
 * ## Every tool names a REAL operation, and a test proves it
 *
 * `every_tool_names_an_operation_the_contract_publishes` resolves each tool's method and path
 * against `docs/openapi/management.json`. That is not bookkeeping: this surface first shipped a
 * `delete_application` tool driving a path the management API does not serve, and every unit
 * test passed because the fake API in those tests answers 200 to anything. An agent would have
 * been offered a delete that always 404s.
 *
 * The contract is the only thing that could have caught it, so the contract is what the tools
 * are checked against.
 *
 * ## Why the surface is small
 *
 * Tenant, application, environment and user administration, which is what the issue names. It is
 * not a wrapper over all 271 management operations, and that restraint is deliberate: every tool
 * here is one a misfiring agent can invoke, so the surface is the set somebody decided an agent
 * should have rather than the set that happened to exist.
 */

/** The management permissions this server knows how to require. */
export type Permission =
  | 'management.read'
  | 'management.write_config'
  | 'management.write_users'
  | 'management.write_organizations'
  | 'management.write_credentials';

/** One tool. */
export interface Tool {
  readonly name: string;
  readonly description: string;
  /** The management permission a credential must hold to invoke it. */
  readonly requires: Permission;
  /**
   * Whether invoking it destroys something.
   *
   * A destructive tool refuses without an explicit `confirm: true` argument (criterion 6). The
   * field is REQUIRED rather than defaulted, so adding a tool means answering the question
   * rather than inheriting an answer.
   */
  readonly destructive: boolean;
  /** The HTTP method and path template it drives. */
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Path template, with `{name}` placeholders filled from the tool's arguments. */
  readonly path: string;
  /** Arguments the caller must supply, beyond `confirm`. */
  readonly required: readonly string[];
}

/**
 * Every tool this server exposes.
 *
 * ORDERED read-then-write per domain, so the list reads as a capability rather than an
 * alphabetical dump.
 */
export const TOOLS: readonly Tool[] = [
  {
    name: 'list_tenants',
    description: 'List the tenants this credential can see.',
    requires: 'management.read',
    destructive: false,
    method: 'GET',
    path: '/v1/tenants',
    required: [],
  },
  {
    name: 'list_environments',
    description: 'List a tenant’s environments.',
    requires: 'management.read',
    destructive: false,
    method: 'GET',
    path: '/v1/tenants/{tenant_id}/environments',
    required: ['tenant_id'],
  },
  {
    name: 'get_application',
    // The management API has no "list applications" operation, so this server has no such tool.
    // The contract check below is what established that -- an earlier draft declared one and
    // would have offered an agent a listing that always 404s.
    description: 'Read one registered OAuth application by its client id.',
    requires: 'management.read',
    destructive: false,
    method: 'GET',
    path: '/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}',
    required: ['tenant_id', 'environment_id', 'client_id'],
  },
  {
    name: 'list_users',
    description: 'List the users in an environment.',
    requires: 'management.read',
    destructive: false,
    method: 'GET',
    path: '/v1/tenants/{tenant_id}/environments/{environment_id}/users',
    required: ['tenant_id', 'environment_id'],
  },
  {
    name: 'get_user',
    description: 'Read one user.',
    requires: 'management.read',
    destructive: false,
    method: 'GET',
    path: '/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}',
    required: ['tenant_id', 'environment_id', 'user_id'],
  },
  {
    name: 'create_user',
    description: 'Create a user in an environment.',
    requires: 'management.write_users',
    // NOT destructive: it creates. A confirmation on every write would train an operator to pass
    // `confirm: true` reflexively, which is exactly how the parameter stops protecting the
    // deletes it exists for.
    destructive: false,
    method: 'POST',
    path: '/v1/tenants/{tenant_id}/environments/{environment_id}/users',
    required: ['tenant_id', 'environment_id'],
  },
  {
    name: 'delete_user',
    description: 'Delete a user. Destructive: requires confirm.',
    requires: 'management.write_users',
    destructive: true,
    method: 'DELETE',
    path: '/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}',
    required: ['tenant_id', 'environment_id', 'user_id'],
  },
  {
    name: 'delete_environment',
    description: 'Delete an environment and everything in it. Destructive: requires confirm.',
    requires: 'management.write_config',
    destructive: true,
    method: 'DELETE',
    path: '/v1/tenants/{tenant_id}/environments/{environment_id}',
    required: ['tenant_id', 'environment_id'],
  },
  {
    name: 'revoke_management_key',
    description: 'Revoke a management key. Destructive: requires confirm.',
    // `write_credentials` and not `write_config`: revoking a credential is a different authority
    // from changing configuration, and a key that may reshape an environment should not
    // implicitly be able to revoke the keys that manage it.
    requires: 'management.write_credentials',
    destructive: true,
    method: 'DELETE',
    path: '/v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}',
    required: ['tenant_id', 'environment_id', 'key_id'],
  },
];
