# @ironauth/mcp

The IronAuth admin MCP server: the management API as agent tools.

## Three rules

**It advertises only what its own key can drive.** `listTools` asks the API what the credential
holds (`GET /v1/me`) and filters. A read-scoped key sees no mutating tool at all -- not a tool
that fails, a tool that is not there. An MCP client shows what it is given, so a tool listed as
"unavailable" is a tool an agent will try.

**A destructive tool refuses without `confirm: true`.** Not `"true"`, not `"yes"`, not `1` --
those are what a model produces when it is guessing at the shape rather than acting on the
message. Non-destructive writes need no confirmation, because a confirmation on every write
trains an operator to pass it reflexively and stops it protecting the deletes it exists for.

**Every request says how it arrived.** The server authenticates with a scoped management key --
there is no super-admin ambient authority anywhere in this package -- and sets
`X-IronAuth-Entry-Path: mcp`, so an operator can tell an agent-driven change from a direct one by
the same identity in the same audit stream.

## The client-side check is not the security boundary

The management API refuses a credential that lacks a permission, and always did. Nothing here can
grant anything: a caller who bypassed this server and called the API directly would get exactly
the same answers.

What this adds is that an **agent is never offered a tool it cannot use**. That is a usability
property with a security consequence -- an agent shown a tool will try it, and an agent that
tries a delete it cannot perform still asked to delete something -- but it is defence in depth.
The fence is on the server.

## Failing closed

If `GET /v1/me` cannot be read, the server advertises **nothing** and refuses every call. An
unreachable introspection endpoint must not be the reason an agent is offered a delete.

## Usage

```ts
import { AdminMcpServer } from '@ironauth/mcp';

const server = new AdminMcpServer({
  apiBase: 'https://admin.example',
  apiKey: process.env.IRONAUTH_MANAGEMENT_KEY,   // scoped; whatever it can do is all this can do
});

await server.listTools();                        // only what the key can drive
await server.callTool('delete_user', {
  tenant_id, environment_id, user_id, confirm: true,
});
```

## Adding a tool

Declare it in `src/tools.ts` with its `requires` permission and its `destructive` flag. Both are
required fields, so a new tool cannot be added without answering both questions.

Two gates then apply, and both have caught real bugs:

- `every_tool_names_an_operation_the_contract_publishes` resolves the tool against
  `docs/openapi/management.json`. It found two tools driving paths the API does not serve, which
  every other test passed because the fake API in them answers 200 to anything.
- `scripts/mcp-entry-path.sh` requires every mutating tool's Rust handler to accept the entry
  path, so an agent-driven mutation cannot land in the audit stream unmarked.
