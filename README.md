# AgentGuard

A lightweight policy enforcement gateway for AI agent tool calls, with a local security console and an insurance-themed synthetic demonstration. Built with Node.js standard-library modules and no third-party runtime dependencies.

## Quick start

Requires Node.js 20 or newer.

```sh
git clone https://github.com/pg-thirion/AgentGuard.git
cd AgentGuard
npm test
npm run demo
npm start
```

Open http://127.0.0.1:8787 and select **Run scenario suite**.

## Architecture

Trusted application identity + proposed tool call → AgentGuard → registered tool handler (only if allowed).

The host must route every tool invocation through the gateway and provide an authenticated, trusted agent identity. Model-generated arguments are untrusted. The gateway is not a network proxy and cannot prevent direct access to tools outside this boundary.

- Default deny; explicit deny overrides allow and review rules.
- Exact tool names, agent matching, required typed arguments, value allowlists and length constraints.
- Fixed-window quotas shared per rule; overlapping rules must all permit arguments.
- Approval-required requests are held (never executed). No approval workflow or override is implemented.
- Separate execution outcome events and hash-linked audit records; no raw argument values or handler outputs in audit.
- Local browser console with editable JSON policy, eight scenarios, counters and JSON audit export.

## Integration

```js
import { AgentGuard } from './src/guard.js';

const guard = new AgentGuard({
  policy: {
    version: '1',
    rules: [{
      id: 'read-only',
      agent: 'claims-agent',
      tool: 'read_claim',
      effect: 'allow',
      arguments: { claimId: { type: 'string', maxLength: 32 } },
      limit: { count: 5, windowSeconds: 60 }
    }]
  },
  tools: {
    read_claim: async ({ claimId }) => ({ claimId, status: 'synthetic' })
  }
});
const result = await guard.invoke('claims-agent', 'read_claim', { claimId: 'CLM-1042' });
```

A real integration must enforce claim-level authorisation inside the tool handler as well. Policy configuration must be restricted to trusted operators. Deny rules match identity and tool unconditionally. Argument schemas require every listed key and reject unknown keys. Supported types: string, number, boolean. Exact value allowlists are optional. String lengths default to 256. Policies are validated before being applied.

## Security boundaries and limitations

This is a portfolio prototype, not a production security product. The browser sandbox binds to IPv4 loopback only, accepts synthetic identities from its request editor and exposes policy editing to local clients. Do not expose it to a network or deploy it as-is. The runtime policy and the last 1,000 audit events are held in memory. Hash chaining can detect changes relative to a trusted anchor, but cannot stop an attacker from rewriting the whole chain. Quotas are process-local and fixed-window; restart resets them. Handler timeouts, distributed quotas, durable signed audit storage, authentication, real approval workflows and MCP/provider adapters are future work. No real claims, emails, credentials or shell operations are used.

## Tests

`npm test` runs built-in Node tests covering precedence, default deny, malformed arguments, quotas, policy validation, review gating, audit integrity and handler errors. `npm run demo` runs the synthetic scenarios in a terminal.

## Project layout

- `src/guard.js`: reusable policy engine and enforcement wrapper
- `src/server.js`: loopback-only sandbox API
- `src/sandbox.js`: synthetic registered handlers and scenarios
- `policies/default.json`: example policy
- `web/`: responsive security console
- `test/`: regression tests
