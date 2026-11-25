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


## Authenticated gateway (v0.2)

The original browser sandbox is unchanged and remains a synthetic local demo. The new authenticated API is a separate service: `npm run secure`. Set `AGENTGUARD_STORAGE_KEY` to a random secret of at least 32 bytes and `AGENTGUARD_CREDENTIALS` to a JSON array of objects with `token` (unique random 32+ character bearer secret), `role` (admin, reviewer, viewer, agent) and `identity` (trusted agent/operator ID). Generate secrets with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. Do not commit them. Default binding is 127.0.0.1:8788. All endpoints require authentication; use an authenticated TLS reverse proxy if remote access is needed, and do not expose the original sandbox.

| Endpoint | Role |
|---|---|
| POST /v1/invoke, /v1/preview | agent; identity from token; body tool, args |
| GET /v1/status, /v1/policy, /v1/history, /v1/alerts | admin, reviewer, viewer |
| GET /v1/audit?decision=deny&limit=50&offset=0 | admin, reviewer, viewer |
| GET /v1/audit/export, /metrics | admin, reviewer, viewer |
| GET /v1/approvals, POST /v1/review | reviewer only; review body approvalId, approve |
| POST /v1/policy | admin; policy, expectedRevision |
| POST /v1/rollback | admin; revision, expectedRevision |
| POST /v1/halt | admin; halted boolean |
| POST /v1/disable | admin; agent, disabled boolean |
| GET /health | any authenticated role |

The API holds review requests in memory for 120 seconds. Reviewers see the exact arguments; agents cannot approve their own request. A review is consumed once, and current policy, quotas and controls are checked before execution. Any policy revision invalidates prior approval. Pending requests are intentionally lost on restart rather than storing arguments. The signed atomic state file retains policy history (20 revisions), quotas, control flags, totals and the last 1,000 audit events. Keep its signing key outside the state directory. A signed older snapshot can still be replayed by an attacker with filesystem access. Single writer only; do not share the file between processes. Storage failure is fail-closed. Credential scanning is heuristic, not complete DLP. Timeouts signal cooperative cancellation; non-cooperative handlers may still have side effects and retain a concurrency slot until settled. Kill switch blocks new execution, not in-flight work. All handlers are synthetic. No external security assessment or production deployment is implied.

See `test/gateway.test.js` and `test/api.test.js` for behavioural and HTTP integration tests.
