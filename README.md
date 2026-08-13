# release-gate

A deterministic policy endpoint that decides whether a GitHub Actions run may
promote a container image.

## Endpoint

`POST /release-gate`

Request body: the payload described in the assignment (`target`, `event`,
`ref`, `workflow`, `image`).

Response:

```json
{"decision": "promote | block", "violations": ["CODE", "..."]}
```

`decision` is `"promote"` only when `violations` is empty.

## Rules enforced (see `policy.js`)

1. **Permissions** must be *exactly* `contents: read`, `packages: write`,
   `id-token: none` — no extra scopes, no substitutions.
   → `EXCESS_PERMISSION`
2. **PR trigger safety** — `pull_request_target` is never allowed; a
   `pull_request` event must be handled by a `pull_request`-triggered
   workflow. → `UNSAFE_PR_TRIGGER`
3. **Complete matrix testing** — tests must have passed, the whole matrix
   must have finished, and `failFast` must be `false`.
   → `TESTS_INCOMPLETE`
4. **Action pinning** — actions owned by `actions` may use a tag; every
   third-party action must be pinned to a full 40-character lowercase hex
   commit SHA. → `MUTABLE_ACTION`
5. **Hardened image**:
   - must be multi-stage → `SINGLE_STAGE_IMAGE`
   - must not run as root → `ROOT_RUNTIME`
   - build secrets must be `none` or `buildkit` (never `arg`/`copy`)
     → `SECRET_IN_LAYER`
   - zero critical vulnerabilities → `CRITICAL_CVE`
   - must be referenced by digest → `UNPINNED_IMAGE`
6. **Production target** additionally requires a `push` to
   `refs/heads/main` (`INVALID_PRODUCTION_REF` otherwise) and
   `workflow.environmentApproval === true` (`APPROVAL_REQUIRED` otherwise).

## Run locally

```bash
npm install
npm start        # serves on PORT (default 3000)
npm test         # runs the policy test suite (node --test)
```

## Deploy

Any Node host works (Render, Railway, Fly.io, a VM, etc.) — it's a plain
Express app with one dependency. Start command: `npm install && npm start`.
Expose the `PORT` environment variable the platform assigns.
