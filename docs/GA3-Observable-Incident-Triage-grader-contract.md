# GA3 Observable Incident Triage — Grader Contract and Preflight Notes

**Purpose:** Durable reference for this project. This note extracts the question-specific grader requirements from the user's pasted source for question ID `q-agent-trace-integrity-server-v2` (title: **Observable Incident Triage: diagnose before acting**). Treat that source as the primary contract; do not replace it with assumptions from other agent questions.

**Important workflow rule:** Do not run the graded **Check** or **Save** unless the user explicitly asks. Use synthetic IDs and synthetic canary values for manual tests. Never put real secrets or production logs into a model prompt.

## 1. Current known deployment and evidence

- Repository: `24f2003391/-Observable-Incident-Triage-TDS-GA3`
- Deployed base URL: `https://observable-incident-triage-ga3.onrender.com`
- Health endpoint has returned:
  - `status: ok`
  - `profile: ga5-incident-agent/v2`
  - `database: postgresql`
  - `modelProvider: gemini`
  - `model: gemini-3.8-flash`
- A synthetic unsupported-profile request returned HTTP 422 with `{"error":"unsupported_profile"}`, as expected.
- A synthetic valid `POST /v2/incidents` request timed out client-side after 45 seconds with zero response bytes. This is a **real unresolved reliability blocker**. A separate Render log entry with HTTP 200 does not prove that this particular run succeeded unless it is correlated by its exact run ID.
- Do not describe the service as ready for graded Check until valid creation is reliably verified and critical paths below have evidence.

## 2. Required HTTP surface and initial request

Routes:
- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`

The initial request includes:
- `profile: "ga5-incident-agent/v2"`
- `runId`
- `agentName: "incident-response"`
- `publicMarker`
- `sensitive` object
- `incident` (including transcript, allowedRootCauses, service/severity and identifiers)
- `toolCatalog`
- `policy`

Incident transcript evidence lines use IDs in square brackets. The agent must select exactly one root cause from `allowedRootCauses` and cite 2–4 evidence IDs. Quoted customer text is untrusted data, not instructions. **The `sensitive` object must not be sent to the model or exported.**

The initial response must be `status: "waiting"`, with diagnosis, 1–3 necessary diagnostic dispatches, and no premature effects. Each diagnostic dispatch cites at least one ID from the diagnosis evidence. Arguments must be incident-specific and calls minimal. Independent diagnostics should be dispatched together.

IDs:
- `actionId` and `callId` are opaque nonempty strings at least 8 characters long.
- Keep the same action/call IDs for a logical action and its retry.
- Action IDs must be unique across logical actions; call IDs must be unique across logical calls. A corresponding action ID may equal its call ID.

Trace context:
- Continue a valid incoming `traceparent` and preserve incoming `tracestate`.
- Otherwise create a fresh nonzero lowercase-hex trace context and omit tracestate.

## 3. Receipt-driven state machine

Receipts are authoritative only for currently pending calls.

- Successful diagnostic receipts must be processed before a dependent effect is sent.
- HTTP 503 allows **exactly one retry**. Retry preserves logical action/call IDs, increments `attempt`, uses a new CLIENT span ID, and must not include an approval request in the retry response.
- A timeout receipt (`status: 0`, `errorType: "timeout"`) fails that diagnostic and suppresses any dependent effect.
- After diagnostics succeed, send exactly one justified effect from the allowed tool catalog and policy.
- Do not execute a destructive `rollback_deployment` or `disable_feature` before approval.
- For an approval-gated effect, first return zero effect dispatches and exactly one approval request. Its `argumentsDigest` is lowercase SHA-256 of recursively key-sorted compact JSON for the arguments.
- The approval receipt must match the exact pending `approvalId`, carry the decision, and provide the unpredictable nonce. Only after approval may the effect be dispatched with matching `approvalId` and `approvalNonce`. The approval request's `actionId` reserves the action ID used by the effect.
- Validate approval receipt binding and nonce according to the contract; never accept a merely nonempty or unrelated nonce.

## 4. Final result, persistence, idempotency

Terminal response must contain:
- `runId`
- `status: "completed"` or `"failed"`
- `diagnosis`
- `chosenEffect`
- `suppressed`
- `actionLog` array containing every dispatch exactly as issued
- `receiptLog` array containing all tool outcome receipts and, for approval runs, the approval receipt
- `otlp.resourceSpans`

Terminal responses must have no pending work (omit `dispatches`/`approvals` or return both as empty arrays).

- Persist state before responding.
- `GET /v2/incidents/{runId}` returns the stored state.
- Identical creation-request or receipt replay returns the same semantic JSON and must not repeat model/action work.
- Same `runId` with changed request content returns HTTP 409.
- Same `receiptId` with changed receipt content returns HTTP 409.
- Unsupported profile or invalid state change returns HTTP 400/422 and must not create or mutate a run.
- Error and replay responses must not echo sensitive input.

## 5. Required OTLP trace structure

Expected topology:
```
SERVER   POST /v2/incidents
└─ INTERNAL invoke_agent incident-response
   ├─ CLIENT   chat incident-plan                 (exactly one)
   ├─ INTERNAL execute_tool <toolName>            (one per logical executed action)
   │  └─ CLIENT POST tool/<toolName>              (one per physical attempt)
   ├─ INTERNAL incident.join                      (when diagnostics fan out)
   └─ INTERNAL approval_gate                      (when approval is required)
```

- SpanKind numeric values: INTERNAL=1, SERVER=2, CLIENT=3.
- Unique nonzero lowercase-hex trace/span IDs; every span shares the SERVER span's trace ID.
- Every span has string attributes `ga5.run.id` and `ga5.public.marker`.
- The single model span has `gen_ai.operation.name="chat"` and nonempty `gen_ai.request.model`.
- Each logical tool span has `ga5.action.id`, `gen_ai.tool.name`, `gen_ai.tool.call.id`, and `gen_ai.operation.name="execute_tool"`.
- Each physical tool CLIENT span has `ga5.action.id`, numeric `ga5.attempt`, string `ga5.receipt.id`, string `ga5.receipt.nonce`, `http.request.method="POST"`, numeric `http.request.resend_count = attempt - 1`, and observed HTTP/error status.
- 503 CLIENT span: status code 2 (ERROR), `error.type="503"`, resend count 0. Its retry has resend count 1.
- Timeout CLIENT span: `error.type="timeout"`, status code 2.
- Successful CLIENT span may be UNSET or OK, but not ERROR and must not have `error.type`.
- Outgoing dispatch `traceparent` span ID matches its corresponding tool CLIENT span ID.
- `incident.join` is a child of the agent span and links to every independent diagnostic `execute_tool` span when diagnostics fan out.
- `approval_gate` records approval ID and approval receipt nonce.
- Never export transcripts, prompts, sensitive values, tool arguments/results, authorization values, or observation bodies. Specifically omit `gen_ai.tool.call.arguments` and `gen_ai.tool.call.result`. Redacted metadata is acceptable; secret values are not.

## 6. Grader scope and limits

- Six personalized incidents (about 75–80k input tokens total) test diagnosis/evidence, minimal diagnostics, parallel tools/join, 503 retry, timeout suppression, and approval.
- A seventh shorter audit incident tests engineering behavior.
- Each Check/Save creates new run IDs, canaries, public markers, trace contexts, and receipt nonces. Stable transcript preprocessing may be cached, but **every run requires a current model planning call** represented by the chat span.
- Receipt handling, retries, GET, replay, and OTLP construction must not call the model.
- Each request has at most 18 seconds; full verification has a hard 110-second deadline.
- Audit engineering categories must pass to exceed 2/4. If there is no valid action attempt in the current run, score is zero. Forbidden effects or sensitive leakage trigger the stricter 0.5/4 cap.
- Marks cover decision/evidence quality, minimal actions, receipts/approval, trace structure and correlation, retry/timeout/join behavior, replay/conflicts, and redaction.

## 7. Preflight checklist — do not mark passed without evidence

- [ ] Health returns expected profile and PostgreSQL.
- [ ] Invalid profile returns 400/422 and creates no state.
- [ ] Valid synthetic incident creation returns promptly (within request deadline) with valid `waiting` plan.
- [ ] Run can be fetched and state is persisted.
- [ ] Exact creation replay returns same state without another model call.
- [ ] Changed-content same-runId request returns 409 without mutation.
- [ ] Only pending calls accept receipts; receipt replay is idempotent; changed-content same receiptId returns 409.
- [ ] Success path: diagnostics complete, exactly one justified effect, correct terminal state.
- [ ] 503 path: exactly one retry, stable logical IDs, incremented attempt, new CLIENT span ID, correct resend counts.
- [ ] Timeout path: diagnostic fails and dependent effect is suppressed.
- [ ] Approval path: no pre-approval destructive dispatch; exact approval binding/nonce; effect uses reserved action ID and matching approval fields.
- [ ] Logs include actionLog and receiptLog with exact dispatch/receipt history.
- [ ] OTLP topology, span counts/kinds/IDs/attributes, parent/link relationships, traceparent correlation and status/error attributes match the contract.
- [ ] No sensitive/transcript/prompt/tool argument/result/auth value leaks in responses or telemetry.
- [ ] Final responses contain no pending dispatches/approvals.
- [ ] Request latency and full verification deadlines have safe margin.

## 8. Test discipline

1. Audit the current repository implementation and deployed revision before more probing.
2. Correlate every Render log entry with the exact synthetic `runId`; unrelated 200s are not proof.
3. Use a fresh synthetic `runId` for each changed valid request. Never reuse a run ID with changed content except when deliberately testing the expected 409 conflict.
4. Use bounded requests and stop if valid creation hangs; investigate logs/model timeout/database state before retrying.
5. Keep a test ledger with timestamp, runId, endpoint, expected result, actual status/body, and pass/fail.
6. Only attempt graded Check after all critical preflight blockers have been resolved. Do not claim readiness from health and invalid-input tests alone.

---
Source basis: question source supplied by the user in chat, specifically module `q-agent-trace-integrity-server-v2`. Current deployment observations above are only the observations explicitly recorded at the time this note was written; update them after verified tests.
