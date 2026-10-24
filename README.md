# Observable Incident Triage — TDS GA3

FastAPI service for the `ga5-incident-agent/v2` contract. PostgreSQL stores each run and receipt before a response is returned. Gemini is used for a first-seen run's diagnosis/action plan; receipt processing, GET and replay do not call the model.

## Deploy

Use the included Render Blueprint (`render.yaml`) or create an Oregon web service and PostgreSQL database in the same region. Set `GEMINI_API_KEY` in the Render service environment. The database URL is supplied by Render's `fromDatabase` reference in the Blueprint.

## API

- `GET /health`
- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`

The implementation validates the profile, allowed root cause, evidence IDs, catalog tool names, diagnostic count, and approval gates. Sensitive request fields are never sent to the model or returned in error messages or telemetry.

## Notes

Tool calls are represented as dispatches for the grader; the grader supplies authoritative outcomes. The service does not execute real production actions. Every accepted receipt is persisted and reflected in action/receipt logs and OTLP spans. Never use real production logs or credentials in test incidents.
