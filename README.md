# webhook-signal

Webhook listener that delivers notifications through [signal-cli](https://github.com/asamk/signal-cli). One process, several endpoints, each with its own secret and recipients.

A push to `main` publishes `ghcr.io/kalex3/webhook-signal:latest`.

## Run

`compose.yml` starts cloudflared, this service, and the signal-cli daemon.

```bash
cp .env.example .env
```

Fill in `SIGNAL_ACCOUNT`, `SIGNAL_RECIPIENT`, `GITHUB_WEBHOOK_SECRET`, and `TUNNEL_TOKEN`. `SIGNAL_RECIPIENT` is one phone number or group id, or several separated by commas. Group ids must not contain commas. The account named by `SIGNAL_ACCOUNT` must already be linked in the `./signal-cli` volume.

```bash
docker compose up -d
```

With no routes file, every `POST` to `WEBHOOK_PATH` (default `/webhook`) is a GitHub webhook signed with `GITHUB_WEBHOOK_SECRET`. `SIGNAL_API` defaults to `http://signal-cli:8080`.

`GET /health` returns `{"status":"ok"}`.

The routes file is read once at startup. Restart the process after editing it.

## Several endpoints

Copy `routes.example.json` to `routes.json` (gitignored), mount it, and set `ROUTES_FILE`. The file must be readable by uid 1000. Compose still requires `GITHUB_WEBHOOK_SECRET` and `SIGNAL_RECIPIENT` to be non-empty. With `ROUTES_FILE` set, the program uses the file instead of `WEBHOOK_PATH` and `GITHUB_WEBHOOK_SECRET`. Routes that omit recipients fall back to `SIGNAL_RECIPIENT`.

```json
{
  "routes": [
    {
      "name": "app",
      "path": "/hooks/app",
      "secretEnv": "APP_WEBHOOK_SECRET",
      "recipients": ["+15551212000"]
    }
  ]
}
```

`secret` and `secretEnv` are mutually exclusive. `recipients` and `recipientsEnv` are merged. Paths are cleaned, must be unique, and `/health` is reserved. A missing or unknown JSON field is rejected at startup.

## Kinds

`kind` defaults to `github`.

### github

Checks `X-Hub-Signature-256` (`sha256=` plus the hex HMAC-SHA256 of the raw body). These deliveries are sent:

- `push`, `create`, `delete`, and `fork`
- `workflow_run` and `check_run` when the action is `completed`
- `page_build` when the status is `built` or `errored`
- `deployment_status` for `success`, `failure`, or `error`
- `pull_request` for `opened`, `reopened`, `closed`, `ready_for_review`, or `converted_to_draft` (a merged pull request is shown as merged)
- `release` for `published` or `released`
- `issues` for `opened`, `reopened`, or `closed`
- `star` when the action is `created`

Anything else, including `ping`, is answered `200` and not forwarded. The set is fixed in the program.

### generic

Any POST body. This is the only kind that does not require `Content-Type: application/json`.

`verify` is `hmac` (default, header `X-Signature-256`) or `token`. A token in `Authorization` must be prefixed with `Bearer `. `title` defaults to the route name.

`fields` are dot paths. A missing value is shown as `unknown`. The first `http` or `https` value is also attached as a link. With no `fields`, the message is the body: compacted JSON when it parses, otherwise the raw text, cut at 400 characters.

### alert

Prometheus Alertmanager, Grafana unified alerting, and the legacy Grafana webhook (`ruleName`, `state`, `evalMatches`). `alertmanager` and `grafana` are aliases. The default check is a bearer token. `fields` is rejected.

Firing alerts are listed up to five, then a count of the rest. A resolved alert strikes the summary. An empty object is rejected.

### map

Declarative match against a JSON object. The first matching rule wins. No match, or a status listed in `ignore`, is answered `200` and not sent. `verify` defaults to HMAC on `X-Signature-256`, same as `generic`.

A rule needs at least one of `title`, `status`, `subject`, `summary`, `fields`, `each`, or `link`.

| Field | Meaning |
| --- | --- |
| `when` | Path to string. All entries must match, case-insensitive. Empty matches every object. |
| `present` | Paths that must be a non-empty string, array, or object. |
| `status` | Path whose value picks the emoji. With a title, the value is also a Status line. |
| `statusMap` | Rewrite that value before the emoji and `ignore` list. Keys are case-insensitive. Requires `status`. |
| `ignore` | Status values to drop. Requires `status`. |
| `subject` | Path appended to the title. |
| `summary` | Path, first line, up to 200 characters. |
| `fields` | `{ "label", "path", "trimPrefix" }`. Missing values are skipped. |
| `each` | Array of objects. `text` is monospace. `short` truncates it, up to 64 characters; `0` leaves it whole. `detail` is the first line, italic, up to 150 characters. `limit` defaults to 5 and caps at 20. |
| `link` | Path to a URL. |

`up`, `resolved`, `ok`, and `closed` strike the summary. Other known words (`success`, `failure`, `down`, `new`, `update`, `killed`, `firing`, `merged`, `pending`, `running`, `cancelled`, `skipped`) set the emoji. Anything else is shown with a bell.

`routes.example.json` has rules for GitLab, Uptime Kuma, Diun, Forgejo, Woodpecker, and borgmatic.

Uptime Kuma does not sign the body. Put the token in an additional header, `Authorization: Bearer <KUMA_TOKEN>`. Numeric `heartbeat.status` is mapped: `0` down, `1` up, `2` pending, `3` maintenance. Pending and maintenance are dropped.

Diun must POST. Set `authorization: Bearer <DIUN_TOKEN>`. Unchanged and skipped images are dropped.

Forgejo's webhook secret is checked against `X-Hub-Signature-256`. The rule sends pushes that include commits.

Woodpecker's `plugins/webhook` leaves `build.status` at `success`. Gate each step with `when.status` and put that word in the body:

```json
{"repo":"{{ repo.owner }}/{{ repo.name }}","status":"failure","branch":"{{ build.branch }}","message":"{{ build.message }}","author":"{{ build.author }}","url":"{{ build.link }}"}
```

Repeat the step for `success`. Pending, running, and started are dropped.

borgmatic has no fixed webhook body. Post this, with `Authorization: Bearer <BORGMATIC_TOKEN>`:

```json
{"status":"error","repository":"{repository}","message":"{error}"}
```

Use `"status":"success"` when the backup finishes.

## Delivery

Each recipient gets its own signal-cli `send` call, in parallel, with a shared 9 second budget. One recipient is a one-element array per call.

| Result | Response |
| --- | --- |
| Sent to every recipient | `200 Notification sent` |
| Sent to some recipients | `200 Notification partially sent` |
| Ignored event | `200 Event ignored` |
| Every send failed | `502 Signal delivery failed` |
| Bad signature | `401 Invalid signature` |
| Bad JSON or body over 1 MiB | `400` |
| Wrong method | `405` |
| Non-generic route without `application/json` | `415` |

A partial success is `200` so the sender does not retry the recipients that already got the message.
