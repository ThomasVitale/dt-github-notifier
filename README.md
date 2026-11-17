# dt-github-notifier

A lightweight Go service that receives [Dependency-Track](https://dependencytrack.org/) v5 webhook
notifications and creates GitHub Issues for policy violations and vulnerabilities.

Built with **[ko](https://ko.build)** (no Dockerfile) and deployed as a
**[Knative Serving](https://knative.dev/docs/serving/)** Service with scale-to-zero
and cluster-local visibility (never exposed to the public internet).

---

## Architecture

```
[Dependency-Track Pod]
        |
        | HTTP POST — cluster-internal DNS only
        | http://dt-github-notifier.dependency-track.svc.cluster.local/webhook
        v
[Knative Service: dt-github-notifier]   <- scales 0 to N on demand
        |
        | HTTPS egress only
        v
[api.github.com - GitHub Issues API]
```

---

## Notification groups handled

| DT Group | GitHub labels |
|---|---|
| `POLICY_VIOLATION` | `security`, `policy-violation`, `dependency-track`, `violation-state:<state>` |
| `NEW_VULNERABILITY` | `security`, `vulnerability`, `dependency-track`, `severity:<level>` |
| `NEW_VULNERABLE_DEPENDENCY` | `security`, `vulnerable-dependency`, `dependency-track` |

All other groups are acknowledged and ignored (HTTP 204).

The service expects the payload produced by the default template of the Dependency-Track v5
[Webhook publisher](https://dependencytrack.github.io/docs/next/reference/notifications/publishers/#webhook)
(groups such as `GROUP_NEW_VULNERABILITY`, subjects as described in the
[notification schema](https://dependencytrack.github.io/docs/next/reference/notifications/schema/)).
Dependency-Track v4 payloads are not supported.

### Repository resolution

Each issue is created in the GitHub repository of the affected project, resolved through the
Dependency-Track REST API in this order:

1. An external reference of type `vcs` pointing to `https://github.com/<owner>/<repo>`
2. A project property with group `github`, name `repo` and value `<owner>/<repo>`
3. A project PURL of the form `pkg:github/<owner>/<repo>`
4. The same hints on the parent project, then its parent (up to 5 levels), so a whole project
   hierarchy can share one repository
5. The `GITHUB_REPO` fallback, if set

Resolved repositories are cached for 5 minutes per project, so a BOM upload that triggers many
notifications for one project costs a single lookup.

### Deduplication

Every issue carries a key that identifies the finding, shown in its footer
(`deduplication key: dtgn-…`):

| DT Group | Finding |
|---|---|
| `NEW_VULNERABILITY` | project + component + vulnerability |
| `NEW_VULNERABLE_DEPENDENCY` | project + component |
| `POLICY_VIOLATION` | project + component + policy condition |

Before creating an issue, the service searches the repository for an **open** issue with the same
key and skips the notification if one exists. Once that issue is closed, a new notification for
the same finding opens a new issue. Issues handled in the last 15 minutes are also remembered in
memory, because GitHub search may not return very recent issues yet, which would otherwise let a
Dependency-Track retry create a duplicate.

The GitHub search API allows 30 requests per minute, and GitHub limits issue creation to about 80
per minute and 500 per hour. Notifications over these limits are answered with 503 and
`Retry-After`, so Dependency-Track delivers them later.

### Responses and retries

Dependency-Track retries a webhook that answers with 429, 502, 503 or 504, honoring
`Retry-After`, and gives up on any other error. The service answers accordingly:

| Status | When |
|---|---|
| 204 | Issue created or already open, or notification group not handled |
| 400 | Malformed payload |
| 401 | Missing or invalid signature (when `DT_WEBHOOK_SECRET` is set) |
| 413 | Payload larger than 10 MiB |
| 422 | No GitHub repository could be resolved and `GITHUB_REPO` is not set |
| 500 | Permanent failure, e.g. GitHub rejected the issue (unknown repo, invalid token) |
| 503 | Transient failure: Dependency-Track API or GitHub unavailable, GitHub rate limits (with `Retry-After` when known) |

---

## Prerequisites

| Tool | Purpose |
|---|---|
| [devenv](https://devenv.sh/getting-started/) | Reproducible development environment (Go, ko, crane, kubectl, Task, golangci-lint, govulncheck, jq) |
| [direnv](https://direnv.net) (optional) | Activate the devenv shell automatically when entering the directory |
| Knative Serving | Already installed in your cluster |

Enter the development environment:
```bash
devenv shell
# or, with direnv
direnv allow
```

All tasks are defined in `Taskfile.yml` and run with [Task](https://taskfile.dev). List them with `task --list`.

---

## Configuration

| Env var | Required | Description |
|---|---|---|
| `GITHUB_TOKEN` | Yes | GitHub PAT with Issues: Read & Write |
| `GITHUB_REPO` | No | Fallback repo for projects without a GitHub hint, e.g. `myorg/myrepo` |
| `GITHUB_API_URL` | No | GitHub REST API base URL (default: `https://api.github.com`) |
| `DT_BASE_URL` | Yes | Dependency-Track API server URL |
| `DT_API_KEY` | Yes | Dependency-Track API key (see [permissions](#dependency-track-api-key-permissions)) |
| `DT_WEBHOOK_SECRET` | No (recommended) | Signing secret of the Dependency-Track webhook alert, used to verify `X-Webhook-Signature` |
| `PORT` | No | Listen port (default: 8080) |
| `LOG_LEVEL` | No | `debug`, `info`, `warn` or `error` (default: `info`); logs are JSON on stderr |
| `KO_DOCKER_REPO` | Yes (build) | Registry to push images to |

---

## Deploying

### 1. Edit deploy/knative.yaml

Optionally set the `GITHUB_REPO` fallback, and adjust `DT_BASE_URL` to your Dependency-Track API server.

### 2. Create the secret

```bash
GITHUB_TOKEN=ghp_yourTokenHere DT_API_KEY=xxx DT_WEBHOOK_SECRET=xxx task secret
```

`DT_WEBHOOK_SECRET` is optional, but without it anyone able to reach the service inside the
cluster can make it open issues.

### 3. Log in to your registry

```bash
ko login ghcr.io -u $GITHUB_USER --password-stdin <<< $GITHUB_TOKEN
```

### 4. Build, push, and deploy in one command

```bash
KO_DOCKER_REPO=ghcr.io/myorg/dt-github-notifier task deploy
```

ko apply will cross-compile for linux/amd64 and linux/arm64, push a multi-arch manifest,
substitute the real image digest into deploy/knative.yaml, and apply it to the cluster.

### 5. Verify

```bash
task status
```

---

## GitOps / CI - render manifests without applying

```bash
KO_DOCKER_REPO=ghcr.io/myorg/dt-github-notifier task resolve > release/knative-resolved.yaml
```

The resolved file contains the full image digest so your GitOps tooling can apply it directly.

---

## Configure Dependency-Track

In Administration → Notifications → Alerts, create an alert
(see [Configuring notification alerts](https://dependencytrack.github.io/docs/next/guides/user/configuring-notifications/)):

- Scope: PORTFOLIO
- Level: INFORMATIONAL
- Publisher: Webhook (default template, *Publish Protobuf* disabled)
- Trigger: Event
- Groups: POLICY_VIOLATION, NEW_VULNERABILITY, NEW_VULNERABLE_DEPENDENCY
- Destination URL: http://dt-github-notifier.dependency-track.svc.cluster.local/webhook
- Signing Secret (Dependency-Track 5.2+): a managed secret holding the same value as `DT_WEBHOOK_SECRET`

Dependency-Track 5.2+ only connects to destinations allowed by `dt.outbound.allowed-destinations`,
so add the service host there.

### Dependency-Track API key permissions

The API key needs these read-only permissions:

- `VIEW_PORTFOLIO`, to read projects (`GET /api/v1/project/{uuid}`)
- `PORTFOLIO_MANAGEMENT_READ`, to read project properties (`GET /api/v1/project/{uuid}/property`).
  Without it, resolution via the `github`/`repo` property is skipped with a warning.

With Portfolio Access Control enabled, the key's team also needs access to the projects
(or `PORTFOLIO_ACCESS_CONTROL_BYPASS`).

---

## Scale-to-zero behavior

The service is configured with min-scale: 0. When idle for ~60 s Knative terminates all
pods. The Knative Activator wakes the service on the next request (typically 1-2 s for
this small binary). Change min-scale to 1 in deploy/knative.yaml to keep a pod always warm.

---

## GitHub token permissions

Fine-grained PAT with Repository access (the target repositories) and Issues: Read & Write.
Issues are searched (for deduplication) and created with this token.

---

## GitHub Labels

Create these labels in your repo before first use:

  security, dependency-track, policy-violation, vulnerability, vulnerable-dependency,
  severity:critical, severity:high, severity:medium, severity:low,
  violation-state:fail, violation-state:warn, violation-state:info

---

## Project structure

```
main.go                                  wiring, logging, HTTP server lifecycle
internal/config/                         configuration from environment variables
internal/webhook/                        HTTP handler: signature, parsing, status codes
internal/notification/                   Dependency-Track v5 notification payloads
internal/notification/notificationtest/  payload fixtures for tests
internal/resolver/                       project → GitHub repo resolution via the DT API
internal/issue/                          issue rendering (Markdown templates in templates/)
internal/github/                         GitHub REST API client
internal/retryable/                      transient-error marker mapped to HTTP 503
deploy/knative.yaml                      Knative Service manifest
```

## Development

```bash
task build              # compile locally
task fmt                # format the code (gofmt + goimports)
task test               # run unit tests (race detector, shuffled order)
task test:coverage      # run unit tests and open the coverage report
task check              # go.mod tidiness, golangci-lint, govulncheck
task image:update-base  # pin the ko base image to its latest digest
```

Issue bodies are rendered from the templates in `internal/issue/templates` and covered by golden
files in `internal/issue/testdata/golden`. After an intended format change, regenerate them with
`go test ./internal/issue -run TestGolden -update` and review the diff.

The parsers and sanitizers of untrusted input have fuzz tests, e.g.:

```bash
go test ./internal/resolver -run '^$' -fuzz FuzzRepoFromURL -fuzztime 30s
```

`task vuln` fails on any vulnerability in code the service calls, except those listed with a
justification in `.govulncheck-ignore`. It also reports entries that are no longer found, so the
list doesn't go stale.

CI (`.github/workflows/ci.yml`) runs `task check`, `task test` and an image build inside the same
devenv environment. Dependabot keeps Go modules and GitHub Actions up to date.

## Deployment commands

```bash
task push       # build+push image only (no deploy)
task resolve    # render manifest with real digest (for GitOps)
task deploy     # build+push+apply
task undeploy   # remove from cluster
task status     # show ksvc + pods
task logs       # tail live logs
```
