# DependencyTrack GitHub Notifier

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

These groups open an issue:

| DT Group | GitHub labels |
|---|---|
| `POLICY_VIOLATION` | `security`, `policy-violation`, `dependency-track`, `violation-state:<state>` |
| `NEW_VULNERABILITY` | `security`, `vulnerability`, `dependency-track`, `severity:<level>` |
| `NEW_VULNERABLE_DEPENDENCY` | `security`, `vulnerable-dependency`, `dependency-track` |

These groups close the open issue about a finding once it no longer needs action, with a comment
explaining why:

| DT Group | Closes the issue when | Closed as |
|---|---|---|
| `PROJECT_AUDIT_CHANGE` | a vulnerability is analyzed as `RESOLVED` | completed |
| `PROJECT_AUDIT_CHANGE` | a vulnerability is analyzed as `NOT_AFFECTED` or `FALSE_POSITIVE`, or suppressed | not planned |
| `PROJECT_AUDIT_CHANGE` | a policy violation is analyzed as `APPROVED`, or suppressed | not planned |
| `VULNERABILITY_RETRACTED` | a reported vulnerability no longer applies to the component | not planned |

Other audit decisions (`IN_TRIAGE`, `EXPLOITABLE`, `REJECTED`) leave the issue open. Issues opened
for `NEW_VULNERABLE_DEPENDENCY` cover several vulnerabilities at once, so they are not closed
automatically. A new notification for a finding whose issue was closed opens a new issue.

All other groups are acknowledged and ignored (HTTP 204).

The service expects the payload produced by the default template of the Dependency-Track v5
[Webhook publisher](https://dependencytrack.github.io/docs/next/reference/notifications/publishers/#webhook)
(groups such as `GROUP_NEW_VULNERABILITY`, subjects as described in the
[notification schema](https://dependencytrack.github.io/docs/next/reference/notifications/schema/)).
Dependency-Track v4 payloads are not supported.

### Repository resolution

Each issue is created in the GitHub repository of the affected project, resolved through the
Dependency-Track REST API in this order (limited to the sources in `REPO_SOURCES`):

1. An external reference of type `vcs` pointing to `https://github.com/<owner>/<repo>`
2. A project property with group `github`, name `repo` and value `<owner>/<repo>`
3. A project PURL of the form `pkg:github/<owner>/<repo>`
4. The same hints on the parent project, then its parent (up to 5 levels), so a whole project
   hierarchy can share one repository
5. The `GITHUB_REPO` fallback, if set

Repositories not matched by `GITHUB_ALLOWED_REPOS` are skipped, and the next hint is tried.
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
| 204 | Issue created, already open or closed; nothing to do; or notification group not handled |
| 400 | Malformed payload |
| 401 | Missing or invalid signature (when `DT_WEBHOOK_SECRET` is set) |
| 413 | Payload larger than 10 MiB |
| 422 | No allowed GitHub repository could be resolved and `GITHUB_REPO` is not set, or the repository is public and `ALLOW_PUBLIC_REPOS` is not set |
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
| `GITHUB_TOKEN` | Yes | GitHub token (see [permissions](#github-token-permissions)) |
| `GITHUB_ALLOWED_REPOS` | Yes | Repositories issues may be created in, comma-separated; `*` matches any owner or repository name, e.g. `myorg/*` or `myorg/app,myorg/lib` |
| `GITHUB_REPO` | No | Fallback repo for projects without a GitHub hint, e.g. `myorg/myrepo`; must be allowed |
| `GITHUB_API_URL` | No | GitHub REST API base URL, HTTPS only (default: `https://api.github.com`) |
| `REPO_SOURCES` | No | Project data trusted to designate a repository, comma-separated among `vcs`, `property` and `purl` (default: all) |
| `ALLOW_PUBLIC_REPOS` | No | Set to `true` to allow issues in public repositories (default: `false`) |
| `DT_BASE_URL` | Yes | Dependency-Track API server URL |
| `DT_API_KEY` | Yes | Dependency-Track API key (see [permissions](#dependency-track-api-key-permissions)) |
| `DT_WEBHOOK_SECRET` | Yes | Signing secret of the Dependency-Track webhook alert, used to verify `X-Webhook-Signature` |
| `ALLOW_UNSIGNED_WEBHOOKS` | No | Set to `true` to run without `DT_WEBHOOK_SECRET`, e.g. with Dependency-Track < 5.2 (default: `false`) |
| `PORT` | No | Listen port (default: 8080) |
| `MAX_NOTIFICATION_AGE` | No | Notifications whose ID (a UUIDv7, embedding its creation time) is older are rejected, limiting replays of captured requests; `0` disables the check (default: `24h`) |
| `LOG_LEVEL` | No | `debug`, `info`, `warn` or `error` (default: `info`); logs are JSON on stderr |

---

## Container image

CI publishes a multi-arch (linux/amd64, linux/arm64) image to
[`ghcr.io/thomasvitale/dt-github-notifier`](https://github.com/ThomasVitale/dt-github-notifier/pkgs/container/dt-github-notifier),
only after checks and tests pass:

| Trigger | Tags |
|---|---|
| Push to `main` | `main`, `sha-<commit>` |
| Version tag `vX.Y.Z` | `X.Y.Z`, `latest`, plus a GitHub release |

Every image carries an SPDX SBOM, a keyless [cosign](https://github.com/sigstore/cosign) signature
and a build provenance attestation, all tied to this repository's CI workflow. Verify them with:

```bash
cosign verify ghcr.io/thomasvitale/dt-github-notifier:<version> \
  --certificate-identity-regexp '^https://github.com/ThomasVitale/dt-github-notifier/\.github/workflows/ci\.yml@refs/(heads/main|tags/v.+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/thomasvitale/dt-github-notifier:<version> \
  --repo ThomasVitale/dt-github-notifier
```

To publish a release, push a version tag:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

---

## Deploying

### 1. Create the secret

```bash
task secret
```

It prompts for the GitHub token, the Dependency-Track API key and the webhook signing secret
(generate one with `openssl rand -hex 32` and configure the same value in Dependency-Track), unless
they are set as `GITHUB_TOKEN`, `DT_API_KEY` and `DT_WEBHOOK_SECRET`. The values never appear in
shell history or process arguments.

Then set `GITHUB_ALLOWED_REPOS` in `deploy/knative.yaml` (or the release's `knative.yaml`) to the
repositories issues may be created in.

### 2. Deploy a release

Each GitHub release has a `knative.yaml` asset: `deploy/knative.yaml` with the image pinned by
digest. Download it, adjust it if needed (`DT_BASE_URL`, the optional `GITHUB_REPO` fallback),
and apply it, or commit it to your GitOps repository:

```bash
curl -fsSLO https://github.com/ThomasVitale/dt-github-notifier/releases/download/v1.0.0/knative.yaml
kubectl apply -f knative.yaml
```

### 3. Verify

```bash
task status
```

### Building and deploying your own image

To deploy local changes, build and push the image with ko and apply `deploy/knative.yaml` in one
step. The image coordinates are Task variables (`REGISTRY`, `IMAGE`, `VERSION`), so you can
publish to your own registry:

```bash
ko login ghcr.io -u $GITHUB_USER --password-stdin <<< $GITHUB_TOKEN
task deploy IMAGE=myorg/dt-github-notifier
```

ko cross-compiles for linux/amd64 and linux/arm64, pushes a multi-arch image tagged `dev` (`latest`
is reserved for releases), substitutes its digest into the manifest, and applies it. To render the
manifest without applying it:

```bash
task resolve IMAGE=myorg/dt-github-notifier > knative-resolved.yaml
```

---

## Configure Dependency-Track

In Administration → Notifications → Alerts, create an alert
(see [Configuring notification alerts](https://dependencytrack.github.io/docs/next/guides/user/configuring-notifications/)):

- Scope: PORTFOLIO
- Level: INFORMATIONAL
- Publisher: Webhook (default template, *Publish Protobuf* disabled)
- Trigger: Event
- Groups: POLICY_VIOLATION, NEW_VULNERABILITY, NEW_VULNERABLE_DEPENDENCY, and, to close issues
  automatically, PROJECT_AUDIT_CHANGE and VULNERABILITY_RETRACTED
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

Fine-grained PAT with Repository access limited to the target repositories, and Issues: Read &
Write (Metadata: Read is included automatically). The token is used to check repository
visibility, search for existing issues (for deduplication) and create issues. Its repository
access is the ultimate bound on where issues can be created, so keep it as narrow as
`GITHUB_ALLOWED_REPOS`.

Issues are authored by the token's owner. A dedicated machine account (or, in the future, a
GitHub App) avoids attributing them to a person.

---

## GitHub Labels

Create these labels in your repo before first use:

  security, dependency-track, policy-violation, vulnerability, vulnerable-dependency,
  severity:critical, severity:high, severity:medium, severity:low,
  violation-state:fail, violation-state:warn, violation-state:info

---

## Security

The service handles untrusted input: notifications, and Dependency-Track project and vulnerability
data that anyone able to upload a BOM can influence. It is designed to fail closed:

- **Authentication**: notifications must carry a valid HMAC signature (`DT_WEBHOOK_SECRET`),
  verified in constant time before parsing. Bodies are limited to 1 MiB and pods to 10
  concurrent requests, bounding memory use.
- **Routing**: BOM uploads set a project's `vcs` reference and PURL, so issues are only created in
  repositories matched by `GITHUB_ALLOWED_REPOS`. To trust only portfolio managers, set
  `REPO_SOURCES=property`.
- **Disclosure**: issues expose unfixed vulnerabilities and internal project inventory, so public
  repositories are refused unless `ALLOW_PUBLIC_REPOS=true`. Consider GitHub's private
  vulnerability reporting for public projects instead.
- **Content**: values from Dependency-Track are rendered as inline code or fenced code blocks, so
  they cannot add links, images, HTML, @-mentions or #references, and titles are neutralized.
- **Transport**: the GitHub API is HTTPS only. The default `DT_BASE_URL` is plain HTTP inside the
  cluster, which exposes the Dependency-Track API key to anyone able to observe pod traffic; prefer
  HTTPS or a service mesh with mTLS.
- **Network**: `deploy/networkpolicy.yaml` is a starting point for restricting egress to DNS,
  Dependency-Track and GitHub. Test it in your cluster before applying it.
- **Kubernetes**: the container runs as non-root with a read-only root filesystem and no
  capabilities, and no service account token is mounted, since the service never calls the
  Kubernetes API.
- **Replays**: Dependency-Track's signature has no timestamp, so notifications older than
  `MAX_NOTIFICATION_AGE` (by the time embedded in their ID) are rejected, and deduplication keeps a
  replayed notification from opening a second issue while the first is open.
- **Logs**: secrets are never logged. Logs contain notification titles, repositories, issue URLs
  and the source address of rejected requests; Dependency-Track error responses are truncated.

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
task deps:update        # update the devenv inputs and pin the base image (both)
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

CI (`.github/workflows/ci.yml`) only calls Task tasks, inside the same devenv environment as local
development: `task check`, `task test` and `task image:build PUSH=false` on every change, then
`image:build`, `image:sign` and `release:manifest` to publish.

Dependabot keeps Go modules and GitHub Actions up to date. A weekly workflow
(`.github/workflows/update.yml`) runs `task deps:update` for the rest (the devenv inputs, including
Go, and the base image digest), verifies the result with `task check` and `task test`, and opens a
pull request. It requires "Allow GitHub Actions to create and approve pull requests" in the
repository settings. Pull requests opened by GitHub Actions do not trigger CI: close and reopen
them to run it.

## Deployment commands

```bash
task image:build       # build+push image only (no deploy); PUSH=false only builds it
task image:sign        # sign the published image with cosign
task release:manifest  # render deploy/knative.yaml with the published image pinned by digest
task resolve           # build+push, render manifest with real digest (for GitOps)
task deploy            # build+push+apply
task undeploy          # remove from cluster
task status            # show ksvc + pods
task logs              # tail live logs
```
