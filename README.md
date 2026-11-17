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
4. The `GITHUB_REPO` fallback, if set

### Responses and retries

Dependency-Track retries a webhook that answers with 429, 502, 503 or 504, honouring
`Retry-After`, and gives up on any other error. The service answers accordingly:

| Status | When |
|---|---|
| 204 | Issue created, or notification group not handled |
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
| [devenv](https://devenv.sh/getting-started/) | Reproducible development environment (Go, ko, kubectl, Task) |
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
| `KO_DOCKER_REPO` | Yes (build) | Registry to push images to |

---

## Deploying

### 1. Edit knative.yaml

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
substitute the real image digest into knative.yaml, and apply it to the cluster.

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

## Scale-to-zero behaviour

The service is configured with min-scale: 0. When idle for ~60 s Knative terminates all
pods. The Knative Activator wakes the service on the next request (typically 1-2 s for
this small binary). Change min-scale to 1 in knative.yaml to keep a pod always warm.

---

## GitHub token permissions

Fine-grained PAT with Repository access (target repo only) and Issues: Read & Write.

---

## GitHub Labels

Create these labels in your repo before first use:

  security, dependency-track, policy-violation, vulnerability, vulnerable-dependency,
  severity:critical, severity:high, severity:medium, severity:low,
  violation-state:fail, violation-state:warn, violation-state:info

---

## Useful commands

```bash
task build      # compile locally
task test       # run tests
task push       # build+push image only (no deploy)
task resolve    # render manifest with real digest (for GitOps)
task deploy     # build+push+apply
task undeploy   # remove from cluster
task status     # show ksvc + pods
task logs       # tail live logs
```
