# dt-github-notifier

A lightweight Go service that receives [Dependency-Track](https://dependencytrack.org/) webhook
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
| `POLICY_VIOLATION` | `policy-violation`, `dependency-track`, `violation-state:<state>` |
| `NEW_VULNERABILITY` | `vulnerability`, `dependency-track`, `severity:<level>` |
| `NEW_VULNERABLE_DEPENDENCY` | `vulnerable-dependency`, `dependency-track` |

All other groups are acknowledged silently (HTTP 204).

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
| `GITHUB_REPO` | Yes | Target repo, e.g. myorg/myrepo |
| `PORT` | No | Listen port (default: 8080) |
| `KO_DOCKER_REPO` | Yes (build) | Registry to push images to |

---

## Deploying

### 1. Edit knative.yaml

Change the GITHUB_REPO env value to your repo.

### 2. Create the GitHub token secret

```bash
GITHUB_TOKEN=ghp_yourTokenHere DT_API_KEY=xxx task secret
```

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

In Administration -> Notifications, create a new rule:

- Scope: PORTFOLIO
- Level: INFORMATIONAL
- Publisher: Outbound Webhook
- Groups: POLICY_VIOLATION, NEW_VULNERABILITY, NEW_VULNERABLE_DEPENDENCY
- Destination: http://dt-github-notifier.dependency-track.svc.cluster.local/webhook

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
