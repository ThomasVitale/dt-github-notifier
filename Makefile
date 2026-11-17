##
## dt-github-notifier — Makefile
## Requires: ko (https://ko.build/install/), kubectl, kustomize (optional)
##

# Your container registry. Override on the command line or via env.
# e.g.  KO_DOCKER_REPO=ghcr.io/myorg/dt-github-notifier make deploy
KO_DOCKER_REPO ?= ghcr.io/yourorg/dt-github-notifier

# Platforms to build for. Override with e.g. --platform=all
KO_DEFAULTPLATFORMS ?= linux/amd64,linux/arm64

export KO_DOCKER_REPO
export KO_DEFAULTPLATFORMS

.PHONY: build push resolve deploy undeploy secret fmt vet test help

## build: compile locally (no image push) — useful to catch errors fast
build:
	go build ./...

## fmt: run gofmt
fmt:
	gofmt -w .

## vet: run go vet
vet:
	go vet ./...

## test: run unit tests
test:
	go test -race ./...

## push: build multi-arch image and push to registry (no deploy)
push:
	ko build --platform=$(KO_DEFAULTPLATFORMS) --bare .

## resolve: render knative.yaml with the real image digest substituted in
## Useful for GitOps — commit the output to your manifest repo.
resolve:
	ko resolve --platform=$(KO_DEFAULTPLATFORMS) --bare -f knative.yaml

## deploy: build, push, and apply the Knative Service to the cluster
deploy:
	ko apply --platform=$(KO_DEFAULTPLATFORMS) --bare -f knative.yaml

## undeploy: remove the Knative Service from the cluster
undeploy:
	kubectl delete -f knative.yaml --ignore-not-found

## secret: create the GitHub token + DT API key secret (run once)
## Usage: GITHUB_TOKEN=ghp_xxx DT_API_KEY=xxx make secret
secret:
	@test -n "$(GITHUB_TOKEN)" || (echo "ERROR: GITHUB_TOKEN is not set" && exit 1)
	@test -n "$(DT_API_KEY)"    || (echo "ERROR: DT_API_KEY is not set" && exit 1)
	kubectl create secret generic dt-github-notifier-secret \
		--from-literal=github-token=$(GITHUB_TOKEN) \
		--from-literal=dt-api-key=$(DT_API_KEY) \
		--namespace dependency-track \
		--dry-run=client -o yaml | kubectl apply -f -

## status: show the Knative Service status
status:
	kubectl get ksvc dt-github-notifier -n dependency-track
	@echo ""
	kubectl get pods -n dependency-track -l serving.knative.dev/service=dt-github-notifier

## logs: tail logs from the bridge (works even with scale-to-zero)
logs:
	kubectl logs -n dependency-track -l serving.knative.dev/service=dt-github-notifier \
		-c bridge --tail=100 -f

## help: print this help
help:
	@grep -E '^##' Makefile | sed 's/## //'
