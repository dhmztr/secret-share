IMAGE ?= secret-share
TAG   ?= latest

# Override REGISTRY to push to a specific registry, e.g.:
#   make push REGISTRY=ghcr.io/youruser
#   make push REGISTRY=docker.io/youruser
REGISTRY ?=

FULL_IMAGE = $(if $(REGISTRY),$(REGISTRY)/$(IMAGE):$(TAG),$(IMAGE):$(TAG))

.PHONY: build push compose-up compose-down

## Build the Docker image locally
build:
	docker build -t $(IMAGE):$(TAG) .

## Tag and push to registry  (set REGISTRY= before calling)
push: build
	@if [ -z "$(REGISTRY)" ]; then \
		echo "Error: set REGISTRY before pushing, e.g.  make push REGISTRY=ghcr.io/youruser"; \
		exit 1; \
	fi
	docker tag $(IMAGE):$(TAG) $(FULL_IMAGE)
	docker push $(FULL_IMAGE)

## Start the full stack (app + postgres + redis) locally
compose-up:
	docker compose up --build -d

## Stop and remove containers
compose-down:
	docker compose down
