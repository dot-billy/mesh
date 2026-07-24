.PHONY: build test docs api-docs pages pages-check docs-check api-docs-check docs-change-gate desktop-check desktop-linux-build desktop-linux-package vet security-baseline image-security-baseline observer-security-baseline origin-image-security-baseline linux-package-security-baseline windows-package-security-baseline darwin-package-security-baseline smoke oidc-breakglass-smoke packet-smoke ui-guided-packet-smoke network-dns-smoke native-dns-smoke network-relay-smoke network-ca-rotation-smoke network-firewall-rollout-smoke routed-subnet-smoke route-transfer-smoke route-profile-smoke route-ecmp-smoke ui-guided-linux-package-smoke backup-restore-smoke nebula-observer-smoke nebula-observer-overlay-smoke nebula-public-endpoint-smoke postgres-multi-replica-smoke postgres-load-soak-smoke postgres-max-document-smoke postgres-sync-failover-smoke postgres-ambiguous-commit-smoke postgres-pitr-smoke postgres-roles-tls-smoke linux-install-smoke bootstrap-verifier-smoke windows-bundle-smoke darwin-bundle-smoke darwin-path-security-smoke darwin-native-runtime-smoke helm-chart-smoke release-origin-helm-smoke helm-runtime-smoke helm-kubernetes-smoke compose-smoke release-origin-smoke dev

build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/mesh-server ./cmd/mesh-server
	go build -buildvcs=false -trimpath -o bin/meshctl ./cmd/meshctl
	go build -buildvcs=false -trimpath -o bin/mesh-install ./cmd/mesh-install
	go build -buildvcs=false -trimpath -o bin/mesh-release ./cmd/mesh-release
	go build -buildvcs=false -trimpath -o bin/mesh-deps ./cmd/mesh-deps
	go build -buildvcs=false -trimpath -o bin/mesh-package ./cmd/mesh-package
	go build -buildvcs=false -trimpath -o bin/mesh-backup ./cmd/mesh-backup
	go build -buildvcs=false -trimpath -o bin/mesh-storage ./cmd/mesh-storage
	go build -buildvcs=false -trimpath -o bin/mesh-healthcheck ./cmd/mesh-healthcheck
	go build -buildvcs=false -trimpath -o bin/mesh-kube-init ./cmd/mesh-kube-init
	go build -buildvcs=false -trimpath -o bin/mesh-origin ./cmd/mesh-origin
	go build -buildvcs=false -trimpath -o bin/mesh-origin-audit ./cmd/mesh-origin-audit
	go build -buildvcs=false -trimpath -o bin/mesh-origin-image-verify ./cmd/mesh-origin-image-verify
	go build -buildvcs=false -trimpath -o bin/mesh-origin-runtime-verify ./cmd/mesh-origin-runtime-verify
	go build -buildvcs=false -trimpath -o bin/mesh-bootstrap-verify ./cmd/mesh-bootstrap-verify

test: docs-check
	go test ./...

docs:
	python3 scripts/generate-public-docs.py
	python3 scripts/generate-api-docs.py

api-docs:
	python3 scripts/generate-api-docs.py

pages:
	python3 scripts/build-pages-site.py

pages-check:
	python3 scripts/pages_site_test.py

docs-check:
	python3 scripts/generate-public-docs.py --check
	python3 scripts/generate-api-docs.py --check
	python3 scripts/public_docs_test.py
	python3 scripts/api_docs_test.py
	python3 scripts/pages_site_test.py

api-docs-check:
	python3 scripts/generate-api-docs.py --check
	python3 scripts/api_docs_test.py

docs-change-gate:
	test -n "$(BASE_REF)"
	test -n "$(HEAD_REF)"
	python3 scripts/public-docs-change-gate.py --base "$(BASE_REF)" --head "$(HEAD_REF)"
	python3 scripts/api-docs-change-gate.py --base "$(BASE_REF)" --head "$(HEAD_REF)"

desktop-check:
	cd desktop && dart pub get --enforce-lockfile
	cd desktop && dart format --output=none --set-exit-if-changed lib test
	cd desktop && flutter analyze
	cd desktop && flutter test

desktop-linux-build: desktop-check
	cd desktop && flutter build linux --release

desktop-linux-package: desktop-linux-build
	./packaging/desktop/linux/build-deb.sh desktop/build/linux/x64/release/bundle

vet:
	go vet ./...

security-baseline:
	./scripts/security-baseline.sh

image-security-baseline:
	./scripts/image-security-baseline.sh

observer-security-baseline:
	./scripts/observer-security-baseline.sh

origin-image-security-baseline:
	./scripts/origin-image-security-baseline.sh

linux-package-security-baseline:
	./scripts/linux-package-security-baseline.sh "$(BUNDLE)"

windows-package-security-baseline:
	./scripts/windows-package-security-baseline.sh "$(BUNDLE)"

darwin-package-security-baseline:
	./scripts/darwin-package-security-baseline.sh "$(BUNDLE)"

smoke: build
	./scripts/lifecycle-smoke.sh

oidc-breakglass-smoke:
	./scripts/oidc-breakglass-smoke.sh

packet-smoke: build
	./scripts/packet-smoke.sh

ui-guided-packet-smoke: build
	./scripts/ui-guided-packet-smoke.sh

network-dns-smoke: build
	./scripts/ui-guided-dns-smoke.sh

native-dns-smoke: build
	./scripts/native-dns-smoke.sh

network-relay-smoke: build
	./scripts/ui-guided-relay-smoke.sh

network-ca-rotation-smoke: build
	./scripts/ui-guided-ca-rotation-smoke.sh

network-firewall-rollout-smoke: build
	./scripts/ui-guided-firewall-rollout-smoke.sh

routed-subnet-smoke: build
	./scripts/ui-guided-routed-subnet-smoke.sh

route-transfer-smoke: build
	./scripts/routed-subnet-transfer-smoke.sh

route-profile-smoke: build
	./scripts/routed-subnet-profile-smoke.sh

route-ecmp-smoke: build
	./scripts/routed-subnet-ecmp-smoke.sh

backup-restore-smoke: build
	./scripts/backup-restore-smoke.sh

nebula-observer-smoke:
	./scripts/nebula-observer-prototype-smoke.sh

nebula-observer-overlay-smoke:
	./scripts/nebula-observer-overlay-smoke.sh

nebula-public-endpoint-smoke:
	./scripts/nebula-public-endpoint-smoke.sh

# Builds its own clean-room binaries and uses one exact disposable PostgreSQL
# container; exit 77 means a local prerequisite is unavailable.
postgres-multi-replica-smoke:
	./scripts/postgres-multi-replica-smoke.sh

# Builds its own clean-room binaries and uses one 2-CPU/512-MiB PostgreSQL 17
# primary plus two real app replicas; exit 77 means a prerequisite is absent.
postgres-load-soak-smoke:
	./scripts/postgres-load-soak-smoke.sh

# Builds a validator-created 62-63 MiB control graph and 7-7.5 MiB identity
# graph, pads them with legal JSON whitespace to their exact 64/8 MiB storage
# ceilings, and exercises one exact labeled capped PostgreSQL 17 authority.
postgres-max-document-smoke:
	./scripts/postgres-max-document-smoke.sh

# Builds its own clean-room binaries and uses one exact labeled PostgreSQL 17
# primary/physical-standby pair; exit 77 means a local prerequisite is unavailable.
postgres-sync-failover-smoke:
	./scripts/postgres-sync-failover-smoke.sh

# Uses exact labeled PostgreSQL 17 primary/standby/divergent authorities and a
# package-internal deterministic commit-boundary harness; exit 77 means a local
# prerequisite is unavailable.
postgres-ambiguous-commit-smoke:
	./scripts/postgres-ambiguous-commit-smoke.sh

# Builds its own clean-room binaries and uses exact labeled PostgreSQL 17
# base-backup, archived-WAL, and isolated recovery resources; exit 77 means a
# local prerequisite is unavailable.
postgres-pitr-smoke:
	./scripts/postgres-pitr-smoke.sh

# Uses exact labeled PostgreSQL 17 and Ubuntu 24.04 containers to prove the
# documented roles and isolated Linux system-trust-path TLS boundary; exit 77
# means a local prerequisite is unavailable.
postgres-roles-tls-smoke:
	./scripts/postgres-roles-tls-smoke.sh

linux-install-smoke:
	./scripts/linux-install-smoke.sh

bootstrap-verifier-smoke:
	./scripts/bootstrap-verifier-smoke.sh

ui-guided-linux-package-smoke:
	./scripts/ui-guided-linux-package-smoke.sh

windows-bundle-smoke:
	./scripts/windows-bundle-smoke.sh

darwin-bundle-smoke:
	./scripts/darwin-bundle-smoke.sh

darwin-path-security-smoke:
	./scripts/darwin-path-security-smoke.sh

darwin-native-runtime-smoke:
	./scripts/darwin-native-runtime-smoke.sh

helm-chart-smoke:
	./scripts/helm-chart-smoke.sh

release-origin-helm-smoke:
	./scripts/release-origin-helm-smoke.sh

helm-runtime-smoke:
	./scripts/helm-runtime-smoke.sh

helm-kubernetes-smoke:
	./scripts/helm-kubernetes-smoke.sh

compose-smoke:
	./scripts/compose-smoke.sh

release-origin-smoke:
	./scripts/release-origin-smoke.sh

dev:
	go run ./cmd/mesh-server --dev
