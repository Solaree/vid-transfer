# Top-level convenience targets. The CLI Makefile and the relay's npm
# scripts are the source of truth; this file just chains them.

.PHONY: all cli relay relay-build relay-dev clean test e2e

all: cli relay-build

cli:
	$(MAKE) -C cli

relay-build:
	cd relay && npm install --silent && npm run build

relay-dev:
	cd relay && npm run dev

clean:
	$(MAKE) -C cli clean
	rm -rf relay/dist relay/node_modules

# End-to-end: builds CLI + relay if needed, then runs scripts/e2e.sh.
test e2e: cli relay-build
	bash scripts/e2e.sh
