#!/usr/bin/env bash
#
# One-command deploy for the vid-transfer relay.
#
#   scripts/deploy.sh fly       # Fly.io   (recommended)
#   scripts/deploy.sh railway   # Railway
#   scripts/deploy.sh docker    # local docker run on :8080
#
# Run from the repository root or anywhere — it cd's into relay/ itself.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAY_DIR="$ROOT/relay"
TARGET="${1:-help}"

cd "$RELAY_DIR"

ok()    { printf '\033[32m[ ok ]\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
err()   { printf '\033[31m[err ]\033[0m %s\n' "$*" >&2; }
info()  { printf '\033[36m[info]\033[0m %s\n' "$*"; }
step()  { printf '\033[1;36m[step]\033[0m %s\n' "$*"; }

# --- preflight: make sure the dist/ build is current ------------------
step "building relay"
npm install --silent
npm run build --silent
ok "relay/dist/ ready"

case "$TARGET" in

  fly)
    if ! command -v fly >/dev/null 2>&1; then
      err "fly CLI not found. Install: brew install flyctl  (or curl -L https://fly.io/install.sh | sh)"
      exit 1
    fi
    if ! fly auth whoami >/dev/null 2>&1; then
      info "you are not logged in. running 'fly auth login'..."
      fly auth login
    fi

    APP="${VIDX_FLY_APP:-}"
    if [ -z "$APP" ]; then
      info "pick an app name (lowercase, dashes ok). example: vid-transfer-relay-$RANDOM"
      printf "app name: "
      read -r APP
    fi
    [ -n "$APP" ] || { err "app name required"; exit 1; }

    if fly apps list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$APP"; then
      info "app '$APP' already exists; deploying to it"
    else
      step "creating app '$APP'"
      fly apps create "$APP" --org "${VIDX_FLY_ORG:-personal}"
    fi

    # Sync the local fly.toml with the chosen app name. We mutate in place
    # because Fly resolves `dockerfile = "Dockerfile"` relative to the toml's
    # directory, so a /tmp copy can't see relay/Dockerfile. The change is
    # idempotent and trivially diff-able if the user wants to revert.
    CURRENT_APP="$(awk -F'"' '/^app = /{print $2; exit}' fly.toml || true)"
    if [ "$CURRENT_APP" != "$APP" ]; then
      step "updating relay/fly.toml: app = \"$APP\" (was \"$CURRENT_APP\")"
      # macOS-portable in-place edit (BSD vs. GNU sed both accept `-i ''` or `-i.bak`).
      sed -i.bak "s/^app = .*/app = \"$APP\"/" fly.toml && rm -f fly.toml.bak
    fi

    step "deploying"
    fly deploy --app "$APP" --ha=false

    URL="https://$APP.fly.dev"
    ok "deployed to $URL"
    info "verify health:"
    info "  curl $URL/healthz"
    info "  curl $URL/v1/info"
    info "use it from the CLI:"
    info "  export VIDX_RELAY=$URL"
    info "  vid-transfer doctor"
    info ""
    info "next: bake this URL in as the CLI's default:"
    info "  sed -i.bak 's|relay.vidtransfer.dev|${URL#https://}|' \\"
    info "    ../cli/src/relay.h ../cli/src/commands/cmd_init.c"
    info "  make -C ../cli release"
    ;;

  railway)
    if ! command -v railway >/dev/null 2>&1; then
      err "railway CLI not found. Install: brew install railway  (or npm i -g @railway/cli)"
      exit 1
    fi
    if ! railway whoami >/dev/null 2>&1; then
      railway login
    fi

    if [ ! -f .railway/project.json ] && [ ! -f .railway/config.json ]; then
      step "linking a railway project"
      railway init --name vid-transfer-relay
    fi

    step "deploying"
    railway up --detach

    info "after deploy, get the URL with:  railway domain"
    ;;

  docker)
    if ! command -v docker >/dev/null 2>&1; then
      err "docker not found"; exit 1
    fi
    step "building image"
    docker build -t vid-transfer-relay:local .

    NAME="${VIDX_DOCKER_NAME:-vid-transfer-relay}"
    PORT="${VIDX_PORT:-8080}"

    docker rm -f "$NAME" 2>/dev/null || true
    step "running container '$NAME' on http://127.0.0.1:$PORT"
    docker run -d --name "$NAME" \
      -p "$PORT:8080" \
      -e VIDX_SESSION_TTL_SEC=300 \
      -e VIDX_MAX_CIPHERTEXT=327680 \
      --read-only --tmpfs /tmp \
      --security-opt no-new-privileges \
      --user 1000 \
      vid-transfer-relay:local

    sleep 1
    if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null; then
      ok "running on http://127.0.0.1:$PORT"
      info "logs: docker logs -f $NAME"
      info "stop: docker rm -f $NAME"
    else
      warn "container started but /healthz did not respond yet — try: docker logs $NAME"
    fi
    ;;

  help|--help|-h|"")
    cat <<EOF
Usage: scripts/deploy.sh <target>

Targets:
  fly       Deploy to Fly.io (recommended). Set VIDX_FLY_APP / VIDX_FLY_ORG
            to skip prompts. Requires the 'fly' CLI and an account.
  railway   Deploy to Railway. Requires the 'railway' CLI and a project.
  docker    Build the image and run locally on \$VIDX_PORT (default 8080).

Examples:
  VIDX_FLY_APP=vid-transfer-acme scripts/deploy.sh fly
  scripts/deploy.sh railway
  VIDX_PORT=9090 scripts/deploy.sh docker

After deploy, point the CLI at the URL:
  export VIDX_RELAY=https://your-relay.example
  vid-transfer doctor
EOF
    ;;

  *)
    err "unknown target: $TARGET"
    echo "run 'scripts/deploy.sh help' for options" >&2
    exit 2
    ;;
esac
