#!/usr/bin/env bash
#
# Source-install vid-transfer CLI from the working tree.
#
#   curl -fsSL https://your-host/scripts/install.sh | bash
#
# Or, from a clone:
#
#   bash scripts/install.sh                # /usr/local/bin (sudo if needed)
#   PREFIX=$HOME/.local bash scripts/install.sh
#
# The script:
#   1. ensures libsodium + libcurl + pkg-config are available,
#   2. builds cli/build/vid-transfer,
#   3. installs into $PREFIX/bin (default /usr/local).
#
# This is intentionally a build-from-source flow rather than a curl-pipe-bash
# of an opaque binary; for a security tool, you want to read what you ran.

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI_DIR="$ROOT/cli"

ok()    { printf '\033[32m[ ok ]\033[0m %s\n' "$*"; }
err()   { printf '\033[31m[err ]\033[0m %s\n' "$*" >&2; }
info()  { printf '\033[36m[info]\033[0m %s\n' "$*"; }
step()  { printf '\033[1;36m[step]\033[0m %s\n' "$*"; }

step "checking dependencies"
need_pkg=()
for pkg in libsodium libcurl; do
  if ! pkg-config --exists "$pkg" 2>/dev/null; then
    need_pkg+=("$pkg")
  fi
done

if [ "${#need_pkg[@]}" -gt 0 ]; then
  case "$(uname -s)" in
    Darwin)
      info "installing via brew: ${need_pkg[*]}"
      command -v brew >/dev/null || { err "brew not found and ${need_pkg[*]} is missing"; exit 1; }
      # libsodium maps directly; libcurl is part of macOS but still detect via pkg-config
      brew install libsodium curl pkg-config
      ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        info "apt-get install libsodium-dev libcurl4-openssl-dev pkg-config"
        sudo apt-get update -qq
        sudo apt-get install -y libsodium-dev libcurl4-openssl-dev pkg-config build-essential
      elif command -v dnf >/dev/null 2>&1; then
        info "dnf install libsodium-devel libcurl-devel pkgconf gcc make"
        sudo dnf install -y libsodium-devel libcurl-devel pkgconf gcc make
      elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm libsodium curl pkgconf base-devel
      else
        err "unsupported distro; install: ${need_pkg[*]} dev headers + build tools manually"
        exit 1
      fi
      ;;
    *)
      err "unsupported OS: $(uname -s); install ${need_pkg[*]} manually"
      exit 1
      ;;
  esac
fi
ok "deps satisfied"

step "building CLI"
make -C "$CLI_DIR" release

DEST="$PREFIX/bin/vid-transfer"
mkdir -p "$PREFIX/bin" 2>/dev/null || sudo mkdir -p "$PREFIX/bin"

step "installing to $DEST"
if [ -w "$(dirname "$DEST")" ]; then
  install -m 0755 "$CLI_DIR/build/vid-transfer" "$DEST"
else
  sudo install -m 0755 "$CLI_DIR/build/vid-transfer" "$DEST"
fi
ok "installed: $DEST"

"$DEST" --version
echo
info "next: verify connectivity to the public relay"
info "  vid-transfer doctor"
info "  (or override with: export VIDX_RELAY=https://your-self-hosted-relay)"
