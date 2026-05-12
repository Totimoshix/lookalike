#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIN_NODE_MAJOR=20

log() {
  printf '[install] %s\n' "$1"
}

fail() {
  printf '[install] ERROR: %s\n' "$1" >&2
  exit 1
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

refresh_shell_path() {
  export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
}

ensure_node_installed() {
  refresh_shell_path

  if has_command node && has_command npm; then
    return
  fi

  case "$(uname -s)" in
    Darwin)
      if has_command brew; then
        log "Node.js was not found. Installing Node.js via Homebrew."
        brew install node
      else
        fail "Node.js 20+ is required. Install Homebrew or install Node.js LTS from https://nodejs.org/ and run this script again."
      fi
      ;;
    Linux)
      if has_command apt-get; then
        log "Node.js was not found. Installing nodejs and npm via apt-get."
        sudo apt-get update
        sudo apt-get install -y nodejs npm
      elif has_command dnf; then
        log "Node.js was not found. Installing nodejs and npm via dnf."
        sudo dnf install -y nodejs npm
      elif has_command yum; then
        log "Node.js was not found. Installing nodejs and npm via yum."
        sudo yum install -y nodejs npm
      else
        fail "Node.js 20+ is required. Install Node.js LTS from https://nodejs.org/ and run this script again."
      fi
      ;;
    *)
      fail "Unsupported operating system. Use install.ps1 on Windows, or install Node.js 20+ manually."
      ;;
  esac

  refresh_shell_path
}

verify_node_version() {
  has_command node || fail "Node.js is still not available after installation."
  has_command npm || fail "npm is still not available after installation."

  local node_major
  node_major="$(node -p "process.versions.node.split('.')[0]")"

  if [[ "$node_major" -lt "$MIN_NODE_MAJOR" ]]; then
    fail "Node.js ${MIN_NODE_MAJOR}+ is required. Found $(node -v). Install a newer Node.js LTS release and run this script again."
  fi

  log "Using $(node -v) and $(npm -v)."
}

ensure_env_file() {
  if [[ -f "$ROOT_DIR/.env" ]]; then
    log ".env already exists. Leaving it unchanged."
    return
  fi

  if [[ -f "$ROOT_DIR/.env.example" ]]; then
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
    log "Created .env from .env.example."
  else
    log "No .env.example file found. Skipping .env creation."
  fi
}

main() {
  cd "$ROOT_DIR"

  log "Checking prerequisites."
  ensure_node_installed
  verify_node_version
  ensure_env_file

  log "Installing npm dependencies."
  npm install

  log "Building all workspaces."
  npm run build

  cat <<'EOF'

[install] Installation complete.
[install] Next steps:
[install] 1. Start the local API with: npm run start
[install] 2. Open chrome://extensions
[install] 3. Enable Developer mode
[install] 4. Load the unpacked extension from: extension/dist
[install] 5. If needed, edit .env to add optional provider keys before starting the API

EOF
}

main "$@"
