#!/usr/bin/env bash
set -euo pipefail

readonly NIX_IMAGE='nixos/nix@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c'
probe_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/heim-pc-nix-signature-probe.XXXXXX")"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$probe_root" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$probe_root/cache"
probe_port="$(
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
)"
python3 -m http.server "$probe_port"   --bind 127.0.0.1   --directory "$probe_root/cache"   >"$probe_root/http.log" 2>&1 &
server_pid="$!"
sleep 1
kill -0 "$server_pid"

docker run --rm   --network host   -e "PROBE_PORT=$probe_port"   -v "$probe_root:/probe"   "$NIX_IMAGE"   sh -c '
    set -eu
    trap "chmod -R a+rwX /probe 2>/dev/null || true" EXIT

    base_config="experimental-features = nix-command flakes
require-sigs = true
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    export NIX_CONFIG="$base_config"

    nix-store --generate-binary-cache-key       heim-pc-ci-cache-untrusted-probe-1       /probe/untrusted.sec       /probe/untrusted.pub

    builder="$(readlink -f "$(command -v sh)")"
    expr="derivation {
      name = \"heim-pc-untrusted-signature-probe\";
      system = builtins.currentSystem;
      builder = \"$builder\";
      args = [ \"-c\" \"printf probe > \\\$out\" ];
    }"
    drv="$(nix-instantiate --expr "$expr")"
    out="$(nix-store --realise "$drv")"

    nix copy --no-recursive       --to "file:///probe/cache?secret-key=/probe/untrusted.sec"       "$out"
    nix-store --delete "$out" >/dev/null

    export NIX_CONFIG="$base_config
substituters = http://127.0.0.1:$PROBE_PORT
fallback = false
max-jobs = 0"

    if nix-store --realise "$drv" >/probe/client.out 2>/probe/client.err; then
      cat /probe/client.out
      cat /probe/client.err >&2
      echo "INVALID_SIGNATURE_ACCEPTED=true" >&2
      exit 42
    fi

    cat /probe/client.err >&2
    grep -Eiq "signature|trusted key|trusted public key|not signed" /probe/client.err
    echo "INVALID_SIGNATURE_REJECTED=true"
  '
